use anyhow::Result;
use serde_json::Value;
use tokio::sync::mpsc;

use super::memory::{
    CallSignature, WorkingMemory, clip_tool_result, extract_facts_from_tool_result, normalize_args,
};
use super::stream::{AgentEvent, ReportKind};
use super::tools::{ToolContext, ToolRegistry};

/// Maximum real tool-executing rounds. The model should never hear about this
/// number — it exists purely as a backstop against runaway loops.
const MAX_TOOL_STEPS: u32 = 25;

/// Max total LLM calls. Includes parse-failure retries, so gives slack
/// over MAX_TOOL_STEPS for things like empty responses or repeat-call
/// corrections that don't consume a real step. Inspired by Raschka's
/// dual-counter pattern.
const MAX_ATTEMPTS: u32 = 35;

/// How many consecutive empty/no-data tool results before escalating.
const DEAD_END_THRESHOLD: u32 = 4;

/// Decide whether a given investigation state represents a final or
/// preliminary report. A final report requires an unescalated run with at
/// least one confirmed fact and at least one suspect service. Anything less
/// rigorous is surfaced as preliminary so the user knows to follow up.
fn decide_report_kind(memory: &WorkingMemory) -> ReportKind {
    if memory.escalation_level < 2
        && !memory.confirmed_facts.is_empty()
        && !memory.suspect_services.is_empty()
    {
        ReportKind::Final
    } else {
        ReportKind::Preliminary
    }
}

/// Configuration for the LLM client used by the agent loop.
/// Decoupled from env vars so tests can point at a mock server.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

impl LlmConfig {
    /// Construct from environment variables:
    /// - LLM_BASE_URL (default: https://api.openai.com)
    /// - LLM_API_KEY (required)
    /// - LLM_MODEL (default: gpt-4o)
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            base_url: std::env::var("LLM_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".to_string()),
            api_key: std::env::var("LLM_API_KEY")
                .map_err(|_| anyhow::anyhow!("LLM_API_KEY not set"))?,
            model: std::env::var("LLM_MODEL").unwrap_or_else(|_| "gpt-4o".to_string()),
        })
    }
}

/// Run the agent investigation loop, sending events to the channel.
pub async fn run(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
) -> Result<()> {
    run_with_config(messages, registry, ctx, tx, LlmConfig::from_env()?).await
}

/// Run the agent loop with an explicit LLM configuration.
pub async fn run_with_config(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
    llm: LlmConfig,
) -> Result<()> {
    let base_url = llm.base_url;
    let api_key = llm.api_key;
    let model = llm.model;

    let client = reqwest::Client::new();
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));

    let mut messages = messages;

    // Extract the initial user task for working memory
    let initial_task = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|v| v.as_str()) == Some("user"))
        .and_then(|m| m.get("content").and_then(|v| v.as_str()))
        .unwrap_or("")
        .chars()
        .take(300)
        .collect::<String>();

    let mut memory = WorkingMemory::new(initial_task);

    let mut total_prompt = 0u64;
    let mut total_completion = 0u64;

    let mut tool_steps = 0u32;
    let mut attempts = 0u32;
    let mut force_summary = false;

    while tool_steps < MAX_TOOL_STEPS && attempts < MAX_ATTEMPTS {
        attempts += 1;

        // Inject working memory as a system message if we have facts to share.
        // This is a fresh view each iteration — the memory persists across compaction.
        let mut turn_messages = messages.clone();
        if !memory.confirmed_facts.is_empty()
            || !memory.suspect_services.is_empty()
            || !memory.ruled_out.is_empty()
        {
            turn_messages.push(serde_json::json!({
                "role": "system",
                "content": memory.to_prompt_block(),
            }));
        }

        // Final round or dead-end: force summary by withholding tools
        let force_final = tool_steps + 1 >= MAX_TOOL_STEPS || force_summary;
        let tools = if force_final {
            None
        } else {
            Some(registry.definitions())
        };

        let mut body = serde_json::json!({
            "model": model,
            "messages": turn_messages,
            "stream": true,
            "stream_options": { "include_usage": true },
        });
        if let Some(tools) = &tools {
            body["tools"] = Value::Array(tools.clone());
        }

        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            let msg = format!(
                "LLM returned {status}: {}",
                &err_body[..err_body.len().min(500)]
            );
            let _ = tx
                .send(AgentEvent::Error {
                    message: msg.clone(),
                })
                .await;
            return Err(anyhow::anyhow!(msg));
        }

        let (content, tool_calls, usage) = parse_streaming_response(resp, tx).await?;
        total_prompt += usage.0;
        total_completion += usage.1;

        // --- Classify response ---
        if tool_calls.is_empty() {
            if content.trim().is_empty() {
                // Parse-retry: empty response, no tools — inject retry notice and loop
                messages.push(serde_json::json!({
                    "role": "system",
                    "content": "Previous response was empty. Either call a tool to gather more \
                               evidence or produce a structured investigation report.",
                }));
                continue;
            }
            // Final answer
            let kind = decide_report_kind(&memory);
            let _ = tx
                .send(AgentEvent::Summary {
                    text: content.clone(),
                    kind,
                })
                .await;
            let _ = tx
                .send(AgentEvent::Done {
                    rounds: tool_steps + 1,
                    prompt_tokens: total_prompt,
                    completion_tokens: total_completion,
                })
                .await;
            return Ok(());
        }

        // Record assistant message with tool calls
        let tc_value: Vec<Value> = tool_calls
            .iter()
            .map(|tc| {
                serde_json::json!({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }
                })
            })
            .collect();

        let mut assistant_msg = serde_json::json!({
            "role": "assistant",
            "tool_calls": tc_value,
        });
        if !content.is_empty() {
            assistant_msg["content"] = Value::String(content);
        }
        messages.push(assistant_msg);

        // Execute each tool call (usually just one per round)
        let mut any_real_work = false;
        for tc in &tool_calls {
            let args: Value = serde_json::from_str(&tc.arguments).unwrap_or(Value::Null);

            let _ = tx
                .send(AgentEvent::ToolCall {
                    name: tc.name.clone(),
                    args: args.clone(),
                })
                .await;

            // Repeat-call detection — return structured error, don't execute
            let sig = CallSignature {
                tool: tc.name.clone(),
                args_normalized: normalize_args(&args),
            };
            let is_repeat = memory.is_repeat_call(&sig);

            let result = if is_repeat {
                format!(
                    "Error: this exact tool call was already made in this investigation. \
                     Do not repeat identical queries. Options:\n\
                     - Vary the time window, service, or filters\n\
                     - Try a different signal source (logs ↔ traces ↔ metrics ↔ k8s)\n\
                     - If you have enough evidence, produce your final report instead\n\
                     Previous call: {} with args matching this one.",
                    tc.name
                )
            } else {
                memory.record_call(sig);
                match registry.execute(&tc.name, args.clone(), ctx).await {
                    Ok(data) => {
                        any_real_work = true;
                        clip_tool_result(&tc.name, &data)
                    }
                    Err(e) => format!("Tool error: {e}"),
                }
            };

            // Update working memory from this result
            if !is_repeat {
                let facts = extract_facts_from_tool_result(&tc.name, &args, &result);
                for svc in facts.services {
                    memory.add_suspect_service(svc);
                }
                if let Some(summary) = facts.summary {
                    memory.add_fact(format!("{}: {}", tc.name, summary));
                }
                if facts.empty_result {
                    memory.consecutive_empty_results += 1;
                } else {
                    memory.consecutive_empty_results = 0;
                }
            }

            let _ = tx
                .send(AgentEvent::ToolResult {
                    name: tc.name.clone(),
                    data: result.clone(),
                })
                .await;

            messages.push(serde_json::json!({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            }));
        }

        // Dead-end detection: too many empty/no-data results in a row.
        // Instead of immediately forcing a summary we escalate through three
        // levels, nudging the model toward progressively broader alternative
        // strategies. Only level 3+ actually withholds tools and forces a
        // preliminary report.
        if memory.consecutive_empty_results >= DEAD_END_THRESHOLD {
            memory.consecutive_empty_results = 0; // reset counter
            memory.escalation_level += 1;

            let nudge = match memory.escalation_level {
                1 => {
                    "Multiple recent tool calls returned no data. Do NOT give up. Try a \
                      DIFFERENT tool category than the one you've been using. If you've been \
                      searching logs, try query_traces or query_metrics. If you've been \
                      checking one service, check its upstream or downstream dependencies \
                      via service_dependencies."
                }
                2 => {
                    "You've tried alternative tool categories without finding the signal. \
                      Do NOT give up. Check the service dependency graph — the root cause \
                      is often in an upstream or downstream service, not the one originally \
                      reported. Use service_dependencies then investigate each adjacent \
                      service. Also try widening your time window."
                }
                _ => {
                    "You have thoroughly explored multiple angles. Before producing a \
                      final conclusion, you MUST enumerate what you've ruled out and what \
                      specific questions remain open. Produce a PRELIMINARY findings report \
                      with explicit open questions, not a 'cannot determine' surrender. \
                      The user may follow up to refine further — give them specific things \
                      to ask about."
                }
            };

            // Inject the nudge as a system message for the next LLM call.
            messages.push(serde_json::json!({
                "role": "system",
                "content": nudge,
            }));

            // Only force summary at level 3+
            if memory.escalation_level >= 3 {
                force_summary = true;
            }
        }

        // Only count as a real tool step if we actually did work (not just repeat errors)
        if any_real_work {
            tool_steps += 1;
        }
    }

    // Budget exhausted without a final answer — emit a preliminary report so
    // the user sees what we learned and can follow up. This branch should be
    // rare because the escalation ladder above usually forces an earlier
    // summary, but we still need a safety net for runaway loops.
    let termination_reason = if attempts >= MAX_ATTEMPTS && tool_steps < MAX_TOOL_STEPS {
        "Too many parse failures or repeat calls"
    } else {
        "Exhausted internal investigation budget"
    };

    let text = format!(
        "## Preliminary Investigation Report\n\n**Status**: {}\n\n{}\n\n\
         The investigation has not produced a confirmed root cause. Follow up with a\n\
         more specific question or an additional angle (upstream service, widened time\n\
         window, different signal source) to continue from this state.",
        termination_reason,
        memory.to_prompt_block()
    );

    let _ = tx
        .send(AgentEvent::Summary {
            text,
            kind: ReportKind::Preliminary,
        })
        .await;
    let _ = tx
        .send(AgentEvent::Done {
            rounds: tool_steps,
            prompt_tokens: total_prompt,
            completion_tokens: total_completion,
        })
        .await;

    Ok(())
}

struct ToolCallAccum {
    id: String,
    name: String,
    arguments: String,
}

/// Parse an OpenAI-compatible streaming response.
/// Returns (content_text, tool_calls, (prompt_tokens, completion_tokens)).
async fn parse_streaming_response(
    resp: reqwest::Response,
    tx: &mpsc::Sender<AgentEvent>,
) -> Result<(String, Vec<ToolCallAccum>, (u64, u64))> {
    let mut content = String::new();
    let mut tool_calls: Vec<ToolCallAccum> = Vec::new();
    let mut prompt_tokens = 0u64;
    let mut completion_tokens = 0u64;

    let full_body = resp.text().await?;

    for line in full_body.lines() {
        let line = line.trim();
        if !line.starts_with("data: ") {
            continue;
        }
        let data = &line[6..];
        if data == "[DONE]" {
            break;
        }

        let chunk: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(usage) = chunk.get("usage") {
            prompt_tokens = usage
                .get("prompt_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(prompt_tokens);
            completion_tokens = usage
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(completion_tokens);
        }

        let choices = match chunk.get("choices").and_then(|c| c.as_array()) {
            Some(c) => c,
            None => continue,
        };

        for choice in choices {
            let delta = match choice.get("delta") {
                Some(d) => d,
                None => continue,
            };

            if let Some(text) = delta.get("content").and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    content.push_str(text);
                    let _ = tx
                        .send(AgentEvent::ThinkingDelta {
                            text: text.to_string(),
                        })
                        .await;
                }
            }

            if let Some(tcs) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                for tc in tcs {
                    let idx = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                    while tool_calls.len() <= idx {
                        tool_calls.push(ToolCallAccum {
                            id: String::new(),
                            name: String::new(),
                            arguments: String::new(),
                        });
                    }

                    if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                        tool_calls[idx].id = id.to_string();
                    }
                    if let Some(func) = tc.get("function") {
                        if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                            tool_calls[idx].name = name.to_string();
                        }
                        if let Some(args) = func.get("arguments").and_then(|v| v.as_str()) {
                            tool_calls[idx].arguments.push_str(args);
                        }
                    }
                }
            }
        }
    }

    Ok((content, tool_calls, (prompt_tokens, completion_tokens)))
}
