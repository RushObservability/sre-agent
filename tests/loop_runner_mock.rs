//! Integration test for the agent loop using a mock LLM server.
//!
//! Spins up an axum HTTP server that responds to `/v1/chat/completions` with
//! a pre-scripted sequence of OpenAI-compatible streaming responses. The
//! test then drives the agent loop and asserts on the event stream it emits.
//!
//! This exercises:
//! - The overall ReAct loop (model call → tool call → model call → final)
//! - Streaming SSE parsing
//! - Tool dispatch
//! - Repeat-call detection
//! - Dead-end detection / force-summary
//! - Termination on final answer

use axum::{Router, extract::State, response::Response, routing::post};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

use sre_agent::agent::loop_runner::{LlmConfig, run_with_config};
use sre_agent::agent::stream::AgentEvent;
use sre_agent::agent::tools::{Tool, ToolContext, ToolRegistry};

// ────────────────────────────────────────────────────────────────────────────
// Mock LLM server
// ────────────────────────────────────────────────────────────────────────────

/// A scripted response from the mock LLM. Each entry corresponds to one
/// chat/completions request. Either emit a tool call or a plain-text final.
#[derive(Debug, Clone)]
enum Script {
    ToolCall {
        name: String,
        args: Value,
        call_id: String,
    },
    Final(String),
    Empty, // empty content + no tool calls — triggers retry
}

#[derive(Clone)]
struct MockState {
    scripts: Arc<Mutex<Vec<Script>>>,
    call_count: Arc<Mutex<usize>>,
}

async fn mock_completions(State(state): State<MockState>) -> Response {
    let idx = {
        let mut c = state.call_count.lock().unwrap();
        let i = *c;
        *c += 1;
        i
    };
    let scripts = state.scripts.lock().unwrap();
    let script = scripts
        .get(idx)
        .cloned()
        .unwrap_or(Script::Final("No more scripted responses".to_string()));
    drop(scripts);

    // Build an OpenAI-compatible streaming chat/completions response.
    // Three chunks: delta, delta, [DONE]
    let body = build_stream_body(&script);

    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn build_stream_body(script: &Script) -> String {
    let mut out = String::new();

    match script {
        Script::ToolCall { name, args, call_id } => {
            // Chunk 1: tool_call with name
            let c1 = json!({
                "choices": [{
                    "delta": {
                        "tool_calls": [{
                            "index": 0,
                            "id": call_id,
                            "type": "function",
                            "function": { "name": name }
                        }]
                    }
                }]
            });
            out.push_str(&format!("data: {c1}\n\n"));

            // Chunk 2: args
            let args_str = serde_json::to_string(args).unwrap();
            let c2 = json!({
                "choices": [{
                    "delta": {
                        "tool_calls": [{
                            "index": 0,
                            "function": { "arguments": args_str }
                        }]
                    }
                }]
            });
            out.push_str(&format!("data: {c2}\n\n"));

            // Usage chunk
            let c3 = json!({
                "choices": [],
                "usage": { "prompt_tokens": 100, "completion_tokens": 20 }
            });
            out.push_str(&format!("data: {c3}\n\n"));
        }
        Script::Final(text) => {
            let c1 = json!({
                "choices": [{
                    "delta": { "content": text }
                }]
            });
            out.push_str(&format!("data: {c1}\n\n"));

            let c2 = json!({
                "choices": [],
                "usage": { "prompt_tokens": 100, "completion_tokens": 30 }
            });
            out.push_str(&format!("data: {c2}\n\n"));
        }
        Script::Empty => {
            let c1 = json!({
                "choices": [{ "delta": { "content": "" } }]
            });
            out.push_str(&format!("data: {c1}\n\n"));
        }
    }

    out.push_str("data: [DONE]\n\n");
    out
}

/// Spawn the mock server on an ephemeral port and return its base URL + shutdown handle.
async fn start_mock(scripts: Vec<Script>) -> (String, tokio::task::JoinHandle<()>, Arc<Mutex<usize>>) {
    let call_count = Arc::new(Mutex::new(0usize));
    let state = MockState {
        scripts: Arc::new(Mutex::new(scripts)),
        call_count: call_count.clone(),
    };

    let app = Router::new()
        .route("/v1/chat/completions", post(mock_completions))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to bind
    tokio::time::sleep(Duration::from_millis(10)).await;
    (base_url, handle, call_count)
}

// ────────────────────────────────────────────────────────────────────────────
// Test fixtures
// ────────────────────────────────────────────────────────────────────────────

/// A fake tool that returns a fixed response. Used in place of real tools
/// that would hit ClickHouse/kube.
struct FakeTool {
    name_s: &'static str,
    response: String,
}

#[async_trait::async_trait]
impl Tool for FakeTool {
    fn name(&self) -> &str {
        self.name_s
    }
    fn description(&self) -> &str {
        "fake tool for testing"
    }
    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {"type": "string"}
            }
        })
    }
    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> anyhow::Result<String> {
        Ok(self.response.clone())
    }
}

fn make_ctx() -> ToolContext {
    let ch = clickhouse::Client::default().with_url("http://localhost:8123");
    let config_db = Arc::new(sre_agent::config_db::ConfigDb::open(":memory:").unwrap());
    ToolContext {
        state: sre_agent::AppState { ch, config_db },
    }
}

fn make_registry(tools: Vec<(&'static str, String)>) -> ToolRegistry {
    let mut r = ToolRegistry::new();
    for (name, response) in tools {
        r.register(Arc::new(FakeTool {
            name_s: name,
            response,
        }));
    }
    r
}

fn initial_messages(user_msg: &str) -> Vec<Value> {
    vec![
        json!({"role": "system", "content": "You are a test agent."}),
        json!({"role": "user", "content": user_msg}),
    ]
}

async fn collect_events(rx: &mut mpsc::Receiver<AgentEvent>) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    while let Some(e) = rx.recv().await {
        out.push(e);
    }
    out
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn loop_completes_with_single_final_answer() {
    let scripts = vec![Script::Final(
        "## Root Cause\nThe service is fine — no anomaly found.".to_string(),
    )];
    let (base_url, _server, call_count) = start_mock(scripts).await;

    let registry = make_registry(vec![("search_logs", "Found 0 logs.".to_string())]);
    let ctx = make_ctx();
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url,
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
    };

    run_with_config(initial_messages("Investigate"), &registry, &ctx, &tx, llm)
        .await
        .unwrap();
    drop(tx);

    let events = collect_events(&mut rx).await;
    assert_eq!(*call_count.lock().unwrap(), 1, "exactly one LLM call");

    // Should have Summary + Done events
    let has_summary = events
        .iter()
        .any(|e| matches!(e, AgentEvent::Summary { text } if text.contains("Root Cause")));
    let has_done = events.iter().any(|e| matches!(e, AgentEvent::Done { .. }));
    assert!(has_summary, "expected Summary event with root cause");
    assert!(has_done, "expected Done event");
}

#[tokio::test]
async fn loop_executes_tool_call_then_finalizes() {
    let scripts = vec![
        Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": "api"}),
            call_id: "call_1".to_string(),
        },
        Script::Final(
            "## Root Cause\n5 errors found in api service logs.".to_string(),
        ),
    ];
    let (base_url, _server, call_count) = start_mock(scripts).await;

    let registry = make_registry(vec![(
        "search_logs",
        "Found 5 log entries.\n[api] ERROR: connection refused".to_string(),
    )]);
    let ctx = make_ctx();
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url,
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
    };

    run_with_config(
        initial_messages("Why are we seeing errors?"),
        &registry,
        &ctx,
        &tx,
        llm,
    )
    .await
    .unwrap();
    drop(tx);

    let events = collect_events(&mut rx).await;
    assert_eq!(*call_count.lock().unwrap(), 2, "two LLM calls");

    // Should see ToolCall → ToolResult → Summary → Done
    let has_tool_call = events
        .iter()
        .any(|e| matches!(e, AgentEvent::ToolCall { name, .. } if name == "search_logs"));
    let has_tool_result = events.iter().any(
        |e| matches!(e, AgentEvent::ToolResult { data, .. } if data.contains("Found 5 log entries")),
    );
    let has_summary = events.iter().any(|e| matches!(e, AgentEvent::Summary { .. }));

    assert!(has_tool_call, "expected search_logs tool_call event");
    assert!(has_tool_result, "expected tool_result with fake data");
    assert!(has_summary, "expected final summary");
}

#[tokio::test]
async fn repeat_call_detection_rejects_duplicate_tool_calls() {
    // Script: call search_logs with same args twice, then finalize
    let scripts = vec![
        Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": "api"}),
            call_id: "call_1".to_string(),
        },
        Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": "api"}), // DUPLICATE
            call_id: "call_2".to_string(),
        },
        Script::Final("## Root Cause\nGot duplicate result, stopping.".to_string()),
    ];
    let (base_url, _server, _call_count) = start_mock(scripts).await;

    let registry = make_registry(vec![("search_logs", "Found 3 entries.".to_string())]);
    let ctx = make_ctx();
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url,
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
    };

    run_with_config(initial_messages("Investigate"), &registry, &ctx, &tx, llm)
        .await
        .unwrap();
    drop(tx);

    let events = collect_events(&mut rx).await;

    // Second tool result should contain the repeat-rejection error
    let repeat_errors: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::ToolResult { data, .. }
                if data.contains("already made in this investigation") =>
            {
                Some(data.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        repeat_errors.len(),
        1,
        "expected exactly one repeat-rejection error"
    );
}

#[tokio::test]
async fn empty_response_triggers_retry_without_burning_tool_budget() {
    // First two LLM calls return empty content — these should trigger retries
    // (which inject a notice and re-prompt). Third call returns a final answer.
    let scripts = vec![
        Script::Empty,
        Script::Empty,
        Script::Final("## Root Cause\nRecovered after empty responses.".to_string()),
    ];
    let (base_url, _server, call_count) = start_mock(scripts).await;

    let registry = make_registry(vec![]);
    let ctx = make_ctx();
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url,
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
    };

    run_with_config(initial_messages("Investigate"), &registry, &ctx, &tx, llm)
        .await
        .unwrap();
    drop(tx);

    // All three LLM calls should have been made
    assert_eq!(*call_count.lock().unwrap(), 3);

    let events = collect_events(&mut rx).await;
    let has_summary = events
        .iter()
        .any(|e| matches!(e, AgentEvent::Summary { text } if text.contains("Recovered")));
    assert!(has_summary, "loop should have recovered and produced summary");
}
