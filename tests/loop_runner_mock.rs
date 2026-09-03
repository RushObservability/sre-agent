//! Integration tests for the agent loop using a mock LLM server.
//!
//! The mock server, fake tools, and the disconnected ToolContext live in
//! `tests/common/mod.rs`. The mock responds to `/v1/chat/completions` with a
//! pre-scripted sequence of OpenAI-compatible streaming responses; the test
//! drives the agent loop and asserts on the event stream it emits.
//!
//! This exercises:
//! - The overall ReAct loop (model call → tool call → model call → final)
//! - Streaming SSE parsing
//! - Tool dispatch
//! - Repeat-call detection
//! - Dead-end detection / force-summary
//! - Termination on final answer
//!
//! No live query-api is needed: the ToolContext is built on
//! a disconnected query-api client, and fake tools never call it.

mod common;

use common::{
    Script, collect_events, count_messages_containing, initial_messages, make_ctx, make_registry,
    start_mock,
};
use serde_json::json;
use tokio::sync::mpsc;

use sre_agent::agent::loop_runner::{
    LlmConfig, LoopBudget, run_with_config, run_with_config_and_budget,
};
use sre_agent::agent::stream::{AgentEvent, ReportKind};

/// Marker text of the root-cause gate's gap system message.
const GATE_GAP_MARKER: &str = "Root cause not yet confirmed";
/// Marker text of the one-shot self-review critique system message.
const CRITIQUE_MARKER: &str = "skeptical senior SRE";

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

/// A run with no tool calls cannot satisfy the root-cause gate (0 steps,
/// 0 signals, 0 facts), so the gate bounces the conclusion 3 times, then
/// steps aside; the self-review critique fires once; the next conclusion is
/// accepted as Preliminary. Empirical call sequence:
///   call 1: Final → gate rejection 1
///   call 2: Final → gate rejection 2
///   call 3: Final → gate rejection 3
///   call 4: Final → gate steps aside, self-review critique injected
///   call 5: Final → accepted (Preliminary)
#[tokio::test]
async fn loop_completes_with_single_final_answer() {
    let scripts = vec![
        Script::Final("## Root Cause\nThe service is fine — no anomaly found.".to_string()),
        Script::Final("## Root Cause\nStill fine.".to_string()),
        Script::Final("## Root Cause\nStill fine.".to_string()),
        Script::Final("## Root Cause\nStill fine.".to_string()),
        Script::Final("## Root Cause\nThe service is fine — no anomaly found.".to_string()),
    ];
    let server = start_mock(scripts).await;

    let registry = make_registry(vec![("search_logs", "Found 0 logs.".to_string())]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url: server.base_url.clone(),
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
        reasoning_effort: None,
    };

    run_with_config(initial_messages("Investigate"), &registry, &ctx, &tx, llm)
        .await
        .unwrap();
    drop(tx);

    let events = collect_events(&mut rx).await;
    assert_eq!(
        server.calls(),
        5,
        "Final → 3 gate bounces → critique → accepted = 5 LLM calls"
    );

    // Summary is Preliminary — the gate criteria were never met.
    let summary_kind = events.iter().find_map(|e| match e {
        AgentEvent::Summary { text, kind } if text.contains("Root Cause") => Some(kind.clone()),
        _ => None,
    });
    assert_eq!(
        summary_kind,
        Some(ReportKind::Preliminary),
        "expected Preliminary Summary with root cause text"
    );
    let has_done = events.iter().any(|e| matches!(e, AgentEvent::Done { .. }));
    assert!(has_done, "expected Done event");

    // Wire-level: the last request carries all 3 gate gap messages and
    // exactly one self-review critique.
    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 5);
    let last = requests.last().unwrap();
    assert_eq!(
        count_messages_containing(last, "system", GATE_GAP_MARKER),
        3,
        "expected exactly 3 gate gap system messages in final transcript"
    );
    assert_eq!(
        count_messages_containing(last, "system", CRITIQUE_MARKER),
        1,
        "expected exactly one self-review critique system message"
    );
}

/// One real tool round (1 step, 1 signal, 1 fact) still fails the gate, so:
///   call 1: ToolCall search_logs → executed (tool step 1)
///   call 2: Final → gate rejection 1
///   call 3: Final → gate rejection 2
///   call 4: Final → gate rejection 3
///   call 5: Final → gate steps aside, self-review critique injected
///   call 6: Final → accepted (Preliminary)
#[tokio::test]
async fn loop_executes_tool_call_then_finalizes() {
    let scripts = vec![
        Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": "api"}),
            call_id: "call_1".to_string(),
        },
        Script::Final("## Root Cause\n5 errors found in api service logs.".to_string()),
        Script::Final("## Root Cause\n5 errors found in api service logs.".to_string()),
        Script::Final("## Root Cause\n5 errors found in api service logs.".to_string()),
        Script::Final("## Root Cause\n5 errors found in api service logs.".to_string()),
        Script::Final("## Root Cause\n5 errors found in api service logs.".to_string()),
    ];
    let server = start_mock(scripts).await;

    let registry = make_registry(vec![(
        "search_logs",
        "Found 5 log entries.\n[api] ERROR: connection refused".to_string(),
    )]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url: server.base_url.clone(),
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
        reasoning_effort: None,
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
    assert_eq!(
        server.calls(),
        6,
        "tool round → 3 gate bounces → critique → accepted = 6 LLM calls"
    );

    // Should see ToolCall → ToolResult → Summary → Done
    let has_tool_call = events
        .iter()
        .any(|e| matches!(e, AgentEvent::ToolCall { name, .. } if name == "search_logs"));
    let has_tool_result = events.iter().any(
        |e| matches!(e, AgentEvent::ToolResult { data, .. } if data.contains("Found 5 log entries")),
    );
    let summary_kind = events.iter().find_map(|e| match e {
        AgentEvent::Summary { kind, .. } => Some(kind.clone()),
        _ => None,
    });

    assert!(has_tool_call, "expected search_logs tool_call event");
    assert!(has_tool_result, "expected tool_result with fake data");
    assert_eq!(
        summary_kind,
        Some(ReportKind::Preliminary),
        "1 step / 1 signal / 1 fact cannot earn a Final report"
    );

    // Wire-level: 3 gate gap messages and exactly one critique.
    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 6);
    let last = requests.last().unwrap();
    assert_eq!(
        count_messages_containing(last, "system", GATE_GAP_MARKER),
        3
    );
    assert_eq!(
        count_messages_containing(last, "system", CRITIQUE_MARKER),
        1
    );
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
    let server = start_mock(scripts).await;

    let registry = make_registry(vec![("search_logs", "Found 3 entries.".to_string())]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url: server.base_url.clone(),
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
        reasoning_effort: None,
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

/// First two LLM calls return empty content — these trigger parse-retries
/// (a system notice is injected and the loop re-prompts without burning a
/// tool step). The conclusion then runs the usual gate/review gauntlet:
///   call 1: Empty → retry notice
///   call 2: Empty → retry notice
///   call 3: Final → gate rejection 1
///   call 4: Final → gate rejection 2
///   call 5: Final → gate rejection 3
///   call 6: Final → gate steps aside, self-review critique injected
///   call 7: Final → accepted (Preliminary)
#[tokio::test]
async fn empty_response_triggers_retry_without_burning_tool_budget() {
    let scripts = vec![
        Script::Empty,
        Script::Empty,
        Script::Final("## Root Cause\nRecovered after empty responses.".to_string()),
        Script::Final("## Root Cause\nRecovered after empty responses.".to_string()),
        Script::Final("## Root Cause\nRecovered after empty responses.".to_string()),
        Script::Final("## Root Cause\nRecovered after empty responses.".to_string()),
        Script::Final("## Root Cause\nRecovered after empty responses.".to_string()),
    ];
    let server = start_mock(scripts).await;

    let registry = make_registry(vec![]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = LlmConfig {
        base_url: server.base_url.clone(),
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
        reasoning_effort: None,
    };

    run_with_config(initial_messages("Investigate"), &registry, &ctx, &tx, llm)
        .await
        .unwrap();
    drop(tx);

    assert_eq!(
        server.calls(),
        7,
        "2 empty retries → 3 gate bounces → critique → accepted = 7 LLM calls"
    );

    let events = collect_events(&mut rx).await;
    let summary_kind = events.iter().find_map(|e| match e {
        AgentEvent::Summary { text, kind } if text.contains("Recovered") => Some(kind.clone()),
        _ => None,
    });
    assert_eq!(
        summary_kind,
        Some(ReportKind::Preliminary),
        "loop should have recovered and produced a Preliminary summary"
    );

    // Wire-level: both empty responses left a retry notice in the transcript,
    // plus the 3 gate gaps and exactly one critique.
    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 7);
    let last = requests.last().unwrap();
    assert_eq!(
        count_messages_containing(last, "system", "Previous response was empty"),
        2,
        "expected one retry notice per empty response"
    );
    assert_eq!(
        count_messages_containing(last, "system", GATE_GAP_MARKER),
        3
    );
    assert_eq!(
        count_messages_containing(last, "system", CRITIQUE_MARKER),
        1
    );
}

#[tokio::test]
async fn concurrent_tool_batch_cannot_bypass_actual_call_budget() {
    let scripts = vec![
        Script::ToolCalls(vec![
            (
                "search_logs".to_string(),
                json!({"service": "api"}),
                "call_1".to_string(),
            ),
            (
                "query_metrics".to_string(),
                json!({"service": "api"}),
                "call_2".to_string(),
            ),
        ]),
        Script::Final("## Root Cause\nBudget test report.".to_string()),
        Script::Final("## Root Cause\nBudget test report.".to_string()),
        Script::Final("## Root Cause\nBudget test report.".to_string()),
        Script::Final("## Root Cause\nBudget test report.".to_string()),
    ];
    let server = start_mock(scripts).await;
    let registry = make_registry(vec![
        ("search_logs", "Found 1 log entry.".to_string()),
        ("query_metrics", "Latest=1".to_string()),
    ]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
    let llm = LlmConfig {
        base_url: server.base_url.clone(),
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
        reasoning_effort: None,
    };
    let budget = LoopBudget {
        max_tool_calls: 3,
        max_tool_steps: 10,
        max_llm_calls: 8,
    };

    let result = run_with_config_and_budget(
        initial_messages("Investigate api"),
        &registry,
        &ctx,
        &tx,
        llm,
        None,
        "sess-budget-cap",
        budget,
    )
    .await
    .unwrap();
    drop(tx);
    let events = collect_events(&mut rx).await;

    let tool_calls = events
        .iter()
        .filter(|event| matches!(event, AgentEvent::ToolCall { .. }))
        .count();
    assert_eq!(
        tool_calls, 1,
        "two-call batch is capped after reserving verification capacity"
    );
    assert_eq!(result.2.evidence.len(), 1);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, AgentEvent::Done { tool_calls: 1, .. }))
    );
}
