//! Phase-2 integration tests for the agent loop against the mock LLM server:
//! gate-earned Final reports, budget exhaustion, client disconnect, transcript
//! compaction on the wire, parallel tool-call ordering, and SSE parser
//! torture via hand-cut byte chunks.
//!
//! No live ClickHouse is needed: the ToolContext is built on
//! `ConfigDb::new_disconnected_for_tests()` and fake tools never query it.

mod common;

use common::{
    FakeTool, Script, SleepTool, collect_events, count_messages_containing, initial_messages,
    make_ctx, make_registry, start_mock,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use sre_agent::agent::loop_runner::{LlmConfig, LoopBudget, run_with_config_and_budget};
use sre_agent::agent::stream::{AgentEvent, ReportKind};
use sre_agent::agent::tools::ToolRegistry;

/// Marker text of the root-cause gate's gap system message.
const GATE_GAP_MARKER: &str = "Root cause not yet confirmed";
/// Marker text of the one-shot self-review critique system message.
const CRITIQUE_MARKER: &str = "skeptical senior SRE";
/// Stub written over compacted tool results (see loop_runner.rs).
const COMPACTED_STUB: &str = "[tool result compacted — key facts retained in working memory]";

fn llm_for(server: &common::MockServer) -> LlmConfig {
    LlmConfig {
        base_url: server.base_url.clone(),
        api_key: "sk-test".to_string(),
        model: "gpt-4o".to_string(),
        reasoning_effort: None,
    }
}

/// Structured tool results with explicit incident/baseline deltas. This keeps
/// the integration test honest: the causal gate must see typed provenance,
/// not infer a baseline change from prose alone.
fn evidence_registry() -> ToolRegistry {
    let window = json!({
        "incident_start": "2026-07-19T10:00:00Z",
        "incident_end": "2026-07-19T11:00:00Z",
        "baseline_start": "2026-07-19T09:00:00Z",
        "baseline_end": "2026-07-19T10:00:00Z",
        "selection_reason": "inferred_onset",
        "timezone": "UTC"
    });
    let logs = json!({
        "status": "ok",
        "source_family": "logs",
        "source_tables": ["logs"],
        "window": window,
        "service": "",
        "operation": "error search",
        "incident_value": 7,
        "baseline_value": 1,
        "absolute_delta": 6,
        "relative_delta": 6.0,
        "sample_count": 7,
        "quality": {"band": "high", "reasons": []},
        "references": ["logs:connection-refused"],
        "query_fingerprint": "sha256:test-logs",
        "summary": "connection refused errors increased during incident window",
        "data": {"count": 7}
    })
    .to_string();
    let metrics = json!({
        "status": "ok",
        "source_family": "otel_metrics",
        "source_tables": ["otel_metrics"],
        "window": window,
        "service": "",
        "operation": "error_rate",
        "incident_value": 0.42,
        "baseline_value": 0.10,
        "absolute_delta": 0.32,
        "relative_delta": 3.2,
        "sample_count": 12,
        "quality": {"band": "high", "reasons": []},
        "references": ["metrics:api:error_rate"],
        "query_fingerprint": "sha256:test-metrics",
        "summary": "api error_rate increased from 0.10 baseline to 0.42 incident",
        "data": {"latest": 0.42}
    })
    .to_string();
    make_registry(vec![("search_logs", logs), ("query_metrics", metrics)])
}

// ────────────────────────────────────────────────────────────────────────────
// a. Earned Final report
// ────────────────────────────────────────────────────────────────────────────

/// 4 distinct tool rounds across 2 signal categories (logs + metrics) with
/// fact-bearing results satisfy every gate criterion (steps ≥ 4, signals ≥ 2,
/// facts ≥ 2, suspect services non-empty), so the conclusion is NOT bounced —
/// the self-review critique fires exactly once, then the next conclusion is
/// accepted as a Final report. Sequence: 4 tool rounds → conclusion (review
/// injected) → conclusion accepted = 6 LLM calls.
#[tokio::test]
async fn earns_final_report() {
    let scripts = vec![
        Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": "api"}),
            call_id: "call_1".to_string(),
        },
        Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": "checkout"}),
            call_id: "call_2".to_string(),
        },
        Script::ToolCall {
            name: "query_metrics".to_string(),
            args: json!({"service": "api"}),
            call_id: "call_3".to_string(),
        },
        Script::ToolCall {
            name: "query_metrics".to_string(),
            args: json!({"service": "checkout"}),
            call_id: "call_4".to_string(),
        },
        Script::Final(
            "HYPOTHESIS H1 | culprit=api | mechanism=error regression | symptom=api | path=api | status=supported | supports=E1,E3 | contradicts= | discriminates=E3 | confidence=high | next_test=check deploy\n## Status\nFinal — high confidence\n## Root Cause\napi error_rate spiked after connection refusals at onset [E1] [E3]\n## Incident Change\nerror rate and latency increased versus baseline; onset was 10:00 UTC [E1] [E3]\n## Causal Path\napi -> api [E3]\n## Evidence\n- [E1] logs\n- [E3] metrics\n## Contradictions and Alternatives\nNo material contradiction remains; E3 was the discriminating check.\n## Impact\napi requests failed\n## Recommended Actions\ncheck deploy\n## Open Questions\nNone material.".to_string(),
        ),
        Script::Final(
            "HYPOTHESIS H1 | culprit=api | mechanism=error regression | symptom=api | path=api | status=supported | supports=E1,E3 | contradicts= | discriminates=E3 | confidence=high | next_test=check deploy\n## Status\nFinal — high confidence\n## Root Cause\napi error_rate spiked after connection refusals at onset [E1] [E3]\n## Incident Change\nerror rate and latency increased versus baseline; onset was 10:00 UTC [E1] [E3]\n## Causal Path\napi -> api [E3]\n## Evidence\n- [E1] logs\n- [E3] metrics\n## Contradictions and Alternatives\nNo material contradiction remains; E3 was the discriminating check.\n## Impact\napi requests failed\n## Recommended Actions\ncheck deploy\n## Open Questions\nNone material. Confidence: high".to_string(),
        ),
    ];
    let server = start_mock(scripts).await;

    let registry = evidence_registry();
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let (text, kind, mem, _, _, _) = run_with_config_and_budget(
        initial_messages("Why is api erroring?"),
        &registry,
        &ctx,
        &tx,
        llm_for(&server),
        None,
        "sess-final",
        LoopBudget::default(),
    )
    .await
    .unwrap();
    drop(tx);

    assert_eq!(
        kind,
        ReportKind::Final,
        "gate criteria met → Final report; memory={mem:?}; text={text}"
    );
    assert!(
        text.contains("Confidence: high"),
        "accepted text is the post-review one: {text}"
    );
    assert_eq!(
        server.calls(),
        6,
        "4 tool rounds → conclusion (critique) → accepted conclusion = 6 calls"
    );

    let events = collect_events(&mut rx).await;
    let summary_kind = events.iter().find_map(|e| match e {
        AgentEvent::Summary { kind, .. } => Some(kind.clone()),
        _ => None,
    });
    assert_eq!(summary_kind, Some(ReportKind::Final));

    // Exactly one critique, zero gate bounces.
    let requests = server.recorded_requests();
    let last = requests.last().unwrap();
    assert_eq!(
        count_messages_containing(last, "system", CRITIQUE_MARKER),
        1,
        "self-review critique fires exactly once"
    );
    assert_eq!(
        count_messages_containing(last, "system", GATE_GAP_MARKER),
        0,
        "a grounded conclusion is never bounced by the gate"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// b. Budget exhaustion → Preliminary
// ────────────────────────────────────────────────────────────────────────────

/// With LoopBudget::from_overrides(Some(4), Some(6)) and a model that ALWAYS
/// returns (distinct) tool calls, the loop hits max_tool_steps and emits the
/// budget-exhaustion preliminary report.
#[tokio::test]
async fn budget_exhaustion_preliminary() {
    // More distinct tool calls than the budget could ever execute.
    let scripts: Vec<Script> = (0..10)
        .map(|i| Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": format!("svc{i}")}),
            call_id: format!("call_{i}"),
        })
        .collect();
    let server = start_mock(scripts).await;

    let registry = make_registry(vec![(
        "search_logs",
        "Found 3 log entries.\n[svc] WARN slow".to_string(),
    )]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let budget = LoopBudget::from_overrides(Some(4), Some(6));
    let (text, kind, _mem, _, _, _) = run_with_config_and_budget(
        initial_messages("Investigate"),
        &registry,
        &ctx,
        &tx,
        llm_for(&server),
        None,
        "sess-budget",
        budget,
    )
    .await
    .unwrap();
    drop(tx);

    assert!(
        text.contains("Preliminary Investigation Report"),
        "budget exhaustion emits the preliminary report: {text}"
    );
    assert_eq!(kind, ReportKind::Preliminary);
    assert!(
        server.calls() <= 6,
        "calls ({}) must never exceed max_llm_calls (6)",
        server.calls()
    );

    let events = collect_events(&mut rx).await;
    assert!(
        events.iter().any(|e| matches!(e, AgentEvent::Done { .. })),
        "a Done event must arrive even on budget exhaustion"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            AgentEvent::Summary { text, kind: ReportKind::Preliminary }
                if text.contains("Preliminary Investigation Report")
        )),
        "Summary event carries the preliminary report"
    );

    // The final-step request must withhold tools (force_final).
    let requests = server.recorded_requests();
    let last = requests.last().unwrap();
    assert!(
        last.get("tools").is_none(),
        "force_final withholds tool definitions on the last step"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// c. Client disconnect aborts the run
// ────────────────────────────────────────────────────────────────────────────

/// Dropping the SSE receiver mid-run makes tx.is_closed() trip at the top of
/// the next loop iteration: the run returns early with a "Client
/// disconnected" preliminary report and stops burning LLM calls.
#[tokio::test]
async fn disconnect_abort() {
    // Enough distinct tool calls that the loop would otherwise grind through
    // the entire default budget.
    let scripts: Vec<Script> = (0..60)
        .map(|i| Script::ToolCall {
            name: "search_logs".to_string(),
            args: json!({"service": format!("svc{i}")}),
            call_id: format!("call_{i}"),
        })
        .collect();
    let server = start_mock(scripts).await;

    // A sleeping tool keeps each round slow enough that our drop lands well
    // before the next loop-top is_closed() check.
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(SleepTool {
        name_s: "search_logs",
        response: "Found 2 log entries.\n[svc] ERROR x".to_string(),
        delay_ms: 100,
    }));
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let llm = llm_for(&server);
    let handle = tokio::spawn(async move {
        run_with_config_and_budget(
            initial_messages("Investigate"),
            &registry,
            &ctx,
            &tx,
            llm,
            None,
            "sess-disconnect",
            LoopBudget::default(),
        )
        .await
    });

    // Collect events manually; drop the receiver after the first ToolResult.
    while let Some(event) = rx.recv().await {
        if matches!(event, AgentEvent::ToolResult { .. }) {
            break;
        }
    }
    drop(rx);

    let (text, kind, _mem, _, _, _) = handle.await.unwrap().unwrap();
    assert!(
        text.contains("Client disconnected"),
        "early-return text mentions the disconnect: {text}"
    );
    assert_eq!(kind, ReportKind::Preliminary);

    // No further LLM calls after the run returned.
    let calls_at_return = server.calls();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        server.calls(),
        calls_at_return,
        "LLM call count must stop growing after the disconnect abort"
    );
    assert!(
        calls_at_return < 60,
        "the run must abort long before exhausting the scripts ({calls_at_return} calls)"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// d. Compaction visible on the wire
// ────────────────────────────────────────────────────────────────────────────

/// After 8 tool rounds, tool results older than the 6 most recent rounds are
/// stubbed in the request transcript. The LAST recorded request must show the
/// 2 oldest tool messages compacted and the 6 most recent intact.
#[tokio::test]
async fn compaction_visible_on_wire() {
    // 8 distinct tool rounds alternating signal categories (so the gate
    // passes), then conclusion → critique → accepted conclusion.
    let mut scripts: Vec<Script> = (0..8)
        .map(|i| {
            let name = if i % 2 == 0 {
                "search_logs"
            } else {
                "query_metrics"
            };
            Script::ToolCall {
                name: name.to_string(),
                args: json!({"service": format!("svc{i}")}),
                call_id: format!("call_{i}"),
            }
        })
        .collect();
    scripts.push(Script::Final(
        "HYPOTHESIS H1 | culprit=svc0 | mechanism=error regression | symptom=svc0 | path=svc0 | status=supported | supports=E1,E2 | contradicts= | discriminates=E2 | confidence=high | next_test=check deploy\n## Status\nFinal — high confidence\n## Root Cause\nsvc0 cascading failure at onset [E1] [E2]\n## Incident Change\nerror rate increased versus baseline; onset was 10:00 UTC [E1] [E2]\n## Causal Path\nsvc0 -> svc0 [E2]\n## Evidence\n- [E1] logs\n- [E2] metrics\n## Contradictions and Alternatives\nNo material contradiction remains; E2 was the discriminating check.\n## Impact\nsvc0 affected\n## Recommended Actions\ncheck deploy\n## Open Questions\nNone material.".to_string(),
    ));
    scripts.push(Script::Final(
        "HYPOTHESIS H1 | culprit=svc0 | mechanism=error regression | symptom=svc0 | path=svc0 | status=supported | supports=E1,E2 | contradicts= | discriminates=E2 | confidence=high | next_test=check deploy\n## Status\nFinal — high confidence\n## Root Cause\nsvc0 cascading failure at onset [E1] [E2]\n## Incident Change\nerror rate increased versus baseline; onset was 10:00 UTC [E1] [E2]\n## Causal Path\nsvc0 -> svc0 [E2]\n## Evidence\n- [E1] logs\n- [E2] metrics\n## Contradictions and Alternatives\nNo material contradiction remains; E2 was the discriminating check.\n## Impact\nsvc0 affected\n## Recommended Actions\ncheck deploy\n## Open Questions\nNone material. Confidence: high".to_string(),
    ));
    let server = start_mock(scripts).await;

    let registry = evidence_registry();
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let (_text, kind, mem, _, _, _) = run_with_config_and_budget(
        initial_messages("Investigate"),
        &registry,
        &ctx,
        &tx,
        llm_for(&server),
        None,
        "sess-compaction",
        LoopBudget::default(),
    )
    .await
    .unwrap();
    drop(tx);
    let _ = collect_events(&mut rx).await;

    assert_eq!(kind, ReportKind::Final, "memory={mem:?}");
    assert_eq!(
        server.calls(),
        10,
        "8 tool rounds + critique round + accepted = 10 calls"
    );

    // Inspect tool messages in the LAST request body, in transcript order.
    let requests = server.recorded_requests();
    let last = requests.last().unwrap();
    let tool_contents: Vec<String> = last["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["role"] == "tool")
        .map(|m| m["content"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        tool_contents.len(),
        8,
        "all 8 tool messages present in transcript"
    );

    let stubbed = tool_contents
        .iter()
        .filter(|c| *c == COMPACTED_STUB)
        .count();
    assert!(
        stubbed >= 1,
        "at least one old tool result must be compacted"
    );
    assert_eq!(
        stubbed, 2,
        "8 rounds with keep=6 → exactly the 2 oldest stubbed"
    );
    assert_eq!(tool_contents[0], COMPACTED_STUB, "oldest round stubbed");
    assert_eq!(
        tool_contents[1], COMPACTED_STUB,
        "second-oldest round stubbed"
    );
    for (i, c) in tool_contents.iter().enumerate().skip(2) {
        assert!(
            c.contains("connection refused errors increased")
                || c.contains("error_rate increased from 0.10"),
            "recent round {i} must keep its full tool result, got: {c}"
        );
    }
}

// ────────────────────────────────────────────────────────────────────────────
// e. Parallel round ordering
// ────────────────────────────────────────────────────────────────────────────

/// One assistant response with TWO tool calls: A (search_logs) sleeps 200ms,
/// B (query_metrics) returns instantly. Both ToolCall events come first (in
/// call order), and ToolResult A still precedes ToolResult B despite B
/// finishing first. The next request body keeps tool messages in call order.
#[tokio::test]
async fn parallel_round_ordering() {
    let scripts = vec![
        Script::ToolCalls(vec![
            (
                "search_logs".to_string(),
                json!({"service": "slow"}),
                "call_a".to_string(),
            ),
            (
                "query_metrics".to_string(),
                json!({"service": "fast"}),
                "call_b".to_string(),
            ),
        ]),
        Script::Final("## Root Cause\nDraft.".to_string()),
        Script::Final("## Root Cause\nDraft.".to_string()),
        Script::Final("## Root Cause\nDraft.".to_string()),
        Script::Final("## Root Cause\nDraft.".to_string()),
        Script::Final("## Root Cause\nDone.".to_string()),
    ];
    let server = start_mock(scripts).await;

    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(SleepTool {
        name_s: "search_logs",
        response: "Found 3 slow entries.".to_string(),
        delay_ms: 200,
    }));
    registry.register(Arc::new(FakeTool {
        name_s: "query_metrics",
        response: "Latest=0.9 Avg=0.5".to_string(),
    }));
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    run_with_config_and_budget(
        initial_messages("Investigate"),
        &registry,
        &ctx,
        &tx,
        llm_for(&server),
        None,
        "sess-parallel",
        LoopBudget::default(),
    )
    .await
    .unwrap();
    drop(tx);

    let events = collect_events(&mut rx).await;

    // Extract the positions of the four round-1 events.
    let pos = |pred: &dyn Fn(&AgentEvent) -> bool| {
        events
            .iter()
            .position(pred)
            .unwrap_or_else(|| panic!("expected event not found in {events:?}"))
    };
    let call_a = pos(&|e| matches!(e, AgentEvent::ToolCall { name, .. } if name == "search_logs"));
    let call_b =
        pos(&|e| matches!(e, AgentEvent::ToolCall { name, .. } if name == "query_metrics"));
    let result_a =
        pos(&|e| matches!(e, AgentEvent::ToolResult { name, .. } if name == "search_logs"));
    let result_b =
        pos(&|e| matches!(e, AgentEvent::ToolResult { name, .. } if name == "query_metrics"));

    assert!(call_a < call_b, "ToolCall events in original call order");
    assert!(
        call_b < result_a,
        "both ToolCall events precede any ToolResult"
    );
    assert!(
        result_a < result_b,
        "ToolResult A (slow) precedes ToolResult B (fast) — call order preserved \
         despite B finishing first"
    );

    // The request following the parallel round carries the tool messages in
    // call order (call_a, then call_b).
    let requests = server.recorded_requests();
    let next = &requests[1];
    let tool_ids: Vec<String> = next["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["role"] == "tool")
        .map(|m| m["tool_call_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        tool_ids,
        vec!["call_a", "call_b"],
        "transcript tool messages in call order"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// f. SSE parser torture
// ────────────────────────────────────────────────────────────────────────────

/// Cut a well-formed streaming response into hostile byte chunks: mid-line,
/// mid-multibyte-UTF-8, tool-call name and arguments fragments split across
/// 3+ chunks, the [DONE] sentinel split mid-token and followed by garbage.
/// The parser must still reassemble the exact content and tool call.
#[tokio::test]
async fn sse_parser_torture() {
    // Response: a content delta with multibyte chars, a tool call whose name
    // and arguments arrive in separate SSE lines, then [DONE].
    let content_line = format!(
        "data: {}\n\n",
        json!({"choices":[{"delta":{"content":"café ☃ snow"}}]})
    );
    let name_line = format!(
        "data: {}\n\n",
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_t","type":"function","function":{"name":"search_logs"}}]}}]})
    );
    let args_line = format!(
        "data: {}\n\n",
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"service\":\"café\"}"}}]}}]})
    );
    let body = format!("{content_line}{name_line}{args_line}data: [DONE]\n\n");
    let bytes = body.as_bytes().to_vec();

    // Hostile cut points (byte offsets into the full body):
    let mut cuts: Vec<usize> = Vec::new();
    cuts.push(10); // mid-line, inside the first JSON object
    // Mid-multibyte: one byte into the 3-byte ☃ (U+2603) in the content line.
    let snowman = body.find('☃').unwrap();
    cuts.push(snowman + 1);
    // Tool-call name split mid-"search_logs".
    let name_off = body.find("search_logs").unwrap();
    cuts.push(name_off + 4);
    // Arguments fragment split inside the escaped JSON string, and inside
    // the é of the args value (mid-multibyte again).
    let svc_off = body[name_off..].find("service").unwrap() + name_off;
    cuts.push(svc_off + 3);
    let args_e = body.rfind('é').unwrap();
    cuts.push(args_e + 1);
    // [DONE] sentinel split mid-token.
    let done_off = body.find("[DONE]").unwrap();
    cuts.push(done_off + 3);
    cuts.sort_unstable();
    cuts.dedup();

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut prev = 0usize;
    for &c in &cuts {
        chunks.push(bytes[prev..c].to_vec());
        prev = c;
    }
    chunks.push(bytes[prev..].to_vec());
    // Garbage after [DONE] must be ignored.
    chunks.push(b"data: GARBAGE NOT JSON \xff\xfe\n\n".to_vec());

    let mut scripts = vec![Script::RawChunks(chunks)];
    // Let the run finish: conclusion → 3 gate bounces → critique → accepted.
    for _ in 0..5 {
        scripts.push(Script::Final(
            "## Root Cause\nTorture survived.".to_string(),
        ));
    }
    let server = start_mock(scripts).await;

    let registry = make_registry(vec![("search_logs", "Found 1 log entry.".to_string())]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    run_with_config_and_budget(
        initial_messages("Investigate"),
        &registry,
        &ctx,
        &tx,
        llm_for(&server),
        None,
        "sess-torture",
        LoopBudget::default(),
    )
    .await
    .unwrap();
    drop(tx);

    let events = collect_events(&mut rx).await;

    // The content deltas reassemble the exact multibyte text.
    let streamed: String = events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::ThinkingDelta { text } => Some(text.as_str()),
            _ => None,
        })
        .take(1) // round 1 emitted exactly one delta line for the content
        .collect();
    assert_eq!(
        streamed, "café ☃ snow",
        "multibyte content reassembled across chunk cuts"
    );

    // The tool call reassembled correctly: right name, exact args.
    let tool_args = events.iter().find_map(|e| match e {
        AgentEvent::ToolCall { name, args } if name == "search_logs" => Some(args.clone()),
        _ => None,
    });
    assert_eq!(
        tool_args,
        Some(json!({"service": "café"})),
        "tool-call name/arguments reassembled across 3+ chunk cuts"
    );

    // The run continued past the torture round and completed normally.
    assert!(
        events.iter().any(
            |e| matches!(e, AgentEvent::Summary { text, .. } if text.contains("Torture survived"))
        ),
        "run completes after the torture response"
    );
}

/// A single SSE line larger than the 4 MiB buffer cap must abort the run with
/// a graceful error (no panic, no unbounded buffering).
#[tokio::test]
async fn sse_oversized_line_errors_gracefully() {
    // One 5 MiB chunk with no newline: the line buffer can never complete a
    // line and crosses the 4 MiB cap.
    let huge = vec![b'a'; 5 * 1024 * 1024];
    let server = start_mock(vec![Script::RawChunks(vec![huge])]).await;

    let registry = make_registry(vec![]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);

    let result = run_with_config_and_budget(
        initial_messages("Investigate"),
        &registry,
        &ctx,
        &tx,
        llm_for(&server),
        None,
        "sess-huge",
        LoopBudget::default(),
    )
    .await;
    drop(tx);
    let _ = collect_events(&mut rx).await;

    let err = result.expect_err("oversized line must error, not hang or panic");
    assert!(
        err.to_string().contains("larger than"),
        "error names the line-size cap: {err}"
    );
    assert_eq!(server.calls(), 1, "the run aborts on the first response");
}
