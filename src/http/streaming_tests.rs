use super::*;
use http_body_util::BodyExt;
fn done() -> AgentEvent {
    AgentEvent::Done {
        rounds: 1,
        tool_calls: 0,
        prompt_tokens: 1,
        completion_tokens: 1,
        session_id: "sensitive-session".into(),
        model: "sensitive-model".into(),
    }
}
#[tokio::test]
async fn useful_event_latency_ignores_session_and_empty_thinking_frames() {
    let metrics = Arc::new(AgentMetrics::new());
    let (tx, rx) = mpsc::channel(8);
    for event in [
        AgentEvent::SessionCreated {
            session_id: "sensitive-session".into(),
        },
        AgentEvent::ThinkingDelta {
            text: String::new(),
        },
        AgentEvent::Summary {
            text: "sensitive-report".into(),
            kind: agent::stream::ReportKind::Final,
        },
        done(),
    ] {
        tx.send(event).await.unwrap();
    }
    drop(tx);
    let cancellation = CancellationToken::new();
    sse_body(
        rx,
        cancellation.clone(),
        metrics.clone(),
        std::time::Instant::now(),
    )
    .collect()
    .await
    .unwrap();
    let out = metrics.render();
    assert!(out.contains("sre_agent_time_to_first_event_seconds_count{event=\"summary\"} 1"));
    assert!(!out.contains("event=\"thinking\""));
    assert!(!out.contains("sensitive"));
    assert!(out.contains("sre_agent_sse_terminal_total{reason=\"completed\"} 1"));
    assert!(out.contains("sre_agent_sse_streams_in_flight 0"));
    assert!(cancellation.is_cancelled());
}
#[tokio::test]
async fn stream_terminal_distinguishes_errors_disconnects_and_unexpected_eof() {
    for mode in ["error", "disconnect", "unexpected_eof"] {
        let metrics = Arc::new(AgentMetrics::new());
        let (tx, rx) = mpsc::channel(8);
        if mode == "error" {
            tx.send(AgentEvent::Error {
                message: "sensitive-error".into(),
            })
            .await
            .unwrap();
            tx.send(done()).await.unwrap();
        }
        let body = sse_body(
            rx,
            CancellationToken::new(),
            metrics.clone(),
            std::time::Instant::now(),
        );
        if mode == "disconnect" {
            drop(body);
            drop(tx);
        } else {
            drop(tx);
            body.collect().await.unwrap();
        }
        let out = metrics.render();
        let reason = if mode == "disconnect" {
            "disconnected"
        } else {
            "error"
        };
        assert!(
            out.contains(&format!(
                "sre_agent_sse_terminal_total{{reason=\"{reason}\"}} 1"
            )),
            "{mode}: {out}"
        );
        assert!(out.contains("sre_agent_sse_streams_in_flight 0"));
        assert!(!out.contains("sensitive"));
    }
}
