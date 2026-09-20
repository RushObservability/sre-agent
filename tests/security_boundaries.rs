mod common;

use axum::{Router, http::StatusCode, response::IntoResponse};
use common::{Script, collect_events, initial_messages, make_ctx, make_registry, start_mock};
use serde_json::json;
use sre_agent::{
    agent::{
        loop_runner::{LlmConfig, run_with_config},
        stream::AgentEvent,
    },
    query_api::QueryApiClient,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::mpsc;

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, handle)
}

#[tokio::test]
async fn internal_clients_never_follow_redirects() {
    let hits = Arc::new(AtomicUsize::new(0));
    let recorded = hits.clone();
    let (sink_url, sink) = serve(Router::new().fallback(move || {
        let recorded = recorded.clone();
        async move {
            recorded.fetch_add(1, Ordering::SeqCst);
            "unexpected request"
        }
    }))
    .await;
    for status in [301, 302, 303, 307, 308] {
        let location = sink_url.clone();
        let (url, redirector) = serve(Router::new().fallback(move || {
            let location = location.clone();
            async move {
                (
                    StatusCode::from_u16(status).unwrap(),
                    [("location", location)],
                )
                    .into_response()
            }
        }))
        .await;
        let client = QueryApiClient::new(&url, "dummy-internal-token".into()).unwrap();
        assert!(client.llm_ready("tenant-a").await.is_err());
        let ctx = make_ctx().await;
        let registry = make_registry(vec![]);
        let (tx, _rx) = mpsc::channel(64);
        let result = run_with_config(
            initial_messages("Inspect"),
            &registry,
            &ctx,
            &tx,
            LlmConfig {
                base_url: format!("{url}/api/v1/internal/sre/llm"),
                api_key: "dummy-internal-token".into(),
                model: "test".into(),
                reasoning_effort: None,
            },
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains(&status.to_string())
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0, "redirect status {status}");
        redirector.abort();
    }
    sink.abort();
}

#[tokio::test]
async fn secrets_do_not_reach_provider_events_or_memory() {
    let mock = start_mock(vec![
        Script::ToolCall {
            name: "search_logs".into(),
            args: json!({"service":"gateway", "filter":"password=dummy-argument"}),
            call_id: "call-1".into(),
        },
        Script::Final("[QUESTION] Which deployment changed?".into()),
    ])
    .await;
    let registry = make_registry(vec![("search_logs", "Found 1 log: password=dummy-password\nAuthorization: Bearer dummy-bearer\npostgres://user:dummy-uri@db/app\n-----BEGIN PRIVATE KEY-----\ndummy-pem\n-----END PRIVATE KEY-----".into())]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel(64);
    run_with_config(
        initial_messages("Inspect gateway logs"),
        &registry,
        &ctx,
        &tx,
        LlmConfig {
            base_url: mock.base_url.clone(),
            api_key: "test".into(),
            model: "test".into(),
            reasoning_effort: None,
        },
    )
    .await
    .unwrap();
    drop(tx);
    let events = collect_events(&mut rx).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolResult { data, .. } if data.contains("redacted")))
    );
    let events = serde_json::to_string(&events).unwrap();
    let requests = mock.recorded_requests();
    assert!(requests.len() >= 2);
    // The next request includes both tool output and the working-memory block.
    let outbound = serde_json::to_string(&requests).unwrap();
    for secret in [
        "dummy-argument",
        "dummy-password",
        "dummy-bearer",
        "dummy-uri",
        "dummy-pem",
    ] {
        assert!(!events.contains(secret), "event leaked {secret}");
        assert!(
            !outbound.contains(secret),
            "provider request leaked {secret}"
        );
    }
}

#[tokio::test]
async fn oversized_complete_sse_line_is_rejected_without_dispatching_tools() {
    let mut line = b"data: ".to_vec();
    line.extend(vec![b' '; 4 * 1024 * 1024]);
    line.push(b'\n');
    let mock = start_mock(vec![Script::RawChunks(vec![line])]).await;
    let registry = make_registry(vec![]);
    let ctx = make_ctx().await;
    let (tx, mut rx) = mpsc::channel(64);
    let result = run_with_config(
        initial_messages("Inspect"),
        &registry,
        &ctx,
        &tx,
        LlmConfig {
            base_url: mock.base_url.clone(),
            api_key: "test".into(),
            model: "test".into(),
            reasoning_effort: None,
        },
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("size limit"));
    drop(tx);
    assert!(
        !collect_events(&mut rx)
            .await
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolCall { .. }))
    );
}
