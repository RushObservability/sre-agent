use super::*;
use crate::query_api::QueryApiClient;
use axum::{http::Method, response::IntoResponse};

fn turn() -> GeneratedTurn<'static> {
    GeneratedTurn {
        tenant_id: "sensitive-tenant",
        session_id: "sensitive-session",
        content: "sensitive-content",
        activity: "[]",
        kind: "final",
        memory: "{}",
        prompt_tokens: 3,
        completion_tokens: 4,
        model: "sensitive-model",
        status: Some("completed"),
    }
}
#[tokio::test]
async fn durable_outcome_requires_each_persistence_step_to_succeed() {
    for failure in ["", "count_turns", "add_turn", "update_session"] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let backend = Router::new().fallback(move |request: axum::extract::Request| {
            let recorded = recorded.clone();
            async move {
                let operation = if request.method() == Method::GET {
                    "count_turns"
                } else if request.method() == Method::POST {
                    "add_turn"
                } else {
                    "update_session"
                };
                recorded.lock().unwrap().push(operation);
                if operation == failure {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                Json(serde_json::json!({"count":7})).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
        let api = QueryApiClient::new(&url, "test-token".into()).unwrap();
        let metrics = Arc::new(AgentMetrics::new());
        let result = persist_assistant_turn(&api, &metrics, turn()).await;
        assert_eq!(result.is_ok(), failure.is_empty());
        let expected = match failure {
            "count_turns" => 1,
            "add_turn" => 2,
            _ => 3,
        };
        assert_eq!(calls.lock().unwrap().len(), expected);
        let out = metrics.render();
        let outcome = if failure.is_empty() {
            "success"
        } else {
            "error"
        };
        assert!(out.contains(&format!(
            "sre_agent_investigation_persistence_total{{outcome=\"{outcome}\"}} 1"
        )));
        if !failure.is_empty() {
            assert!(out.contains(&format!("operation=\"{failure}\",outcome=\"error\"}} 1")));
        }
        assert!(!out.contains("sensitive"));
        server.abort();
    }
}
#[tokio::test]
async fn cancelled_persistence_is_not_reported_as_saved() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let notify = entered.clone();
    let backend = Router::new().fallback(move || {
        let notify = notify.clone();
        async move {
            notify.notify_one();
            std::future::pending::<StatusCode>().await
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
    let metrics = Arc::new(AgentMetrics::new());
    let recorded = metrics.clone();
    let task = tokio::spawn(async move {
        let api = QueryApiClient::new(&url, "test-token".into()).unwrap();
        persist_assistant_turn(&api, &recorded, turn()).await
    });
    entered.notified().await;
    task.abort();
    let _ = task.await;
    let out = metrics.render();
    assert!(out.contains("sre_agent_investigation_persistence_total{outcome=\"cancelled\"} 1"));
    assert!(!out.contains("outcome=\"success\""));
    server.abort();
}
