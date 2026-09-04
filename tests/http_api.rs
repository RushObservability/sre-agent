//! HTTP-surface tests: drive the exact production router built by
//! `sre_agent::http::router` with `tower::ServiceExt::oneshot` — no socket,
//! no live query-api. The disconnected client fails requests immediately.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

use sre_agent::AppState;
use sre_agent::http::router;
use sre_agent::query_api::QueryApiClient;

const INTERNAL_TOKEN: &str = "test-internal-token";

/// Build the production router on a fully disconnected AppState — the same
/// pattern as tests/common::make_ctx (no live backends, fail-fast queries).
fn test_router() -> axum::Router {
    let state = AppState {
        query_api: Arc::new(QueryApiClient::new_disconnected_for_tests()),
        internal_auth_token: INTERNAL_TOKEN.to_string(),
        caches: Arc::new(Default::default()),
        metrics: Arc::new(sre_agent::metrics::AgentMetrics::new()),
        admission: Arc::new(sre_agent::state::InvestigationAdmission::new(
            4,
            16,
            Arc::new(sre_agent::metrics::AgentMetrics::new()),
        )),
    };
    router(state)
}

#[tokio::test]
async fn healthz_returns_200_ok() {
    let app = test_router();
    let resp = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn readyz_reports_unavailable_dependency_without_leaking_secrets() {
    let app = test_router();
    let resp = app
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "not_ready");
    assert_eq!(json["checks"]["query_api"], false);
    assert!(
        !body
            .windows(INTERNAL_TOKEN.len())
            .any(|window| window == INTERNAL_TOKEN.as_bytes())
    );
}

#[tokio::test]
async fn metrics_preserves_internal_token_protection() {
    let app = test_router();
    let unauthorized = app
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::get("/metrics")
                .header("x-rush-internal-token", INTERNAL_TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
    assert_eq!(
        authorized.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let body = authorized.into_body().collect().await.unwrap().to_bytes();
    assert!(body.starts_with(b"# HELP sre_agent_investigations_in_flight"));
}

#[tokio::test]
async fn agent_api_rejects_requests_without_internal_token() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::post("/api/v1/investigate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn investigate_with_empty_fields_returns_400() {
    // No event_id, no question, no session_id, no prior_messages → the
    // handler must reject before touching any backend.
    let app = test_router();
    let resp = app
        .oneshot(
            Request::post("/api/v1/investigate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-rush-internal-token", INTERNAL_TOKEN)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("event_id") || text.contains("question") || text.contains("session_id"),
        "400 body names the missing fields: {text}"
    );
}

/// When query-api cannot confirm a configured tenant model, the investigate
/// stream must open (200 SSE) and carry a setup-oriented error instead of
/// starting a doomed investigation.
#[tokio::test]
async fn investigate_without_tenant_llm_streams_not_configured_error() {
    // Legacy follow-up shape (prior_messages + question, no session_id):
    // skips session creation against the disconnected DB so the request
    // reaches the LLM-config check.
    let req_body = serde_json::json!({
        "question": "why are we erroring?",
        "prior_messages": [{"role": "user", "content": "earlier turn"}],
    });

    let app = test_router();
    let resp = app
        .oneshot(
            Request::post("/api/v1/investigate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-rush-internal-token", INTERNAL_TOKEN)
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    // The error is the only event; the channel closes right after, so the
    // whole body is collectable.
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("LLM not configured"),
        "first SSE frames must carry the setup error, got: {text}"
    );
    assert!(
        text.starts_with("data: "),
        "SSE framing expected, got: {text}"
    );
}

#[tokio::test]
async fn public_session_routes_are_not_exposed_by_the_agent() {
    let app = test_router();
    let requests = [
        Request::get("/api/v1/sessions"),
        Request::get("/api/v1/sessions/session-1"),
        Request::delete("/api/v1/sessions/session-1"),
    ];

    for request in requests {
        let response = app
            .clone()
            .oneshot(
                request
                    .header("x-rush-internal-token", INTERNAL_TOKEN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
