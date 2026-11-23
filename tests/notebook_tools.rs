mod common;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use sre_agent::{
    agent::{built_in, tools::ToolRegistry},
    query_api::QueryApiClient,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
struct Backend {
    revoked: Arc<AtomicBool>,
    writes: Arc<Mutex<Vec<Value>>>,
}
const ID: &str = "00000000-0000-0000-0000-000000000001";

async fn backend(State(state): State<Backend>, req: Request) -> Response {
    assert_eq!(req.headers()["x-rush-tenant"], "tenant-a");
    assert_eq!(req.headers()["x-rush-internal-token"], "test-internal");
    assert_eq!(
        req.headers()["x-rush-notebook-access"],
        "opaque-notebook-grant"
    );
    assert!(
        req.headers()["user-agent"]
            .to_str()
            .unwrap()
            .starts_with("rush-sre-agent/")
    );
    if state.revoked.load(Ordering::SeqCst) {
        return (StatusCode::FORBIDDEN, "write access revoked").into_response();
    }
    let is_post = req.method() == Method::POST;
    let cell = req.uri().path().ends_with("/cells");
    let list = req.uri().path() == "/api/v1/internal/sre/notebooks";
    if is_post {
        let bytes = axum::body::to_bytes(req.into_body(), 100000).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("tenant_id").is_none());
        assert!(value.get("notebook_access").is_none());
        // Make overlapping mutations observable. The registry must serialize them.
        if value["title"] == "first" {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        state.writes.lock().unwrap().push(value.clone());
        if cell {
            return Json(json!({"id":"cell-1","cell_type":value["cell_type"],"title":value["title"],"position":1000})).into_response();
        }
        return Json(json!({"id":ID,"name":value["name"],"cells":[]})).into_response();
    }
    if list {
        Json(json!({"notebooks":[{"id":ID,"name":"Incident"}]})).into_response()
    } else {
        Json(json!({"id":ID,"name":"Incident","cells":[]})).into_response()
    }
}

#[tokio::test]
async fn registered_notebook_tools_use_delegation_serialize_additions_and_surface_revocation() {
    let state = Backend::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new().fallback(backend).with_state(state.clone()),
        )
        .into_future(),
    );
    let mut ctx = common::make_ctx().await;
    ctx.tenant_id = "tenant-a".into();
    ctx.state.query_api = Arc::new(
        QueryApiClient::new(&format!("http://{addr}"), "test-internal".into())
            .unwrap()
            .with_notebook_access(Some("opaque-notebook-grant".into())),
    );
    let mut registry = ToolRegistry::new();
    built_in::register_all(&mut registry);
    let created = registry
        .execute(
            "create_notebook",
            json!({"name":"Incident","incident_start":"2026-11-23T00:00:00Z"}),
            &ctx,
        )
        .await
        .unwrap();
    assert!(!created.contains("opaque-notebook-grant"));
    assert_eq!(serde_json::from_str::<Value>(&created).unwrap()["id"], ID);
    let first = registry.execute(
        "add_notebook_cell",
        json!({"notebook_id":ID,"cell_type":"note","title":"first","body":"Evidence"}),
        &ctx,
    );
    let second=registry.execute("add_notebook_cell",json!({"notebook_id":ID,"cell_type":"logs","title":"second","query_config":{"search":"service_name=checkout"}}),&ctx);
    let (a, b) = tokio::join!(first, second);
    a.unwrap();
    b.unwrap();
    let writes = state.writes.lock().unwrap().clone();
    assert_eq!(writes[1]["title"], "first");
    assert_eq!(writes[2]["title"], "second");
    assert_eq!(writes[2]["time"]["mode"], "inherit");
    registry
        .execute("list_notebooks", json!({}), &ctx)
        .await
        .unwrap();
    registry
        .execute("get_notebook", json!({"notebook_id":ID}), &ctx)
        .await
        .unwrap();
    assert!(registry.execute("create_notebook",json!({"name":"Incident","incident_start":"2026-11-23T00:00:00Z","tenant_id":"other"}),&ctx).await.is_err());
    state.revoked.store(true, Ordering::SeqCst);
    let error = registry
        .execute(
            "add_notebook_cell",
            json!({"notebook_id":ID,"cell_type":"note","body":"Not saved"}),
            &ctx,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("403"));
    assert_eq!(state.writes.lock().unwrap().len(), 3);
    server.abort();
}

#[tokio::test]
async fn turns_without_delegation_cannot_write() {
    let ctx = common::make_ctx().await;
    let mut registry = ToolRegistry::new();
    built_in::register_all(&mut registry);
    let error = registry
        .execute(
            "create_notebook",
            json!({"name":"Incident","incident_start":"2026-11-23T00:00:00Z"}),
            &ctx,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Notebook access is unavailable"));
}
