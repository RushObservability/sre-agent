use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::Response,
    routing::{get, post},
};
use clickhouse::Client;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use sre_agent::agent::stream::AgentEvent;
use sre_agent::agent::tools::{ToolContext, ToolRegistry};
use sre_agent::config_db::ConfigDb;
use sre_agent::{AppState, agent};

#[derive(Debug, Deserialize)]
struct InvestigateRequest {
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    question: String,
    #[serde(default)]
    additional_context: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("sre_agent=debug,tower_http=debug")
        }))
        .init();

    let clickhouse_url =
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    let clickhouse_db =
        std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "observability".to_string());
    let clickhouse_user =
        std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_string());
    let clickhouse_password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();

    let ch = Client::default()
        .with_url(&clickhouse_url)
        .with_database(&clickhouse_db)
        .with_user(&clickhouse_user)
        .with_password(&clickhouse_password)
        .with_option("max_execution_time", "30");

    let config_db_path =
        std::env::var("WIDE_CONFIG_DB").unwrap_or_else(|_| "./wide_config.db".to_string());
    let config_db = Arc::new(ConfigDb::open(&config_db_path)?);
    tracing::info!("sre-agent config db opened at {config_db_path}");

    let state = AppState { ch, config_db };

    let port: u16 = std::env::var("SRE_AGENT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8081);

    let app = Router::new()
        .route("/api/v1/investigate", post(investigate))
        .route("/healthz", get(healthz))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("sre-agent listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn investigate(
    State(state): State<AppState>,
    Json(req): Json<InvestigateRequest>,
) -> Result<Response, (StatusCode, String)> {
    if req.event_id.is_empty() && req.question.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "provide event_id or question".to_string(),
        ));
    }

    // Build initial messages
    let system_msg = serde_json::json!({
        "role": "system",
        "content": agent::prompt::system_prompt(),
    });

    let user_content = if !req.event_id.is_empty() {
        // Load anomaly context
        let event = state
            .config_db
            .get_anomaly_event(&req.event_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "anomaly event not found".to_string()))?;
        let rule = state
            .config_db
            .get_anomaly_rule(&event.rule_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "anomaly rule not found".to_string()))?;

        let mut ctx = agent::prompt::anomaly_context(&event, &rule);
        if !req.additional_context.is_empty() {
            ctx.push_str(&format!(
                "\n\nAdditional context from the user:\n{}",
                req.additional_context
            ));
        }
        ctx
    } else {
        agent::prompt::question_context(&req.question, &req.additional_context)
    };

    let user_msg = serde_json::json!({
        "role": "user",
        "content": user_content,
    });

    let messages = vec![system_msg, user_msg];

    // Set up tool registry
    let mut registry = ToolRegistry::new();
    agent::built_in::register_all(&mut registry);

    let tool_ctx = ToolContext { state: state.clone() };

    // Create a channel for SSE events
    let (tx, rx) = mpsc::channel::<AgentEvent>(64);

    // Spawn the agent loop in a background task
    tokio::spawn(async move {
        if let Err(e) = agent::loop_runner::run(messages, &registry, &tool_ctx, &tx).await {
            let _ = tx.send(AgentEvent::Error { message: e.to_string() }).await;
        }
    });

    // Convert the receiver into an SSE byte stream
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body_stream = futures_util::StreamExt::map(stream, |event| {
        Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(event.to_sse_bytes()))
    });

    let body = Body::from_stream(body_stream);

    Ok(Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(body)
        .unwrap())
}
