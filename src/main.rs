use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use sre_agent::AppState;
use sre_agent::metrics::AgentMetrics;
use sre_agent::query_api::QueryApiClient;
use sre_agent::state::InvestigationAdmission;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("sre_agent=debug,tower_http=debug")),
        )
        .init();

    let internal_auth_token = std::env::var("SRE_AGENT_INTERNAL_TOKEN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!(
            "SRE_AGENT_INTERNAL_TOKEN must be set; refusing to expose the SRE agent without internal authentication"
        ))?;
    let query_api_url = std::env::var("QUERY_API_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "QUERY_API_URL must be set; the SRE agent does not connect to ClickHouse directly"
            )
        })?;
    let query_api = Arc::new(QueryApiClient::new(
        &query_api_url,
        internal_auth_token.clone(),
    )?);
    query_api.ready("default").await?;
    tracing::info!(query_api = %query_api.base_url(), "sre-agent data plane connected");

    let metrics = Arc::new(AgentMetrics::new());
    sre_agent::process_metrics::sample(&metrics);
    sre_agent::process_metrics::spawn(metrics.clone());
    let state = AppState {
        query_api,
        internal_auth_token,
        caches: Arc::new(Default::default()),
        admission: Arc::new(InvestigationAdmission::from_env(metrics.clone())),
        metrics,
    };

    let port: u16 = std::env::var("SRE_AGENT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8081);

    let app = sre_agent::http::router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("sre-agent listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
