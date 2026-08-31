use clickhouse::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use sre_agent::AppState;
use sre_agent::config_db::ConfigDb;
use sre_agent::metrics::AgentMetrics;
use sre_agent::state::InvestigationAdmission;
use sre_agent::state::probe_row_policy_support;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("sre_agent=debug,tower_http=debug")),
        )
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

    probe_row_policy_support(&ch).await;

    // ConfigDb uses the session-default database (`default`), matching query-api —
    // config_* tables live there, not in `observability` (which holds telemetry data).
    let config_db =
        Arc::new(ConfigDb::open(&clickhouse_url, &clickhouse_user, &clickhouse_password).await?);
    tracing::info!(
        "sre-agent config db opened against ClickHouse at {clickhouse_url} (config tables in default database)"
    );

    // Optional: URL of the query-api used to fetch custom skills.
    let query_api_url = std::env::var("QUERY_API_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());
    if let Some(url) = &query_api_url {
        tracing::info!("sre-agent will fetch custom skills from query-api at {url}");
    } else {
        tracing::info!("QUERY_API_URL not set; custom skills will read from local config_db");
    }

    let internal_auth_token = std::env::var("SRE_AGENT_INTERNAL_TOKEN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!(
            "SRE_AGENT_INTERNAL_TOKEN must be set; refusing to expose the SRE agent without internal authentication"
        ))?;

    let metrics = Arc::new(AgentMetrics::new());
    sre_agent::process_metrics::sample(&metrics);
    sre_agent::process_metrics::spawn(metrics.clone());
    let state = AppState {
        ch,
        config_db,
        query_api_url,
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
