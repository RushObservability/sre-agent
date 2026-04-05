//! Shared application state for the SRE agent.
//!
//! Much simpler than the query-api's AppState — the agent only needs ClickHouse
//! (for telemetry queries) and the shared SQLite config DB (for anomaly events,
//! deploy markers, and settings).

use clickhouse::Client;
use std::sync::Arc;

use crate::config_db::ConfigDb;

#[derive(Clone)]
pub struct AppState {
    pub ch: Client,
    pub config_db: Arc<ConfigDb>,
    /// Optional base URL of query-api (e.g. `http://rush-o11y-query-api:8080`).
    /// When set, the agent fetches custom skills from query-api over HTTP on
    /// each investigation so query-api remains the single source of truth. When
    /// `None`, the agent falls back to reading custom skills from the local
    /// config_db (useful for local dev and tests).
    pub query_api_url: Option<String>,
}
