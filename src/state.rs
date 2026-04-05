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
}
