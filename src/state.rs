//! Shared application state for the SRE agent.
//!
//! Much simpler than the query-api's AppState — the agent only needs ClickHouse
//! (for telemetry queries) and the shared ClickHouse config tables (for anomaly
//! events, deploy markers, and settings).

use clickhouse::{Client, query::Query};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;

use crate::agent::loop_runner::LoopBudget;
use crate::agent::skill_store::SkillStore;
use crate::config_db::ConfigDb;

/// Tri-state flag for whether ClickHouse accepts the `rush_tenant_id` custom setting.
/// 0 = untested, 1 = supported, 2 = not supported (graceful fallback).
static ROW_POLICY_SUPPORTED: AtomicU8 = AtomicU8::new(0);

/// Probe ClickHouse once at startup to see if custom_settings_prefixes includes 'rush_'.
pub async fn probe_row_policy_support(ch: &Client) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    #[allow(dead_code)] // field populated by ClickHouse row deserialization; only the query success matters
    struct Probe {
        n: u8,
    }
    let result = ch
        .query("SELECT 1 AS n")
        .with_option("rush_tenant_id", "probe")
        .fetch_one::<Probe>()
        .await;
    match result {
        Ok(_) => {
            tracing::info!(
                "ClickHouse accepts rush_tenant_id custom setting — row policies enforcing"
            );
            ROW_POLICY_SUPPORTED.store(1, Ordering::Relaxed);
        }
        Err(_) => {
            tracing::warn!(
                "ClickHouse does not accept rush_tenant_id custom setting — row policies permissive. \
                 To enable, add custom_settings_prefixes='rush_' to your ClickHouse server config."
            );
            ROW_POLICY_SUPPORTED.store(2, Ordering::Relaxed);
        }
    }
}

/// Create a ClickHouse query, optionally scoped to a tenant via the `rush_tenant_id`
/// custom setting. Falls back to an unscoped query if the setting is not supported.
pub fn tenant_query(ch: &Client, sql: &str, tenant_id: &str) -> Query {
    let q = ch.query(sql);
    if ROW_POLICY_SUPPORTED.load(Ordering::Relaxed) == 1 {
        q.with_option("rush_tenant_id", tenant_id)
    } else {
        q
    }
}

/// Short-TTL caches for per-request setup work. Both values are cheap to
/// rebuild and only need bounded staleness: skills can lag edits by up to a
/// minute, budget settings by 30s — acceptable for both, and it removes a
/// fresh HTTP fetch plus two `config_settings FINAL` scans from every
/// investigation start.
#[derive(Default)]
pub struct RuntimeCaches {
    /// (built_at, store) — refreshed when older than 60s.
    pub skills: RwLock<Option<(Instant, Arc<SkillStore>)>>,
    /// (read_at, budget) — refreshed when older than 30s.
    pub budget: RwLock<Option<(Instant, LoopBudget)>>,
}

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
    /// Shared secret required on every non-health HTTP request. Only query-api
    /// receives this value in a production deployment.
    pub internal_auth_token: String,
    /// Short-TTL caches for per-request setup (skill store, loop budget).
    pub caches: Arc<RuntimeCaches>,
}
