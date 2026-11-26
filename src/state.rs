//! Shared application state for the SRE agent.
//!
//! The agent keeps one authenticated query-api client for telemetry,
//! configuration, and investigation sessions.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::agent::loop_runner::LoopBudget;
use crate::agent::skill_store::SkillStore;
use crate::metrics::AgentMetrics;
use crate::query_api::QueryApiClient;

/// Most tenants one cache holds. Past this, expired entries are pruned and
/// then the oldest entry is evicted, so memory stays bounded.
const MAX_CACHED_TENANTS: usize = 1024;

/// Short-TTL cache keyed by tenant id. Every cached value here is derived from
/// tenant-scoped data, so it must never be served to a different tenant.
pub struct TenantCache<V> {
    ttl: Duration,
    entries: RwLock<HashMap<String, (Instant, V)>>,
}

impl<V: Clone> TenantCache<V> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// The tenant's cached value, if it is younger than the TTL.
    pub async fn get(&self, tenant_id: &str) -> Option<V> {
        self.entries
            .read()
            .await
            .get(tenant_id)
            .filter(|(stored_at, _)| stored_at.elapsed() < self.ttl)
            .map(|(_, value)| value.clone())
    }

    pub async fn insert(&self, tenant_id: &str, value: V) {
        let mut entries = self.entries.write().await;
        if entries.len() >= MAX_CACHED_TENANTS && !entries.contains_key(tenant_id) {
            entries.retain(|_, (stored_at, _)| stored_at.elapsed() < self.ttl);
            if entries.len() >= MAX_CACHED_TENANTS
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, (stored_at, _))| *stored_at)
                    .map(|(tenant, _)| tenant.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(tenant_id.to_string(), (Instant::now(), value));
    }
}

/// Short-TTL, per-tenant caches for per-request setup work. Both values are
/// cheap to rebuild and only need bounded staleness: skills can lag edits by
/// up to a minute, budget settings by 30s — acceptable for both, and it
/// removes a fresh HTTP fetch plus two `config_settings FINAL` scans from
/// every investigation start.
pub struct RuntimeCaches {
    /// Tenant's skill store (built-ins plus its custom skills), 60s TTL.
    pub skills: TenantCache<Arc<SkillStore>>,
    /// Tenant's loop budget settings, 30s TTL.
    pub budget: TenantCache<LoopBudget>,
}

impl Default for RuntimeCaches {
    fn default() -> Self {
        Self {
            skills: TenantCache::new(Duration::from_secs(60)),
            budget: TenantCache::new(Duration::from_secs(30)),
        }
    }
}

impl RuntimeCaches {
    /// The tenant's skill store, loaded from query-api on a cache miss.
    pub async fn skill_store(
        &self,
        query_api: &Arc<QueryApiClient>,
        tenant_id: &str,
        metrics: Option<&AgentMetrics>,
    ) -> Arc<SkillStore> {
        if let Some(store) = self.skills.get(tenant_id).await {
            return store;
        }
        let store = Arc::new(SkillStore::load_with_metrics(query_api, tenant_id, metrics).await);
        self.skills.insert(tenant_id, store.clone()).await;
        store
    }
}

#[derive(Clone)]
pub struct AppState {
    /// Sole data-plane dependency. Telemetry and configuration are both read
    /// through query-api, which owns tenant enforcement and ClickHouse access.
    pub query_api: Arc<QueryApiClient>,
    /// Shared credential for investigation API calls from query-api.
    pub internal_auth_token: String,
    /// Optional credential authorized only for the metrics route.
    pub metrics_auth_token: Option<String>,
    /// Short-TTL caches for per-request setup (skill store, loop budget).
    pub caches: Arc<RuntimeCaches>,
    /// Process-local Prometheus registry and counters.
    pub metrics: Arc<AgentMetrics>,
    /// Bounded investigation admission control shared by every HTTP request.
    pub admission: Arc<InvestigationAdmission>,
}

pub struct InvestigationAdmission {
    semaphore: Arc<tokio::sync::Semaphore>,
    queued: std::sync::atomic::AtomicUsize,
    max_queue: usize,
    metrics: Arc<AgentMetrics>,
}

pub struct InvestigationPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    metrics: Arc<AgentMetrics>,
}

struct QueueReservation {
    admission: Arc<InvestigationAdmission>,
    active: bool,
}

impl Drop for QueueReservation {
    fn drop(&mut self) {
        if self.active {
            self.admission.queued.fetch_sub(1, Ordering::Relaxed);
            self.admission
                .metrics
                .set_queued(self.admission.queued.load(Ordering::Relaxed));
        }
    }
}

impl Drop for InvestigationPermit {
    fn drop(&mut self) {
        self.metrics.investigation_released();
    }
}

impl InvestigationAdmission {
    pub fn from_env(metrics: Arc<AgentMetrics>) -> Self {
        let max_concurrent = env_usize("SRE_AGENT_MAX_CONCURRENT_INVESTIGATIONS", 4, 1, 1024);
        let max_queue = env_usize("SRE_AGENT_MAX_QUEUED_INVESTIGATIONS", 16, 0, 4096);
        Self::new(max_concurrent, max_queue, metrics)
    }

    pub fn new(max_concurrent: usize, max_queue: usize, metrics: Arc<AgentMetrics>) -> Self {
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1))),
            queued: std::sync::atomic::AtomicUsize::new(0),
            max_queue,
            metrics,
        }
    }

    pub async fn acquire(self: &Arc<Self>) -> Result<InvestigationPermit, AdmissionError> {
        let started = Instant::now();
        if let Ok(permit) = self.semaphore.clone().try_acquire_owned() {
            self.metrics.observe_queue_wait(started.elapsed());
            self.metrics.investigation_started();
            return Ok(InvestigationPermit {
                _permit: permit,
                metrics: self.metrics.clone(),
            });
        }

        let mut current = self.queued.load(Ordering::Relaxed);
        loop {
            if current >= self.max_queue {
                self.metrics.investigation_rejected();
                return Err(AdmissionError::QueueFull);
            }
            match self.queued.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        self.metrics.set_queued(self.queued.load(Ordering::Relaxed));
        let mut reservation = QueueReservation {
            admission: self.clone(),
            active: true,
        };
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AdmissionError::Closed)?;
        reservation.active = false;
        self.queued.fetch_sub(1, Ordering::Relaxed);
        self.metrics.set_queued(self.queued.load(Ordering::Relaxed));
        self.metrics.observe_queue_wait(started.elapsed());
        self.metrics.investigation_started();
        Ok(InvestigationPermit {
            _permit: permit,
            metrics: self.metrics.clone(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("investigation capacity is full")]
    QueueFull,
    #[error("investigation admission is closed")]
    Closed,
}

fn env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn skill_cache_keeps_each_tenants_store_separate() {
        use axum::{Json, Router, http::HeaderMap, routing::post};
        use std::sync::Mutex;

        let fetches = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = fetches.clone();
        let app = Router::new().route(
            "/api/v1/internal/sre/context",
            post(move |headers: HeaderMap| {
                let seen = seen.clone();
                async move {
                    let tenant = headers["x-rush-tenant"].to_str().unwrap().to_string();
                    seen.lock().unwrap().push(tenant.clone());
                    Json(serde_json::json!({"data": [{
                        "id": format!("{tenant}-id"),
                        "name": format!("{tenant}-skill"),
                        "title": "t", "description": "d", "content": "secret body",
                        "allowed_tools": [], "enabled": true, "created_by": tenant,
                        "created_at": "", "updated_at": ""
                    }]}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let query_api =
            Arc::new(QueryApiClient::new(&format!("http://{address}"), "token".into()).unwrap());
        let caches = RuntimeCaches::default();

        let a = caches.skill_store(&query_api, "tenant-a", None).await;
        let b = caches.skill_store(&query_api, "tenant-b", None).await;
        assert!(a.get("custom:tenant-a-skill").is_some());
        assert!(a.get("custom:tenant-b-skill").is_none());
        assert!(b.get("custom:tenant-b-skill").is_some());
        assert!(b.get("custom:tenant-a-skill").is_none());

        // A repeat request for the same tenant is served from its own cache entry.
        let a_again = caches.skill_store(&query_api, "tenant-a", None).await;
        assert!(Arc::ptr_eq(&a, &a_again));
        assert_eq!(*fetches.lock().unwrap(), ["tenant-a", "tenant-b"]);
        server.abort();
    }

    #[tokio::test]
    async fn tenant_cache_is_bounded() {
        let cache = TenantCache::new(Duration::from_secs(60));
        for i in 0..=MAX_CACHED_TENANTS {
            cache.insert(&format!("tenant-{i}"), i).await;
        }
        assert_eq!(cache.entries.read().await.len(), MAX_CACHED_TENANTS);
        assert_eq!(cache.get("tenant-0").await, None);
        assert_eq!(
            cache.get(&format!("tenant-{MAX_CACHED_TENANTS}")).await,
            Some(MAX_CACHED_TENANTS)
        );
    }

    #[tokio::test]
    async fn admission_rejects_when_active_capacity_and_queue_are_full() {
        let metrics = Arc::new(AgentMetrics::new());
        let admission = Arc::new(InvestigationAdmission::new(1, 0, metrics.clone()));
        let permit = admission.acquire().await.expect("first request admitted");
        let rejected = admission.acquire().await;
        assert!(matches!(rejected, Err(AdmissionError::QueueFull)));
        assert!(
            metrics
                .render()
                .contains("sre_agent_investigations_rejected_total 1")
        );
        drop(permit);
        assert!(
            metrics
                .render()
                .contains("sre_agent_investigations_in_flight 0")
        );
    }
}
