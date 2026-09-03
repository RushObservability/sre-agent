//! Shared application state for the SRE agent.
//!
//! The agent keeps one authenticated query-api client for telemetry,
//! configuration, and investigation sessions.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::agent::loop_runner::LoopBudget;
use crate::agent::skill_store::SkillStore;
use crate::metrics::AgentMetrics;
use crate::query_api::QueryApiClient;

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
    /// Sole data-plane dependency. Telemetry and configuration are both read
    /// through query-api, which owns tenant enforcement and ClickHouse access.
    pub query_api: Arc<QueryApiClient>,
    /// Shared secret required on every non-health HTTP request. Only query-api
    /// receives this value in a production deployment.
    pub internal_auth_token: String,
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
