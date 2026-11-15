//! Durable-turn accounting, separate from successful model generation.
use super::{AgentMetrics, HISTOGRAM_BUCKETS, Histogram};
use std::{
    collections::BTreeMap,
    fmt::Write,
    future::Future,
    sync::{Arc, Mutex},
    time::Instant,
};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Operation {
    CountTurns,
    AddTurn,
    UpdateSession,
}
impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::CountTurns => "count_turns",
            Self::AddTurn => "add_turn",
            Self::UpdateSession => "update_session",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    Success,
    Error,
    Cancelled,
}
impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        }
    }
}
#[derive(Default)]
pub(super) struct PersistenceMetrics {
    operations: Mutex<BTreeMap<(Operation, Outcome), Histogram>>,
    turns: Mutex<BTreeMap<Outcome, u64>>,
}
impl PersistenceMetrics {
    pub(super) fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# TYPE sre_agent_session_persistence_total counter\n# TYPE sre_agent_session_persistence_duration_seconds histogram\n# TYPE sre_agent_investigation_persistence_total counter"
        );
        for ((operation, outcome), h) in self
            .operations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let labels = format!(
                "operation=\"{}\",outcome=\"{}\"",
                operation.label(),
                outcome.label()
            );
            let _ = writeln!(
                out,
                "sre_agent_session_persistence_total{{{labels}}} {}",
                h.count
            );
            for (i, b) in HISTOGRAM_BUCKETS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "sre_agent_session_persistence_duration_seconds_bucket{{{labels},le=\"{b}\"}} {}",
                    h.buckets[i]
                );
            }
            let _ = writeln!(
                out,
                "sre_agent_session_persistence_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}\nsre_agent_session_persistence_duration_seconds_sum{{{labels}}} {}\nsre_agent_session_persistence_duration_seconds_count{{{labels}}} {}",
                h.count, h.sum, h.count
            );
        }
        for (outcome, count) in self.turns.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            let _ = writeln!(
                out,
                "sre_agent_investigation_persistence_total{{outcome=\"{}\"}} {count}",
                outcome.label()
            );
        }
    }
}
struct OperationGuard {
    metrics: Arc<AgentMetrics>,
    operation: Operation,
    started: Instant,
    outcome: Outcome,
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.metrics
            .persistence
            .operations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((self.operation, self.outcome))
            .or_default()
            .observe(self.started.elapsed().as_secs_f64());
    }
}
pub(crate) async fn observe<T>(
    metrics: &Arc<AgentMetrics>,
    operation: Operation,
    future: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let mut guard = OperationGuard {
        metrics: metrics.clone(),
        operation,
        started: Instant::now(),
        outcome: Outcome::Cancelled,
    };
    let result = future.await;
    guard.outcome = if result.is_ok() {
        Outcome::Success
    } else {
        Outcome::Error
    };
    result
}
pub(crate) struct TurnGuard {
    metrics: Arc<AgentMetrics>,
    outcome: Outcome,
}
impl TurnGuard {
    pub(crate) fn new(metrics: Arc<AgentMetrics>) -> Self {
        Self {
            metrics,
            outcome: Outcome::Cancelled,
        }
    }
    pub(crate) fn finish(&mut self, success: bool) {
        self.outcome = if success {
            Outcome::Success
        } else {
            Outcome::Error
        };
    }
}
impl Drop for TurnGuard {
    fn drop(&mut self) {
        *self
            .metrics
            .persistence
            .turns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(self.outcome)
            .or_default() += 1;
    }
}
