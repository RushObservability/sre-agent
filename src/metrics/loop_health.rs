//! Agent decisions and per-run work, independent of provider billing/retries.
use super::AgentMetrics;
use crate::cancellation::CancellationToken;
use std::{
    collections::BTreeMap,
    fmt::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
const WORK_BUCKETS: &[u64] = &[0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512];
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Correction {
    EmptyResponse,
    RepeatCall,
    CausalGate,
    DeadEnd,
    SelfReview,
}
impl Correction {
    fn label(self) -> &'static str {
        match self {
            Self::EmptyResponse => "empty_response",
            Self::RepeatCall => "repeat_call",
            Self::CausalGate => "causal_gate",
            Self::DeadEnd => "dead_end",
            Self::SelfReview => "self_review",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum StopReason {
    Final,
    Question,
    Preliminary,
    BudgetExhausted,
    DeadEnd,
    Disconnected,
    Error,
}
impl StopReason {
    fn label(self) -> &'static str {
        match self {
            Self::Final => "final",
            Self::Question => "question",
            Self::Preliminary => "preliminary",
            Self::BudgetExhausted => "budget_exhausted",
            Self::DeadEnd => "dead_end",
            Self::Disconnected => "disconnected",
            Self::Error => "error",
        }
    }
}
#[derive(Default)]
struct WorkHistogram {
    buckets: [u64; WORK_BUCKETS.len()],
    count: u64,
    sum: u64,
}
impl WorkHistogram {
    fn observe(&mut self, value: u64) {
        self.count += 1;
        self.sum += value;
        for (i, b) in WORK_BUCKETS.iter().enumerate() {
            if value <= *b {
                self.buckets[i] += 1;
            }
        }
    }
    fn render(&self, out: &mut String, name: &str) {
        let _ = writeln!(out, "# TYPE {name} histogram");
        for (i, b) in WORK_BUCKETS.iter().enumerate() {
            let _ = writeln!(out, "{name}_bucket{{le=\"{b}\"}} {}", self.buckets[i]);
        }
        let _ = writeln!(
            out,
            "{name}_bucket{{le=\"+Inf\"}} {}\n{name}_sum {}\n{name}_count {}",
            self.count, self.sum, self.count
        );
    }
}
#[derive(Default)]
pub(super) struct LoopHealthMetrics {
    corrections: Mutex<BTreeMap<Correction, u64>>,
    stops: Mutex<BTreeMap<StopReason, u64>>,
    llm_work: Mutex<WorkHistogram>,
    tool_work: Mutex<WorkHistogram>,
}
impl LoopHealthMetrics {
    pub(super) fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# TYPE sre_agent_loop_corrections_total counter\n# TYPE sre_agent_investigation_stops_total counter"
        );
        for (reason, count) in self
            .corrections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "sre_agent_loop_corrections_total{{reason=\"{}\"}} {count}",
                reason.label()
            );
        }
        for (reason, count) in self.stops.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            let _ = writeln!(
                out,
                "sre_agent_investigation_stops_total{{reason=\"{}\"}} {count}",
                reason.label()
            );
        }
        self.llm_work
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .render(out, "sre_agent_investigation_llm_calls");
        self.tool_work
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .render(out, "sre_agent_investigation_tool_calls");
    }
}
#[derive(Default)]
pub(crate) struct WorkCounters {
    llm: AtomicU64,
    tools: AtomicU64,
}
impl WorkCounters {
    pub(crate) fn tool_call(&self) {
        self.tools.fetch_add(1, Ordering::Relaxed);
    }
}
pub(crate) struct LoopMetricsGuard {
    metrics: Arc<AgentMetrics>,
    cancellation: CancellationToken,
    work: Arc<WorkCounters>,
    reason: StopReason,
}
impl LoopMetricsGuard {
    pub(crate) fn new(metrics: Arc<AgentMetrics>, cancellation: CancellationToken) -> Self {
        Self {
            metrics,
            cancellation,
            work: Arc::new(WorkCounters::default()),
            reason: StopReason::Error,
        }
    }
    pub(crate) fn llm_call(&self) {
        self.work.llm.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn work(&self) -> Arc<WorkCounters> {
        self.work.clone()
    }
    pub(crate) fn correction(&self, reason: Correction) {
        *self
            .metrics
            .loop_health
            .corrections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(reason)
            .or_default() += 1;
    }
    pub(crate) fn stop(&mut self, reason: StopReason) {
        self.reason = reason;
    }
}
impl Drop for LoopMetricsGuard {
    fn drop(&mut self) {
        let reason = if self.cancellation.is_cancelled() {
            StopReason::Disconnected
        } else {
            self.reason
        };
        *self
            .metrics
            .loop_health
            .stops
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(reason)
            .or_default() += 1;
        self.metrics
            .loop_health
            .llm_work
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .observe(self.work.llm.load(Ordering::Relaxed));
        self.metrics
            .loop_health
            .tool_work
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .observe(self.work.tools.load(Ordering::Relaxed));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_partial_work_for_errors_and_disconnects() {
        let metrics = Arc::new(AgentMetrics::new());
        {
            let guard = LoopMetricsGuard::new(metrics.clone(), CancellationToken::new());
            guard.llm_call();
            guard.llm_call();
            guard.work().tool_call();
            guard.correction(Correction::RepeatCall);
        }
        let cancelled = CancellationToken::new();
        let guard = LoopMetricsGuard::new(metrics.clone(), cancelled.clone());
        cancelled.cancel();
        drop(guard);
        let out = metrics.render();
        for expected in [
            "sre_agent_investigation_stops_total{reason=\"error\"} 1",
            "sre_agent_investigation_stops_total{reason=\"disconnected\"} 1",
            "sre_agent_investigation_llm_calls_sum 2",
            "sre_agent_investigation_tool_calls_sum 1",
            "sre_agent_investigation_llm_calls_count 2",
            "sre_agent_loop_corrections_total{reason=\"repeat_call\"} 1",
        ] {
            assert!(out.contains(expected), "{expected}: {out}");
        }
    }
}
