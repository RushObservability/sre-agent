//! Exactly one terminal outcome for each admitted investigation.
use super::{AgentMetrics, HISTOGRAM_BUCKETS, Histogram};
use std::{
    collections::BTreeMap,
    fmt::Write,
    sync::{Arc, Mutex},
    time::Instant,
};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Outcome {
    Completed,
    Failed,
    Cancelled,
}
impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Setup,
    Execution,
}
impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Execution => "execution",
        }
    }
}
#[derive(Default)]
pub(super) struct LifecycleMetrics {
    outcomes: Mutex<BTreeMap<(Stage, Outcome), u64>>,
    setup: Mutex<Histogram>,
}
impl LifecycleMetrics {
    pub(super) fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# TYPE sre_agent_investigation_terminal_total counter\n# TYPE sre_agent_investigation_setup_duration_seconds histogram"
        );
        for ((stage, outcome), count) in self
            .outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "sre_agent_investigation_terminal_total{{stage=\"{}\",outcome=\"{}\"}} {count}",
                stage.label(),
                outcome.label()
            );
        }
        let h = self.setup.lock().unwrap_or_else(|e| e.into_inner());
        for (i, b) in HISTOGRAM_BUCKETS.iter().enumerate() {
            let _ = writeln!(
                out,
                "sre_agent_investigation_setup_duration_seconds_bucket{{le=\"{b}\"}} {}",
                h.buckets[i]
            );
        }
        let _ = writeln!(
            out,
            "sre_agent_investigation_setup_duration_seconds_bucket{{le=\"+Inf\"}} {}\nsre_agent_investigation_setup_duration_seconds_sum {}\nsre_agent_investigation_setup_duration_seconds_count {}",
            h.count, h.sum, h.count
        );
    }
}
pub(crate) struct InvestigationLifecycle {
    metrics: Arc<AgentMetrics>,
    started: Instant,
    stage: Stage,
    finished: bool,
}
impl InvestigationLifecycle {
    pub(crate) fn new(metrics: Arc<AgentMetrics>) -> Self {
        Self {
            metrics,
            started: Instant::now(),
            stage: Stage::Setup,
            finished: false,
        }
    }
    pub(crate) fn begin_execution(&mut self) {
        if self.stage == Stage::Setup {
            self.observe_setup();
            self.stage = Stage::Execution;
        }
    }
    fn observe_setup(&self) {
        self.metrics
            .lifecycle
            .setup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .observe(self.started.elapsed().as_secs_f64());
    }
    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.record(outcome);
        self.finished = true;
    }
    fn record(&self, outcome: Outcome) {
        if self.stage == Stage::Setup {
            self.observe_setup();
        }
        *self
            .metrics
            .lifecycle
            .outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((self.stage, outcome))
            .or_default() += 1;
        let elapsed = self.started.elapsed();
        match outcome {
            Outcome::Completed => self.metrics.investigation_completed(elapsed),
            Outcome::Failed => self.metrics.investigation_failed(elapsed),
            Outcome::Cancelled => self.metrics.investigation_cancelled(elapsed),
        }
    }
}
impl Drop for InvestigationLifecycle {
    fn drop(&mut self) {
        if !self.finished {
            self.record(if std::thread::panicking() {
                Outcome::Failed
            } else {
                Outcome::Cancelled
            });
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_outcome_is_recorded_once_after_setup_or_execution() {
        let metrics = Arc::new(AgentMetrics::new());
        InvestigationLifecycle::new(metrics.clone()).finish(Outcome::Failed);
        let mut run = InvestigationLifecycle::new(metrics.clone());
        run.begin_execution();
        run.begin_execution();
        run.finish(Outcome::Completed);
        drop(InvestigationLifecycle::new(metrics.clone()));
        let out = metrics.render();
        for expected in [
            "sre_agent_investigations_completed_total 1",
            "sre_agent_investigations_failed_total 1",
            "sre_agent_investigations_cancelled_total 1",
            "sre_agent_investigation_setup_duration_seconds_count 3",
            "stage=\"setup\",outcome=\"failed\"} 1",
            "stage=\"execution\",outcome=\"completed\"} 1",
        ] {
            assert!(out.contains(expected), "{expected}: {out}");
        }
    }
}
