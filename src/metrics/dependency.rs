//! Client-side dependency accounting. Labels are selected from fixed enums.
use super::{AgentMetrics, HISTOGRAM_BUCKETS, Histogram};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Operation {
    Probe,
    Query,
    Profiles,
    Context,
    Session,
    Kubernetes,
    Audit,
    Other,
}
impl Operation {
    fn from_path(path: &str) -> Self {
        if path == "/healthz" || path.ends_with("/llm/ready") {
            Self::Probe
        } else if path.starts_with("/api/v1/internal/sre/sessions") {
            Self::Session
        } else if path == "/api/v1/internal/sre/context" {
            Self::Context
        } else if path == "/api/v1/profiles" {
            Self::Profiles
        } else if path == "/api/v1/internal/kubernetes-access-events" {
            Self::Kubernetes
        } else if path == "/api/v1/internal/repository-access-audit" {
            Self::Audit
        } else if path.starts_with("/api/v1/query")
            || path.starts_with("/api/v1/traces/")
            || path.starts_with("/prom/")
            || path == "/api/v1/services/graph"
        {
            Self::Query
        } else {
            Self::Other
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Query => "query",
            Self::Profiles => "profiles",
            Self::Context => "context",
            Self::Session => "session",
            Self::Kubernetes => "kubernetes",
            Self::Audit => "audit",
            Self::Other => "other",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Outcome {
    Success,
    HttpError,
    Timeout,
    TransportError,
    DecodeError,
    InvalidResponse,
    Cancelled,
}
impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::HttpError => "http_error",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
            Self::DecodeError => "decode_error",
            Self::InvalidResponse => "invalid_response",
            Self::Cancelled => "cancelled",
        }
    }
}
#[derive(Default)]
pub(super) struct DependencyMetrics {
    observations: Mutex<BTreeMap<(Operation, Outcome), Histogram>>,
}
impl DependencyMetrics {
    pub(super) fn render(&self, output: &mut String) {
        let observations = self.observations.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(
            output,
            "# TYPE sre_agent_query_api_request_outcomes_total counter\n# TYPE sre_agent_query_api_operation_duration_seconds histogram"
        );
        for ((operation, outcome), h) in observations.iter() {
            let labels = format!(
                "operation=\"{}\",outcome=\"{}\"",
                operation.label(),
                outcome.label()
            );
            let _ = writeln!(
                output,
                "sre_agent_query_api_request_outcomes_total{{{labels}}} {}",
                h.count
            );
            for (i, boundary) in HISTOGRAM_BUCKETS.iter().enumerate() {
                let _ = writeln!(
                    output,
                    "sre_agent_query_api_operation_duration_seconds_bucket{{{labels},le=\"{boundary}\"}} {}",
                    h.buckets[i]
                );
            }
            let _ = writeln!(
                output,
                "sre_agent_query_api_operation_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}\nsre_agent_query_api_operation_duration_seconds_sum{{{labels}}} {}\nsre_agent_query_api_operation_duration_seconds_count{{{labels}}} {}",
                h.count, h.sum, h.count
            );
        }
    }
}
pub(crate) struct RequestGuard {
    metrics: Option<Arc<AgentMetrics>>,
    operation: Operation,
    started: Instant,
    outcome: Option<Outcome>,
}
impl RequestGuard {
    pub(crate) fn new(metrics: Option<Arc<AgentMetrics>>, path: &str) -> Self {
        if let Some(metrics) = &metrics {
            metrics.query_api_started();
        }
        Self {
            metrics,
            operation: Operation::from_path(path),
            started: Instant::now(),
            outcome: None,
        }
    }
    pub(crate) fn set_http_status(&mut self, status: reqwest::StatusCode) {
        if !status.is_success() {
            self.outcome = Some(Outcome::HttpError);
        }
    }
    pub(crate) fn finish(&mut self, outcome: Outcome) {
        self.outcome = Some(outcome);
    }
    pub(crate) fn reqwest_error(&mut self, error: &reqwest::Error) {
        self.finish(if error.is_timeout() {
            Outcome::Timeout
        } else if error.is_decode() {
            Outcome::DecodeError
        } else {
            Outcome::TransportError
        });
    }
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(metrics) = &self.metrics {
            let duration = self.started.elapsed();
            let outcome = self.outcome.unwrap_or(Outcome::Cancelled);
            metrics.query_api_finished(duration, outcome != Outcome::Success);
            metrics
                .dependency
                .observations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry((self.operation, outcome))
                .or_default()
                .observe(duration.as_secs_f64());
        }
    }
}
