//! Bounded tool-level diagnostics. Unknown and future names share one bucket.
use super::{HISTOGRAM_BUCKETS, Histogram};
use std::{collections::BTreeMap, fmt::Write, sync::Mutex, time::Duration};
pub(super) fn bounded_name(name: &str) -> &'static str {
    match name {
        "analyze_trace_critical_path" => "analyze_trace_critical_path",
        "compare_service_windows" => "compare_service_windows",
        "detect_service_silence" => "detect_service_silence",
        "get_anomaly_context" => "get_anomaly_context",
        "get_argocd_app" => "get_argocd_app",
        "get_flux_resource" => "get_flux_resource",
        "get_insights" => "get_insights",
        "get_resource_saturation" => "get_resource_saturation",
        "get_trace" => "get_trace",
        "inspect_mysql" => "inspect_mysql",
        "inspect_postgresql" => "inspect_postgresql",
        "inspect_profiles" => "inspect_profiles",
        "kube_describe" => "kube_describe",
        "kube_events" => "kube_events",
        "list_changes" => "list_changes",
        "list_deploys" => "list_deploys",
        "list_metric_catalog" => "list_metric_catalog",
        "list_repository_files" => "list_repository_files",
        "list_services" => "list_services",
        "load_skill" => "load_skill",
        "query_metrics" => "query_metrics",
        "query_traces" => "query_traces",
        "rank_slow_dependencies" => "rank_slow_dependencies",
        "read_repository_file" => "read_repository_file",
        "search_kubernetes_access" => "search_kubernetes_access",
        "search_logs" => "search_logs",
        "search_past_incidents" => "search_past_incidents",
        "search_repository" => "search_repository",
        "service_dependencies" => "service_dependencies",
        _ => "unknown",
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Outcome {
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
pub(super) struct ToolMetrics {
    observations: Mutex<BTreeMap<(&'static str, Outcome), Histogram>>,
    results: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    repeats: Mutex<BTreeMap<&'static str, u64>>,
}
impl ToolMetrics {
    pub(super) fn observe(&self, name: &'static str, outcome: Outcome, duration: Duration) {
        self.observations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((name, outcome))
            .or_default()
            .observe(duration.as_secs_f64());
    }
    pub(super) fn result(&self, name: &str, useful: bool, empty: bool) {
        let result = if useful {
            "useful"
        } else if empty {
            "empty"
        } else {
            "other"
        };
        *self
            .results
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((bounded_name(name), result))
            .or_default() += 1;
    }
    pub(super) fn repeat(&self, name: &str) {
        *self
            .repeats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(bounded_name(name))
            .or_default() += 1;
    }
    pub(super) fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# TYPE sre_agent_tool_outcomes_total counter\n# TYPE sre_agent_tool_operation_duration_seconds histogram\n# TYPE sre_agent_tool_results_total counter\n# TYPE sre_agent_tool_suppressed_total counter"
        );
        for ((name, outcome), h) in self
            .observations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let labels = format!("tool=\"{name}\",outcome=\"{}\"", outcome.label());
            let _ = writeln!(out, "sre_agent_tool_outcomes_total{{{labels}}} {}", h.count);
            for (i, b) in HISTOGRAM_BUCKETS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "sre_agent_tool_operation_duration_seconds_bucket{{{labels},le=\"{b}\"}} {}",
                    h.buckets[i]
                );
            }
            let _ = writeln!(
                out,
                "sre_agent_tool_operation_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}\nsre_agent_tool_operation_duration_seconds_sum{{{labels}}} {}\nsre_agent_tool_operation_duration_seconds_count{{{labels}}} {}",
                h.count, h.sum, h.count
            );
        }
        for ((name, result), count) in self
            .results
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "sre_agent_tool_results_total{{tool=\"{name}\",result=\"{result}\"}} {count}"
            );
        }
        for (name, count) in self
            .repeats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "sre_agent_tool_suppressed_total{{tool=\"{name}\",reason=\"repeat\"}} {count}"
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::AgentMetrics;
    use std::sync::Arc;
    #[test]
    fn every_registered_builtin_has_a_bounded_label() {
        let mut registry = crate::agent::tools::ToolRegistry::new();
        crate::agent::built_in::register_all(&mut registry);
        for definition in registry.definitions() {
            let name = definition["function"]["name"].as_str().unwrap();
            assert_eq!(bounded_name(name), name);
        }
    }
    #[test]
    fn successes_errors_cancellation_results_and_repeats_are_distinct() {
        let metrics = Arc::new(AgentMetrics::new());
        metrics.tool_call_for("query_metrics").finish(false);
        metrics.tool_call_for("query_metrics").finish(true);
        drop(metrics.tool_call_for("secret-user-defined-name"));
        metrics.tool_result_observed("query_metrics", true, false);
        metrics.tool_result_observed("query_metrics", false, true);
        metrics.tool_repeat_suppressed("secret-user-defined-name");
        let out = metrics.render();
        for expected in [
            "tool=\"query_metrics\",outcome=\"success\"} 1",
            "tool=\"query_metrics\",outcome=\"error\"} 1",
            "tool=\"unknown\",outcome=\"cancelled\"} 1",
            "tool=\"unknown\",reason=\"repeat\"} 1",
            "tool=\"query_metrics\",result=\"empty\"} 1",
            "sre_agent_tool_calls_in_flight 0",
            "sre_agent_tool_calls_total 3",
        ] {
            assert!(out.contains(expected), "{expected}: {out}");
        }
        assert!(!out.contains("secret-user-defined-name"));
    }
}
