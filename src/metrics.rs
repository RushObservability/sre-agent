//! Low-cardinality Prometheus metrics for the SRE agent.
//!
//! This is intentionally implemented without a global metrics facade: the agent
//! has one process-local registry, and keeping the names here explicit makes it
//! difficult to accidentally add tenant IDs, session IDs, queries, or arbitrary
//! user/tool input as label values.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const HISTOGRAM_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];

#[derive(Default)]
struct Histogram {
    buckets: [u64; HISTOGRAM_BUCKETS.len()],
    count: u64,
    sum: f64,
}

impl Histogram {
    fn observe(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        for (index, boundary) in HISTOGRAM_BUCKETS.iter().enumerate() {
            if value <= *boundary {
                self.buckets[index] += 1;
            }
        }
    }
}

#[derive(Default)]
pub struct AgentMetrics {
    investigations_in_flight: AtomicI64,
    investigations_queued: AtomicI64,
    investigations_started: AtomicU64,
    investigations_completed: AtomicU64,
    investigations_failed: AtomicU64,
    investigations_cancelled: AtomicU64,
    investigations_rejected: AtomicU64,
    investigations_final: AtomicU64,
    investigations_preliminary: AtomicU64,
    investigations_questions: AtomicU64,
    investigation_tool_calls: AtomicU64,
    investigation_llm_calls: AtomicU64,
    investigation_result_bytes: AtomicU64,
    client_disconnects: AtomicU64,
    cancellations: AtomicU64,
    llm_in_flight: AtomicI64,
    llm_requests: AtomicU64,
    llm_errors: AtomicU64,
    llm_prompt_tokens: AtomicU64,
    llm_completion_tokens: AtomicU64,
    llm_status_2xx: AtomicU64,
    llm_status_4xx: AtomicU64,
    llm_status_5xx: AtomicU64,
    query_api_in_flight: AtomicI64,
    query_api_requests: AtomicU64,
    query_api_errors: AtomicU64,
    clickhouse_probes: AtomicU64,
    clickhouse_errors: AtomicU64,
    process_resident_memory_bytes: AtomicU64,
    process_max_resident_memory_bytes: AtomicU64,
    process_cpu_seconds_bits: AtomicU64,
    process_open_fds: AtomicU64,
    process_threads: AtomicU64,
    process_start_time_bits: AtomicU64,
    runtime_workers: AtomicU64,
    runtime_alive_tasks: AtomicU64,
    tool_in_flight: AtomicI64,
    tool_calls: AtomicU64,
    tool_errors: AtomicU64,
    tool_empty_results: AtomicU64,
    sse_streams_in_flight: AtomicI64,
    sse_streams_closed: AtomicU64,
    readiness: AtomicI64,
    investigation_duration: Mutex<Histogram>,
    investigation_queue_wait: Mutex<Histogram>,
    llm_duration: Mutex<Histogram>,
    tool_duration: Mutex<Histogram>,
    cancellation_latency: Mutex<Histogram>,
    query_api_duration: Mutex<Histogram>,
    clickhouse_probe_duration: Mutex<Histogram>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcessRuntimeSample {
    pub resident_memory_bytes: u64,
    pub max_resident_memory_bytes: u64,
    pub cpu_seconds: f64,
    pub open_fds: u64,
    pub threads: u64,
    pub start_time_seconds: f64,
    pub workers: u64,
    pub alive_tasks: u64,
}

/// RAII guard for an in-flight tool call. Dropping a cancelled future still
/// closes the gauge, which prevents stale concurrency from hiding capacity.
pub struct ToolCallGuard {
    metrics: Arc<AgentMetrics>,
    started: std::time::Instant,
    finished: bool,
}

impl ToolCallGuard {
    pub fn finish(mut self, error: bool) {
        self.metrics.tool_finished(self.started.elapsed(), error);
        self.finished = true;
    }
}

impl Drop for ToolCallGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics.tool_finished(self.started.elapsed(), true);
        }
    }
}

impl AgentMetrics {
    pub fn new() -> Self {
        Self {
            readiness: AtomicI64::new(0),
            ..Self::default()
        }
    }

    pub fn set_queued(&self, value: usize) {
        self.investigations_queued
            .store(value.min(i64::MAX as usize) as i64, Ordering::Relaxed);
    }

    pub fn set_ready(&self, value: bool) {
        self.readiness.store(value as i64, Ordering::Relaxed);
    }

    pub fn investigation_started(&self) {
        self.investigations_started.fetch_add(1, Ordering::Relaxed);
        self.investigations_in_flight
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn investigation_released(&self) {
        self.investigations_in_flight
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn investigation_completed(&self, duration: Duration) {
        self.investigations_completed
            .fetch_add(1, Ordering::Relaxed);
        self.observe(&self.investigation_duration, duration);
    }

    pub fn investigation_failed(&self, duration: Duration) {
        self.investigations_failed.fetch_add(1, Ordering::Relaxed);
        self.observe(&self.investigation_duration, duration);
    }

    pub fn investigation_cancelled(&self, duration: Duration) {
        self.investigations_cancelled
            .fetch_add(1, Ordering::Relaxed);
        self.observe(&self.investigation_duration, duration);
    }

    pub fn investigation_rejected(&self) {
        self.investigations_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the shape and work of a report. `kind` is supplied only by the
    /// fixed report-kind enum in the loop; it is never user input or a label.
    pub fn investigation_reported(
        &self,
        kind: &'static str,
        tool_calls: u32,
        llm_calls: u32,
        result_bytes: usize,
    ) {
        match kind {
            "final" => self.investigations_final.fetch_add(1, Ordering::Relaxed),
            "preliminary" => self
                .investigations_preliminary
                .fetch_add(1, Ordering::Relaxed),
            "question" => self
                .investigations_questions
                .fetch_add(1, Ordering::Relaxed),
            _ => return,
        };
        self.investigation_tool_calls
            .fetch_add(tool_calls as u64, Ordering::Relaxed);
        self.investigation_llm_calls
            .fetch_add(llm_calls as u64, Ordering::Relaxed);
        self.investigation_result_bytes
            .fetch_add(result_bytes as u64, Ordering::Relaxed);
    }

    /// Account for work spent on an investigation that ended before a report
    /// could be emitted, such as a client disconnect.
    pub fn investigation_work(&self, tool_calls: u32, llm_calls: u32) {
        self.investigation_tool_calls
            .fetch_add(tool_calls as u64, Ordering::Relaxed);
        self.investigation_llm_calls
            .fetch_add(llm_calls as u64, Ordering::Relaxed);
    }

    pub fn client_disconnected(&self) {
        self.client_disconnects.fetch_add(1, Ordering::Relaxed);
        self.cancellations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_queue_wait(&self, duration: Duration) {
        self.observe(&self.investigation_queue_wait, duration);
    }

    pub fn llm_started(&self) {
        self.llm_requests.fetch_add(1, Ordering::Relaxed);
        self.llm_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn llm_finished(&self, duration: Duration, error: bool) {
        if error {
            self.llm_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.llm_in_flight.fetch_sub(1, Ordering::Relaxed);
        self.observe(&self.llm_duration, duration);
    }

    pub fn llm_usage(&self, prompt_tokens: u64, completion_tokens: u64) {
        self.llm_prompt_tokens
            .fetch_add(prompt_tokens, Ordering::Relaxed);
        self.llm_completion_tokens
            .fetch_add(completion_tokens, Ordering::Relaxed);
    }

    pub fn llm_status(&self, status: u16) {
        match status {
            200..=299 => self.llm_status_2xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.llm_status_4xx.fetch_add(1, Ordering::Relaxed),
            _ => self.llm_status_5xx.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn query_api_started(&self) {
        self.query_api_requests.fetch_add(1, Ordering::Relaxed);
        self.query_api_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn query_api_finished(&self, duration: Duration, ok: bool) {
        if !ok {
            self.query_api_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.query_api_in_flight.fetch_sub(1, Ordering::Relaxed);
        self.observe(&self.query_api_duration, duration);
    }

    pub fn clickhouse_probe_finished(&self, duration: Duration, ok: bool) {
        self.clickhouse_probes.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.clickhouse_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.observe(&self.clickhouse_probe_duration, duration);
    }

    pub(crate) fn set_process_runtime(&self, sample: ProcessRuntimeSample) {
        self.process_resident_memory_bytes
            .store(sample.resident_memory_bytes, Ordering::Relaxed);
        self.process_max_resident_memory_bytes
            .store(sample.max_resident_memory_bytes, Ordering::Relaxed);
        self.process_cpu_seconds_bits
            .store(sample.cpu_seconds.to_bits(), Ordering::Relaxed);
        self.process_open_fds
            .store(sample.open_fds, Ordering::Relaxed);
        self.process_threads
            .store(sample.threads, Ordering::Relaxed);
        self.process_start_time_bits
            .store(sample.start_time_seconds.to_bits(), Ordering::Relaxed);
        self.runtime_workers
            .store(sample.workers, Ordering::Relaxed);
        self.runtime_alive_tasks
            .store(sample.alive_tasks, Ordering::Relaxed);
    }

    pub fn tool_started(&self) {
        self.tool_calls.fetch_add(1, Ordering::Relaxed);
        self.tool_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tool_call(self: &Arc<Self>) -> ToolCallGuard {
        self.tool_started();
        ToolCallGuard {
            metrics: self.clone(),
            started: std::time::Instant::now(),
            finished: false,
        }
    }

    pub fn tool_finished(&self, duration: Duration, error: bool) {
        if error {
            self.tool_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.tool_in_flight.fetch_sub(1, Ordering::Relaxed);
        self.observe(&self.tool_duration, duration);
    }

    pub fn tool_result_empty(&self) {
        self.tool_empty_results.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_opened(&self) {
        self.sse_streams_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_closed(&self) {
        self.sse_streams_closed.fetch_add(1, Ordering::Relaxed);
        self.sse_streams_in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn observe_cancellation_latency(&self, duration: Duration) {
        self.observe(&self.cancellation_latency, duration);
    }

    fn observe(&self, histogram: &Mutex<Histogram>, duration: Duration) {
        let mut histogram = histogram.lock().unwrap_or_else(|error| error.into_inner());
        histogram.observe(duration.as_secs_f64());
    }

    /// Render the registry in the Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut output = String::with_capacity(4096);
        gauge(
            &mut output,
            "sre_agent_investigations_in_flight",
            "Number of investigations currently executing.",
            self.investigations_in_flight.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "sre_agent_investigations_queued",
            "Number of investigations waiting for an execution slot.",
            self.investigations_queued.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_started_total",
            "Investigations admitted for execution.",
            self.investigations_started.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_completed_total",
            "Investigations completed with a report.",
            self.investigations_completed.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_failed_total",
            "Investigations that failed before producing a report.",
            self.investigations_failed.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_cancelled_total",
            "Investigations cancelled because their client disconnected.",
            self.investigations_cancelled.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_rejected_total",
            "Investigations rejected because the admission queue was full.",
            self.investigations_rejected.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_final_total",
            "Investigations that produced a final report.",
            self.investigations_final.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_preliminary_total",
            "Investigations that produced a preliminary report.",
            self.investigations_preliminary.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigations_questions_total",
            "Investigations that returned a clarifying question.",
            self.investigations_questions.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigation_tool_calls_total",
            "Tool calls used by reported investigations.",
            self.investigation_tool_calls.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigation_llm_calls_total",
            "LLM calls used by investigations.",
            self.investigation_llm_calls.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_investigation_result_bytes_total",
            "Bytes in investigation reports emitted by the agent.",
            self.investigation_result_bytes.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_client_disconnects_total",
            "Client disconnects observed during investigations.",
            self.client_disconnects.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_cancellations_total",
            "Investigation cancellations.",
            self.cancellations.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "sre_agent_llm_requests_in_flight",
            "LLM requests currently in flight.",
            self.llm_in_flight.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_llm_requests_total",
            "LLM requests started.",
            self.llm_requests.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_llm_errors_total",
            "LLM requests that returned an error.",
            self.llm_errors.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_llm_prompt_tokens_total",
            "Prompt tokens reported by the LLM provider.",
            self.llm_prompt_tokens.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_llm_completion_tokens_total",
            "Completion tokens reported by the LLM provider.",
            self.llm_completion_tokens.load(Ordering::Relaxed),
        );
        let _ = writeln!(
            &mut output,
            "# HELP sre_agent_llm_responses_total LLM HTTP responses.\n# TYPE sre_agent_llm_responses_total counter"
        );
        counter_with_label(
            &mut output,
            "2xx",
            self.llm_status_2xx.load(Ordering::Relaxed),
        );
        counter_with_label(
            &mut output,
            "4xx",
            self.llm_status_4xx.load(Ordering::Relaxed),
        );
        counter_with_label(
            &mut output,
            "5xx",
            self.llm_status_5xx.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "sre_agent_query_api_requests_in_flight",
            "Query-api dependency requests currently in flight.",
            self.query_api_in_flight.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_query_api_requests_total",
            "Requests made to query-api.",
            self.query_api_requests.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_query_api_errors_total",
            "Requests to query-api that failed.",
            self.query_api_errors.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_clickhouse_probes_total",
            "ClickHouse dependency probes.",
            self.clickhouse_probes.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_clickhouse_probe_errors_total",
            "ClickHouse dependency probes that failed.",
            self.clickhouse_errors.load(Ordering::Relaxed),
        );
        gauge_u64(
            &mut output,
            "sre_agent_process_resident_memory_bytes",
            self.process_resident_memory_bytes.load(Ordering::Relaxed),
        );
        gauge_u64(
            &mut output,
            "sre_agent_process_max_resident_memory_bytes",
            self.process_max_resident_memory_bytes
                .load(Ordering::Relaxed),
        );
        gauge_f64(
            &mut output,
            "sre_agent_process_cpu_seconds_total",
            f64::from_bits(self.process_cpu_seconds_bits.load(Ordering::Relaxed)),
        );
        gauge_u64(
            &mut output,
            "sre_agent_process_open_fds",
            self.process_open_fds.load(Ordering::Relaxed),
        );
        gauge_u64(
            &mut output,
            "sre_agent_process_threads",
            self.process_threads.load(Ordering::Relaxed),
        );
        gauge_f64(
            &mut output,
            "sre_agent_process_start_time_seconds",
            f64::from_bits(self.process_start_time_bits.load(Ordering::Relaxed)),
        );
        gauge_u64(
            &mut output,
            "sre_agent_runtime_workers",
            self.runtime_workers.load(Ordering::Relaxed),
        );
        gauge_u64(
            &mut output,
            "sre_agent_runtime_alive_tasks",
            self.runtime_alive_tasks.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "sre_agent_tool_calls_in_flight",
            "Tool calls currently in flight.",
            self.tool_in_flight.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_tool_calls_total",
            "Tool calls started.",
            self.tool_calls.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_tool_errors_total",
            "Tool calls that returned an error.",
            self.tool_errors.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_tool_empty_results_total",
            "Tool results classified as empty.",
            self.tool_empty_results.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "sre_agent_sse_streams_in_flight",
            "SSE streams currently open.",
            self.sse_streams_in_flight.load(Ordering::Relaxed),
        );
        counter(
            &mut output,
            "sre_agent_sse_streams_closed_total",
            "SSE streams closed.",
            self.sse_streams_closed.load(Ordering::Relaxed),
        );
        gauge(
            &mut output,
            "sre_agent_readiness",
            "Whether required dependencies are ready.",
            self.readiness.load(Ordering::Relaxed),
        );
        histogram(
            &mut output,
            "sre_agent_investigation_duration_seconds",
            "Investigation duration in seconds.",
            &self.investigation_duration,
        );
        histogram(
            &mut output,
            "sre_agent_investigation_queue_wait_seconds",
            "Investigation admission queue wait in seconds.",
            &self.investigation_queue_wait,
        );
        histogram(
            &mut output,
            "sre_agent_llm_request_duration_seconds",
            "LLM request duration in seconds.",
            &self.llm_duration,
        );
        histogram(
            &mut output,
            "sre_agent_tool_duration_seconds",
            "Tool call duration in seconds.",
            &self.tool_duration,
        );
        histogram(
            &mut output,
            "sre_agent_cancellation_latency_seconds",
            "Time spent between cancellation and loop shutdown in seconds.",
            &self.cancellation_latency,
        );
        histogram(
            &mut output,
            "sre_agent_query_api_request_duration_seconds",
            "Query-api dependency request duration in seconds.",
            &self.query_api_duration,
        );
        histogram(
            &mut output,
            "sre_agent_clickhouse_probe_duration_seconds",
            "ClickHouse dependency probe duration in seconds.",
            &self.clickhouse_probe_duration,
        );
        output
    }
}

fn counter(output: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(
        output,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
    );
}

fn counter_with_label(output: &mut String, value: &str, count: u64) {
    let _ = writeln!(
        output,
        "sre_agent_llm_responses_total{{status_class=\"{value}\"}} {count}"
    );
}

fn gauge(output: &mut String, name: &str, help: &str, value: i64) {
    let _ = writeln!(
        output,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    );
}

fn gauge_u64(output: &mut String, name: &str, value: u64) {
    let _ = writeln!(output, "# TYPE {name} gauge\n{name} {value}");
}

fn gauge_f64(output: &mut String, name: &str, value: f64) {
    let _ = writeln!(output, "# TYPE {name} gauge\n{name} {value}");
}

fn histogram(output: &mut String, name: &str, help: &str, histogram: &Mutex<Histogram>) {
    let histogram = histogram.lock().unwrap_or_else(|error| error.into_inner());
    let _ = writeln!(output, "# HELP {name} {help}\n# TYPE {name} histogram");
    for (index, boundary) in HISTOGRAM_BUCKETS.iter().enumerate() {
        let _ = writeln!(
            output,
            "{name}_bucket{{le=\"{boundary}\"}} {}",
            histogram.buckets[index]
        );
    }
    let _ = writeln!(
        output,
        "{name}_bucket{{le=\"+Inf\"}} {}\n{name}_sum {}\n{name}_count {}",
        histogram.count, histogram.sum, histogram.count
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_only_fixed_low_cardinality_metrics() {
        let metrics = AgentMetrics::new();
        metrics.investigation_started();
        metrics.investigation_completed(Duration::from_millis(25));
        metrics.llm_status(200);
        metrics.llm_usage(11, 7);
        metrics.query_api_started();
        metrics.query_api_finished(Duration::from_millis(3), false);
        metrics.clickhouse_probe_finished(Duration::from_millis(2), true);
        metrics.investigation_reported("final", 3, 4, 128);
        metrics.set_process_runtime(ProcessRuntimeSample {
            resident_memory_bytes: 10,
            max_resident_memory_bytes: 20,
            cpu_seconds: 1.5,
            open_fds: 4,
            threads: 2,
            start_time_seconds: 100.0,
            workers: 4,
            alive_tasks: 8,
        });
        let output = metrics.render();
        assert!(output.contains("sre_agent_investigations_completed_total 1"));
        assert!(output.contains("sre_agent_investigation_duration_seconds_bucket"));
        assert!(output.contains("sre_agent_llm_prompt_tokens_total 11"));
        assert!(output.contains("sre_agent_query_api_errors_total 1"));
        assert!(output.contains("sre_agent_investigations_final_total 1"));
        assert!(output.contains("sre_agent_investigation_tool_calls_total 3"));
        assert!(output.contains("sre_agent_process_resident_memory_bytes 10"));
        assert!(!output.contains("tenant"));
        assert!(!output.contains("session"));
    }
}
