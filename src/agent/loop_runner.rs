use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use super::memory::{
    CallSignature, EvidenceItem, Hypothesis, WorkingMemory, clip_tool_result,
    extract_facts_from_tool_result, normalize_args, truncate_at_char_boundary,
};
use super::stream::{AgentEvent, ReportKind};
use super::tools::{ToolContext, ToolRegistry};
use crate::cancellation::CancellationToken;

/// Default maximum real tool calls. The model should never hear about this
/// number — it exists purely as a backstop against runaway loops.
/// Operators can override per deployment via the `sre_agent_max_tool_steps`
/// setting (see `LoopBudget`).
const DEFAULT_MAX_TOOL_STEPS: u32 = 40;

/// Default max total LLM calls. Includes parse-failure retries, so gives slack
/// over max_tool_steps for things like empty responses or repeat-call
/// corrections that don't consume a real step. Inspired by Raschka's
/// dual-counter pattern. Overridable via `sre_agent_max_llm_calls`.
const DEFAULT_MAX_ATTEMPTS: u32 = 55;

/// Cost-control budgets for one investigation run. Values arrive from the
/// `config_settings` table (set in Settings → AI Agent) or env vars; both
/// paths are untrusted strings, so construction clamps to sane bounds.
#[derive(Debug, Clone, Copy)]
pub struct LoopBudget {
    /// Max model-dispatched tool calls before a summary is forced. Concurrent
    /// calls in one response each consume one unit.
    pub max_tool_calls: u32,
    /// Max tool-bearing LLM rounds before a summary is forced.
    pub max_tool_steps: u32,
    /// Max total LLM calls (tool rounds + retries + critique + summary).
    pub max_llm_calls: u32,
}

impl Default for LoopBudget {
    fn default() -> Self {
        Self {
            max_tool_calls: DEFAULT_MAX_TOOL_STEPS,
            max_tool_steps: DEFAULT_MAX_TOOL_STEPS,
            max_llm_calls: DEFAULT_MAX_ATTEMPTS,
        }
    }
}

impl LoopBudget {
    /// Build from optional override values, clamping to bounds that keep the
    /// agent functional (too low → it can't investigate; absurdly high → no
    /// cost protection at all).
    pub fn from_overrides(max_tool_steps: Option<u32>, max_llm_calls: Option<u32>) -> Self {
        let steps = max_tool_steps
            .unwrap_or(DEFAULT_MAX_TOOL_STEPS)
            .clamp(4, 200);
        // LLM calls must exceed tool steps or the loop dies on retries first.
        let calls = max_llm_calls
            .unwrap_or(DEFAULT_MAX_ATTEMPTS)
            .clamp(steps.saturating_add(2), 300);
        Self {
            max_tool_calls: steps,
            max_tool_steps: steps,
            max_llm_calls: calls,
        }
    }

    /// Minimum tool steps the root-cause gate demands before accepting a
    /// final answer — adapts downward when the operator sets a small budget.
    fn min_depth(&self) -> u32 {
        MIN_INVESTIGATION_DEPTH
            .min(self.max_tool_steps.saturating_sub(1))
            .max(1)
    }
}

/// How many consecutive empty/no-data tool results before escalating.
const DEAD_END_THRESHOLD: u32 = 4;

/// Minimum real tool steps before the root-cause gate will accept a final
/// answer. Prevents the model from concluding after a single lookup.
const MIN_INVESTIGATION_DEPTH: u32 = 4;

/// Minimum number of distinct signal types (logs/traces/metrics/…) that must
/// have returned real data before the gate will accept a Final report.
const MIN_SIGNAL_TYPES: usize = 2;

/// Maximum times the root-cause gate will bounce a premature conclusion back
/// per session. After this many rejections the gate steps aside to avoid an
/// infinite loop, and the report is surfaced as Preliminary.
const MAX_GATE_REJECTIONS: u32 = 3;

/// Keep two actual tool-call slots available for a refutation check and final
/// verification after the exploratory portion of a run.
const RESERVED_VERIFICATION_CALLS: u32 = 2;

#[derive(Debug, Default)]
struct ToolTelemetry {
    dispatched_calls: u32,
    useful_results: u32,
    empty_results: u32,
    result_bytes: u64,
    context_tokens: u64,
    duration_ms: u64,
    per_tool: BTreeMap<String, ToolTelemetryEntry>,
}

#[derive(Debug, Default)]
struct ToolTelemetryEntry {
    calls: u32,
    useful_results: u32,
    result_bytes: u64,
    context_tokens: u64,
    duration_ms: u64,
}

impl ToolTelemetry {
    fn record(
        &mut self,
        tool: &str,
        duration: Duration,
        result_bytes: usize,
        context_tokens: u64,
        useful: bool,
        empty: bool,
    ) {
        let duration_ms = duration.as_millis() as u64;
        self.dispatched_calls += 1;
        self.result_bytes += result_bytes as u64;
        self.context_tokens += context_tokens;
        self.duration_ms += duration_ms;
        if useful {
            self.useful_results += 1;
        }
        if empty {
            self.empty_results += 1;
        }
        let entry = self.per_tool.entry(tool.to_string()).or_default();
        entry.calls += 1;
        entry.result_bytes += result_bytes as u64;
        entry.context_tokens += context_tokens;
        entry.duration_ms += duration_ms;
        if useful {
            entry.useful_results += 1;
        }
    }

    fn log_stop(&self, session_id: &str, reason: &str, tool_steps: u32, attempts: u32) {
        tracing::info!(
            session_id,
            stop_reason = reason,
            tool_steps,
            tool_calls = self.dispatched_calls,
            llm_calls = attempts,
            useful_results = self.useful_results,
            empty_results = self.empty_results,
            result_bytes = self.result_bytes,
            context_tokens = self.context_tokens,
            duration_ms = self.duration_ms,
            per_tool = ?self.per_tool,
            "investigation stop telemetry"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn disconnected_report(
    memory: WorkingMemory,
    model: &str,
    session_id: &str,
    telemetry: &ToolTelemetry,
    tool_steps: u32,
    attempts: u32,
    total_prompt: u64,
    total_completion: u64,
    metrics: &crate::metrics::AgentMetrics,
    cancellation: &CancellationToken,
) -> (String, ReportKind, WorkingMemory, u64, u64, String) {
    cancellation.cancel();
    metrics.client_disconnected();
    metrics.investigation_work(telemetry.dispatched_calls, attempts);
    if let Some(latency) = cancellation.elapsed_since_cancelled() {
        metrics.observe_cancellation_latency(latency);
    }
    tracing::info!(
        session_id,
        tool_steps,
        attempts,
        "client disconnected — aborting investigation early"
    );
    telemetry.log_stop(session_id, "client_disconnected", tool_steps, attempts);
    let text = format!(
        "## Preliminary Investigation Report\n\n**Status**: Client disconnected before \
         the investigation completed\n\n{}",
        memory.to_prompt_block()
    );
    (
        text,
        ReportKind::Preliminary,
        memory,
        total_prompt,
        total_completion,
        model.to_string(),
    )
}

/// Decide whether a given investigation state represents a final or
/// preliminary report. The causal gate is intentionally deterministic: model
/// prose can propose hypotheses and links, but it cannot bypass missing
/// evidence, contradictions, propagation, or report citations.
fn decide_report_kind(
    memory: &WorkingMemory,
    content: &str,
    tool_steps: u32,
    min_depth: u32,
) -> ReportKind {
    // Detect [QUESTION] prefix — agent is asking the user a clarifying question.
    let trimmed = content.trim_start();
    if trimmed.starts_with("[QUESTION]") {
        return ReportKind::Question;
    }

    if memory.escalation_level < 2
        && root_cause_gate(memory, content, tool_steps, min_depth).is_none()
    {
        ReportKind::Final
    } else {
        ReportKind::Preliminary
    }
}

/// Map a tool name to the signal category it belongs to.
fn tool_signal_type(tool_name: &str) -> Option<&'static str> {
    match tool_name {
        "search_logs" => Some("logs"),
        "query_traces"
        | "get_trace"
        | "list_services"
        | "service_dependencies"
        | "compare_service_windows"
        | "rank_slow_dependencies"
        | "analyze_trace_critical_path"
        | "detect_service_silence" => Some("traces"),
        "query_metrics" | "get_resource_saturation" | "list_metric_catalog" => Some("metrics"),
        "kube_describe"
        | "kube_events"
        | "get_argocd_app"
        | "get_flux_resource"
        | "search_kubernetes_access" => Some("kubernetes"),
        "list_deploys" => Some("deploys"),
        _ => None,
    }
}

/// Extract the model's explicit alternative-hypothesis conclusions into the
/// durable ledger. This is intentionally conservative: only content under a
/// heading/label that mentions ruled-out or refuted alternatives is recorded.
fn capture_report_state(memory: &mut WorkingMemory, content: &str) {
    for line in content.lines() {
        if let Some(hypothesis) = parse_hypothesis_line(line) {
            memory.upsert_hypothesis(hypothesis);
        }
    }
    let mut in_ruled_out = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        let lower = line.to_ascii_lowercase();
        if lower.contains("ruled out")
            || lower.contains("refuted alternative")
            || lower.contains("alternatives rejected")
        {
            in_ruled_out = true;
            if let Some((_, value)) = line.split_once(':') {
                let value = value.trim().trim_start_matches(['-', '*']).trim();
                if !value.is_empty() && !is_empty_hypothesis(value) {
                    memory.add_ruled_out(value.to_string());
                    memory.add_failed_hypothesis(value.to_string());
                }
            }
            continue;
        }
        if in_ruled_out && line.starts_with('#') {
            in_ruled_out = false;
            continue;
        }
        if in_ruled_out {
            let value = line.trim_start_matches(['-', '*', ' ']).trim();
            if !value.is_empty() && !is_empty_hypothesis(value) {
                memory.add_ruled_out(value.to_string());
                memory.add_failed_hypothesis(value.to_string());
            }
        }
    }
}

/// Parse the compact, machine-readable ledger line required by the prompt:
/// `HYPOTHESIS H1 | culprit=media | mechanism=cpu throttling | ...`.
/// A markdown-table fallback is accepted for compatibility with older model
/// responses, but the key/value form is preferred because it is unambiguous.
fn parse_hypothesis_line(line: &str) -> Option<Hypothesis> {
    let trimmed = line.trim();
    let fields: Vec<&str> = if let Some(rest) = trimmed.strip_prefix("HYPOTHESIS ") {
        rest.split('|').map(str::trim).collect()
    } else if trimmed.starts_with('|') && trimmed.ends_with('|') {
        trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect()
    } else {
        return None;
    };
    let id = fields.first()?.trim();
    if !id.starts_with('H') || !id[1..].chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let mut hypothesis = Hypothesis {
        id: id.to_string(),
        culprit_service: String::new(),
        mechanism: String::new(),
        symptom_service: String::new(),
        propagation_path: Vec::new(),
        expected_if_true: Vec::new(),
        expected_if_false: Vec::new(),
        supporting_evidence_ids: Vec::new(),
        contradicting_evidence_ids: Vec::new(),
        discriminating_evidence_ids: Vec::new(),
        status: "open".into(),
        confidence: 0.0,
        confidence_band: "low".into(),
        next_best_test: String::new(),
        historical: false,
        carry_reason: String::new(),
    };
    let key_value_form = fields.iter().skip(1).any(|field| field.contains('='));
    if key_value_form {
        for field in fields.iter().skip(1) {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "culprit" | "culprit_service" => hypothesis.culprit_service = value.into(),
                "mechanism" => hypothesis.mechanism = value.into(),
                "symptom" | "symptom_service" => hypothesis.symptom_service = value.into(),
                "path" | "propagation_path" => {
                    hypothesis.propagation_path = value
                        .split("->")
                        .map(|item| item.trim().to_string())
                        .filter(|item| !item.is_empty())
                        .collect()
                }
                "status" => hypothesis.status = value.into(),
                "supports" | "supporting" => {
                    hypothesis.supporting_evidence_ids = parse_evidence_ids(value)
                }
                "contradicts" | "contradicting" => {
                    hypothesis.contradicting_evidence_ids = parse_evidence_ids(value)
                }
                "discriminates" | "discriminating" => {
                    hypothesis.discriminating_evidence_ids = parse_evidence_ids(value)
                }
                "confidence" => {
                    hypothesis.confidence_band = value.into();
                    hypothesis.confidence = match value.to_ascii_lowercase().as_str() {
                        "high" => 0.85,
                        "medium" | "med" => 0.6,
                        _ => 0.25,
                    };
                }
                "confidence_score" => hypothesis.confidence = value.parse().unwrap_or(0.0),
                "next_test" | "next_best_test" => hypothesis.next_best_test = value.into(),
                _ => {}
            }
        }
    } else if fields.len() >= 6 {
        // Legacy table: ID | hypothesis | status | support IDs | contradiction IDs | confidence
        let description = fields[1];
        hypothesis.mechanism = description.into();
        hypothesis.culprit_service = description
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .into();
        hypothesis.status = fields[2].into();
        hypothesis.supporting_evidence_ids = parse_evidence_ids(fields[3]);
        hypothesis.contradicting_evidence_ids = parse_evidence_ids(fields[4]);
        hypothesis.confidence_band = fields[5].into();
        hypothesis.confidence = match fields[5].to_ascii_lowercase().as_str() {
            "high" => 0.85,
            "medium" | "med" => 0.6,
            _ => 0.25,
        };
    }
    Some(hypothesis)
}

fn parse_evidence_ids(value: &str) -> Vec<String> {
    value
        .replace(['[', ']', '(', ')'], "")
        .split([',', ';', ' '])
        .map(str::trim)
        .filter(|item| item.starts_with('E') && item[1..].chars().all(|ch| ch.is_ascii_digit()))
        .map(ToOwned::to_owned)
        .collect()
}

fn is_empty_hypothesis(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "none" | "none yet" | "nothing" | "n/a" | "unknown"
    )
}

/// Root-cause gate: examine the investigation state and return structured gap
/// codes if the agent should remain preliminary. The requirements mirror the
/// PRD's causal final-report contract.
fn root_cause_gate(
    memory: &WorkingMemory,
    content: &str,
    tool_steps: u32,
    min_depth: u32,
) -> Option<String> {
    let mut gaps: Vec<String> = Vec::new();

    if tool_steps < min_depth {
        gaps.push(format!(
            "Only {tool_steps} investigation step(s) completed. \
             Dig deeper — aim for at least {min_depth} before concluding."
        ));
    }

    let unique_signals = memory.unique_signal_count();
    if unique_signals < MIN_SIGNAL_TYPES {
        let consulted: std::collections::HashSet<&str> = memory
            .signals_consulted
            .iter()
            .map(|s| s.as_str())
            .collect();
        let missing: Vec<&str> = ["logs", "traces", "metrics"]
            .iter()
            .copied()
            .filter(|&s| !consulted.contains(s))
            .take(2)
            .collect();
        gaps.push(format!(
            "Only {unique_signals} signal type(s) checked (need {MIN_SIGNAL_TYPES}). \
             Verify the root cause with at least one of: {}. \
             Cross-signal confirmation is required before concluding.",
            if missing.is_empty() {
                "a different signal category".to_string()
            } else {
                missing.join(", ")
            }
        ));
    }

    let active_evidence_count = memory.active_evidence_count();
    if active_evidence_count < 2 {
        gaps.push(format!(
            "Fewer than 2 concrete evidence records in working memory (have {active_evidence_count}). \
             Run targeted queries that return timestamps, values, IDs, or specific messages before concluding."
        ));
    }

    let supported = memory
        .hypotheses
        .iter()
        .filter(|hypothesis| hypothesis.status == "supported" && !hypothesis.historical)
        .max_by(|left, right| left.confidence.total_cmp(&right.confidence));
    let Some(leading) = supported else {
        gaps.push(
            "missing_supported_hypothesis: no supported leading hypothesis is recorded".into(),
        );
        return Some(format_gate_gaps(gaps));
    };
    if leading.culprit_service.is_empty() {
        gaps.push(
            "missing_culprit_service: the leading hypothesis names no culprit service".into(),
        );
    }
    if leading.mechanism.is_empty() {
        gaps.push(
            "missing_mechanism_evidence: the leading hypothesis names no specific mechanism".into(),
        );
    }
    if leading.symptom_service.is_empty() {
        gaps.push("missing_symptom_service: the reported symptom service is not recorded".into());
    }
    if leading.propagation_path.len() < 2 && leading.culprit_service != leading.symptom_service {
        gaps.push(
            "no_propagation_path: the causal path does not connect culprit to symptom".into(),
        );
    }
    let supporting = linked_evidence(memory, &leading.supporting_evidence_ids);
    if supporting.is_empty() {
        gaps.push(
            "missing_mechanism_evidence: the leading hypothesis has no valid supporting evidence"
                .into(),
        );
    }
    if !supporting.iter().any(|item| has_material_change(item)) {
        gaps.push("no_baseline_delta: supporting evidence contains no typed incident-versus-baseline change".into());
    }
    if !supporting.iter().any(|item| {
        service_matches(&item.service, &leading.culprit_service) && has_material_change(item)
    }) {
        gaps.push("culprit_symptom_only: the culprit's own telemetry has not changed".into());
    }
    if !supporting
        .iter()
        .any(|item| mechanism_matches(&leading.mechanism, item))
    {
        gaps.push(
            "missing_mechanism_evidence: no supporting result matches the proposed mechanism"
                .into(),
        );
    }
    if linked_evidence(memory, &leading.discriminating_evidence_ids).is_empty() {
        gaps.push("strong_alternative_untested: no discriminating check is linked to the leading hypothesis".into());
    }
    if supporting.len() >= 2
        && !supporting.iter().enumerate().any(|(index, item)| {
            supporting
                .iter()
                .skip(index + 1)
                .any(|other| evidence_is_independent(item, other))
        })
    {
        gaps.push("same_source_corroboration: supporting evidence does not use independent source families/tables".into());
    }
    for evidence_id in &leading.contradicting_evidence_ids {
        if let Some(item) = memory.evidence.iter().find(|item| &item.id == evidence_id)
            && item.quality.band == crate::agent::contracts::QualityBand::High
        {
            gaps.push(format!("unresolved_contradiction:{evidence_id}"));
        }
    }
    if !supporting
        .iter()
        .any(|item| item.window.is_some() && has_material_change(item))
        || !content.to_ascii_lowercase().contains("onset")
    {
        gaps.push("onset_order_invalid: supporting evidence has no bounded incident window".into());
    }
    let cited = evidence_ids_in_text(content);
    if !content_has_required_sections(content) {
        gaps.push(
            "report_contract_incomplete: final report is missing one or more required sections"
                .into(),
        );
    }
    if !leading
        .supporting_evidence_ids
        .iter()
        .all(|id| cited.contains(id))
    {
        gaps.push(
            "missing_evidence_citation: final report does not cite the leading evidence IDs".into(),
        );
    }

    if gaps.is_empty() {
        return None;
    }
    Some(format_gate_gaps(gaps))
}

fn format_gate_gaps(gaps: Vec<String>) -> String {
    format!(
        "Root cause not yet confirmed. The following causal evidence gaps remain:\n{}\n\nContinue the investigation; do not label this report Final until each gap is resolved.",
        gaps.iter()
            .map(|gap| format!("- {gap}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn linked_evidence<'a>(memory: &'a WorkingMemory, ids: &[String]) -> Vec<&'a EvidenceItem> {
    ids.iter()
        .filter_map(|id| {
            memory
                .evidence
                .iter()
                .find(|item| &item.id == id && !item.historical)
        })
        .collect()
}

fn service_matches(value: &str, service: &str) -> bool {
    value.split(',').map(str::trim).any(|item| item == service) || value == service
}

fn evidence_is_independent(left: &EvidenceItem, right: &EvidenceItem) -> bool {
    left.source_family != right.source_family
        && left
            .source_tables
            .iter()
            .all(|table| !right.source_tables.contains(table))
}

fn has_material_change(item: &EvidenceItem) -> bool {
    item.delta.as_ref().is_some_and(value_has_material_number)
        || item.summary.to_ascii_lowercase().contains("increas")
        || item.summary.to_ascii_lowercase().contains("degrad")
        || item.summary.to_ascii_lowercase().contains("silence")
}

fn value_has_material_number(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_f64().is_some_and(|value| value.abs() > 0.000_001),
        Value::Array(values) => values.iter().any(value_has_material_number),
        Value::Object(values) => values.values().any(value_has_material_number),
        _ => false,
    }
}

fn mechanism_matches(mechanism: &str, evidence: &EvidenceItem) -> bool {
    let mechanism = mechanism.to_ascii_lowercase();
    let text = format!(
        "{} {} {}",
        evidence.tool, evidence.summary, evidence.observation
    )
    .to_ascii_lowercase();
    let families: &[(&str, &[&str])] = &[
        ("cpu", &["cpu", "throttl", "resource"]),
        ("memory", &["memory", "oom", "working_set"]),
        ("oom", &["oom", "memory"]),
        ("restart", &["restart", "evict", "oom"]),
        ("silent", &["silence", "detect_service_silence"]),
        ("down", &["silence", "detect_service_silence"]),
        (
            "database",
            &["dependency", "postgres", "mysql", "database", "db"],
        ),
        ("pool", &["pool", "connection", "database"]),
        ("deploy", &["deploy", "revision"]),
        ("config", &["config", "setting"]),
        ("error", &["error", "status"]),
    ];
    families.iter().any(|(key, markers)| {
        mechanism.contains(key) && markers.iter().any(|marker| text.contains(marker))
    }) || text.contains(&mechanism)
}

fn evidence_ids_in_text(content: &str) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    for token in content.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        if token.starts_with('E')
            && token.len() > 1
            && token[1..].chars().all(|ch| ch.is_ascii_digit())
        {
            ids.insert(token.to_string());
        }
    }
    ids
}

fn content_has_required_sections(content: &str) -> bool {
    let sections = [
        "status",
        "root cause",
        "incident change",
        "causal path",
        "evidence",
        "contradictions",
        "impact",
        "recommended actions",
        "open questions",
    ];
    let positions: Option<Vec<usize>> = sections
        .iter()
        .map(|section| {
            content.lines().position(|line| {
                let heading = line
                    .trim()
                    .trim_start_matches('#')
                    .trim()
                    .to_ascii_lowercase();
                heading.starts_with(section)
            })
        })
        .collect();
    positions.is_some_and(|positions| positions.windows(2).all(|pair| pair[0] < pair[1]))
}

/// Strip the `[QUESTION]` prefix from content if present, returning the
/// clean text to show to the user.
fn strip_question_prefix(content: &str) -> String {
    let trimmed = content.trim_start();
    if let Some(rest) = trimmed.strip_prefix("[QUESTION]") {
        rest.trim_start().to_string()
    } else {
        content.to_string()
    }
}

/// Shared HTTP client for LLM calls. Built once per process with explicit
/// timeouts so a hung LLM backend can never pin a worker forever:
/// - connect: 10s (fail fast on unreachable backends)
/// - total: 300s per call (generous for long streamed generations; streaming
///   reads count against it)
///
/// Reusing one client also keeps the TLS connection pool warm across runs.
fn llm_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("failed to build LLM HTTP client")
    })
}

/// Stub text written over old tool results during transcript compaction.
const COMPACTED_TOOL_RESULT: &str =
    "[tool result compacted — key facts retained in working memory]";

/// How many most-recent assistant-tool-call rounds keep their full tool
/// results in the transcript. Older tool results are stubbed — their key
/// facts already live in working memory (`memory.to_prompt_block()`), so
/// resending multi-KB raw results every round is pure prompt-token waste.
const KEEP_RECENT_TOOL_ROUNDS: usize = 6;

/// Replace the content of tool-result messages older than the most recent
/// `keep_recent_rounds` assistant-tool-call rounds with a one-line stub.
///
/// Rounds are counted from the END of the transcript: each assistant message
/// carrying `tool_calls` marks a round boundary. Tool messages appearing
/// BEFORE the cutoff round's assistant message are stubbed; everything at or
/// after it is left intact. System/user/assistant messages are never touched,
/// and already-stubbed messages are skipped (idempotent).
fn compact_old_tool_results(messages: &mut [Value], keep_recent_rounds: usize) {
    // Find the index of the keep_recent_rounds-th most recent assistant
    // message that carries tool_calls. Tool messages before that index are old.
    let mut rounds_seen = 0usize;
    let mut cutoff: Option<usize> = None;
    for (idx, msg) in messages.iter().enumerate().rev() {
        let is_assistant_tool_round = msg.get("role").and_then(|r| r.as_str()) == Some("assistant")
            && msg.get("tool_calls").is_some_and(|tc| !tc.is_null());
        if is_assistant_tool_round {
            rounds_seen += 1;
            if rounds_seen == keep_recent_rounds {
                cutoff = Some(idx);
                break;
            }
        }
    }
    let Some(cutoff) = cutoff else {
        // Fewer than keep_recent_rounds rounds in the transcript — nothing old.
        return;
    };

    for msg in messages.iter_mut().take(cutoff) {
        if msg.get("role").and_then(|r| r.as_str()) != Some("tool") {
            continue;
        }
        if msg.get("content").and_then(|c| c.as_str()) == Some(COMPACTED_TOOL_RESULT) {
            continue; // already stubbed
        }
        msg["content"] = Value::String(COMPACTED_TOOL_RESULT.to_string());
    }
}

/// Request body for the chat-completions call. Borrows the live transcript
/// so each round serializes straight to the request bytes instead of deep
/// cloning the whole message Vec into an intermediate `Value`.
#[derive(serde::Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [Value],
    stream: bool,
    stream_options: StreamOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct StreamOptions {
    include_usage: bool,
}

/// Configuration for the LLM client used by the agent loop.
/// Decoupled from env vars so tests can point at a mock server.
#[derive(Debug, Clone, Default)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    /// Reasoning effort for thinking models (minimal/low/medium/high). Only sent to the
    /// API when the model is a reasoning model — non-reasoning models reject it.
    pub reasoning_effort: Option<String>,
}

pub const DEFAULT_MODEL: &str = "gpt-4o";

/// Heuristic: does this model support the `reasoning_effort` parameter (OpenAI gpt-5 / o-series)?
pub fn is_reasoning_model(model: &str) -> bool {
    let m = model.trim().to_ascii_lowercase();
    m.starts_with("gpt-5") || m.starts_with("o1") || m.starts_with("o3") || m.starts_with("o4")
}

impl LlmConfig {
    /// Construct the provider connection from environment variables. The model is
    /// intentionally not read from the environment; app settings choose it.
    /// - `OPENAI_API_KEY` (required)
    /// - `OPENAI_BASE_URL` (default: https://api.openai.com)
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("OPENAI_API_KEY is not set"))?;
        Ok(Self {
            base_url: std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".to_string()),
            api_key,
            model: DEFAULT_MODEL.to_string(),
            reasoning_effort: None,
        })
    }

    /// Resolve the configured OpenAI API key.
    pub fn api_key_from_env() -> Option<String> {
        std::env::var("OPENAI_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }
}

/// Run the agent investigation loop, sending events to the channel.
/// Backward-compatible entry point (no session persistence).
pub async fn run(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
) -> Result<()> {
    run_with_config(messages, registry, ctx, tx, LlmConfig::from_env()?).await
}

/// Run the agent loop with an explicit LLM configuration.
/// Backward-compatible entry point (no session persistence).
pub async fn run_with_config(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
    llm: LlmConfig,
) -> Result<()> {
    let (_, _, _, _, _, _) = run_inner(
        messages,
        registry,
        ctx,
        tx,
        llm,
        None,
        "",
        LoopBudget::default(),
        CancellationToken::new(),
    )
    .await?;
    Ok(())
}

/// Session-aware entry point. Accepts optional restored working memory from a
/// prior turn and returns `(summary_text, report_kind, final_working_memory)`
/// so the caller can persist the state. The `session_id` is included in the
/// `Done` event sent over SSE.
/// Returns `(summary_text, report_kind, final_memory, prompt_tokens, completion_tokens, model)`
pub async fn run_with_session(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
    restored_memory: Option<WorkingMemory>,
    session_id: &str,
    budget: LoopBudget,
) -> Result<(String, ReportKind, WorkingMemory, u64, u64, String)> {
    run_inner(
        messages,
        registry,
        ctx,
        tx,
        LlmConfig::from_env()?,
        restored_memory,
        session_id,
        budget,
        CancellationToken::new(),
    )
    .await
}

/// Test-oriented entry point: like [`run_with_session`] but with an explicit
/// [`LlmConfig`] (so tests can point at a mock server without env vars) AND an
/// explicit [`LoopBudget`]. Thin public wrapper over the core loop.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_config_and_budget(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
    llm: LlmConfig,
    restored_memory: Option<WorkingMemory>,
    session_id: &str,
    budget: LoopBudget,
) -> Result<(String, ReportKind, WorkingMemory, u64, u64, String)> {
    run_with_config_and_budget_cancelable(
        messages,
        registry,
        ctx,
        tx,
        llm,
        restored_memory,
        session_id,
        budget,
        CancellationToken::new(),
    )
    .await
}

/// Session-aware loop entry point with cancellation propagated to the LLM
/// stream and concurrent tool calls. The HTTP layer cancels this token when
/// the SSE response body is dropped by the client.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_config_and_budget_cancelable(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
    llm: LlmConfig,
    restored_memory: Option<WorkingMemory>,
    session_id: &str,
    budget: LoopBudget,
    cancellation: CancellationToken,
) -> Result<(String, ReportKind, WorkingMemory, u64, u64, String)> {
    run_inner(
        messages,
        registry,
        ctx,
        tx,
        llm,
        restored_memory,
        session_id,
        budget,
        cancellation,
    )
    .await
}

/// Core agent loop implementation.
///
/// Returns `(summary_text, report_kind, final_working_memory)` when the loop
/// completes. For backward-compatible callers these are ignored; for
/// session-aware callers they enable persistence.
#[allow(clippy::too_many_arguments)]
async fn run_inner(
    messages: Vec<Value>,
    registry: &ToolRegistry,
    ctx: &ToolContext,
    tx: &mpsc::Sender<AgentEvent>,
    llm: LlmConfig,
    restored_memory: Option<WorkingMemory>,
    session_id: &str,
    budget: LoopBudget,
    cancellation: CancellationToken,
) -> Result<(String, ReportKind, WorkingMemory, u64, u64, String)> {
    let base_url = llm.base_url;
    let api_key = llm.api_key;
    let model = llm.model;
    // Only thinking models accept reasoning_effort; others 400 on it.
    let reasoning_effort: Option<String> = if is_reasoning_model(&model) {
        llm.reasoning_effort
    } else {
        None
    };

    let client = llm_client();
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));

    // Tool definitions are immutable for the whole run — build them once
    // instead of re-serializing every tool's JSON schema each round.
    let tool_definitions = Value::Array(registry.definitions());

    let mut messages = messages;

    // Extract the initial user task for working memory
    let initial_task = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|v| v.as_str()) == Some("user"))
        .and_then(|m| m.get("content").and_then(|v| v.as_str()))
        .unwrap_or("")
        .chars()
        .take(300)
        .collect::<String>();

    // Use restored memory if provided, otherwise create fresh.
    let mut memory = if let Some(mut mem) = restored_memory {
        // Update task with the latest user question
        if !initial_task.is_empty() {
            mem.task = initial_task;
        }
        // Reset transient per-turn counters
        mem.consecutive_empty_results = 0;
        mem
    } else {
        WorkingMemory::new(initial_task)
    };

    let mut total_prompt = 0u64;
    let mut total_completion = 0u64;

    let mut tool_steps = 0u32;
    let mut tool_calls_dispatched = 0u32;
    let mut attempts = 0u32;
    let mut force_summary = false;
    let mut reserve_mode = false;
    let mut gate_rejection_count = 0u32;
    let mut telemetry = ToolTelemetry::default();
    let min_depth = budget.min_depth();
    // One self-critique cycle per run: when a conclusion passes the gate for
    // the first time, the agent is asked to challenge it (and may run more
    // tools) before the report is accepted.
    let mut self_review_done = false;

    while tool_steps < budget.max_tool_steps
        && tool_calls_dispatched < budget.max_tool_calls
        && attempts < budget.max_llm_calls
    {
        // Client disconnected (SSE receiver dropped) — every send would be
        // discarded and each further round only burns LLM tokens. Stop now
        // and hand back the memory gathered so far so the caller persists it.
        if cancellation.is_cancelled() || tx.is_closed() {
            return Ok(disconnected_report(
                memory,
                &model,
                session_id,
                &telemetry,
                tool_steps,
                attempts,
                total_prompt,
                total_completion,
                &ctx.state.metrics,
                &cancellation,
            ));
        }

        attempts += 1;

        // Compact tool results older than the recent rounds — their key facts
        // already live in working memory, so resending the raw payloads every
        // round is pure prompt-token waste (O(n²) growth over a long run).
        compact_old_tool_results(&mut messages, KEEP_RECENT_TOOL_ROUNDS);

        // Inject working memory as a TRANSIENT system message if we have facts
        // to share. This is a fresh view each iteration — it's pushed onto the
        // live transcript only for the duration of the request and popped
        // right after, so it never persists in the durable transcript (and we
        // avoid deep-cloning the whole message Vec every round).
        let injected_memory = !memory.confirmed_facts.is_empty()
            || !memory.suspect_services.is_empty()
            || !memory.ruled_out.is_empty();
        if injected_memory {
            messages.push(serde_json::json!({
                "role": "system",
                "content": memory.to_prompt_block(),
            }));
        }

        // Final round, dead-end, or the exploration phase reaching its
        // reserved verification capacity: force a report-shaped response.
        let reserve_threshold = budget
            .max_tool_calls
            .saturating_sub(RESERVED_VERIFICATION_CALLS);
        if !self_review_done && !force_summary && tool_calls_dispatched >= reserve_threshold {
            reserve_mode = true;
        }
        let force_final = tool_steps + 1 >= budget.max_tool_steps
            || tool_calls_dispatched >= budget.max_tool_calls
            || force_summary
            || reserve_mode;

        let llm_started = Instant::now();
        ctx.state.metrics.llm_started();
        let resp = {
            let body = ChatRequest {
                model: &model,
                messages: &messages,
                stream: true,
                stream_options: StreamOptions {
                    include_usage: true,
                },
                tools: if force_final {
                    None
                } else {
                    Some(&tool_definitions)
                },
                reasoning_effort: reasoning_effort.as_deref(),
            };
            tokio::select! {
                _ = cancellation.cancelled() => {
                    ctx.state.metrics.llm_finished(llm_started.elapsed(), true);
                    return Ok(disconnected_report(
                        memory,
                        &model,
                        session_id,
                        &telemetry,
                        tool_steps,
                        attempts,
                        total_prompt,
                        total_completion,
                        &ctx.state.metrics,
                        &cancellation,
                    ));
                }
                result = client
                    .post(&url)
                    .header("Authorization", format!("Bearer {api_key}"))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send() => result
            }
        };

        // Remove the transient memory message BEFORE any error propagation or
        // transcript appends, so it can never leak into the durable transcript.
        if injected_memory {
            messages.pop();
        }
        let resp = match resp {
            Ok(response) => response,
            Err(error) => {
                ctx.state.metrics.llm_finished(llm_started.elapsed(), true);
                if cancellation.is_cancelled() || tx.is_closed() {
                    return Ok(disconnected_report(
                        memory,
                        &model,
                        session_id,
                        &telemetry,
                        tool_steps,
                        attempts,
                        total_prompt,
                        total_completion,
                        &ctx.state.metrics,
                        &cancellation,
                    ));
                }
                return Err(error.into());
            }
        };

        ctx.state.metrics.llm_status(resp.status().as_u16());
        if !resp.status().is_success() {
            ctx.state.metrics.llm_finished(llm_started.elapsed(), true);
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            let msg = format!(
                "LLM returned {status}: {}",
                truncate_at_char_boundary(&err_body, 500)
            );
            let _ = tx
                .send(AgentEvent::Error {
                    message: msg.clone(),
                })
                .await;
            return Err(anyhow::anyhow!(msg));
        }

        let parsed = parse_streaming_response(resp, tx, cancellation.clone()).await;
        let (content, mut tool_calls, usage) = match parsed {
            Ok(value) => {
                ctx.state.metrics.llm_finished(llm_started.elapsed(), false);
                value
            }
            Err(_error) if cancellation.is_cancelled() || tx.is_closed() => {
                ctx.state.metrics.llm_finished(llm_started.elapsed(), true);
                return Ok(disconnected_report(
                    memory,
                    &model,
                    session_id,
                    &telemetry,
                    tool_steps,
                    attempts,
                    total_prompt,
                    total_completion,
                    &ctx.state.metrics,
                    &cancellation,
                ));
            }
            Err(error) => {
                ctx.state.metrics.llm_finished(llm_started.elapsed(), true);
                return Err(error);
            }
        };
        total_prompt += usage.0;
        total_completion += usage.1;
        ctx.state.metrics.llm_usage(usage.0, usage.1);

        // --- Classify response ---
        if tool_calls.is_empty() {
            if content.trim().is_empty() {
                // Parse-retry: empty response, no tools — inject retry notice and loop
                messages.push(serde_json::json!({
                    "role": "system",
                    "content": "Previous response was empty. Either call a tool to gather more \
                               evidence or produce a structured investigation report.",
                }));
                continue;
            }

            // Preserve the model's explicit alternative-hypothesis work in
            // durable memory before the gate evaluates the report.
            capture_report_state(&mut memory, &content);

            // Root-cause gate: bounce premature conclusions back until the
            // agent has gathered sufficient multi-signal evidence, or until
            // the gate has rejected MAX_GATE_REJECTIONS times (at which point
            // we surface a Preliminary report rather than looping forever).
            if gate_rejection_count < MAX_GATE_REJECTIONS {
                if let Some(gap_msg) = root_cause_gate(&memory, &content, tool_steps, min_depth) {
                    gate_rejection_count += 1;
                    messages.push(serde_json::json!({
                        "role": "assistant",
                        "content": content.clone(),
                    }));
                    messages.push(serde_json::json!({
                        "role": "system",
                        "content": gap_msg,
                    }));
                    continue;
                }
            }

            // Self-review pass: the first time a conclusion clears the gate
            // (i.e. it would be accepted), make the agent challenge its own
            // root cause before we take it. Tools stay available so it can go
            // verify or revisit something — "question yourself, then look
            // again". One cycle per run keeps the added cost bounded; skipped
            // when the budget forced this summary or for clarifying questions.
            let is_question = content.trim_start().starts_with("[QUESTION]");
            if !self_review_done
                && !is_question
                && (!force_final || reserve_mode)
                && memory.escalation_level < 2
                && attempts + 2 <= budget.max_llm_calls
            {
                self_review_done = true;
                reserve_mode = false;
                force_summary = false;
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": content.clone(),
                }));
                messages.push(serde_json::json!({
                    "role": "system",
                    "content": "Before this conclusion is accepted, review it as a skeptical \
                        senior SRE who did NOT run this investigation:\n\
                        1. What alternative explanations fit the same evidence? Name the strongest one.\n\
                        2. Does anything in the gathered evidence contradict or weaken your root cause?\n\
                        3. Is there ONE targeted check that would materially confirm or refute it \
                        (e.g. the suspect's upstream dependency, the deploy timeline, a narrower \
                        time window around onset)? If yes, RUN IT NOW with a tool.\n\
                        Then produce your final report. State a confidence level (high/medium/low) \
                        with one line of justification, and list what you ruled out. If the review \
                        changed your conclusion, say so explicitly and continue investigating instead.",
                }));
                continue;
            }

            // Final answer (or question)
            let kind = decide_report_kind(&memory, &content, tool_steps, min_depth);
            let kind_name = match &kind {
                ReportKind::Final => "final",
                ReportKind::Preliminary => "preliminary",
                ReportKind::Question => "question",
            };
            let stop_reason = match kind {
                ReportKind::Final => "causal_gate_passed",
                ReportKind::Question => "clarifying_question",
                ReportKind::Preliminary => "preliminary_report",
            };
            telemetry.log_stop(session_id, stop_reason, tool_steps, attempts);
            let display_text = strip_question_prefix(&content);
            ctx.state.metrics.investigation_reported(
                kind_name,
                telemetry.dispatched_calls,
                attempts,
                display_text.len(),
            );
            let _ = tx
                .send(AgentEvent::Summary {
                    text: display_text.clone(),
                    kind: kind.clone(),
                })
                .await;
            let _ = tx
                .send(AgentEvent::Done {
                    rounds: tool_steps + 1,
                    tool_calls: telemetry.dispatched_calls,
                    prompt_tokens: total_prompt,
                    completion_tokens: total_completion,
                    session_id: session_id.to_string(),
                    model: model.clone(),
                })
                .await;
            return Ok((
                display_text,
                kind,
                memory,
                total_prompt,
                total_completion,
                model,
            ));
        }

        // Enforce the actual tool-call budget before dispatching. A single
        // model response may contain several concurrent calls, so a batch
        // cannot bypass the cap merely by being concurrent.
        let reserved = if self_review_done {
            0
        } else {
            RESERVED_VERIFICATION_CALLS
        };
        let remaining = budget
            .max_tool_calls
            .saturating_sub(tool_calls_dispatched.saturating_add(reserved));
        if remaining == 0 {
            reserve_mode = true;
            messages.push(serde_json::json!({
                "role": "system",
                "content": "The exploratory tool budget is exhausted. Use the reserved capacity only for a targeted refutation or final verification, then produce the required report.",
            }));
            continue;
        }
        if tool_calls.len() > remaining as usize {
            tracing::debug!(
                session_id,
                requested = tool_calls.len(),
                allowed = remaining,
                "truncating concurrent tool batch to remaining budget"
            );
            tool_calls.truncate(remaining as usize);
        }
        tool_calls_dispatched += tool_calls.len() as u32;

        // Record assistant message with the budget-approved tool calls
        let tc_value: Vec<Value> = tool_calls
            .iter()
            .map(|tc| {
                serde_json::json!({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }
                })
            })
            .collect();

        let mut assistant_msg = serde_json::json!({
            "role": "assistant",
            "tool_calls": tc_value,
        });
        if !content.is_empty() {
            assistant_msg["content"] = Value::String(content);
        }
        messages.push(assistant_msg);

        // Execute the round's tool calls (usually just one per round).
        //
        // Pass 1 — synchronous bookkeeping in call order. Repeat-call
        // detection must see earlier calls from the SAME round. Signal
        // coverage is deliberately recorded later, after a result proves
        // that the query returned usable data.
        enum Planned {
            /// Repeat call — precomputed structured error, never executed.
            PrecomputedError(String),
            /// New call — execute against the registry.
            Execute,
        }
        let mut planned: Vec<(Value, Planned)> = Vec::with_capacity(tool_calls.len());
        for tc in &tool_calls {
            let args: Value = serde_json::from_str(&tc.arguments).unwrap_or(Value::Null);

            let sig = CallSignature {
                tool: tc.name.clone(),
                args_normalized: normalize_args(&args),
            };
            let plan = if memory.is_repeat_call(&sig) {
                Planned::PrecomputedError(format!(
                    "Error: this exact tool call was already made in this investigation. \
                     Do not repeat identical queries. Options:\n\
                     - Vary the time window, service, or filters\n\
                     - Try a different signal source (logs ↔ traces ↔ metrics ↔ k8s)\n\
                     - If you have enough evidence, produce your final report instead\n\
                     Previous call: {} with args matching this one.",
                    tc.name
                ))
            } else {
                memory.record_call(sig);
                Planned::Execute
            };
            planned.push((args, plan));
        }

        // Announce every call (including repeats) in order before execution.
        for (tc, (args, _)) in tool_calls.iter().zip(&planned) {
            let _ = tx
                .send(AgentEvent::ToolCall {
                    name: tc.name.clone(),
                    args: args.clone(),
                })
                .await;
        }

        // Pass 2 — run the real calls concurrently: round wall time becomes
        // max(tool latencies) instead of their sum. Each future yields
        // (did_real_work, result_text).
        struct ToolOutcome {
            real_work: bool,
            result: String,
            duration: Duration,
            error: bool,
        }
        let metrics = ctx.state.metrics.clone();
        let tool_futures = tool_calls.iter().zip(&planned).map(|(tc, (args, plan))| {
            let metrics = metrics.clone();
            async move {
                let started = Instant::now();
                match plan {
                    Planned::PrecomputedError(msg) => ToolOutcome {
                        real_work: false,
                        result: msg.clone(),
                        duration: started.elapsed(),
                        error: false,
                    },
                    Planned::Execute => {
                        let tool_guard = metrics.tool_call();
                        let (real_work, result, error) =
                            match registry.execute(&tc.name, args.clone(), ctx).await {
                                Ok(data) => (true, clip_tool_result(&tc.name, &data), false),
                                Err(e) => (false, format!("Tool error: {e}"), true),
                            };
                        let duration = started.elapsed();
                        tool_guard.finish(error);
                        ToolOutcome {
                            real_work,
                            result,
                            duration,
                            error,
                        }
                    }
                }
            }
        });
        let outcomes: Vec<ToolOutcome> = tokio::select! {
            _ = cancellation.cancelled() => {
                return Ok(disconnected_report(
                    memory,
                    &model,
                    session_id,
                    &telemetry,
                    tool_steps,
                    attempts,
                    total_prompt,
                    total_completion,
                    &ctx.state.metrics,
                    &cancellation,
                ));
            }
            outcomes = futures_util::future::join_all(tool_futures) => outcomes,
        };

        // Pass 3 — apply results in original call order, with the same
        // per-call sequence as the old sequential loop: memory fact
        // extraction → empty-result accounting → ToolResult event →
        // transcript push.
        let mut any_real_work = false;
        for ((tc, (args, plan)), outcome) in tool_calls.iter().zip(&planned).zip(outcomes) {
            let real_work = outcome.real_work;
            let result = outcome.result;
            if real_work {
                any_real_work = true;
            }

            // Update working memory from this result (skipped for repeats,
            // matching the previous behavior).
            let facts = extract_facts_from_tool_result(&tc.name, args, &result);
            let useful_result = facts.has_data;
            let empty_result = facts.empty_result;
            let context_tokens = (result.len() as u64).div_ceil(4);
            telemetry.record(
                &tc.name,
                outcome.duration,
                result.len(),
                context_tokens,
                useful_result,
                empty_result,
            );
            if empty_result {
                ctx.state.metrics.tool_result_empty();
            }
            tracing::debug!(
                session_id,
                tool = %tc.name,
                duration_ms = outcome.duration.as_millis() as u64,
                result_bytes = result.len(),
                context_tokens,
                useful = useful_result,
                empty = empty_result,
                error = outcome.error,
                "tool result telemetry"
            );
            let provenance = crate::agent::contracts::ToolResultEnvelope::from_legacy(
                &tc.name,
                args,
                &result,
                facts.summary.as_deref(),
            );

            if !matches!(plan, Planned::PrecomputedError(_)) {
                for svc in facts.services {
                    memory.add_suspect_service(svc);
                }
                if let Some(summary) = facts.summary {
                    memory.add_fact(format!("{}: {}", tc.name, summary.clone()));
                    if facts.has_data {
                        if let Some(sig_type) = tool_signal_type(&tc.name) {
                            memory.record_signal(sig_type);
                            let _ = memory.add_evidence_from_envelope(&tc.name, &provenance);
                        }
                    }
                }
                if facts.empty_result {
                    memory.consecutive_empty_results += 1;
                } else {
                    memory.consecutive_empty_results = 0;
                }
            }

            let _ = tx
                .send(AgentEvent::ToolResult {
                    name: tc.name.clone(),
                    data: result.clone(),
                    provenance: Box::new(provenance),
                })
                .await;

            messages.push(serde_json::json!({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            }));
        }

        // Dead-end detection: too many empty/no-data results in a row.
        // Instead of immediately forcing a summary we escalate through three
        // levels, nudging the model toward progressively broader alternative
        // strategies. Only level 3+ actually withholds tools and forces a
        // preliminary report.
        if memory.consecutive_empty_results >= DEAD_END_THRESHOLD {
            memory.consecutive_empty_results = 0; // reset counter
            memory.escalation_level += 1;

            let nudge = match memory.escalation_level {
                1 => {
                    "Multiple recent tool calls returned no data. Do NOT give up. Try a \
                      DIFFERENT tool category than the one you've been using. If you've been \
                      searching logs, try query_traces or query_metrics. If you've been \
                      checking one service, check its upstream or downstream dependencies \
                      via service_dependencies."
                }
                2 => {
                    "You've tried alternative tool categories without finding the signal. \
                      Do NOT give up. Check the service dependency graph — the root cause \
                      is often in an upstream or downstream service, not the one originally \
                      reported. Use service_dependencies then investigate each adjacent \
                      service. Also try widening your time window."
                }
                _ => {
                    "You have thoroughly explored multiple angles. Before producing a \
                      final conclusion, you MUST enumerate what you've ruled out and what \
                      specific questions remain open. Produce a PRELIMINARY findings report \
                      with explicit open questions, not a 'cannot determine' surrender. \
                      The user may follow up to refine further — give them specific things \
                      to ask about."
                }
            };

            // Inject the nudge as a system message for the next LLM call.
            messages.push(serde_json::json!({
                "role": "system",
                "content": nudge,
            }));

            // Only force summary at level 3+
            if memory.escalation_level >= 3 {
                force_summary = true;
            }
        }

        // Only count as a real tool step if we actually did work (not just repeat errors)
        if any_real_work {
            tool_steps += 1;
        }
    }

    // Budget exhausted without a final answer — emit a preliminary report so
    // the user sees what we learned and can follow up. This branch should be
    // rare because the escalation ladder above usually forces an earlier
    // summary, but we still need a safety net for runaway loops.
    let termination_reason =
        if attempts >= budget.max_llm_calls && tool_steps < budget.max_tool_steps {
            "Too many parse failures or repeat calls"
        } else {
            "Exhausted internal investigation budget"
        };
    telemetry.log_stop(session_id, "budget_exhausted", tool_steps, attempts);

    let text = format!(
        "## Preliminary Investigation Report\n\n**Status**: {}\n\n{}\n\n\
         The investigation has not produced a confirmed root cause. Follow up with a\n\
         more specific question or an additional angle (upstream service, widened time\n\
         window, different signal source) to continue from this state.",
        termination_reason,
        memory.to_prompt_block()
    );

    let _ = tx
        .send(AgentEvent::Summary {
            text: text.clone(),
            kind: ReportKind::Preliminary,
        })
        .await;
    ctx.state.metrics.investigation_reported(
        "preliminary",
        telemetry.dispatched_calls,
        attempts,
        text.len(),
    );
    let _ = tx
        .send(AgentEvent::Done {
            rounds: tool_steps,
            tool_calls: telemetry.dispatched_calls,
            prompt_tokens: total_prompt,
            completion_tokens: total_completion,
            session_id: session_id.to_string(),
            model: model.clone(),
        })
        .await;

    Ok((
        text,
        ReportKind::Preliminary,
        memory,
        total_prompt,
        total_completion,
        model,
    ))
}

struct ToolCallAccum {
    id: String,
    name: String,
    arguments: String,
}

/// Mutable accumulation state for one streaming LLM response.
#[derive(Default)]
struct StreamAccum {
    content: String,
    tool_calls: Vec<ToolCallAccum>,
    prompt_tokens: u64,
    completion_tokens: u64,
}

/// Process one complete SSE line. Forwards content deltas over `tx` as they
/// arrive and accumulates tool-call fragments and usage. Returns `true` when
/// the `[DONE]` sentinel is seen. Malformed lines are tolerated (skipped).
async fn process_sse_line(
    line: &str,
    accum: &mut StreamAccum,
    tx: &mpsc::Sender<AgentEvent>,
) -> bool {
    let line = line.trim();
    if !line.starts_with("data: ") {
        return false;
    }
    let data = &line[6..];
    if data == "[DONE]" {
        return true;
    }

    let chunk: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(_) => return false,
    };

    if let Some(usage) = chunk.get("usage") {
        accum.prompt_tokens = usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(accum.prompt_tokens);
        accum.completion_tokens = usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(accum.completion_tokens);
    }

    let choices = match chunk.get("choices").and_then(|c| c.as_array()) {
        Some(c) => c,
        None => return false,
    };

    for choice in choices {
        let delta = match choice.get("delta") {
            Some(d) => d,
            None => continue,
        };

        if let Some(text) = delta.get("content").and_then(|v| v.as_str())
            && !text.is_empty()
        {
            accum.content.push_str(text);
            let _ = tx
                .send(AgentEvent::ThinkingDelta {
                    text: text.to_string(),
                })
                .await;
        }

        if let Some(tcs) = delta.get("tool_calls").and_then(|v| v.as_array()) {
            for tc in tcs {
                let idx = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                while accum.tool_calls.len() <= idx {
                    accum.tool_calls.push(ToolCallAccum {
                        id: String::new(),
                        name: String::new(),
                        arguments: String::new(),
                    });
                }

                if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                    accum.tool_calls[idx].id = id.to_string();
                }
                if let Some(func) = tc.get("function") {
                    if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                        accum.tool_calls[idx].name = name.to_string();
                    }
                    if let Some(args) = func.get("arguments").and_then(|v| v.as_str()) {
                        accum.tool_calls[idx].arguments.push_str(args);
                    }
                }
            }
        }
    }

    false
}

/// Parse an OpenAI-compatible streaming response incrementally.
///
/// Consumes the body chunk-by-chunk via `bytes_stream()` so content deltas
/// reach the SSE channel in real time, rather than buffering the entire
/// generation (10–60s) before emitting anything.
/// Returns (content_text, tool_calls, (prompt_tokens, completion_tokens)).
async fn parse_streaming_response(
    resp: reqwest::Response,
    tx: &mpsc::Sender<AgentEvent>,
    cancellation: CancellationToken,
) -> Result<(String, Vec<ToolCallAccum>, (u64, u64))> {
    use futures_util::StreamExt;

    /// Defensive cap on the partial-line accumulation buffer. No legitimate
    /// SSE line approaches this; if exceeded, the upstream is misbehaving and
    /// we fail rather than buffer without bound.
    const MAX_LINE_BUFFER: usize = 4 * 1024 * 1024; // 4 MiB

    let mut accum = StreamAccum::default();
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    let mut done = false;

    'recv: while let Some(chunk) = tokio::select! {
        _ = cancellation.cancelled() => {
            return Err(anyhow::anyhow!("client disconnected"));
        }
        chunk = stream.next() => chunk
    } {
        let chunk = chunk?;
        buf.extend_from_slice(&chunk);

        // Process every complete line currently in the buffer. A cursor scan
        // with a single drain at the end avoids shifting the whole remaining
        // buffer to the front once per line.
        let mut cursor = 0usize;
        while let Some(rel) = buf[cursor..].iter().position(|&b| b == b'\n') {
            let end = cursor + rel;
            let line = String::from_utf8_lossy(&buf[cursor..=end]);
            if process_sse_line(&line, &mut accum, tx).await {
                done = true;
                break 'recv; // [DONE] — anything after it is ignored
            }
            cursor = end + 1;
        }
        buf.drain(..cursor);

        if buf.len() > MAX_LINE_BUFFER {
            return Err(anyhow::anyhow!(
                "LLM stream sent a line larger than {MAX_LINE_BUFFER} bytes — aborting"
            ));
        }
    }

    // Tolerate a final line without a trailing newline (matches the previous
    // `.lines()` behavior over the fully-buffered body).
    if !done && !buf.is_empty() {
        let line = String::from_utf8_lossy(&buf);
        let _ = process_sse_line(&line, &mut accum, tx).await;
    }

    Ok((
        accum.content,
        accum.tool_calls,
        (accum.prompt_tokens, accum.completion_tokens),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::contracts::{InvestigationWindow, WindowSelectionReason};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    /// Build one investigation round: assistant tool-call message + tool result.
    fn round(n: usize) -> Vec<Value> {
        vec![
            json!({
                "role": "assistant",
                "tool_calls": [{
                    "id": format!("call_{n}"),
                    "type": "function",
                    "function": {"name": "search_logs", "arguments": "{}"}
                }]
            }),
            json!({
                "role": "tool",
                "tool_call_id": format!("call_{n}"),
                "content": format!("tool result {n}")
            }),
        ]
    }

    fn transcript(rounds: usize) -> Vec<Value> {
        let mut msgs = vec![
            json!({"role": "system", "content": "You are a test agent."}),
            json!({"role": "user", "content": "Investigate the outage."}),
        ];
        for n in 0..rounds {
            msgs.extend(round(n));
        }
        msgs
    }

    fn tool_contents(msgs: &[Value]) -> Vec<String> {
        msgs.iter()
            .filter(|m| m["role"] == "tool")
            .map(|m| m["content"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn compaction_stubs_only_old_tool_results() {
        // 9 rounds, keep 6 → rounds 0..=2 are older than the cutoff (round 3
        // is the 6th most recent) and get stubbed; rounds 3..=8 stay intact.
        let mut msgs = transcript(9);
        compact_old_tool_results(&mut msgs, 6);

        let contents = tool_contents(&msgs);
        assert_eq!(contents.len(), 9);
        for (n, c) in contents.iter().enumerate() {
            if n < 3 {
                assert_eq!(c, COMPACTED_TOOL_RESULT, "round {n} should be stubbed");
            } else {
                assert_eq!(c, &format!("tool result {n}"), "round {n} should be intact");
            }
        }

        // System/user/assistant messages are never touched.
        assert_eq!(msgs[0]["content"], "You are a test agent.");
        assert_eq!(msgs[1]["content"], "Investigate the outage.");
        for m in &msgs {
            if m["role"] == "assistant" {
                assert!(
                    m.get("tool_calls").is_some(),
                    "assistant tool_calls preserved"
                );
            }
        }
    }

    #[test]
    fn compaction_noop_when_few_rounds() {
        let mut msgs = transcript(6);
        let before = msgs.clone();
        compact_old_tool_results(&mut msgs, 6);
        assert_eq!(
            msgs, before,
            "exactly keep_recent_rounds rounds → nothing stubbed"
        );

        let mut msgs = transcript(2);
        let before = msgs.clone();
        compact_old_tool_results(&mut msgs, 6);
        assert_eq!(msgs, before, "fewer rounds than keep → nothing stubbed");
    }

    #[test]
    fn compaction_is_idempotent_and_advances_with_new_rounds() {
        let mut msgs = transcript(8);
        compact_old_tool_results(&mut msgs, 6);
        let after_first = msgs.clone();
        compact_old_tool_results(&mut msgs, 6);
        assert_eq!(msgs, after_first, "second pass must change nothing");

        // A new round arrives → exactly one more old result gets stubbed.
        msgs.extend(round(8));
        compact_old_tool_results(&mut msgs, 6);
        let contents = tool_contents(&msgs);
        assert_eq!(
            contents
                .iter()
                .filter(|c| *c == COMPACTED_TOOL_RESULT)
                .count(),
            3
        );
        assert_eq!(contents.last().unwrap(), "tool result 8");
    }

    #[test]
    fn compaction_skips_mixed_non_tool_messages() {
        // Interleave system nudges (as the loop does for gate rejections /
        // dead-end escalations) and verify they survive untouched.
        let mut msgs = transcript(3);
        msgs.push(json!({"role": "system", "content": "nudge: try traces"}));
        for n in 3..8 {
            msgs.extend(round(n));
        }
        compact_old_tool_results(&mut msgs, 6);

        let nudge_intact = msgs
            .iter()
            .any(|m| m["role"] == "system" && m["content"] == "nudge: try traces");
        assert!(nudge_intact, "system nudge must not be stubbed");

        let contents = tool_contents(&msgs);
        // 8 rounds, keep 6 → rounds 0..=1 stubbed.
        assert_eq!(contents[0], COMPACTED_TOOL_RESULT);
        assert_eq!(contents[1], COMPACTED_TOOL_RESULT);
        for (i, c) in contents.iter().enumerate().skip(2) {
            assert_eq!(c, &format!("tool result {i}"));
        }
    }

    // ── root_cause_gate ──────────────────────────────────────────────────

    /// Memory satisfying every gate criterion: ≥2 signals, ≥2 concrete records.
    fn satisfied_memory() -> WorkingMemory {
        let mut mem = WorkingMemory::new("investigate".to_string());
        mem.record_signal("logs");
        mem.record_signal("traces");
        mem.add_fact("search_logs: 5 errors in api".to_string());
        mem.add_fact("query_traces: p99 spike at 10:30".to_string());
        mem.add_evidence(
            "logs",
            "search_logs",
            "api",
            "Found 5 error entries at 10:30".to_string(),
        );
        mem.add_evidence(
            "traces",
            "query_traces",
            "api",
            "Found 12 error spans at 10:30".to_string(),
        );
        let window = InvestigationWindow::new(
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 11, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
            WindowSelectionReason::UserProvidedRange,
        )
        .unwrap();
        mem.evidence[0].window = Some(window.clone());
        mem.evidence[0].source_tables = vec!["logs".into()];
        mem.evidence[0].incident_value = Some(json!({"errors": 5}));
        mem.evidence[0].baseline_value = Some(json!({"errors": 0}));
        mem.evidence[0].delta = Some(json!({"errors_delta": 5}));
        mem.evidence[1].window = Some(window);
        mem.evidence[1].source_tables = vec!["spans".into()];
        mem.evidence[1].incident_value = Some(json!({"p99_ms": 900}));
        mem.evidence[1].baseline_value = Some(json!({"p99_ms": 100}));
        mem.evidence[1].delta = Some(json!({"p99_delta_ms": 800}));
        mem.upsert_hypothesis(Hypothesis {
            id: "H1".into(),
            culprit_service: "api".into(),
            mechanism: "error regression".into(),
            symptom_service: "api".into(),
            propagation_path: vec!["api".into()],
            expected_if_true: vec!["errors rise".into()],
            expected_if_false: vec!["errors remain flat".into()],
            supporting_evidence_ids: vec!["E1".into(), "E2".into()],
            contradicting_evidence_ids: vec![],
            discriminating_evidence_ids: vec!["E2".into()],
            status: "supported".into(),
            confidence: 0.8,
            confidence_band: "high".into(),
            next_best_test: "check the deploy timeline".into(),
            historical: false,
            carry_reason: String::new(),
        });
        mem.add_ruled_out("No matching deploy in the incident window".to_string());
        mem
    }

    fn valid_report() -> &'static str {
        "## Status\nFinal — high confidence\n\n## Root Cause\napi error regression began at 10:00 UTC [E1] [E2]\n\n## Incident Change\nerrors and p99 increased versus baseline; onset was 10:00 UTC [E1] [E2]\n\n## Causal Path\napi -> api [E2]\n\n## Evidence\n- [E1] logs show errors\n- [E2] traces show p99 delta\n\n## Contradictions and Alternatives\nNo material contradiction remains; E2 was the discriminating trace check.\n\n## Impact\napi requests failed\n\n## Recommended Actions\nrollback the change\n\n## Open Questions\nNone material."
    }

    #[test]
    fn gate_rejects_insufficient_depth_with_step_counts() {
        let mem = satisfied_memory();
        let msg =
            root_cause_gate(&mem, valid_report(), 1, 4).expect("gate must reject depth 1 < 4");
        assert!(
            msg.contains("Only 1 investigation step(s)"),
            "mentions current steps: {msg}"
        );
        assert!(
            msg.contains("at least 4"),
            "mentions required min depth: {msg}"
        );
    }

    #[test]
    fn gate_rejects_single_signal_and_names_missing_signal_types() {
        let mut mem = WorkingMemory::new("investigate".to_string());
        mem.record_signal("logs");
        mem.add_fact("fact one".to_string());
        mem.add_fact("fact two".to_string());
        let msg =
            root_cause_gate(&mem, valid_report(), 5, 4).expect("gate must reject 1 signal type");
        assert!(msg.contains("Only 1 signal type(s) checked"), "{msg}");
        // logs already consulted → the two suggested missing types are traces, metrics
        assert!(
            msg.contains("traces, metrics"),
            "names unconsulted signal types: {msg}"
        );
    }

    #[test]
    fn gate_rejects_fewer_than_two_facts() {
        let mut mem = WorkingMemory::new("investigate".to_string());
        mem.record_signal("logs");
        mem.record_signal("metrics");
        mem.add_fact("only one fact".to_string());
        let msg = root_cause_gate(&mem, valid_report(), 5, 4).expect("gate must reject <2 facts");
        assert!(
            msg.contains("Fewer than 2 concrete evidence records"),
            "{msg}"
        );
        assert!(
            msg.contains("(have 0)"),
            "reports current evidence count: {msg}"
        );
    }

    #[test]
    fn gate_passes_when_all_criteria_satisfied() {
        let mem = satisfied_memory();
        assert_eq!(
            root_cause_gate(&mem, valid_report(), 4, 4),
            None,
            "depth == min_depth must pass"
        );
        assert_eq!(root_cause_gate(&mem, valid_report(), 10, 4), None);
    }

    #[test]
    fn gate_lists_all_gaps_when_everything_is_missing() {
        let mem = WorkingMemory::new("investigate".to_string());
        let msg =
            root_cause_gate(&mem, "## Root Cause", 0, 4).expect("fresh memory must be rejected");
        assert!(msg.contains("Only 0 investigation step(s)"), "{msg}");
        assert!(msg.contains("Only 0 signal type(s)"), "{msg}");
        assert!(
            msg.contains("Fewer than 2 concrete evidence records"),
            "{msg}"
        );
    }

    // ── decide_report_kind ───────────────────────────────────────────────

    #[test]
    fn question_prefix_yields_question_kind() {
        // Even a fully satisfied memory: [QUESTION] always wins.
        let mem = satisfied_memory();
        let kind = decide_report_kind(&mem, "  [QUESTION] Which env?", 10, 4);
        assert_eq!(kind, ReportKind::Question);
    }

    #[test]
    fn escalated_memory_yields_preliminary() {
        let mut mem = satisfied_memory();
        mem.add_suspect_service("api".to_string());
        mem.escalation_level = 2;
        let kind = decide_report_kind(&mem, valid_report(), 10, 4);
        assert_eq!(kind, ReportKind::Preliminary);
    }

    #[test]
    fn happy_path_yields_final() {
        let mut mem = satisfied_memory();
        mem.add_suspect_service("api".to_string());
        let kind = decide_report_kind(&mem, valid_report(), 5, 4);
        assert_eq!(kind, ReportKind::Final);
    }

    #[test]
    fn insufficient_depth_yields_preliminary() {
        let mut mem = satisfied_memory();
        mem.add_suspect_service("api".to_string());
        let kind = decide_report_kind(&mem, valid_report(), 3, 4);
        assert_eq!(kind, ReportKind::Preliminary);
    }

    #[test]
    fn facts_without_evidence_cannot_be_final() {
        let mut mem = WorkingMemory::new("investigate".to_string());
        mem.record_signal("logs");
        mem.record_signal("traces");
        mem.add_fact("generic count".to_string());
        mem.add_suspect_service("api".to_string());
        assert_eq!(
            decide_report_kind(&mem, valid_report(), 10, 4),
            ReportKind::Preliminary
        );
    }

    #[test]
    fn report_state_captures_ruled_out_alternatives() {
        let mut mem = WorkingMemory::new("investigate".to_string());
        capture_report_state(
            &mut mem,
            "## Reflection\nWhat I ruled out:\n- No deploy preceded the onset\n- The upstream gateway was healthy\n\n## Root Cause",
        );
        assert_eq!(mem.ruled_out.len(), 2);
        assert_eq!(mem.failed_hypotheses.len(), 2);
    }

    #[test]
    fn report_state_parses_hypothesis_links_and_polarity() {
        let mut mem = satisfied_memory();
        capture_report_state(
            &mut mem,
            "HYPOTHESIS H2 | culprit=db | mechanism=database latency | symptom=api | path=db -> api | status=refuted | supports=E2 | contradicts=E1 | discriminates=E1 | confidence=low | next_test=check db pool",
        );
        let hypothesis = mem.hypotheses.iter().find(|item| item.id == "H2").unwrap();
        assert_eq!(hypothesis.culprit_service, "db");
        assert_eq!(hypothesis.status, "refuted");
        assert_eq!(hypothesis.supporting_evidence_ids, vec!["E2"]);
        assert_eq!(hypothesis.contradicting_evidence_ids, vec!["E1"]);
        assert_eq!(
            mem.evidence[0].polarity,
            crate::agent::contracts::EvidencePolarity::Neutral
        );
        assert_eq!(
            mem.evidence[1].polarity,
            crate::agent::contracts::EvidencePolarity::Supports
        );
    }

    #[test]
    fn causal_gate_names_missing_report_contract_and_discriminating_check() {
        let mut mem = satisfied_memory();
        mem.hypotheses[0].discriminating_evidence_ids.clear();
        let msg = root_cause_gate(&mem, "## Root Cause\napi error regression", 10, 4).unwrap();
        assert!(msg.contains("strong_alternative_untested"), "{msg}");
        assert!(msg.contains("report_contract_incomplete"), "{msg}");
        assert!(msg.contains("missing_evidence_citation"), "{msg}");
    }

    // ── LoopBudget ───────────────────────────────────────────────────────

    #[test]
    fn budget_defaults_when_no_overrides() {
        let b = LoopBudget::from_overrides(None, None);
        assert_eq!(b.max_tool_calls, 40);
        assert_eq!(b.max_tool_steps, 40);
        assert_eq!(b.max_llm_calls, 55);
    }

    #[test]
    fn budget_low_steps_clamp_to_four_and_calls_floor_at_steps_plus_two() {
        let b = LoopBudget::from_overrides(Some(1), Some(1));
        assert_eq!(b.max_tool_calls, 4);
        assert_eq!(b.max_tool_steps, 4, "steps clamp up to 4");
        assert_eq!(b.max_llm_calls, 6, "calls floored at steps + 2");

        // Calls below steps+2 get raised even with default steps.
        let b = LoopBudget::from_overrides(Some(10), Some(5));
        assert_eq!(b.max_tool_steps, 10);
        assert_eq!(b.max_llm_calls, 12);
    }

    #[test]
    fn budget_caps_at_200_and_300() {
        let b = LoopBudget::from_overrides(Some(9999), Some(9999));
        assert_eq!(b.max_tool_calls, 200);
        assert_eq!(b.max_tool_steps, 200);
        assert_eq!(b.max_llm_calls, 300);
    }

    #[test]
    fn budget_min_depth_adapts_to_small_step_budgets() {
        // Default budget → full MIN_INVESTIGATION_DEPTH.
        assert_eq!(LoopBudget::default().min_depth(), MIN_INVESTIGATION_DEPTH);
        // Smallest legal budget (4 steps) → depth shrinks below the constant.
        assert_eq!(LoopBudget::from_overrides(Some(1), None).min_depth(), 3);
        // Pathological direct construction still bottoms out at 1.
        let b = LoopBudget {
            max_tool_calls: 1,
            max_tool_steps: 1,
            max_llm_calls: 3,
        };
        assert_eq!(b.min_depth(), 1);
    }

    // ── strip_question_prefix ────────────────────────────────────────────

    #[test]
    fn strip_question_prefix_variants() {
        assert_eq!(strip_question_prefix("[QUESTION] Which one?"), "Which one?");
        assert_eq!(
            strip_question_prefix("  [QUESTION]   Which one?"),
            "Which one?"
        );
        assert_eq!(strip_question_prefix("No prefix here"), "No prefix here");
        // Prefix not at the start is left alone.
        assert_eq!(
            strip_question_prefix("answer [QUESTION] mid"),
            "answer [QUESTION] mid"
        );
    }

    // ── tool_signal_type ─────────────────────────────────────────────────

    #[test]
    fn tool_signal_type_maps_every_arm() {
        assert_eq!(tool_signal_type("search_logs"), Some("logs"));
        for t in [
            "query_traces",
            "get_trace",
            "list_services",
            "service_dependencies",
        ] {
            assert_eq!(tool_signal_type(t), Some("traces"), "{t}");
        }
        assert_eq!(tool_signal_type("query_metrics"), Some("metrics"));
        for t in [
            "kube_describe",
            "kube_events",
            "get_argocd_app",
            "get_flux_resource",
            "search_kubernetes_access",
        ] {
            assert_eq!(tool_signal_type(t), Some("kubernetes"), "{t}");
        }
        assert_eq!(tool_signal_type("list_deploys"), Some("deploys"));
        assert_eq!(tool_signal_type("read_skill"), None);
        assert_eq!(tool_signal_type(""), None);
    }

    // ── process_sse_line ─────────────────────────────────────────────────

    /// Drive process_sse_line over a sequence of lines and return the final
    /// accumulator plus all events emitted, plus whether [DONE] was seen.
    async fn run_lines(lines: &[&str]) -> (StreamAccum, Vec<AgentEvent>, bool) {
        let (tx, mut rx) = mpsc::channel::<AgentEvent>(64);
        let mut accum = StreamAccum::default();
        let mut done = false;
        for line in lines {
            if process_sse_line(line, &mut accum, &tx).await {
                done = true;
            }
        }
        drop(tx);
        let mut events = Vec::new();
        while let Some(e) = rx.recv().await {
            events.push(e);
        }
        (accum, events, done)
    }

    #[tokio::test]
    async fn sse_content_deltas_append_and_emit() {
        let (accum, events, done) = run_lines(&[
            r#"data: {"choices":[{"delta":{"content":"Hel"}}]}"#,
            r#"data: {"choices":[{"delta":{"content":"lo"}}]}"#,
        ])
        .await;
        assert_eq!(accum.content, "Hello");
        assert!(!done);
        let deltas: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                AgentEvent::ThinkingDelta { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            deltas,
            vec!["Hel", "lo"],
            "each delta emitted as it arrives"
        );
    }

    #[tokio::test]
    async fn sse_tool_call_fragments_accumulate_by_index_across_lines() {
        let (accum, _events, _done) = run_lines(&[
            // Tool 0: id + name, then args split over two lines.
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"search_logs"}}]}}]}"#,
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"service\":"}}]}}]}"#,
            // Tool 1 arrives interleaved before tool 0 finishes.
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"query_traces","arguments":"{}"}}]}}]}"#,
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"api\"}"}}]}}]}"#,
        ])
        .await;
        assert_eq!(accum.tool_calls.len(), 2);
        assert_eq!(accum.tool_calls[0].id, "call_a");
        assert_eq!(accum.tool_calls[0].name, "search_logs");
        assert_eq!(accum.tool_calls[0].arguments, r#"{"service":"api"}"#);
        assert_eq!(accum.tool_calls[1].id, "call_b");
        assert_eq!(accum.tool_calls[1].name, "query_traces");
        assert_eq!(accum.tool_calls[1].arguments, "{}");
    }

    #[tokio::test]
    async fn sse_usage_chunk_is_parsed() {
        let (accum, _events, _done) = run_lines(&[
            r#"data: {"choices":[],"usage":{"prompt_tokens":123,"completion_tokens":45}}"#,
        ])
        .await;
        assert_eq!(accum.prompt_tokens, 123);
        assert_eq!(accum.completion_tokens, 45);
    }

    #[tokio::test]
    async fn sse_done_sentinel_is_terminal() {
        let (accum, _events, done) = run_lines(&["data: [DONE]"]).await;
        assert!(done);
        assert_eq!(accum.content, "");
    }

    #[tokio::test]
    async fn sse_malformed_json_is_tolerated() {
        let (accum, events, done) = run_lines(&[
            "data: {this is not json",
            r#"data: {"choices":[{"delta":{"content":"ok"}}]}"#,
        ])
        .await;
        assert!(!done);
        assert_eq!(accum.content, "ok", "parsing continues after a bad line");
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn sse_non_data_lines_are_ignored() {
        let (accum, events, done) =
            run_lines(&["", ": keep-alive comment", "event: message", "id: 7"]).await;
        assert!(!done);
        assert_eq!(accum.content, "");
        assert!(accum.tool_calls.is_empty());
        assert!(events.is_empty());
    }
}
