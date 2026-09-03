//! Deterministic PR6 evaluation and release-gate support.
//!
//! Replay cases are deliberately data-only: they exercise the same report
//! scoring rules used by the live harness, but replace query-api and the LLM
//! with captured tool results and a captured report. This makes the suite
//! suitable for every pull request and gives release comparisons stable input.

use std::collections::HashSet;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use sre_agent::agent::contracts::ToolResultEnvelope;

use super::{EvalCase, Scorer, extract_candidates};

pub const REPLAY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayExpectation {
    #[serde(default)]
    pub mechanism_keywords: Vec<String>,
    #[serde(default)]
    pub causal_path: Vec<String>,
    #[serde(default)]
    pub evidence_classes: Vec<String>,
    #[serde(default = "default_corroboration")]
    pub minimum_corroboration: usize,
    #[serde(default = "default_report_kind")]
    pub report_kind: String,
}

impl Default for ReplayExpectation {
    fn default() -> Self {
        Self {
            mechanism_keywords: Vec::new(),
            causal_path: Vec::new(),
            evidence_classes: Vec::new(),
            minimum_corroboration: default_corroboration(),
            report_kind: default_report_kind(),
        }
    }
}

fn default_corroboration() -> usize {
    2
}

fn default_report_kind() -> String {
    "final".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayFixture {
    #[serde(default)]
    pub report: String,
    #[serde(default)]
    pub tool_results: Vec<ReplayToolResult>,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub wall_time_ms: u64,
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayToolResult {
    pub name: String,
    #[serde(default)]
    pub args: Value,
    pub data: String,
    #[serde(default)]
    pub tenant_id: String,
    pub source_family: String,
    #[serde(default)]
    pub source_tables: Vec<String>,
    #[serde(default = "default_status")]
    pub status: String,
}

fn default_status() -> String {
    "ok".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayedToolResult {
    pub name: String,
    pub args: Value,
    pub data: String,
    pub tenant_id: String,
    pub provenance: ToolResultEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayToolCall {
    pub name: String,
    pub args: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayArtifact {
    pub schema_version: u32,
    pub case_id: String,
    pub tenant_id: String,
    pub question: String,
    pub context: String,
    pub expected: ReplayExpectation,
    pub report: String,
    pub report_kind: String,
    pub tool_calls: Vec<ReplayToolCall>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub wall_time_ms: u64,
    pub replayed_tool_results: Vec<ReplayedToolResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayCaseResult {
    pub id: String,
    pub source: Option<String>,
    pub ac1: bool,
    pub ac3: bool,
    pub mechanism_accuracy: f64,
    pub causal_chain_completeness: f64,
    pub confidence: f64,
    pub confidence_brier: f64,
    pub false_final: bool,
    pub preliminary_useful: bool,
    pub report_kind: String,
    pub tool_calls: u32,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub wall_time_ms: u64,
    pub tenant_scope_failures: u32,
    pub provenance_failures: u32,
    pub candidates: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayMetrics {
    pub case_count: usize,
    pub ac1_rate: f64,
    pub ac3_rate: f64,
    pub mechanism_accuracy: f64,
    pub causal_chain_completeness: f64,
    pub confidence_brier: f64,
    pub false_final_rate: f64,
    pub preliminary_usefulness: f64,
    pub avg_tool_calls: f64,
    pub median_tool_calls: f64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub wall_time_ms: u64,
    pub tenant_scope_failures: u32,
    pub provenance_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRun {
    pub schema_version: u32,
    pub run_id: String,
    pub suite: String,
    pub started_at: String,
    pub metrics: ReplayMetrics,
    pub cases: Vec<ReplayCaseResult>,
    #[serde(default)]
    pub artifacts: Vec<ReplayArtifact>,
}

#[derive(Debug, Clone)]
pub struct ReleaseGate {
    pub passed: bool,
    pub failures: Vec<String>,
    pub current: ReplayMetrics,
}

impl ReleaseGate {
    pub fn render(&self) -> String {
        let status = if self.passed { "PASS" } else { "FAIL" };
        let mut out = format!("PR6 release gate: {status}\n\n");
        out.push_str(&format!(
            "AC@1 {:.1}% | mechanism {:.1}% | false-final {:.1}% | median calls {:.1}\n",
            self.current.ac1_rate * 100.0,
            self.current.mechanism_accuracy * 100.0,
            self.current.false_final_rate * 100.0,
            self.current.median_tool_calls
        ));
        if !self.failures.is_empty() {
            out.push_str("\nFailures:\n");
            for failure in &self.failures {
                out.push_str(&format!("- {failure}\n"));
            }
        }
        out
    }
}

pub fn evaluate(run_id: &str, cases: &[EvalCase], scorer: &Scorer) -> Result<ReplayRun> {
    let mut results = Vec::with_capacity(cases.len());
    let mut artifacts = Vec::with_capacity(cases.len());
    for case in cases {
        let (result, artifact) = evaluate_case(case, scorer)
            .with_context(|| format!("evaluating replay case {}", case.id))?;
        results.push(result);
        artifacts.push(artifact);
    }
    let metrics = aggregate(&results);
    Ok(ReplayRun {
        schema_version: REPLAY_SCHEMA_VERSION,
        run_id: run_id.into(),
        suite: "sre-agent-pr6-replay".into(),
        started_at: chrono::Utc::now().to_rfc3339(),
        metrics,
        cases: results,
        artifacts,
    })
}

fn evaluate_case(case: &EvalCase, scorer: &Scorer) -> Result<(ReplayCaseResult, ReplayArtifact)> {
    let fixture = case.replay.as_ref().context("missing replay fixture")?;
    if fixture.tenant_id.is_empty() {
        anyhow::bail!("replay fixture must declare tenant_id");
    }
    if fixture.report.trim().is_empty() {
        anyhow::bail!("replay fixture must contain a captured report");
    }

    let vocabulary = scorer.service_vocabulary(case);
    let candidates = extract_candidates(&fixture.report, &vocabulary);
    let acceptable: HashSet<String> =
        std::iter::once(case.ground_truth.root_cause_service.to_lowercase())
            .chain(case.ground_truth.related.iter().map(|s| s.to_lowercase()))
            .collect();
    let ac1 = candidates
        .first()
        .is_some_and(|candidate| acceptable.contains(&candidate.to_lowercase()));
    let ac3 = candidates
        .iter()
        .take(3)
        .any(|candidate| acceptable.contains(&candidate.to_lowercase()));

    let report_lower = fixture.report.to_lowercase();
    let mechanism_accuracy = if case.expectation.mechanism_keywords.is_empty() {
        0.0
    } else {
        case.expectation
            .mechanism_keywords
            .iter()
            .filter(|keyword| report_lower.contains(&keyword.to_lowercase()))
            .count() as f64
            / case.expectation.mechanism_keywords.len() as f64
    };
    let causal_chain_completeness =
        ordered_path_score(&report_lower, &case.expectation.causal_path);
    let confidence = parse_confidence(&report_lower).unwrap_or(0.5);
    let correct = ac1 && mechanism_accuracy >= 0.5;
    let confidence_brier = (confidence - if correct { 1.0 } else { 0.0 }).powi(2);
    let report_kind = detect_report_kind(&report_lower);
    let false_final =
        report_kind == "final" && (case.expectation.report_kind != "final" || !correct);
    let positive_results = fixture
        .tool_results
        .iter()
        .filter(|result| result.status == "ok" || result.status == "partial")
        .count();
    let preliminary_useful = case.expectation.report_kind == "preliminary"
        && positive_results >= case.expectation.minimum_corroboration
        && (report_lower.contains("next")
            || report_lower.contains("open")
            || report_lower.contains("unknown"));

    let mut tenant_scope_failures = 0;
    let mut provenance_failures = 0;
    let mut replayed = Vec::with_capacity(fixture.tool_results.len());
    for result in &fixture.tool_results {
        if result.tenant_id.is_empty() || result.tenant_id != fixture.tenant_id {
            tenant_scope_failures += 1;
        }
        let provenance = result.envelope();
        let actual_source_family = serde_json::to_value(&provenance.source_family)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string));
        if result.source_family.is_empty()
            || result.source_tables.is_empty()
            || provenance.summary.is_empty()
            || actual_source_family.is_none()
            || actual_source_family.as_deref() != Some(result.source_family.as_str())
        {
            provenance_failures += 1;
        }
        replayed.push(ReplayedToolResult {
            name: result.name.clone(),
            args: result.args.clone(),
            data: result.data.clone(),
            tenant_id: result.tenant_id.clone(),
            provenance,
        });
    }

    let artifact = ReplayArtifact {
        schema_version: REPLAY_SCHEMA_VERSION,
        case_id: case.id.clone(),
        tenant_id: fixture.tenant_id.clone(),
        question: case.input.text.clone(),
        context: case.description.clone().unwrap_or_default(),
        expected: case.expectation.clone(),
        report: fixture.report.clone(),
        report_kind: report_kind.clone(),
        tool_calls: fixture
            .tool_results
            .iter()
            .map(|result| ReplayToolCall {
                name: result.name.clone(),
                args: result.args.clone(),
            })
            .collect(),
        prompt_tokens: fixture.prompt_tokens,
        completion_tokens: fixture.completion_tokens,
        wall_time_ms: fixture.wall_time_ms,
        replayed_tool_results: replayed,
    };
    Ok((
        ReplayCaseResult {
            id: case.id.clone(),
            source: case.source.clone(),
            ac1,
            ac3,
            mechanism_accuracy,
            causal_chain_completeness,
            confidence,
            confidence_brier,
            false_final,
            preliminary_useful,
            report_kind,
            tool_calls: fixture.tool_results.len() as u32,
            prompt_tokens: fixture.prompt_tokens,
            completion_tokens: fixture.completion_tokens,
            wall_time_ms: fixture.wall_time_ms,
            tenant_scope_failures,
            provenance_failures,
            candidates,
            error: None,
        },
        artifact,
    ))
}

impl ReplayToolResult {
    fn envelope(&self) -> ToolResultEnvelope {
        let mut envelope =
            ToolResultEnvelope::from_legacy(&self.name, &self.args, &self.data, None);
        envelope.source_tables = self.source_tables.clone();
        envelope.status = match self.status.as_str() {
            "partial" => sre_agent::agent::contracts::ResultStatus::Partial,
            "no_data" => sre_agent::agent::contracts::ResultStatus::NoData,
            "error" => sre_agent::agent::contracts::ResultStatus::Error,
            "access_denied" => sre_agent::agent::contracts::ResultStatus::AccessDenied,
            _ => sre_agent::agent::contracts::ResultStatus::Ok,
        };
        envelope
    }
}

fn detect_report_kind(report: &str) -> String {
    if report.contains("preliminary") || report.contains("not enough evidence") {
        "preliminary".into()
    } else if report.contains("clarifying question") {
        "question".into()
    } else {
        "final".into()
    }
}

fn parse_confidence(report: &str) -> Option<f64> {
    for token in report.split_whitespace() {
        let candidate = token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        if candidate.contains('.') {
            if let Ok(value) = candidate.parse::<f64>() {
                if (0.0..=1.0).contains(&value) {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn ordered_path_score(report: &str, path: &[String]) -> f64 {
    if path.is_empty() {
        return 0.0;
    }
    let mut cursor = 0;
    let mut matched = 0;
    for service in path {
        if let Some(position) = report[cursor..].find(&service.to_lowercase()) {
            cursor += position + service.len();
            matched += 1;
        }
    }
    matched as f64 / path.len() as f64
}

fn aggregate(results: &[ReplayCaseResult]) -> ReplayMetrics {
    let n = results.len() as f64;
    let mut calls: Vec<u32> = results.iter().map(|r| r.tool_calls).collect();
    calls.sort_unstable();
    let median_tool_calls = if calls.is_empty() {
        0.0
    } else if calls.len() % 2 == 0 {
        (calls[calls.len() / 2 - 1] as f64 + calls[calls.len() / 2] as f64) / 2.0
    } else {
        calls[calls.len() / 2] as f64
    };
    ReplayMetrics {
        case_count: results.len(),
        ac1_rate: results.iter().filter(|r| r.ac1).count() as f64 / n,
        ac3_rate: results.iter().filter(|r| r.ac3).count() as f64 / n,
        mechanism_accuracy: results.iter().map(|r| r.mechanism_accuracy).sum::<f64>() / n,
        causal_chain_completeness: results
            .iter()
            .map(|r| r.causal_chain_completeness)
            .sum::<f64>()
            / n,
        confidence_brier: results.iter().map(|r| r.confidence_brier).sum::<f64>() / n,
        false_final_rate: results.iter().filter(|r| r.false_final).count() as f64 / n,
        preliminary_usefulness: results.iter().filter(|r| r.preliminary_useful).count() as f64 / n,
        avg_tool_calls: results.iter().map(|r| r.tool_calls as f64).sum::<f64>() / n,
        median_tool_calls,
        prompt_tokens: results.iter().map(|r| r.prompt_tokens).sum(),
        completion_tokens: results.iter().map(|r| r.completion_tokens).sum(),
        wall_time_ms: results.iter().map(|r| r.wall_time_ms).sum(),
        tenant_scope_failures: results.iter().map(|r| r.tenant_scope_failures).sum(),
        provenance_failures: results.iter().map(|r| r.provenance_failures).sum(),
    }
}

pub fn release_gate(current: &ReplayRun, baseline: Option<&ReplayRun>) -> ReleaseGate {
    let m = &current.metrics;
    let mut failures = Vec::new();
    if m.case_count < 20 {
        failures.push(format!("case count {} is below 20", m.case_count));
    }
    if m.ac1_rate < 0.90 {
        failures.push(format!("AC@1 {:.3} < 0.900", m.ac1_rate));
    }
    if m.mechanism_accuracy < 0.85 {
        failures.push(format!(
            "mechanism accuracy {:.3} < 0.850",
            m.mechanism_accuracy
        ));
    }
    if m.false_final_rate > 0.02 {
        failures.push(format!(
            "false-final rate {:.3} > 0.020",
            m.false_final_rate
        ));
    }
    if m.median_tool_calls > 12.0 {
        failures.push(format!(
            "median actual calls {:.1} > 12",
            m.median_tool_calls
        ));
    }
    if m.tenant_scope_failures != 0 {
        failures.push(format!("{} tenant-scope failures", m.tenant_scope_failures));
    }
    if m.provenance_failures != 0 {
        failures.push(format!("{} provenance failures", m.provenance_failures));
    }
    if let Some(base) = baseline {
        if m.ac1_rate + 0.05 < base.metrics.ac1_rate {
            failures.push("AC@1 regressed by more than 5 points versus baseline".into());
        }
        if m.mechanism_accuracy + 0.05 < base.metrics.mechanism_accuracy {
            failures
                .push("mechanism accuracy regressed by more than 5 points versus baseline".into());
        }
        if m.false_final_rate > base.metrics.false_final_rate + 0.02 {
            failures
                .push("false-final rate regressed by more than 2 points versus baseline".into());
        }
    }
    ReleaseGate {
        passed: failures.is_empty(),
        failures,
        current: m.clone(),
    }
}

pub fn render_markdown(run: &ReplayRun) -> String {
    let m = &run.metrics;
    format!(
        "# SRE Agent PR6 Replay `{}`\n\n\
         - Cases: {}\n- AC@1: {:.1}%\n- AC@3: {:.1}%\n\
         - Mechanism accuracy: {:.1}%\n- Causal-chain completeness: {:.1}%\n\
         - Confidence Brier score: {:.3}\n- False-final rate: {:.1}%\n\
         - Preliminary usefulness: {:.1}%\n- Median actual tool calls: {:.1}\n\n\
         | Case | AC@1 | AC@3 | Mechanism | Chain | Kind | Calls | Scope | Provenance |\n\
         |---|---:|---:|---:|---:|---|---:|---:|---:|\n{}",
        run.run_id,
        m.case_count,
        m.ac1_rate * 100.0,
        m.ac3_rate * 100.0,
        m.mechanism_accuracy * 100.0,
        m.causal_chain_completeness * 100.0,
        m.confidence_brier,
        m.false_final_rate * 100.0,
        m.preliminary_usefulness * 100.0,
        m.median_tool_calls,
        run.cases
            .iter()
            .map(|case| {
                format!(
                    "| {} | {} | {} | {:.0}% | {:.0}% | {} | {} | {} | {} |\n",
                    case.id,
                    if case.ac1 { "yes" } else { "no" },
                    if case.ac3 { "yes" } else { "no" },
                    case.mechanism_accuracy * 100.0,
                    case.causal_chain_completeness * 100.0,
                    case.report_kind,
                    case.tool_calls,
                    case.tenant_scope_failures,
                    case.provenance_failures
                )
            })
            .collect::<String>()
    )
}

pub fn render_comparison(current: &ReplayRun, baseline: &ReplayRun) -> String {
    let c = &current.metrics;
    let b = &baseline.metrics;
    format!(
        "PR6 replay comparison\n\n| Metric | Baseline | Current | Delta |\n|---|---:|---:|---:|\n| AC@1 | {:.3} | {:.3} | {:+.3} |\n| AC@3 | {:.3} | {:.3} | {:+.3} |\n| Mechanism | {:.3} | {:.3} | {:+.3} |\n| Chain completeness | {:.3} | {:.3} | {:+.3} |\n| Confidence Brier | {:.3} | {:.3} | {:+.3} |\n| False-final | {:.3} | {:.3} | {:+.3} |\n| Median calls | {:.1} | {:.1} | {:+.1} |\n| Prompt tokens | {} | {} | {:+} |\n| Completion tokens | {} | {} | {:+} |\n",
        b.ac1_rate,
        c.ac1_rate,
        c.ac1_rate - b.ac1_rate,
        b.ac3_rate,
        c.ac3_rate,
        c.ac3_rate - b.ac3_rate,
        b.mechanism_accuracy,
        c.mechanism_accuracy,
        c.mechanism_accuracy - b.mechanism_accuracy,
        b.causal_chain_completeness,
        c.causal_chain_completeness,
        c.causal_chain_completeness - b.causal_chain_completeness,
        b.confidence_brier,
        c.confidence_brier,
        c.confidence_brier - b.confidence_brier,
        b.false_final_rate,
        c.false_final_rate,
        c.false_final_rate - b.false_final_rate,
        b.median_tool_calls,
        c.median_tool_calls,
        c.median_tool_calls - b.median_tool_calls,
        b.prompt_tokens,
        c.prompt_tokens,
        c.prompt_tokens as i128 - b.prompt_tokens as i128,
        b.completion_tokens,
        c.completion_tokens,
        c.completion_tokens as i128 - b.completion_tokens as i128,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CasesFile, LlmConfig};

    fn scorer() -> Scorer {
        Scorer::new(LlmConfig {
            base_url: "http://replay.invalid".into(),
            api_key: "replay".into(),
            model: "deterministic-replay".into(),
            reasoning_effort: None,
        })
    }

    #[test]
    fn suite_has_at_least_twenty_cases_and_all_are_replayable() {
        let cases: CasesFile =
            serde_yaml::from_str(include_str!("../../../evals/replay_cases.yaml"))
                .expect("replay suite YAML must parse");
        assert!(cases.cases.len() >= 20);
        for case in &cases.cases {
            let fixture = case
                .replay
                .as_ref()
                .expect("case must have a replay fixture");
            assert!(!fixture.tenant_id.is_empty(), "{} missing tenant", case.id);
            assert!(!fixture.report.is_empty(), "{} missing report", case.id);
            assert!(
                !fixture.tool_results.is_empty(),
                "{} missing tool results",
                case.id
            );
            assert!(
                !case.expectation.evidence_classes.is_empty(),
                "{} missing evidence classes",
                case.id
            );
        }
    }

    #[test]
    fn replay_suite_meets_pr6_quality_gate() {
        let cases: CasesFile =
            serde_yaml::from_str(include_str!("../../../evals/replay_cases.yaml"))
                .expect("replay suite YAML must parse");
        let run = evaluate("test", &cases.cases, &scorer()).expect("suite should evaluate");
        let gate = release_gate(&run, None);
        assert!(gate.passed, "{}", gate.render());
        assert_eq!(run.metrics.tenant_scope_failures, 0);
        assert_eq!(run.metrics.provenance_failures, 0);
        assert_eq!(run.artifacts.len(), cases.cases.len());
    }

    #[test]
    fn report_scoring_detects_false_final_and_incomplete_chain() {
        assert_eq!(
            detect_report_kind("## Preliminary Findings\nnot enough evidence"),
            "preliminary"
        );
        assert_eq!(
            ordered_path_score("media -> gateway", &["media".into(), "gateway".into()]),
            1.0
        );
        assert_eq!(
            ordered_path_score("gateway -> media", &["media".into(), "gateway".into()]),
            0.5
        );
        assert_eq!(parse_confidence("Confidence 0.83"), Some(0.83));
    }
}
