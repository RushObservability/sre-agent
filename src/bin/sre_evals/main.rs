//! Manual (NOT-CI) RCA evaluation harness for the SRE agent.
//!
//! Drives the agent headlessly over labeled incident cases and scores
//! root-cause localization (AC@1 / AC@3) plus an LLM-judge reason match.
//!
//! It supports three ground-truth sources, all of which reduce to the same
//! labeled-case schema ([`EvalCase`]):
//!   A) curated real incidents      (source: "curated")
//!   B) seeded / synthetic faults    (source: "seeded")
//!   C) public-benchmark adapter     (source: "benchmark", via `convert-*`)
//!
//! REQUIREMENTS to actually RUN (not needed to build):
//!   - a live query-api backed by populated telemetry (QUERY_API_URL)
//!   - the shared SRE_AGENT_INTERNAL_TOKEN
//!   - OPENAI_API_KEY (+ optional OPENAI_BASE_URL) for both the agent and the judge
//!
//! Usage:
//!   sre_evals run [--cases evals/cases.yaml] [--limit N] [--out evals/out]
//!   sre_evals convert-rcaeval <labels-file.csv|json>
//!   sre_evals convert-openrca <labels-file.json>
//!
//! This binary is intentionally read-only against production code: it reuses
//! the crate's public APIs (loop_runner, prompt, built_in, tools, state) and
//! never mutates the agent's prompts or behavior.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use sre_agent::AppState;
use sre_agent::agent::built_in;
use sre_agent::agent::loop_runner::{LlmConfig, LoopBudget, run_with_config_and_budget};
use sre_agent::agent::prompt::{question_context, system_prompt};
use sre_agent::agent::skill_store::SkillStore;
use sre_agent::agent::stream::AgentEvent;
use sre_agent::agent::tools::{ToolContext, ToolRegistry};
use sre_agent::query_api::QueryApiClient;

mod rca_convert;
mod replay;
use replay::{
    ReplayArtifact, ReplayExpectation, ReplayFixture, ReplayToolCall, ReplayedToolResult,
};

/// The demo-stack service vocabulary. Used as the fallback token set when
/// extracting candidate root-cause services from the agent's final report.
/// Real labeled cases extend this implicitly via the case's ground_truth +
/// related fields (see [`Scorer::service_vocabulary`]).
const DEMO_SERVICES: &[&str] = &[
    "articles",
    "gateway",
    "media",
    "notifications",
    "payments",
    "users",
];

// ─────────────────────────────────────────────────────────────────────────
// 1. Scenario schema
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvalCase {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    pub input: CaseInput,
    #[serde(default)]
    pub window: Option<CaseWindow>,
    pub ground_truth: GroundTruth,
    /// Deterministic PR6 evaluation contract. Live cases may omit this and
    /// use the legacy ground-truth fields only.
    #[serde(default)]
    pub expectation: ReplayExpectation,
    /// Replayed tool results and a captured report for offline regression
    /// testing. This is intentionally separate from live query-api cases.
    #[serde(default)]
    pub replay: Option<ReplayFixture>,
    /// "curated" | "seeded" | "benchmark"
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaseInput {
    /// "question" | "anomaly"
    pub kind: String,
    pub text: String,
    /// RFC3339 timestamp the incident centered on (passed to the agent so its
    /// time-aware tools center their windows there).
    #[serde(default)]
    pub around: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaseWindow {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroundTruth {
    pub root_cause_service: String,
    pub reason: String,
    /// Acceptable adjacent services — a candidate matching any of these counts
    /// as a correct localization too (cascading failures blur the boundary).
    #[serde(default)]
    pub related: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CasesFile {
    pub cases: Vec<EvalCase>,
}

// ─────────────────────────────────────────────────────────────────────────
// Result schema (written to JSON)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub source: Option<String>,
    pub ac1: bool,
    pub ac3: bool,
    pub reason_match: Option<bool>,
    pub reason_why: Option<String>,
    /// Ranked candidate root-cause services extracted from the final report.
    pub candidates: Vec<String>,
    pub ground_truth_service: String,
    pub report_kind: String,
    pub tool_calls: u32,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    #[serde(default)]
    pub wall_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ReplayArtifact>,
    /// Set when the run itself errored (no report produced).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub run_id: String,
    pub started_at: String,
    pub case_count: usize,
    pub ac1_rate: f64,
    pub ac3_rate: f64,
    pub reason_accuracy: f64,
    pub avg_tool_calls: f64,
    #[serde(default)]
    pub total_prompt_tokens: u64,
    #[serde(default)]
    pub total_completion_tokens: u64,
    #[serde(default)]
    pub median_tool_calls: f64,
    #[serde(default)]
    pub wall_time_ms: u64,
    pub cases: Vec<CaseResult>,
}

// ─────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────

fn print_usage() {
    eprintln!(
        "sre_evals — manual RCA evaluation harness for the SRE agent\n\n\
         USAGE:\n\
         \x20 sre_evals run [--cases <file>] [--limit <N>] [--out <dir>]\n\
         \x20 sre_evals convert-rcaeval <labels-file.csv|json>\n\
         \x20 sre_evals convert-openrca <labels-file.json>\n\n\
         Defaults: --cases evals/cases.yaml  --out evals/out\n\
         RUN requires a live query-api and OPENAI_API_KEY in the environment."
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env the same way the production binary does, so query-api and LLM
    // settings line up with a local dev setup.
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let subcommand = args.first().map(|s| s.as_str()).unwrap_or("");

    match subcommand {
        "run" => run_command(&args[1..]).await,
        "replay" => replay_command(&args[1..]),
        "compare" => compare_command(&args[1..]),
        "release-gate" => release_gate_command(&args[1..]),
        "convert-rcaeval" => {
            let path = args
                .get(1)
                .context("convert-rcaeval requires a <labels-file> argument")?;
            let yaml = rca_convert::convert_rcaeval(Path::new(path))?;
            print!("{yaml}");
            Ok(())
        }
        "convert-openrca" => {
            let path = args
                .get(1)
                .context("convert-openrca requires a <labels-file> argument")?;
            let yaml = rca_convert::convert_openrca(Path::new(path))?;
            print!("{yaml}");
            Ok(())
        }
        "-h" | "--help" | "help" | "" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("unknown subcommand: {other}\n");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn replay_command(args: &[String]) -> Result<()> {
    let flags = parse_flags(args);
    let cases_path = flags
        .get("cases")
        .cloned()
        .unwrap_or_else(|| "evals/replay_cases.yaml".to_string());
    let out_dir = flags
        .get("out")
        .cloned()
        .unwrap_or_else(|| "evals/out".to_string());
    let raw = std::fs::read_to_string(&cases_path)
        .with_context(|| format!("reading replay cases file {cases_path}"))?;
    let parsed: CasesFile = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing replay cases file {cases_path}"))?;
    if parsed.cases.is_empty() {
        anyhow::bail!("no replay cases found in {cases_path}");
    }
    let run_id = std::env::var("SRE_EVALS_RUN_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string());
    let scorer = Scorer::new(LlmConfig {
        base_url: "http://replay.invalid".into(),
        api_key: "replay".into(),
        model: "deterministic-replay".into(),
        reasoning_effort: None,
    });
    let report = replay::evaluate(&run_id, &parsed.cases, &scorer)?;
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating output dir {out_dir}"))?;
    let path = PathBuf::from(&out_dir).join(format!("{run_id}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&report)?)
        .with_context(|| format!("writing {}", path.display()))?;
    let artifact_dir = PathBuf::from(&out_dir).join("artifacts").join(&run_id);
    std::fs::create_dir_all(&artifact_dir)?;
    for artifact in &report.artifacts {
        let artifact_path = artifact_dir.join(format!("{}.json", artifact.case_id));
        std::fs::write(artifact_path, serde_json::to_string_pretty(artifact)?)?;
    }
    let markdown = replay::render_markdown(&report);
    let md_path = PathBuf::from(&out_dir).join(format!("{run_id}.md"));
    std::fs::write(&md_path, &markdown)?;
    println!("{markdown}");
    eprintln!("Wrote {} and {}", path.display(), md_path.display());
    Ok(())
}

fn load_report(path: &str) -> Result<replay::ReplayRun> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading report {path}"))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing report {path}"))
}

fn compare_command(args: &[String]) -> Result<()> {
    let flags = parse_flags(args);
    let current = flags.get("current").context("compare requires --current")?;
    let baseline = flags
        .get("baseline")
        .context("compare requires --baseline")?;
    let current = load_report(current)?;
    let baseline = load_report(baseline)?;
    println!("{}", replay::render_comparison(&current, &baseline));
    Ok(())
}

fn release_gate_command(args: &[String]) -> Result<()> {
    let flags = parse_flags(args);
    let current_path = flags
        .get("current")
        .cloned()
        .unwrap_or_else(|| "evals/out/latest.json".to_string());
    let baseline_path = flags
        .get("baseline")
        .cloned()
        .unwrap_or_else(|| "evals/baseline-pr6.json".to_string());
    let current = load_report(&current_path)?;
    let baseline = load_report(&baseline_path)?;
    let gate = replay::release_gate(&current, Some(&baseline));
    println!("{}", gate.render());
    if !gate.passed {
        anyhow::bail!("PR6 release gate failed");
    }
    Ok(())
}

/// Minimal hand-rolled `--flag value` parser (no clap dependency).
fn parse_flags(args: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(key) = a.strip_prefix("--") {
            // `--flag value` form. We have no boolean flags in this harness.
            if let Some(val) = args.get(i + 1) {
                out.insert(key.to_string(), val.clone());
                i += 2;
            } else {
                out.insert(key.to_string(), String::new());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

fn median_tool_calls(results: &[CaseResult]) -> f64 {
    if results.is_empty() {
        return 0.0;
    }
    let mut values: Vec<u32> = results.iter().map(|r| r.tool_calls).collect();
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] as f64 + values[mid] as f64) / 2.0
    } else {
        values[mid] as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Runner
// ─────────────────────────────────────────────────────────────────────────

async fn run_command(args: &[String]) -> Result<()> {
    let flags = parse_flags(args);
    let cases_path = flags
        .get("cases")
        .cloned()
        .unwrap_or_else(|| "evals/cases.yaml".to_string());
    let out_dir = flags
        .get("out")
        .cloned()
        .unwrap_or_else(|| "evals/out".to_string());
    let limit: Option<usize> = flags.get("limit").and_then(|v| v.parse().ok());

    // ── Load cases ──────────────────────────────────────────────────────
    let raw = std::fs::read_to_string(&cases_path)
        .with_context(|| format!("reading cases file {cases_path}"))?;
    let parsed: CasesFile =
        serde_yaml::from_str(&raw).with_context(|| format!("parsing YAML {cases_path}"))?;
    let mut cases = parsed.cases;
    if let Some(n) = limit {
        cases.truncate(n);
    }
    if cases.is_empty() {
        anyhow::bail!("no cases to run (file empty or --limit 0)");
    }
    eprintln!("Loaded {} case(s) from {cases_path}", cases.len());

    // ── Construct shared state once (same env-driven wiring as main.rs) ──
    let state = build_app_state().await.context("building AppState")?;
    let llm = LlmConfig::from_eval_env()
        .context("building evaluation LlmConfig (OPENAI_API_KEY required)")?;

    let run_id = std::env::var("SRE_EVALS_RUN_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string());
    let started_at = chrono::Utc::now().to_rfc3339();

    let scorer = Scorer::new(llm.clone());

    let mut results: Vec<CaseResult> = Vec::with_capacity(cases.len());
    for (idx, case) in cases.iter().enumerate() {
        eprintln!("[{}/{}] running case '{}' …", idx + 1, cases.len(), case.id);
        let result = run_one_case(&state, &llm, &scorer, case).await;
        match &result {
            Ok(r) => eprintln!(
                "    → ac1={} ac3={} reason={:?} candidates={:?}",
                r.ac1, r.ac3, r.reason_match, r.candidates
            ),
            Err(e) => eprintln!("    → ERROR: {e:#}"),
        }
        // Errors are recorded as zero-score case results rather than aborting
        // the whole run — one flaky case shouldn't lose the rest of the suite.
        results.push(result.unwrap_or_else(|e| CaseResult {
            id: case.id.clone(),
            source: case.source.clone(),
            ac1: false,
            ac3: false,
            reason_match: None,
            reason_why: None,
            candidates: Vec::new(),
            ground_truth_service: case.ground_truth.root_cause_service.clone(),
            report_kind: "error".to_string(),
            tool_calls: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            wall_time_ms: 0,
            artifact: None,
            error: Some(format!("{e:#}")),
        }));
    }

    // ── Aggregate ───────────────────────────────────────────────────────
    let n = results.len() as f64;
    let ac1_rate = results.iter().filter(|r| r.ac1).count() as f64 / n;
    let ac3_rate = results.iter().filter(|r| r.ac3).count() as f64 / n;
    let reason_scored: Vec<&CaseResult> = results
        .iter()
        .filter(|r| r.reason_match.is_some())
        .collect();
    let reason_accuracy = if reason_scored.is_empty() {
        0.0
    } else {
        reason_scored
            .iter()
            .filter(|r| r.reason_match == Some(true))
            .count() as f64
            / reason_scored.len() as f64
    };
    let avg_tool_calls = results.iter().map(|r| r.tool_calls as f64).sum::<f64>() / n;

    let report = RunReport {
        run_id: run_id.clone(),
        started_at,
        case_count: results.len(),
        ac1_rate,
        ac3_rate,
        reason_accuracy,
        avg_tool_calls,
        total_prompt_tokens: results.iter().map(|r| r.prompt_tokens).sum(),
        total_completion_tokens: results.iter().map(|r| r.completion_tokens).sum(),
        median_tool_calls: median_tool_calls(&results),
        wall_time_ms: results.iter().map(|r| r.wall_time_ms).sum(),
        cases: results,
    };

    // ── Write JSON + markdown ───────────────────────────────────────────
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating output dir {out_dir}"))?;
    let json_path = PathBuf::from(&out_dir).join(format!("{run_id}.json"));
    let md_path = PathBuf::from(&out_dir).join(format!("{run_id}.md"));
    std::fs::write(&json_path, serde_json::to_string_pretty(&report)?)
        .with_context(|| format!("writing {}", json_path.display()))?;
    let artifact_dir = PathBuf::from(&out_dir).join("artifacts").join(&run_id);
    std::fs::create_dir_all(&artifact_dir)?;
    for case in &report.cases {
        if let Some(artifact) = &case.artifact {
            let artifact_path = artifact_dir.join(format!("{}.json", artifact.case_id));
            std::fs::write(artifact_path, serde_json::to_string_pretty(artifact)?)?;
        }
    }
    let markdown = render_markdown(&report);
    std::fs::write(&md_path, &markdown)
        .with_context(|| format!("writing {}", md_path.display()))?;

    // Markdown summary to stdout too.
    println!("{markdown}");
    eprintln!("\nWrote {} and {}", json_path.display(), md_path.display());
    Ok(())
}

/// Construct [`AppState`] from env vars, mirroring `src/main.rs` exactly so the
/// harness talks to the same query-api endpoints as production.
async fn build_app_state() -> Result<AppState> {
    let query_api_url =
        std::env::var("QUERY_API_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let internal_auth_token = std::env::var("SRE_AGENT_INTERNAL_TOKEN")
        .unwrap_or_else(|_| "dev-local-agent-token".into());
    let query_api = Arc::new(QueryApiClient::new(
        &query_api_url,
        internal_auth_token.clone(),
    )?);

    Ok(AppState {
        query_api,
        internal_auth_token,
        caches: Arc::new(Default::default()),
        metrics: Arc::new(sre_agent::metrics::AgentMetrics::new()),
        admission: Arc::new(sre_agent::state::InvestigationAdmission::new(
            4,
            16,
            Arc::new(sre_agent::metrics::AgentMetrics::new()),
        )),
    })
}

/// Build the GitOps controller list the same way `http.rs` does (env-driven).
fn gitops_from_env() -> Vec<String> {
    let mut gitops = Vec::new();
    if std::env::var("ARGOCD_NAMESPACE").is_ok() {
        gitops.push("argocd".to_string());
    }
    if std::env::var("FLUXCD_NAMESPACE").is_ok() {
        gitops.push("flux".to_string());
    }
    gitops
}

/// Drive the agent loop for one case and score the resulting final report.
async fn run_one_case(
    state: &AppState,
    llm: &LlmConfig,
    scorer: &Scorer,
    case: &EvalCase,
) -> Result<CaseResult> {
    let started = Instant::now();
    let scopes = vec!["all".to_string()];

    // Skill store + system prompt, built the same way the HTTP handler does.
    let skill_store = Arc::new(SkillStore::load(&state.query_api, "default").await);
    let gitops = gitops_from_env();
    let system_content = system_prompt(&skill_store.catalog(), &scopes, &gitops);

    // User turn: question_context, plus an explicit time hint if the case
    // carries one so the agent's `around`-aware tools center correctly.
    let mut additional = String::new();
    if let Some(around) = &case.input.around {
        additional.push_str(&format!(
            "The incident is centered around {around}. Use this timestamp as the `around` \
             parameter on your first search_logs / query_traces / query_metrics calls."
        ));
    }
    if let Some(w) = &case.window {
        if !additional.is_empty() {
            additional.push('\n');
        }
        additional.push_str(&format!(
            "The incident window is from {} to {}. Center your investigation there.",
            w.start, w.end
        ));
    }
    let user_content = question_context(&case.input.text, &additional);

    let messages: Vec<Value> = vec![
        serde_json::json!({ "role": "system", "content": system_content }),
        serde_json::json!({ "role": "user", "content": user_content }),
    ];

    // Registry + context.
    let mut registry = ToolRegistry::new();
    built_in::register_all(&mut registry);
    let ctx = ToolContext {
        state: state.clone(),
        skill_store,
        tenant_id: "default".to_string(),
        scopes,
    };

    // Collect streamed events. A generous channel and a drain task so the
    // loop never blocks on a full channel during a long run.
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(256);
    let collector = tokio::spawn(async move {
        let mut events = Vec::new();
        while let Some(ev) = rx.recv().await {
            events.push(ev);
        }
        events
    });

    let session_id = format!("eval-{}", case.id);
    // Cap investigation depth for evals (keeps cost/latency bounded). Override with
    // SRE_EVAL_MAX_TOOL_STEPS; default is the agent's normal budget.
    let budget = match std::env::var("SRE_EVAL_MAX_TOOL_STEPS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        Some(n) => LoopBudget::from_overrides(Some(n), None),
        None => LoopBudget::default(),
    };
    let outcome = run_with_config_and_budget(
        messages,
        &registry,
        &ctx,
        &tx,
        llm.clone(),
        None,
        &session_id,
        budget,
    )
    .await;

    // Drop our sender so the collector task can finish counting.
    drop(tx);
    let events = collector.await.unwrap_or_default();
    let stream_tool_calls = events
        .iter()
        .filter(|event| matches!(event, AgentEvent::ToolCall { .. }))
        .count() as u32;

    let (report_text, report_kind, _mem, prompt_tokens, completion_tokens, _model) =
        outcome.context("agent loop returned an error")?;

    // ── Score ─────────────────────────────────────────────────────────
    let vocabulary = scorer.service_vocabulary(case);
    let candidates = extract_candidates(&report_text, &vocabulary);
    let (ac1, ac3) = scorer.localization(case, &candidates);

    // Surface judge failures (instead of silently nulling them) so a broken judge
    // doesn't masquerade as an unjudged case.
    let (reason_match, reason_why) = match scorer.reason_match(case, &report_text).await {
        Ok(pair) => pair,
        Err(e) => (None, Some(format!("judge error: {e}"))),
    };

    let tool_calls = events
        .iter()
        .filter_map(|event| match event {
            AgentEvent::ToolCall { name, args } => Some(ReplayToolCall {
                name: name.clone(),
                args: args.clone(),
            }),
            _ => None,
        })
        .collect();
    let replayed_tool_results = events
        .iter()
        .filter_map(|event| match event {
            AgentEvent::ToolResult {
                name,
                data,
                provenance,
            } => Some(ReplayedToolResult {
                name: name.clone(),
                args: Value::Null,
                data: data.clone(),
                tenant_id: "default".into(),
                provenance: provenance.as_ref().clone(),
            }),
            _ => None,
        })
        .collect();
    let artifact = ReplayArtifact {
        schema_version: replay::REPLAY_SCHEMA_VERSION,
        case_id: case.id.clone(),
        tenant_id: "default".into(),
        question: case.input.text.clone(),
        context: case.description.clone().unwrap_or_default(),
        expected: case.expectation.clone(),
        report: report_text.clone(),
        report_kind: format!("{report_kind:?}").to_lowercase(),
        tool_calls,
        prompt_tokens,
        completion_tokens,
        wall_time_ms: started.elapsed().as_millis() as u64,
        replayed_tool_results,
    };

    Ok(CaseResult {
        id: case.id.clone(),
        source: case.source.clone(),
        ac1,
        ac3,
        reason_match,
        reason_why,
        candidates,
        ground_truth_service: case.ground_truth.root_cause_service.clone(),
        report_kind: format!("{report_kind:?}").to_lowercase(),
        tool_calls: stream_tool_calls,
        prompt_tokens,
        completion_tokens,
        wall_time_ms: started.elapsed().as_millis() as u64,
        artifact: Some(artifact),
        error: None,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Scorer
// ─────────────────────────────────────────────────────────────────────────

/// Extract a RANKED list of candidate root-cause services from the agent's
/// final report.
///
/// Ranking strategy:
///   1. The service named in the `## Root Cause` section comes FIRST.
///   2. Then HYPOTHESIS LEDGER rows, ranked by Confidence (high > med > low)
///      and preferring Status=supported over open/refuted. Service names are
///      pulled from each row by matching any vocabulary token in the row text.
///
/// `vocabulary` is the set of known service names (case's ground_truth +
/// related + the demo-stack list). Matching is whole-word, case-insensitive.
fn extract_candidates(report: &str, vocabulary: &[String]) -> Vec<String> {
    let mut ranked: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let push =
        |svc: String, ranked: &mut Vec<String>, seen: &mut std::collections::HashSet<String>| {
            let key = svc.to_lowercase();
            if seen.insert(key) {
                ranked.push(svc);
            }
        };

    // 1. Root Cause section — first vocabulary match wins the top rank.
    if let Some(section) = extract_section(report, "Root Cause") {
        // only the first named service in the Root Cause section
        if let Some(svc) = match_services(&section, vocabulary).into_iter().next() {
            push(svc, &mut ranked, &mut seen);
        }
    }

    // 2. Hypothesis ledger rows, ranked.
    for svc in ledger_ranked_services(report, vocabulary) {
        push(svc, &mut ranked, &mut seen);
    }

    // 3. Fallback: any vocabulary service appearing anywhere in the report,
    //    in document order. Ensures we still produce candidates when the
    //    report lacks the structured sections (preliminary reports).
    for svc in match_services(report, vocabulary) {
        push(svc, &mut ranked, &mut seen);
    }

    ranked
}

/// Pull the body of a markdown `## <heading>` section (until the next `##`).
fn extract_section(report: &str, heading: &str) -> Option<String> {
    let lower_heading = heading.to_lowercase();
    let lines: Vec<&str> = report.lines().collect();
    let mut start: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("##") {
            if rest.trim().to_lowercase().starts_with(&lower_heading) {
                start = Some(i + 1);
                break;
            }
        }
    }
    let start = start?;
    let mut body = String::new();
    for line in &lines[start..] {
        if line.trim_start().starts_with("##") {
            break;
        }
        body.push_str(line);
        body.push('\n');
    }
    Some(body)
}

/// Return every vocabulary service mentioned in `text`, in order of first
/// appearance, de-duplicated. Matching is a case-insensitive whole-token match
/// so `payments` does not match inside `repayments-foo`.
fn match_services(text: &str, vocabulary: &[String]) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut found: Vec<(usize, String)> = Vec::new();
    for svc in vocabulary {
        let needle = svc.to_lowercase();
        if let Some(pos) = find_whole_word(&lower, &needle) {
            found.push((pos, svc.clone()));
        }
    }
    found.sort_by_key(|(pos, _)| *pos);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (_, svc) in found {
        if seen.insert(svc.to_lowercase()) {
            out.push(svc);
        }
    }
    out
}

/// Find `needle` as a whole word in `haystack` (both already lowercased).
/// A boundary is anything that is not an ASCII alphanumeric, `_` or `-`.
fn find_whole_word(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let bytes = haystack.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let start = from + rel;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return Some(start);
        }
        from = start + 1;
        if from >= haystack.len() {
            break;
        }
    }
    None
}

/// Parse the HYPOTHESIS LEDGER markdown table and return services ranked by
/// (confidence, status). The ledger columns are:
///   # | Hypothesis | Status | Supporting evidence | Contradicting evidence | Confidence
fn ledger_ranked_services(report: &str, vocabulary: &[String]) -> Vec<String> {
    // Confidence weight: high=3 med/medium=2 low=1, unknown=0.
    // Status weight: supported=2 open=1 refuted=0 (refuted hypotheses rank last).
    struct Row {
        services: Vec<String>,
        conf: u8,
        status: u8,
    }
    let mut rows: Vec<Row> = Vec::new();

    for line in report.lines() {
        let t = line.trim();
        // A table data row: starts with '|' and contains multiple cells. Skip
        // the header (contains "Hypothesis") and the separator (--- only).
        if !t.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = t.trim_matches('|').split('|').map(|c| c.trim()).collect();
        if cells.len() < 3 {
            continue;
        }
        let joined = cells.join(" ").to_lowercase();
        if joined.contains("hypothesis") && joined.contains("status") {
            continue; // header
        }
        if cells.iter().all(|c| {
            c.chars()
                .all(|ch| ch == '-' || ch == ':' || ch.is_whitespace())
        }) {
            continue; // separator row
        }

        let row_text = cells.join(" ");
        let services = match_services(&row_text, vocabulary);
        if services.is_empty() {
            continue;
        }

        // Confidence is conventionally the LAST column; scan all cells to
        // handle column drift.
        let conf = if joined.contains("high") {
            3
        } else if joined.contains("med") {
            2
        } else if joined.contains("low") {
            1
        } else {
            0
        };
        let status = if joined.contains("supported") {
            2
        } else if joined.contains("refuted") {
            0
        } else {
            1 // open / unknown
        };
        rows.push(Row {
            services,
            conf,
            status,
        });
    }

    // Stable sort: highest (status_weight, confidence) first. Refuted rows sink.
    rows.sort_by(|a, b| (b.status, b.conf).cmp(&(a.status, a.conf)));

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for row in rows {
        for svc in row.services {
            if seen.insert(svc.to_lowercase()) {
                out.push(svc);
            }
        }
    }
    out
}

/// The scorer holds the LLM config for the reason-match judge call.
struct Scorer {
    llm: LlmConfig,
    http: reqwest::Client,
}

impl Scorer {
    fn new(llm: LlmConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("failed to build judge HTTP client");
        Self { llm, http }
    }

    /// Build the service vocabulary used to extract candidates for a case:
    /// the labeled root cause + related services + the demo-stack list. This
    /// lets real (non-demo) cases work without editing DEMO_SERVICES.
    fn service_vocabulary(&self, case: &EvalCase) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        v.push(case.ground_truth.root_cause_service.clone());
        v.extend(case.ground_truth.related.iter().cloned());
        v.extend(DEMO_SERVICES.iter().map(|s| s.to_string()));
        // De-dup preserving order.
        let mut seen = std::collections::HashSet::new();
        v.retain(|s| seen.insert(s.to_lowercase()));
        v
    }

    /// Compute (AC@1, AC@3) for a ranked candidate list. The ground-truth
    /// service OR any `related` service counts as correct.
    fn localization(&self, case: &EvalCase, candidates: &[String]) -> (bool, bool) {
        let acceptable: std::collections::HashSet<String> =
            std::iter::once(case.ground_truth.root_cause_service.to_lowercase())
                .chain(case.ground_truth.related.iter().map(|s| s.to_lowercase()))
                .collect();

        let hit_at = |k: usize| {
            candidates
                .iter()
                .take(k)
                .any(|c| acceptable.contains(&c.to_lowercase()))
        };
        (hit_at(1), hit_at(3))
    }

    /// Single conservative LLM-judge call comparing the agent's stated cause to
    /// the labeled reason. Returns (match, why). Returns (None, None) on any
    /// transport / parse failure so a flaky judge never sinks the whole run.
    async fn reason_match(
        &self,
        case: &EvalCase,
        report: &str,
    ) -> Result<(Option<bool>, Option<String>)> {
        // Keep the report bounded — the judge only needs the conclusion.
        let report_excerpt: String = report.chars().take(6000).collect();

        let system = "You are a strict, conservative grader for an SRE root-cause analysis \
            evaluation. You compare an agent's stated root cause against the ground-truth \
            reason for an incident. Mark match=true ONLY if the agent's conclusion identifies \
            the SAME underlying cause (same failing component AND same failure mechanism). \
            A correct affected service but a wrong mechanism is NOT a match. Vague or hedged \
            conclusions that do not commit to the ground-truth cause are NOT a match. \
            Respond with STRICT JSON only: {\"match\": true|false, \"why\": \"one sentence\"}.";

        let user = format!(
            "GROUND TRUTH root cause service: {}\n\
             GROUND TRUTH reason: {}\n\n\
             AGENT FINAL REPORT (may be truncated):\n{}\n\n\
             Does the agent's report identify the same root cause as the ground truth? \
             Reply with strict JSON only.",
            case.ground_truth.root_cause_service, case.ground_truth.reason, report_excerpt
        );

        // NOTE: no `temperature` field — gpt-5 / reasoning models reject any non-default
        // value (HTTP 400), which previously made the judge silently return None.
        let body = serde_json::json!({
            "model": self.llm.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": false,
        });

        let url = format!(
            "{}/v1/chat/completions",
            self.llm.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.llm.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("judge request failed")?;

        if !resp.status().is_success() {
            anyhow::bail!("judge returned HTTP {}", resp.status());
        }

        let v: Value = resp.json().await.context("parsing judge response")?;
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .context("judge response missing content")?;

        let parsed = parse_judge_json(content)?;
        Ok((Some(parsed.0), Some(parsed.1)))
    }
}

/// Parse the judge's `{"match": bool, "why": "..."}` — tolerant of code fences
/// and surrounding prose by extracting the first {...} block.
fn parse_judge_json(content: &str) -> Result<(bool, String)> {
    let json_slice = if let (Some(start), Some(end)) = (content.find('{'), content.rfind('}')) {
        &content[start..=end]
    } else {
        content
    };
    let v: Value = serde_json::from_str(json_slice).context("judge did not return valid JSON")?;
    let m = v["match"]
        .as_bool()
        .context("judge JSON missing boolean `match`")?;
    let why = v["why"].as_str().unwrap_or("").to_string();
    Ok((m, why))
}

// ─────────────────────────────────────────────────────────────────────────
// 4. Report rendering
// ─────────────────────────────────────────────────────────────────────────

fn render_markdown(report: &RunReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("# SRE RCA Eval Run `{}`\n\n", report.run_id));
    s.push_str(&format!("- Started: {}\n", report.started_at));
    s.push_str(&format!("- Cases: {}\n", report.case_count));
    s.push_str(&format!("- **AC@1**: {:.1}%\n", report.ac1_rate * 100.0));
    s.push_str(&format!("- **AC@3**: {:.1}%\n", report.ac3_rate * 100.0));
    s.push_str(&format!(
        "- **Reason accuracy**: {:.1}% (LLM judge)\n",
        report.reason_accuracy * 100.0
    ));
    s.push_str(&format!(
        "- Avg tool calls: {:.1}\n\n",
        report.avg_tool_calls
    ));
    s.push_str(&format!(
        "- Median tool calls: {:.1}\n- Prompt tokens: {}\n- Completion tokens: {}\n- Wall time: {} ms\n\n",
        report.median_tool_calls,
        report.total_prompt_tokens,
        report.total_completion_tokens,
        report.wall_time_ms
    ));

    s.push_str("## Per-case\n\n");
    s.push_str("| Case | Source | AC@1 | AC@3 | Reason | Kind | Tools | Top candidate |\n");
    s.push_str("|------|--------|------|------|--------|------|-------|---------------|\n");
    for c in &report.cases {
        let reason = match c.reason_match {
            Some(true) => "✓",
            Some(false) => "✗",
            None => "—",
        };
        let top = c
            .candidates
            .first()
            .cloned()
            .unwrap_or_else(|| "—".to_string());
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            c.id,
            c.source.clone().unwrap_or_default(),
            if c.ac1 { "✓" } else { "✗" },
            if c.ac3 { "✓" } else { "✗" },
            reason,
            c.report_kind,
            c.tool_calls,
            top,
        ));
    }
    s.push('\n');
    s
}

// ─────────────────────────────────────────────────────────────────────────
// Tests (pure scoring logic — no network / DB needed)
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn vocab() -> Vec<String> {
        DEMO_SERVICES.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn find_whole_word_respects_boundaries() {
        assert!(find_whole_word("the payments service", "payments").is_some());
        assert!(find_whole_word("repayments-foo broke", "payments").is_none());
        assert!(find_whole_word("payments", "payments").is_some());
        // '-' and '_' count as word chars, so hyphen/underscore-joined names do
        // NOT match a bare service token (avoids spurious "users" in "users-db").
        assert!(find_whole_word("users-db", "users").is_none());
        assert!(find_whole_word("users_db", "users").is_none());
        // Surrounded by non-word punctuation/space → matches.
        assert!(find_whole_word("the users.", "users").is_some());
    }

    #[test]
    fn extract_section_pulls_root_cause_body() {
        let report = "## Root Cause\nThe payments service failed.\n\n## Evidence\nfoo\n";
        let body = extract_section(report, "Root Cause").unwrap();
        assert!(body.contains("payments"));
        assert!(!body.contains("Evidence"));
    }

    #[test]
    fn root_cause_service_ranks_first() {
        let report = "## Root Cause\nThe payments service started failing at 10:00.\n\n\
                      ## Evidence\ngateway and users also showed errors.\n";
        let cands = extract_candidates(report, &vocab());
        assert_eq!(cands.first().map(|s| s.as_str()), Some("payments"));
    }

    #[test]
    fn ledger_ranks_supported_high_confidence_first() {
        let report = "\
## Hypothesis Ledger

| # | Hypothesis | Status | Supporting evidence | Contradicting evidence | Confidence |
|---|------------|--------|---------------------|------------------------|------------|
| 1 | users latency | open | none | some | low |
| 2 | payments deploy regression | supported | error spike post-deploy | none | high |
| 3 | media issue | refuted | none | healthy | low |
";
        let ranked = ledger_ranked_services(report, &vocab());
        assert_eq!(ranked.first().map(|s| s.as_str()), Some("payments"));
        // media is refuted → must rank after the open `users` row.
        let media_pos = ranked.iter().position(|s| s == "media");
        let users_pos = ranked.iter().position(|s| s == "users");
        assert!(users_pos < media_pos);
    }

    fn case_with(root: &str, related: &[&str]) -> EvalCase {
        EvalCase {
            id: "t".into(),
            description: None,
            input: CaseInput {
                kind: "question".into(),
                text: "x".into(),
                around: None,
            },
            window: None,
            ground_truth: GroundTruth {
                root_cause_service: root.into(),
                reason: "r".into(),
                related: related.iter().map(|s| s.to_string()).collect(),
            },
            expectation: ReplayExpectation::default(),
            replay: None,
            source: Some("seeded".into()),
        }
    }

    #[test]
    fn localization_ac1_and_ac3() {
        let scorer = Scorer::new(LlmConfig {
            base_url: "http://x".into(),
            api_key: "k".into(),
            model: "m".into(),
            reasoning_effort: None,
        });
        let case = case_with("payments", &["gateway"]);

        // payments is #1 → ac1 and ac3.
        let (a1, a3) = scorer.localization(&case, &["payments".into(), "users".into()]);
        assert!(a1 && a3);

        // related service `gateway` at #1 counts as correct.
        let (a1, _) = scorer.localization(&case, &["gateway".into()]);
        assert!(a1);

        // ground truth at #3 only → ac3 but not ac1.
        let (a1, a3) =
            scorer.localization(&case, &["users".into(), "media".into(), "payments".into()]);
        assert!(!a1 && a3);

        // not in top 3 → neither.
        let (a1, a3) = scorer.localization(
            &case,
            &[
                "users".into(),
                "media".into(),
                "notifications".into(),
                "payments".into(),
            ],
        );
        assert!(!a1 && !a3);
    }

    #[test]
    fn parse_judge_json_tolerates_fences() {
        let (m, why) =
            parse_judge_json("```json\n{\"match\": true, \"why\": \"same cause\"}\n```").unwrap();
        assert!(m);
        assert_eq!(why, "same cause");

        let (m, _) =
            parse_judge_json("The verdict: {\"match\": false, \"why\": \"diff\"}").unwrap();
        assert!(!m);
    }
}
