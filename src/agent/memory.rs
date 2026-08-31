use crate::agent::contracts::{
    EvidencePolarity, InvestigationWindow, ResultQuality, ResultStatus, ToolResultEnvelope,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const CURRENT_MEMORY_SCHEMA_VERSION: u32 = 4;
const LEGACY_MEMORY_SCHEMA_VERSION: u32 = 1;
const DEFAULT_PROMPT_MEMORY_LIMIT: usize = 12_000;

fn legacy_memory_schema_version() -> u32 {
    LEGACY_MEMORY_SCHEMA_VERSION
}

/// Working memory — distilled facts that survive aggressive transcript compaction.
/// Based on Raschka's two-layer memory pattern: transcript is for prompt reconstruction,
/// working memory is for task continuity.
///
/// Serializable to JSON so it can be persisted across investigation turns in the
/// `investigation_sessions.working_memory` column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingMemory {
    /// Version of this persisted object, not the database row version.
    /// Missing values are treated as the pre-versioning schema and migrated
    /// explicitly by `from_json`.
    #[serde(default = "legacy_memory_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub task: String,
    #[serde(default)]
    pub suspect_services: Vec<String>, // LRU, max 8
    #[serde(default)]
    pub confirmed_facts: Vec<String>, // max 10
    #[serde(default)]
    pub ruled_out: Vec<String>, // max 10
    #[serde(skip)]
    pub recent_tool_calls: Vec<CallSignature>, // transient: per-turn repeat detection
    #[serde(skip)]
    pub consecutive_empty_results: u32, // transient: per-turn dead-end detection
    /// Hypotheses we explored and ruled out (LRU, max 5). Used to discourage
    /// re-exploring dead ends across escalation rounds.
    #[serde(default)]
    pub failed_hypotheses: Vec<String>,
    /// Dead-end escalation level.
    ///   0 = initial investigation
    ///   1 = nudged to try alternative tool categories
    ///   2 = nudged to check dependency graph / widen window
    ///   3+ = force preliminary report
    #[serde(default)]
    pub escalation_level: u32,
    /// Signal types that have produced real data in this investigation (e.g.
    /// "logs", "traces", "metrics", "kubernetes", "deploys"). Persisted across
    /// turns so the root-cause gate can require cross-signal confirmation.
    /// LRU-capped at 10.
    #[serde(default)]
    pub signals_consulted: Vec<String>,
    /// Concrete result-backed evidence records. These are intentionally
    /// compact so they can survive persisted-session compaction while still
    /// giving the root-cause gate something stronger than a tool-call count.
    #[serde(default)]
    pub evidence: Vec<EvidenceItem>,
    /// Exact effective incident/baseline contract for the active turn.
    #[serde(default)]
    pub window: Option<InvestigationWindow>,
    /// Structured hypotheses are persisted in PR1 even though the causal gate
    /// remains a PR4 concern.
    #[serde(default)]
    pub hypotheses: Vec<Hypothesis>,
}

impl Default for WorkingMemory {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_MEMORY_SCHEMA_VERSION,
            task: String::new(),
            suspect_services: Vec::new(),
            confirmed_facts: Vec::new(),
            ruled_out: Vec::new(),
            recent_tool_calls: Vec::new(),
            consecutive_empty_results: 0,
            failed_hypotheses: Vec::new(),
            escalation_level: 0,
            signals_consulted: Vec::new(),
            evidence: Vec::new(),
            window: None,
            hypotheses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceItem {
    pub id: String,
    /// Kept for compatibility with the current gate and prompt.
    pub signal: String,
    pub tool: String,
    pub service: String,
    pub summary: String,
    #[serde(default)]
    pub source_family: String,
    #[serde(default)]
    pub source_tables: Vec<String>,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub query_fingerprint: String,
    #[serde(default)]
    pub window: Option<InvestigationWindow>,
    #[serde(default)]
    pub observation: String,
    #[serde(default)]
    pub incident_value: Option<serde_json::Value>,
    #[serde(default)]
    pub baseline_value: Option<serde_json::Value>,
    #[serde(default)]
    pub delta: Option<serde_json::Value>,
    #[serde(default)]
    pub polarity: EvidencePolarity,
    #[serde(default)]
    pub quality: ResultQuality,
    #[serde(default)]
    pub references: Vec<String>,
    /// Evidence retained from a previous follow-up scope. Historical items
    /// remain available for context but are excluded from the active causal
    /// gate until a new tool result validates them again.
    #[serde(default)]
    pub historical: bool,
    #[serde(default)]
    pub carry_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Hypothesis {
    pub id: String,
    #[serde(default)]
    pub culprit_service: String,
    #[serde(default)]
    pub mechanism: String,
    #[serde(default)]
    pub symptom_service: String,
    #[serde(default)]
    pub propagation_path: Vec<String>,
    #[serde(default)]
    pub expected_if_true: Vec<String>,
    #[serde(default)]
    pub expected_if_false: Vec<String>,
    #[serde(default)]
    pub supporting_evidence_ids: Vec<String>,
    #[serde(default)]
    pub contradicting_evidence_ids: Vec<String>,
    #[serde(default)]
    pub discriminating_evidence_ids: Vec<String>,
    #[serde(default = "default_hypothesis_status")]
    pub status: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default = "default_confidence_band")]
    pub confidence_band: String,
    #[serde(default)]
    pub next_best_test: String,
    /// Hypotheses from an earlier follow-up scope are retained for auditability
    /// but cannot become the active leading hypothesis without new evidence.
    #[serde(default)]
    pub historical: bool,
    #[serde(default)]
    pub carry_reason: String,
}

fn default_hypothesis_status() -> String {
    "open".into()
}

fn default_confidence_band() -> String {
    "low".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallSignature {
    pub tool: String,
    pub args_normalized: String, // stable representation of args
}

impl WorkingMemory {
    pub fn new(task: String) -> Self {
        Self {
            task,
            ..Default::default()
        }
    }

    /// Deserialize and migrate a persisted memory object. The database row
    /// itself remains tenant-scoped by ConfigDb; this method only handles the
    /// JSON payload and never changes the owning session or tenant.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let mut memory: Self = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        memory.migrate().map_err(|e| e.to_string())?;
        Ok(memory)
    }

    pub fn migrate(&mut self) -> Result<(), MemoryMigrationError> {
        if self.schema_version > CURRENT_MEMORY_SCHEMA_VERSION {
            return Err(MemoryMigrationError::UnsupportedVersion(
                self.schema_version,
            ));
        }

        // Version 1 was the existing free-form memory object. Preserve all
        // fields, then backfill the structured provenance fields from its
        // signal/tool pair. This is intentionally deterministic and does not
        // infer evidence from args or no-data strings.
        for (index, item) in self.evidence.iter_mut().enumerate() {
            if item.id.is_empty() {
                item.id = format!("E{}", index + 1);
            }
            if item.source_family.is_empty() {
                item.source_family = item.signal.clone();
            }
            if item.source_tables.is_empty() {
                item.source_tables = legacy_source_tables(&item.signal);
            }
            if item.observation.is_empty() {
                item.observation = item.summary.clone();
            }
            if item.quality.reasons.is_empty() {
                item.quality = ResultQuality::legacy();
            }
        }
        for hypothesis in &mut self.hypotheses {
            keep_recent(&mut hypothesis.supporting_evidence_ids, 20);
            keep_recent(&mut hypothesis.contradicting_evidence_ids, 20);
            keep_recent(&mut hypothesis.discriminating_evidence_ids, 20);
            normalize_hypothesis(hypothesis);
        }
        keep_recent(&mut self.suspect_services, 8);
        keep_recent(&mut self.confirmed_facts, 10);
        keep_recent(&mut self.ruled_out, 10);
        keep_recent(&mut self.failed_hypotheses, 5);
        keep_recent(&mut self.signals_consulted, 10);
        keep_recent(&mut self.evidence, 20);
        self.schema_version = CURRENT_MEMORY_SCHEMA_VERSION;
        Ok(())
    }

    /// Prepare persisted working memory for a follow-up turn. Transient loop
    /// state is always reset. Causal state is retained only when the new
    /// question overlaps the prior scope and the caller did not select a new
    /// incident window; otherwise old evidence/hypotheses are marked
    /// historical and excluded from the active final-report gate.
    pub fn prepare_follow_up(
        &mut self,
        task: String,
        requested_window: Option<InvestigationWindow>,
        continue_dead_end: bool,
    ) -> FollowUpTransition {
        let window_changed = requested_window
            .as_ref()
            .is_some_and(|window| self.window.as_ref() != Some(window));
        let scope_changed = !task_scope_overlaps(&self.task, &task, &self.hypotheses);
        let retire_active_scope = window_changed || scope_changed;
        let reason = if window_changed {
            "retired: incident window changed"
        } else if scope_changed {
            "retired: follow-up question changed investigation scope"
        } else {
            "carried forward: overlapping question and incident window"
        };

        let mut historical_evidence = 0;
        for item in &mut self.evidence {
            if retire_active_scope && !item.historical {
                item.historical = true;
                historical_evidence += 1;
            }
            if !item.historical || retire_active_scope {
                item.carry_reason = reason.to_string();
            }
        }
        let mut retired_hypotheses = 0;
        for hypothesis in &mut self.hypotheses {
            if retire_active_scope && !hypothesis.historical {
                hypothesis.historical = true;
                hypothesis.status = "inconclusive".into();
                retired_hypotheses += 1;
            }
            if !hypothesis.historical || retire_active_scope {
                hypothesis.carry_reason = reason.to_string();
            }
        }

        if retire_active_scope {
            self.suspect_services.clear();
            self.confirmed_facts.clear();
            self.ruled_out.clear();
            self.failed_hypotheses.clear();
            self.signals_consulted.clear();
        }
        self.task = task;
        if requested_window.is_some() {
            self.window = requested_window;
        }
        self.recent_tool_calls.clear();
        self.consecutive_empty_results = 0;
        if !continue_dead_end {
            self.escalation_level = 0;
        }
        self.apply_evidence_polarity();

        FollowUpTransition {
            scope_changed: retire_active_scope,
            window_changed,
            historical_evidence,
            retired_hypotheses,
            reason: reason.to_string(),
        }
    }

    pub fn active_evidence_count(&self) -> usize {
        self.evidence.iter().filter(|item| !item.historical).count()
    }

    pub fn active_signal_count(&self) -> usize {
        self.signals_consulted.len()
    }

    /// LRU insert: remove existing, push to end, cap size.
    fn remember<T: PartialEq + Clone>(bucket: &mut Vec<T>, item: T, limit: usize) {
        bucket.retain(|x| *x != item);
        bucket.push(item);
        if bucket.len() > limit {
            let drop = bucket.len() - limit;
            bucket.drain(..drop);
        }
    }

    pub fn add_suspect_service(&mut self, svc: String) {
        if svc.is_empty() {
            return;
        }
        Self::remember(&mut self.suspect_services, svc, 8);
    }

    pub fn add_fact(&mut self, fact: String) {
        if fact.is_empty() {
            return;
        }
        Self::remember(&mut self.confirmed_facts, fact, 10);
    }

    pub fn add_ruled_out(&mut self, item: String) {
        if item.is_empty() {
            return;
        }
        Self::remember(&mut self.ruled_out, item, 10);
    }

    /// Record a hypothesis that was explored but ruled out. LRU-capped at 5.
    pub fn add_failed_hypothesis(&mut self, item: String) {
        if item.is_empty() {
            return;
        }
        Self::remember(&mut self.failed_hypotheses, item, 5);
    }

    /// Record that a tool from the given signal category returned real data.
    /// `signal` should be one of "logs", "traces", "metrics", "kubernetes", "deploys".
    pub fn record_signal(&mut self, signal: &str) {
        if signal.is_empty() {
            return;
        }
        Self::remember(&mut self.signals_consulted, signal.to_string(), 10);
    }

    /// Add a compact, result-backed evidence item. Unlike `record_signal`,
    /// this should only be called after a tool returned meaningful data.
    pub fn add_evidence(&mut self, signal: &str, tool: &str, service: &str, summary: String) {
        if signal.is_empty() || tool.is_empty() || summary.is_empty() {
            return;
        }
        let summary = crate::agent::memory::truncate_at_char_boundary(&summary, 360).to_string();
        let item = EvidenceItem {
            id: self.next_evidence_id(),
            signal: signal.to_string(),
            tool: tool.to_string(),
            service: service.to_string(),
            summary,
            source_family: signal.to_string(),
            source_tables: legacy_source_tables(signal),
            operation: String::new(),
            query_fingerprint: String::new(),
            window: self.window.clone(),
            observation: String::new(),
            incident_value: None,
            baseline_value: None,
            delta: None,
            polarity: EvidencePolarity::Neutral,
            quality: ResultQuality::legacy(),
            references: Vec::new(),
            historical: false,
            carry_reason: String::new(),
        };
        self.evidence.push(item);
        if self.evidence.len() > 20 {
            self.evidence.drain(..self.evidence.len() - 20);
        }
    }

    /// Add evidence only from a validated positive result envelope. `no_data`,
    /// access-denied, and error results are intentionally excluded.
    pub fn add_evidence_from_envelope(
        &mut self,
        tool: &str,
        envelope: &ToolResultEnvelope,
    ) -> bool {
        if !envelope.is_positive_evidence() {
            return false;
        }
        let source_family = serde_json::to_value(&envelope.source_family)
            .ok()
            .and_then(|v| v.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".into());
        let historical = match (&self.window, &envelope.window) {
            (Some(active), Some(result_window)) if active != result_window => true,
            (None, Some(result_window)) => {
                self.window = Some(result_window.clone());
                false
            }
            _ => false,
        };
        let item = EvidenceItem {
            id: self.next_evidence_id(),
            signal: source_family.clone(),
            tool: tool.to_string(),
            service: envelope.service.clone(),
            summary: truncate_at_char_boundary(&envelope.summary, 360).to_string(),
            source_family,
            source_tables: envelope.source_tables.clone(),
            operation: envelope.operation.clone(),
            query_fingerprint: envelope.query_fingerprint.clone(),
            window: envelope.window.clone(),
            observation: truncate_at_char_boundary(&envelope.summary, 360).to_string(),
            incident_value: envelope.incident_value.clone(),
            baseline_value: envelope.baseline_value.clone(),
            delta: envelope.absolute_delta.clone(),
            polarity: EvidencePolarity::Neutral,
            quality: envelope.quality.clone(),
            references: envelope.references.clone(),
            historical,
            carry_reason: if historical {
                "historical: tool result used a different incident window".into()
            } else {
                String::new()
            },
        };
        self.evidence.push(item);
        if self.evidence.len() > 20 {
            self.evidence.drain(..self.evidence.len() - 20);
        }
        true
    }

    /// Persist a model-declared hypothesis update. The model may propose the
    /// state, but IDs and evidence links are normalized and validated here so
    /// the causal gate never trusts an unbounded or unknown reference.
    pub fn upsert_hypothesis(&mut self, mut hypothesis: Hypothesis) {
        normalize_hypothesis(&mut hypothesis);
        if hypothesis.id.is_empty() {
            return;
        }
        if let Some(existing) = self
            .hypotheses
            .iter_mut()
            .find(|item| item.id == hypothesis.id)
        {
            *existing = hypothesis;
        } else {
            self.hypotheses.push(hypothesis);
        }
        if self.hypotheses.len() > 12 {
            self.hypotheses.drain(..self.hypotheses.len() - 12);
        }
        self.apply_evidence_polarity();
    }

    /// Apply hypothesis links to the validated evidence ledger. A single
    /// evidence item can support one hypothesis and contradict another; in
    /// that ambiguous aggregate case the item-level polarity is neutral and
    /// the per-hypothesis links remain authoritative.
    pub fn apply_evidence_polarity(&mut self) {
        let mut supporting = HashSet::new();
        let mut contradicting = HashSet::new();
        for hypothesis in &self.hypotheses {
            supporting.extend(hypothesis.supporting_evidence_ids.iter().cloned());
            contradicting.extend(hypothesis.contradicting_evidence_ids.iter().cloned());
        }
        for evidence in &mut self.evidence {
            evidence.polarity = match (
                supporting.contains(&evidence.id),
                contradicting.contains(&evidence.id),
            ) {
                (true, false) => EvidencePolarity::Supports,
                (false, true) => EvidencePolarity::Contradicts,
                _ => EvidencePolarity::Neutral,
            };
        }
    }

    fn next_evidence_id(&self) -> String {
        let next = self
            .evidence
            .iter()
            .filter_map(|item| item.id.strip_prefix('E'))
            .filter_map(|value| value.parse::<u32>().ok())
            .max()
            .unwrap_or(0)
            + 1;
        format!("E{next}")
    }

    /// Number of distinct signal types that have returned real data.
    pub fn unique_signal_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for s in &self.signals_consulted {
            seen.insert(s.as_str());
        }
        seen.len()
    }

    /// Check if this exact tool call was made recently (exact dup).
    pub fn is_repeat_call(&self, sig: &CallSignature) -> bool {
        self.recent_tool_calls.iter().any(|c| c == sig)
    }

    pub fn record_call(&mut self, sig: CallSignature) {
        self.recent_tool_calls.push(sig);
        // Keep only last 20 call signatures
        if self.recent_tool_calls.len() > 20 {
            let drop = self.recent_tool_calls.len() - 20;
            self.recent_tool_calls.drain(..drop);
        }
    }

    /// Render working memory as a bounded string for prompt injection.
    pub fn to_prompt_block(&self) -> String {
        self.to_prompt_block_with_limit(DEFAULT_PROMPT_MEMORY_LIMIT)
    }

    pub fn to_prompt_block_with_limit(&self, limit: usize) -> String {
        let block = self.render_prompt_block();
        if block.len() <= limit {
            return block;
        }
        let suffix = "\n...[working memory truncated]";
        let head = truncate_at_char_boundary(&block, limit.saturating_sub(suffix.len()));
        format!("{head}{suffix}")
    }

    fn render_prompt_block(&self) -> String {
        let mut out = String::from("## Working Memory\n");
        if !self.task.is_empty() {
            out.push_str(&format!("**Task**: {}\n", self.task));
        }
        if let Some(window) = &self.window {
            out.push_str(&format!(
                "**Active incident window**: {} to {}; baseline {} to {}\n",
                window.incident_start.to_rfc3339(),
                window.incident_end.to_rfc3339(),
                window.baseline_start.to_rfc3339(),
                window.baseline_end.to_rfc3339()
            ));
        }
        if !self.suspect_services.is_empty() {
            out.push_str(&format!(
                "**Suspect services**: {}\n",
                self.suspect_services.join(", ")
            ));
        }
        if !self.hypotheses.is_empty() {
            out.push_str("**Active hypotheses:**\n");
            for hypothesis in self
                .hypotheses
                .iter()
                .filter(|h| h.status != "refuted" && !h.historical)
                .take(6)
            {
                let path = if hypothesis.propagation_path.is_empty() {
                    String::new()
                } else {
                    format!(" path={}", hypothesis.propagation_path.join(" -> "))
                };
                out.push_str(&format!(
                    "- [{}] {} / {} status={} confidence={} next_test={}{}\n",
                    hypothesis.id,
                    hypothesis.culprit_service,
                    hypothesis.mechanism,
                    hypothesis.status,
                    hypothesis.confidence_band,
                    hypothesis.next_best_test,
                    path
                ));
                if !hypothesis.carry_reason.is_empty() {
                    out.push_str(&format!("  lifecycle: {}\n", hypothesis.carry_reason));
                }
                if !hypothesis.contradicting_evidence_ids.is_empty() {
                    out.push_str(&format!(
                        "  contradictions={}\n",
                        hypothesis.contradicting_evidence_ids.join(", ")
                    ));
                }
            }
        }
        if !self.confirmed_facts.is_empty() {
            out.push_str("**Confirmed facts**:\n");
            for f in &self.confirmed_facts {
                out.push_str(&format!("- {f}\n"));
            }
        }
        if !self.ruled_out.is_empty() {
            out.push_str("**Ruled out**:\n");
            for r in &self.ruled_out {
                out.push_str(&format!("- {r}\n"));
            }
        }
        if !self.failed_hypotheses.is_empty() {
            out.push_str("**Previously ruled out (don't revisit):**\n");
            for h in &self.failed_hypotheses {
                out.push_str(&format!("- {h}\n"));
            }
        }
        if !self.signals_consulted.is_empty() {
            let unique: std::collections::HashSet<&str> =
                self.signals_consulted.iter().map(|s| s.as_str()).collect();
            let mut sorted: Vec<&str> = unique.into_iter().collect();
            sorted.sort();
            out.push_str(&format!(
                "**Signals consulted ({})**: {}\n",
                sorted.len(),
                sorted.join(", ")
            ));
        }
        if !self.evidence.is_empty() {
            out.push_str("**Evidence ledger:**\n");
            for item in self.evidence.iter().rev().take(10).rev() {
                let service = if item.service.is_empty() {
                    String::new()
                } else {
                    format!(" service={}", item.service)
                };
                out.push_str(&format!(
                    "- [{}] {} via {}{}: {}\n",
                    item.id, item.signal, item.tool, service, item.summary
                ));
                if !item.carry_reason.is_empty() {
                    out.push_str(&format!("  lifecycle: {}\n", item.carry_reason));
                }
            }
        }
        if self.escalation_level > 0 {
            let stage_hint = match self.escalation_level {
                1 => {
                    " (already tried alternative tool categories — now must check dependency graph)"
                }
                2 => {
                    " (already widened scope — now must produce a preliminary report with open questions)"
                }
                _ => " (must emit a preliminary report with explicit open questions)",
            };
            out.push_str(&format!(
                "**Escalation level:** {}{}\n",
                self.escalation_level, stage_hint
            ));
        }
        out
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemoryMigrationError {
    #[error(
        "unsupported working memory schema version {0}; newest supported version is {CURRENT_MEMORY_SCHEMA_VERSION}"
    )]
    UnsupportedVersion(u32),
}

fn legacy_source_tables(signal: &str) -> Vec<String> {
    match signal {
        "logs" => vec!["logs".into()],
        "traces" | "metrics" => vec!["spans".into()],
        "kubernetes" => vec!["kubernetes_api".into()],
        "deploys" => vec!["config_deploys".into()],
        "repository" => vec!["repository_api".into()],
        _ => Vec::new(),
    }
}

fn normalize_hypothesis(hypothesis: &mut Hypothesis) {
    hypothesis.status = match hypothesis.status.to_ascii_lowercase().as_str() {
        "supported" => "supported",
        "refuted" => "refuted",
        "inconclusive" => "inconclusive",
        _ => "open",
    }
    .into();
    hypothesis.confidence = hypothesis.confidence.clamp(0.0, 1.0);
    hypothesis.confidence_band = match hypothesis.confidence_band.to_ascii_lowercase().as_str() {
        "high" => "high",
        "medium" | "med" => "medium",
        _ => "low",
    }
    .into();
    for values in [
        &mut hypothesis.propagation_path,
        &mut hypothesis.expected_if_true,
        &mut hypothesis.expected_if_false,
        &mut hypothesis.supporting_evidence_ids,
        &mut hypothesis.contradicting_evidence_ids,
        &mut hypothesis.discriminating_evidence_ids,
    ] {
        values.retain(|value| !value.trim().is_empty());
        values.truncate(20);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowUpTransition {
    pub scope_changed: bool,
    pub window_changed: bool,
    pub historical_evidence: usize,
    pub retired_hypotheses: usize,
    pub reason: String,
}

fn task_scope_overlaps(old_task: &str, new_task: &str, hypotheses: &[Hypothesis]) -> bool {
    if old_task.trim().is_empty() || new_task.trim().is_empty() {
        return true;
    }
    let old = scope_tokens(old_task);
    let new = scope_tokens(new_task);
    if old.iter().any(|token| new.contains(token)) {
        return true;
    }
    let new_lower = new_task.to_ascii_lowercase();
    hypotheses.iter().any(|hypothesis| {
        !hypothesis.historical
            && (!hypothesis.culprit_service.is_empty()
                && new_lower.contains(&hypothesis.culprit_service.to_ascii_lowercase())
                || !hypothesis.symptom_service.is_empty()
                    && new_lower.contains(&hypothesis.symptom_service.to_ascii_lowercase()))
    })
}

fn scope_tokens(value: &str) -> HashSet<String> {
    const STOP_WORDS: &[&str] = &[
        "about",
        "after",
        "agent",
        "an",
        "and",
        "are",
        "can",
        "check",
        "continue",
        "did",
        "for",
        "from",
        "how",
        "investigate",
        "is",
        "it",
        "me",
        "of",
        "on",
        "or",
        "please",
        "show",
        "the",
        "this",
        "to",
        "what",
        "why",
        "with",
    ];
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .map(str::to_ascii_lowercase)
        .filter(|token| token.len() >= 3 && !STOP_WORDS.contains(&token.as_str()))
        .collect()
}

fn keep_recent<T>(items: &mut Vec<T>, limit: usize) {
    if items.len() > limit {
        let keep_from = items.len() - limit;
        items.drain(..keep_from);
    }
}

/// Normalize args into a stable string for repeat detection.
/// Collapses equivalent queries (sorted keys, whitespace removed).
pub fn normalize_args(args: &serde_json::Value) -> String {
    fn walk(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(k);
                    out.push(':');
                    walk(&m[*k], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(arr) => {
                out.push('[');
                for (i, v) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    walk(v, out);
                }
                out.push(']');
            }
            serde_json::Value::String(s) => out.push_str(s),
            serde_json::Value::Number(n) => out.push_str(&n.to_string()),
            serde_json::Value::Bool(b) => out.push_str(&b.to_string()),
            serde_json::Value::Null => out.push_str("null"),
        }
    }
    let mut s = String::new();
    walk(args, &mut s);
    s
}

/// Extract signal-worthy facts from a tool result for working memory.
/// Returns (suspect_services, facts) tuples to add.
pub fn extract_facts_from_tool_result(
    tool_name: &str,
    args: &serde_json::Value,
    result: &str,
) -> ExtractedFacts {
    let mut out = ExtractedFacts::default();

    // PR2 causal tools return the PR1 envelope with a `data` member. Only
    // positive structured results can create facts/evidence; arguments alone
    // still never enter working memory.
    if let Ok(envelope) = serde_json::from_str::<ToolResultEnvelope>(result) {
        if envelope.is_positive_evidence() {
            if !envelope.service.is_empty() {
                out.services.insert(envelope.service.clone());
            } else if let Some(service) = args
                .get("service")
                .or_else(|| args.get("service_name"))
                .and_then(|value| value.as_str())
                && !service.is_empty()
            {
                out.services.insert(service.to_string());
            }
        }
        out.summary = (!envelope.summary.is_empty()).then_some(envelope.summary.clone());
        out.empty_result = matches!(envelope.status, ResultStatus::NoData);
        out.has_data = envelope.is_positive_evidence();
        return out;
    }

    // Detect empty/no-data/blocked results. A successful HTTP response that
    // says "Access denied" is still not usable evidence.
    let low = result.to_lowercase();
    if low.contains("no matching")
        || low.contains("no data")
        || low.contains("not found")
        || low.contains("no spans found")
        || low.contains("no logs found")
        || low.contains("no service traffic")
        || low.contains("no cross-service calls")
        || low.contains("no deploys")
    {
        out.empty_result = true;
    }
    let blocked = low.starts_with("access denied")
        || low.starts_with("tool error:")
        || low.starts_with("error:");

    // Service arguments become suspects only after a result has produced
    // usable data. Arguments alone are never evidence or suspect attribution.
    if !blocked && !out.empty_result {
        if let Some(svc) = args.get("service").and_then(|v| v.as_str())
            && !svc.is_empty()
        {
            out.services.insert(svc.to_string());
        }
        if let Some(svc) = args.get("service_name").and_then(|v| v.as_str())
            && !svc.is_empty()
        {
            out.services.insert(svc.to_string());
        }
    }

    // Tool-specific summarization
    match tool_name {
        "search_logs" => {
            // Keep the count plus one timestamped/correlated sample. A count
            // alone is useful for navigation but is not enough to support a
            // causal conclusion.
            if let Some(first_line) = result.lines().next()
                && first_line.contains("Found")
            {
                let detail = result
                    .lines()
                    .find(|line| line.contains("] [") && line.contains(":"))
                    .map(str::trim)
                    .unwrap_or("");
                out.summary = Some(if detail.is_empty() {
                    first_line.to_string()
                } else {
                    format!("{first_line} sample={detail}")
                });
            }
        }
        "query_traces" => {
            if let Some(first_line) = result.lines().next()
                && first_line.contains("Found")
            {
                let latency = result
                    .lines()
                    .find(|line| line.trim_start().starts_with("Latency:"))
                    .map(str::trim)
                    .unwrap_or("");
                out.summary = Some(if latency.is_empty() {
                    first_line.to_string()
                } else {
                    format!("{first_line} {latency}")
                });
            }
        }
        "query_metrics" => {
            // Metrics output has "Latest=X Avg=Y Min=Z Max=W"
            let header = result.lines().next().unwrap_or("").trim();
            let stats = result
                .lines()
                .take(5)
                .find(|line| line.contains("Latest="))
                .map(str::trim)
                .unwrap_or("");
            if !stats.is_empty() {
                out.summary = Some(format!("{header} {stats}"));
            } else if header.contains("error_rate") || header.contains("latency") {
                out.summary = Some(header.to_string());
            }
        }
        "list_services" | "service_dependencies" | "list_deploys" | "get_trace" => {
            if let Some(first_line) = result.lines().next()
                && !first_line.trim().is_empty()
            {
                let detail = result
                    .lines()
                    .skip(1)
                    .find(|line| !line.trim().is_empty() && !line.trim().starts_with('-'))
                    .map(str::trim)
                    .unwrap_or("");
                out.summary = Some(if detail.is_empty() {
                    first_line.trim().to_string()
                } else {
                    format!("{} sample={detail}", first_line.trim())
                });
            }
        }
        "get_argocd_app" => {
            // Extract health status
            for line in result.lines().take(10) {
                if line.starts_with("Health:") || line.starts_with("Sync:") {
                    out.summary = Some(line.trim().to_string());
                    break;
                }
            }
        }
        "get_flux_resource" => {
            // Extract the Ready / Suspended line
            for line in result.lines().take(10) {
                if line.starts_with("Ready:") || line.starts_with("Suspended:") {
                    out.summary = Some(line.trim().to_string());
                    break;
                }
            }
        }
        "kube_describe" => {
            // Extract pod phase / container state
            for line in result.lines().take(20) {
                if line.contains("Phase:")
                    || line.contains("WAITING:")
                    || line.contains("TERMINATED:")
                    || line.contains("CrashLoop")
                    || line.contains("OOMKill")
                {
                    out.summary = Some(line.trim().to_string());
                    break;
                }
            }
        }
        _ => {}
    }

    out.has_data = !out.empty_result && !blocked && out.summary.is_some();

    out
}

#[derive(Debug, Default)]
pub struct ExtractedFacts {
    pub services: HashSet<String>,
    pub summary: Option<String>,
    pub empty_result: bool,
    pub has_data: bool,
}

/// Clip a tool result to a budget specific to the tool type.
/// Based on Raschka's per-event clipping, but bucketed by signal type since
/// logs/traces/metrics have different information density.
pub fn clip_tool_result(tool_name: &str, result: &str) -> String {
    let limit = match tool_name {
        "search_logs" => 4000,
        "query_traces" => 3000,
        "get_trace" => 4000,
        "query_metrics" => 1500,
        "list_services" => 2000,
        "service_dependencies" => 1500,
        "list_deploys" => 2000,
        "get_anomaly_context" => 2000,
        "get_argocd_app" => 3000,
        "get_flux_resource" => 3000,
        "kube_describe" => 2500,
        "kube_events" => 2500,
        "search_kubernetes_access" => 8000,
        "load_skill" => 6000, // skills are intentional content
        "compare_service_windows" | "rank_slow_dependencies" => 12_000,
        _ => 2000,
    };

    if matches!(
        tool_name,
        "compare_service_windows" | "rank_slow_dependencies"
    ) {
        return clip_structured_tool_result(result, limit);
    }

    if result.len() <= limit {
        return result.to_string();
    }
    let head = truncate_at_char_boundary(result, limit);
    format!(
        "{}\n...[truncated {} chars]",
        head,
        result.len() - head.len()
    )
}

/// Keep causal results valid JSON while bounding large endpoint/edge arrays.
/// A byte slice would destroy the PR1 envelope and make provenance impossible
/// to recover in the streaming layer.
fn clip_structured_tool_result(result: &str, limit: usize) -> String {
    if result.len() <= limit {
        return result.to_string();
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(result) else {
        return clip_tool_result("unknown", result);
    };
    if let Some(data) = value
        .get_mut("data")
        .and_then(|value| value.as_object_mut())
    {
        for key in ["services", "client_wait", "endpoints", "dependencies"] {
            if let Some(items) = data.get_mut(key).and_then(|value| value.as_array_mut()) {
                let cap = match key {
                    "endpoints" => 20,
                    "dependencies" => 20,
                    _ => 20,
                };
                items.truncate(cap);
            }
        }
        data.insert("truncated".into(), serde_json::Value::Bool(true));
    }
    let compact = serde_json::to_string(&value).unwrap_or_else(|_| result.to_string());
    if compact.len() <= limit {
        return compact;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "data".into(),
            serde_json::json!({"truncated": true, "reason": "prompt size budget"}),
        );
    }
    serde_json::to_string(&value).unwrap_or_else(|_| result.to_string())
}

/// Truncate `s` to at most `max` bytes without splitting a multi-byte
/// character. Slicing at a raw byte index (`&s[..max]`) panics when the cut
/// lands inside a UTF-8 sequence (smart quotes, emoji, non-Latin log text);
/// this walks back to the nearest char boundary instead.
pub(crate) fn truncate_at_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── normalize_args ──

    #[test]
    fn normalize_args_stable_across_key_order() {
        let a = json!({"service": "foo", "minutes": 15});
        let b = json!({"minutes": 15, "service": "foo"});
        assert_eq!(normalize_args(&a), normalize_args(&b));
    }

    #[test]
    fn normalize_args_distinguishes_different_values() {
        let a = json!({"service": "foo"});
        let b = json!({"service": "bar"});
        assert_ne!(normalize_args(&a), normalize_args(&b));
    }

    #[test]
    fn normalize_args_nested_objects() {
        let a = json!({"filter": {"x": 1, "y": 2}});
        let b = json!({"filter": {"y": 2, "x": 1}});
        assert_eq!(normalize_args(&a), normalize_args(&b));
    }

    #[test]
    fn normalize_args_handles_null() {
        assert_eq!(normalize_args(&json!(null)), "null");
    }

    // ── WorkingMemory LRU behavior ──

    #[test]
    fn suspect_services_lru_caps_at_8() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..15 {
            m.add_suspect_service(format!("svc{i}"));
        }
        assert_eq!(m.suspect_services.len(), 8);
        // Most recent 8 should be kept (svc7..svc14)
        assert!(m.suspect_services.contains(&"svc14".to_string()));
        assert!(m.suspect_services.contains(&"svc7".to_string()));
        assert!(!m.suspect_services.contains(&"svc0".to_string()));
    }

    #[test]
    fn suspect_services_reinsert_moves_to_end() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_suspect_service("a".to_string());
        m.add_suspect_service("b".to_string());
        m.add_suspect_service("c".to_string());
        m.add_suspect_service("a".to_string()); // should move to end
        assert_eq!(
            m.suspect_services,
            vec!["b".to_string(), "c".to_string(), "a".to_string()]
        );
    }

    #[test]
    fn empty_service_not_added() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_suspect_service(String::new());
        assert!(m.suspect_services.is_empty());
    }

    #[test]
    fn confirmed_facts_lru_caps_at_10() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..15 {
            m.add_fact(format!("fact-{i}"));
        }
        assert_eq!(m.confirmed_facts.len(), 10);
        assert!(m.confirmed_facts.contains(&"fact-14".to_string()));
        assert!(!m.confirmed_facts.contains(&"fact-0".to_string()));
    }

    #[test]
    fn failed_hypotheses_lru_caps_at_5() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..8 {
            m.add_failed_hypothesis(format!("h-{i}"));
        }
        assert_eq!(m.failed_hypotheses.len(), 5);
        assert!(m.failed_hypotheses.contains(&"h-7".to_string()));
        assert!(!m.failed_hypotheses.contains(&"h-0".to_string()));
    }

    #[test]
    fn empty_failed_hypothesis_not_added() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_failed_hypothesis(String::new());
        assert!(m.failed_hypotheses.is_empty());
    }

    #[test]
    fn prompt_block_renders_failed_hypotheses_when_present() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_failed_hypothesis("checkout db slow query".to_string());
        let block = m.to_prompt_block();
        assert!(block.contains("Previously ruled out"));
        assert!(block.contains("checkout db slow query"));
    }

    #[test]
    fn prompt_block_renders_escalation_level_when_non_zero() {
        let mut m = WorkingMemory::new("t".to_string());
        m.escalation_level = 2;
        let block = m.to_prompt_block();
        assert!(block.contains("Escalation level"));
        assert!(block.contains('2'));
    }

    #[test]
    fn prompt_block_omits_escalation_when_zero() {
        let m = WorkingMemory::new("t".to_string());
        let block = m.to_prompt_block();
        assert!(!block.contains("Escalation level"));
    }

    // ── Repeat call detection ──

    #[test]
    fn is_repeat_call_false_on_new_signature() {
        let m = WorkingMemory::new("t".to_string());
        let sig = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:foo}".to_string(),
        };
        assert!(!m.is_repeat_call(&sig));
    }

    #[test]
    fn is_repeat_call_true_after_record() {
        let mut m = WorkingMemory::new("t".to_string());
        let sig = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:foo}".to_string(),
        };
        m.record_call(sig.clone());
        assert!(m.is_repeat_call(&sig));
    }

    #[test]
    fn different_signatures_are_not_repeats() {
        let mut m = WorkingMemory::new("t".to_string());
        let s1 = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:foo}".to_string(),
        };
        let s2 = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:bar}".to_string(),
        };
        m.record_call(s1.clone());
        assert!(!m.is_repeat_call(&s2));
    }

    #[test]
    fn recent_tool_calls_capped_at_20() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..25 {
            m.record_call(CallSignature {
                tool: "t".to_string(),
                args_normalized: format!("arg{i}"),
            });
        }
        assert_eq!(m.recent_tool_calls.len(), 20);
    }

    // ── Prompt block rendering ──

    #[test]
    fn prompt_block_omits_empty_sections() {
        let m = WorkingMemory::new("find the bug".to_string());
        let block = m.to_prompt_block();
        assert!(block.contains("find the bug"));
        // Empty sections shouldn't render headers
        assert!(!block.contains("Suspect services"));
        assert!(!block.contains("Confirmed facts"));
    }

    #[test]
    fn prompt_block_includes_facts_and_services() {
        let mut m = WorkingMemory::new("task".to_string());
        m.add_suspect_service("checkout".to_string());
        m.add_fact("error rate is 5%".to_string());
        let block = m.to_prompt_block();
        assert!(block.contains("checkout"));
        assert!(block.contains("error rate is 5%"));
    }

    // ── extract_facts_from_tool_result ──

    #[test]
    fn extract_facts_search_logs() {
        let args = json!({"service": "checkout", "minutes": 15});
        let result = "Found 42 log entries (last 15m).\nTop message patterns:\n";
        let facts = extract_facts_from_tool_result("search_logs", &args, result);
        assert!(facts.services.contains("checkout"));
        assert_eq!(
            facts.summary,
            Some("Found 42 log entries (last 15m).".to_string())
        );
        assert!(!facts.empty_result);
    }

    #[test]
    fn extract_facts_empty_logs() {
        let args = json!({});
        let facts = extract_facts_from_tool_result("search_logs", &args, "No matching logs found.");
        assert!(facts.empty_result);
    }

    #[test]
    fn extract_facts_empty_traces() {
        let args = json!({});
        let facts = extract_facts_from_tool_result("query_traces", &args, "No spans found.");
        assert!(facts.empty_result);
    }

    #[test]
    fn blocked_results_are_not_evidence() {
        let facts = extract_facts_from_tool_result(
            "search_logs",
            &json!({"service": "checkout"}),
            "Access denied: your account does not have permission to search logs.",
        );
        assert!(!facts.has_data);
        assert!(facts.summary.is_none());
    }

    #[test]
    fn tool_arguments_do_not_create_suspects_for_no_data() {
        let facts = extract_facts_from_tool_result(
            "query_traces",
            &json!({"service": "checkout"}),
            "No spans found.",
        );
        assert!(facts.services.is_empty());
        assert!(!facts.has_data);
    }

    #[test]
    fn structured_causal_results_are_clipped_without_breaking_json() {
        let result = serde_json::json!({
            "status":"ok",
            "source_family":"traces",
            "source_tables":["spans"],
            "window": null,
            "quality":{"band":"medium","reasons":[]},
            "summary":"comparison",
            "data":{"endpoints":(0..1000).map(|i| serde_json::json!({"endpoint": i})).collect::<Vec<_>>()}
        })
        .to_string();
        let clipped = clip_tool_result("compare_service_windows", &result);
        let parsed: serde_json::Value = serde_json::from_str(&clipped).unwrap();
        assert_eq!(parsed["data"]["truncated"], true);
        assert!(parsed["data"]["endpoints"].as_array().unwrap().len() <= 20);
    }

    #[test]
    fn extract_facts_metrics_summary() {
        let args = json!({"service": "api", "metric": "error_rate"});
        let result =
            "api error_rate (last 30m, 30 data points):\nLatest=0.05 Avg=0.03 Min=0.01 Max=0.08\n";
        let facts = extract_facts_from_tool_result("query_metrics", &args, result);
        assert!(facts.services.contains("api"));
        // Summary grabs the first matching line — either the header ("error_rate")
        // or the stats line ("Latest="). Both are informative.
        let summary = facts.summary.as_ref().unwrap();
        assert!(
            summary.contains("error_rate") || summary.contains("Latest="),
            "unexpected summary: {summary}"
        );
    }

    #[test]
    fn extract_facts_argocd_health() {
        let args = json!({"name": "my-app"});
        let result = "ArgoCD Application: my-app\nProject: default\nHealth: Degraded — pods not ready\nSync: Synced (revision: abc1234)\n";
        let facts = extract_facts_from_tool_result("get_argocd_app", &args, result);
        assert!(facts.summary.as_ref().unwrap().contains("Degraded"));
    }

    #[test]
    fn extract_facts_kube_describe_crashloop() {
        let args = json!({"kind": "pod", "name": "my-pod", "namespace": "default"});
        let result = "pod/my-pod\nPhase: Running\nContainers (1):\n  app: ready=false restarts=12\n    WAITING: CrashLoopBackOff — back-off 5m restarting\n";
        let facts = extract_facts_from_tool_result("kube_describe", &args, result);
        let summary = facts.summary.unwrap();
        assert!(
            summary.contains("Phase:")
                || summary.contains("CrashLoop")
                || summary.contains("WAITING")
        );
    }

    // ── clip_tool_result ──

    #[test]
    fn clip_respects_search_logs_budget() {
        let long = "x".repeat(10_000);
        let clipped = clip_tool_result("search_logs", &long);
        assert!(clipped.contains("[truncated"));
        // Budget is 4000
        assert!(clipped.len() < 5000);
    }

    #[test]
    fn clip_respects_metrics_budget() {
        let long = "x".repeat(10_000);
        let clipped = clip_tool_result("query_metrics", &long);
        // Budget is 1500 — should be much smaller than search_logs
        assert!(clipped.len() < 2000);
    }

    #[test]
    fn clip_short_input_unchanged() {
        let short = "Found 5 entries.";
        assert_eq!(clip_tool_result("search_logs", short), short);
    }

    #[test]
    fn clip_unknown_tool_uses_default_budget() {
        let long = "x".repeat(5_000);
        let clipped = clip_tool_result("mystery_tool", &long);
        assert!(clipped.contains("[truncated"));
    }

    // ── truncate_at_char_boundary ──

    #[test]
    fn truncate_at_char_boundary_no_panic_on_multibyte() {
        // '…' is 3 bytes in UTF-8; for most `max` values the cut lands mid-char.
        let s = "…".repeat(100); // 300 bytes
        for max in 0..=s.len() {
            let t = truncate_at_char_boundary(&s, max);
            assert!(
                t.len() <= max,
                "result must be ≤{max} bytes, got {}",
                t.len()
            );
            assert!(s.starts_with(t));
        }
        // Same for a 4-byte emoji.
        let e = "🚨".repeat(10); // 40 bytes
        let t = truncate_at_char_boundary(&e, 6);
        assert_eq!(t, "🚨"); // 4 bytes — walked back from byte 6
    }

    #[test]
    fn truncate_at_char_boundary_short_input_unchanged() {
        assert_eq!(truncate_at_char_boundary("abc", 10), "abc");
        assert_eq!(truncate_at_char_boundary("abc", 3), "abc");
        assert_eq!(truncate_at_char_boundary("abcdef", 3), "abc");
    }

    #[test]
    fn clip_does_not_panic_when_budget_splits_multibyte_char() {
        // query_metrics budget is 1500 bytes; fill with 3-byte chars so the
        // cut at 1500 lands cleanly, then shift by a 1-byte prefix so it
        // falls mid-char. Both must not panic and stay within budget + suffix.
        for prefix in ["", "a", "ab"] {
            let long = format!("{prefix}{}", "…".repeat(1000)); // > 1500 bytes
            let clipped = clip_tool_result("query_metrics", &long);
            assert!(clipped.contains("[truncated"));
            let head = clipped.split("\n...[truncated").next().unwrap();
            assert!(head.len() <= 1500);
            assert!(long.starts_with(head));
        }
    }

    // ── PR1 memory schema and provenance ──

    #[test]
    fn migrates_current_unversioned_memory_and_backfills_provenance() {
        let raw = r#"{
            "task":"investigate api",
            "suspect_services":["api"],
            "confirmed_facts":["trace latency increased"],
            "ruled_out":[],
            "failed_hypotheses":[],
            "escalation_level":0,
            "signals_consulted":["traces"],
            "evidence":[{
                "id":"E1",
                "signal":"traces",
                "tool":"query_traces",
                "service":"api",
                "summary":"p99 increased"
            }]
        }"#;
        let memory = WorkingMemory::from_json(raw).unwrap();
        assert_eq!(memory.schema_version, CURRENT_MEMORY_SCHEMA_VERSION);
        assert_eq!(memory.task, "investigate api");
        assert_eq!(memory.evidence[0].source_family, "traces");
        assert_eq!(memory.evidence[0].source_tables, vec!["spans"]);
        assert_eq!(memory.evidence[0].observation, "p99 increased");
    }

    #[test]
    fn rejects_memory_from_a_newer_schema() {
        let raw = r#"{"schema_version":99,"task":"future"}"#;
        let err = WorkingMemory::from_json(raw).unwrap_err();
        assert!(err.contains("unsupported working memory schema version 99"));
    }

    #[test]
    fn serialized_memory_contains_schema_version() {
        let memory = WorkingMemory::new("task".into());
        let json = serde_json::to_value(&memory).unwrap();
        assert_eq!(json["schema_version"], CURRENT_MEMORY_SCHEMA_VERSION);
    }

    #[test]
    fn only_positive_envelopes_enter_evidence_ledger() {
        let mut memory = WorkingMemory::new("task".into());
        let no_data = ToolResultEnvelope::from_legacy(
            "query_traces",
            &serde_json::json!({"service":"api"}),
            "No spans found.",
            None,
        );
        assert!(!memory.add_evidence_from_envelope("query_traces", &no_data));
        assert!(memory.evidence.is_empty());

        let ok = ToolResultEnvelope::from_legacy(
            "query_traces",
            &serde_json::json!({"service":"api"}),
            "Found 4 spans",
            Some("Found 4 spans; Latency: 900ms"),
        );
        assert!(memory.add_evidence_from_envelope("query_traces", &ok));
        assert_eq!(memory.evidence.len(), 1);
        assert_eq!(memory.evidence[0].source_tables, vec!["spans"]);
    }

    #[test]
    fn hypothesis_relationships_preserve_cross_hypothesis_conflict() {
        let mut memory = WorkingMemory::new("task".into());
        memory.add_evidence("logs", "search_logs", "api", "connection refused".into());
        memory.upsert_hypothesis(Hypothesis {
            id: "H1".into(),
            culprit_service: "api".into(),
            mechanism: "error regression".into(),
            symptom_service: "api".into(),
            supporting_evidence_ids: vec!["E1".into()],
            ..Default::default()
        });
        memory.upsert_hypothesis(Hypothesis {
            id: "H2".into(),
            culprit_service: "db".into(),
            mechanism: "database failure".into(),
            symptom_service: "api".into(),
            contradicting_evidence_ids: vec!["E1".into()],
            ..Default::default()
        });

        assert_eq!(memory.hypotheses[0].supporting_evidence_ids, vec!["E1"]);
        assert_eq!(memory.hypotheses[1].contradicting_evidence_ids, vec!["E1"]);
        assert_eq!(memory.evidence[0].polarity, EvidencePolarity::Neutral);
    }

    #[test]
    fn follow_up_partitions_changed_scope_and_resets_transient_state() {
        use crate::agent::contracts::WindowSelectionReason;
        use chrono::{TimeZone, Utc};

        let first_window = InvestigationWindow::new(
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 11, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
            WindowSelectionReason::UserProvidedRange,
        )
        .unwrap();
        let second_window = InvestigationWindow::new(
            Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 13, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 11, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
            WindowSelectionReason::UserProvidedRange,
        )
        .unwrap();

        let mut memory = WorkingMemory::new("Why is api erroring?".into());
        memory.window = Some(first_window);
        memory.add_evidence("logs", "search_logs", "api", "errors increased".into());
        memory.add_suspect_service("api".into());
        memory.add_fact("api errors increased".into());
        memory.record_signal("logs");
        memory.escalation_level = 2;
        memory.record_call(CallSignature {
            tool: "search_logs".into(),
            args_normalized: "{service:api}".into(),
        });

        let transition =
            memory.prepare_follow_up("Why is checkout slow?".into(), Some(second_window), false);

        assert!(transition.scope_changed);
        assert!(transition.window_changed);
        assert_eq!(transition.historical_evidence, 1);
        assert!(memory.evidence[0].historical);
        assert_eq!(memory.active_evidence_count(), 0);
        assert!(memory.suspect_services.is_empty());
        assert!(memory.confirmed_facts.is_empty());
        assert!(memory.signals_consulted.is_empty());
        assert!(memory.recent_tool_calls.is_empty());
        assert_eq!(memory.consecutive_empty_results, 0);
        assert_eq!(memory.escalation_level, 0);
        assert!(transition.reason.contains("window changed"));
    }

    #[test]
    fn bounded_prompt_prioritizes_active_hypotheses() {
        let mut memory = WorkingMemory::new("task".into());
        memory.hypotheses.push(Hypothesis {
            id: "H1".into(),
            culprit_service: "media".into(),
            mechanism: "cpu_throttling".into(),
            symptom_service: "gateway".into(),
            propagation_path: vec!["media".into(), "gateway".into()],
            expected_if_true: vec!["throttling rises".into()],
            expected_if_false: vec![],
            supporting_evidence_ids: vec![],
            contradicting_evidence_ids: vec!["E9".into()],
            discriminating_evidence_ids: vec!["E10".into()],
            status: "open".into(),
            confidence: 0.4,
            confidence_band: "low".into(),
            next_best_test: "compare media resource metrics".into(),
            historical: false,
            carry_reason: String::new(),
        });
        for _ in 0..50 {
            memory.add_fact("large fact ".repeat(50));
        }
        let block = memory.to_prompt_block_with_limit(500);
        assert!(block.len() <= 500);
        assert!(block.contains("Active hypotheses"));
        assert!(block.contains("media"));
        assert!(block.contains("contradictions=E9"));
    }
}
