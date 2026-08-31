//! Shared contracts for causal investigations.
//!
//! PR 1 deliberately keeps the existing string-based tool API compatible with
//! the agent prompt. These types provide the typed boundary around those
//! strings so later causal tools can use the same windows and provenance
//! without inventing their own formats.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const UTC_TIMEZONE: &str = "UTC";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WindowSelectionReason {
    AlertWindow,
    UserProvidedRange,
    InferredOnset,
    Fallback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvestigationWindow {
    /// Inclusive incident start, always serialized as UTC.
    pub incident_start: DateTime<Utc>,
    /// Exclusive incident end, always serialized as UTC.
    pub incident_end: DateTime<Utc>,
    /// Inclusive baseline start, always serialized as UTC.
    pub baseline_start: DateTime<Utc>,
    /// Exclusive baseline end, always serialized as UTC.
    pub baseline_end: DateTime<Utc>,
    pub selection_reason: WindowSelectionReason,
    #[serde(default = "utc_timezone")]
    pub timezone: String,
}

fn utc_timezone() -> String {
    UTC_TIMEZONE.to_string()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WindowError {
    #[error("incident window must have a positive duration")]
    EmptyIncident,
    #[error("baseline window must have a positive duration")]
    EmptyBaseline,
    #[error("incident and baseline windows must have equal duration")]
    UnequalDurations,
    #[error("incident timestamp {timestamp} is in the future relative to {as_of}")]
    FutureTimestamp {
        timestamp: DateTime<Utc>,
        as_of: DateTime<Utc>,
    },
    #[error("window timezone must be UTC")]
    NonUtcTimezone,
}

impl InvestigationWindow {
    pub fn new(
        incident_start: DateTime<Utc>,
        incident_end: DateTime<Utc>,
        baseline_start: DateTime<Utc>,
        baseline_end: DateTime<Utc>,
        selection_reason: WindowSelectionReason,
    ) -> Result<Self, WindowError> {
        let window = Self {
            incident_start,
            incident_end,
            baseline_start,
            baseline_end,
            selection_reason,
            timezone: utc_timezone(),
        };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), WindowError> {
        if self.timezone != UTC_TIMEZONE {
            return Err(WindowError::NonUtcTimezone);
        }
        let incident_duration = self.incident_end - self.incident_start;
        if incident_duration <= Duration::zero() {
            return Err(WindowError::EmptyIncident);
        }
        let baseline_duration = self.baseline_end - self.baseline_start;
        if baseline_duration <= Duration::zero() {
            return Err(WindowError::EmptyBaseline);
        }
        if incident_duration != baseline_duration {
            return Err(WindowError::UnequalDurations);
        }
        Ok(())
    }

    /// Select a bounded incident window centered on an anomaly timestamp and
    /// the immediately preceding equal-duration baseline. `as_of` is explicit
    /// so replayed investigations never depend on the wall clock.
    pub fn centered_on(
        timestamp: DateTime<Utc>,
        duration: Duration,
        as_of: DateTime<Utc>,
        reason: WindowSelectionReason,
    ) -> Result<Self, WindowError> {
        if timestamp > as_of {
            return Err(WindowError::FutureTimestamp { timestamp, as_of });
        }
        if duration <= Duration::zero() {
            return Err(WindowError::EmptyIncident);
        }
        let half = duration / 2;
        let incident_start = timestamp - half;
        let incident_end = incident_start + duration;
        let baseline_end = incident_start;
        let baseline_start = baseline_end - duration;
        Self::new(
            incident_start,
            incident_end,
            baseline_start,
            baseline_end,
            reason,
        )
    }

    pub fn recent(
        now: DateTime<Utc>,
        duration: Duration,
        reason: WindowSelectionReason,
    ) -> Result<Self, WindowError> {
        if duration <= Duration::zero() {
            return Err(WindowError::EmptyIncident);
        }
        let incident_end = now;
        let incident_start = incident_end - duration;
        let baseline_end = incident_start;
        let baseline_start = baseline_end - duration;
        Self::new(
            incident_start,
            incident_end,
            baseline_start,
            baseline_end,
            reason,
        )
    }

    pub fn incident_duration(&self) -> Duration {
        self.incident_end - self.incident_start
    }

    pub fn baseline_duration(&self) -> Duration {
        self.baseline_end - self.baseline_start
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Ok,
    NoData,
    Partial,
    AccessDenied,
    Error,
}

impl ResultStatus {
    pub fn contributes_positive_evidence(&self) -> bool {
        matches!(self, Self::Ok | Self::Partial)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SourceFamily {
    Traces,
    Logs,
    #[serde(rename = "otel_metrics")]
    OTelMetrics,
    Database,
    Kubernetes,
    Deploys,
    Repository,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualityBand {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResultQuality {
    pub band: QualityBand,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl Default for ResultQuality {
    fn default() -> Self {
        Self::legacy()
    }
}

impl ResultQuality {
    pub fn legacy() -> Self {
        Self {
            band: QualityBand::Low,
            reasons: vec!["legacy string tool result; structured measurements unavailable".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePolarity {
    Supports,
    Contradicts,
    Neutral,
}

impl Default for EvidencePolarity {
    fn default() -> Self {
        Self::Neutral
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolResultEnvelope {
    pub status: ResultStatus,
    pub source_family: SourceFamily,
    #[serde(default)]
    pub source_tables: Vec<String>,
    /// `None` is retained only for legacy tools that do not yet accept the PR1
    /// window contract. New causal tools must use `from_causal_result` with a
    /// concrete window.
    pub window: Option<InvestigationWindow>,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub incident_value: Option<serde_json::Value>,
    #[serde(default)]
    pub baseline_value: Option<serde_json::Value>,
    #[serde(default)]
    pub absolute_delta: Option<serde_json::Value>,
    #[serde(default)]
    pub relative_delta: Option<serde_json::Value>,
    #[serde(default)]
    pub sample_count: u64,
    pub quality: ResultQuality,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub query_fingerprint: String,
    pub summary: String,
}

impl ToolResultEnvelope {
    pub fn from_causal_result(
        status: ResultStatus,
        source_family: SourceFamily,
        source_tables: Vec<String>,
        window: InvestigationWindow,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            status,
            source_family,
            source_tables,
            window: Some(window),
            service: String::new(),
            operation: String::new(),
            incident_value: None,
            baseline_value: None,
            absolute_delta: None,
            relative_delta: None,
            sample_count: 0,
            quality: ResultQuality {
                band: QualityBand::High,
                reasons: Vec::new(),
            },
            references: Vec::new(),
            query_fingerprint: String::new(),
            summary: sanitize_summary(&summary.into()),
        }
    }

    /// Wrap an existing string tool result without pretending it has an exact
    /// window. This is the compatibility bridge until each tool is migrated.
    pub fn from_legacy(
        tool_name: &str,
        args: &serde_json::Value,
        result: &str,
        summary: Option<&str>,
    ) -> Self {
        // New causal tools serialize the envelope at the top level and add a
        // bounded `data` field. Accept that shape here so the streaming layer
        // exposes the exact structured provenance rather than reconstructing
        // it as a legacy string result.
        if result.trim_start().starts_with('{') {
            if let Ok(mut structured) = serde_json::from_str::<Self>(result) {
                if structured.window.is_none() {
                    structured.window = try_window_from_args(args);
                }
                if structured.service.is_empty() {
                    structured.service = service_from_args(args);
                }
                if structured.query_fingerprint.is_empty() {
                    structured.query_fingerprint = fingerprint_args(args);
                }
                return structured;
            }
        }
        let lower = result.trim_start().to_ascii_lowercase();
        let status = if lower.starts_with("access denied") {
            ResultStatus::AccessDenied
        } else if lower.starts_with("tool error:") || lower.starts_with("error:") {
            ResultStatus::Error
        } else if looks_like_no_data(&lower) {
            ResultStatus::NoData
        } else {
            ResultStatus::Ok
        };
        let source_family = source_family_for_tool(tool_name);
        let source_tables = source_tables_for_tool(tool_name);
        let summary = sanitize_summary(summary.unwrap_or(result));
        Self {
            status,
            source_family,
            source_tables,
            window: try_window_from_args(args),
            service: service_from_args(args),
            operation: args
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            incident_value: None,
            baseline_value: None,
            absolute_delta: None,
            relative_delta: None,
            sample_count: 0,
            quality: ResultQuality::legacy(),
            references: Vec::new(),
            query_fingerprint: fingerprint_args(args),
            summary,
        }
    }

    /// Parse an exact incident/baseline contract supplied by a causal tool.
    /// Causal tools intentionally fail when these bounds are absent instead
    /// of falling back to the current wall clock.
    pub fn require_window_from_args(
        args: &serde_json::Value,
    ) -> Result<InvestigationWindow, String> {
        try_window_from_args(args).ok_or_else(|| {
            "exact incident_start, incident_end, baseline_start, and baseline_end UTC RFC3339 bounds are required".to_string()
        })
    }

    pub fn is_positive_evidence(&self) -> bool {
        self.status.contributes_positive_evidence() && !self.summary.is_empty()
    }

    /// Two envelopes are independent only when neither their source families
    /// nor their physical source tables overlap. A metrics view over `spans`
    /// therefore cannot masquerade as independent from a trace query over
    /// `spans`.
    pub fn is_independent_from(&self, other: &Self) -> bool {
        self.source_family != other.source_family
            && self
                .source_tables
                .iter()
                .collect::<BTreeSet<_>>()
                .is_disjoint(&other.source_tables.iter().collect())
    }
}

fn utc_datetime(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    value
        .as_str()
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn try_window_from_args(args: &serde_json::Value) -> Option<InvestigationWindow> {
    let incident_start = utc_datetime(args.get("incident_start")?)?;
    let incident_end = utc_datetime(args.get("incident_end")?)?;
    let baseline_start = utc_datetime(args.get("baseline_start")?)?;
    let baseline_end = utc_datetime(args.get("baseline_end")?)?;
    let reason = match args
        .get("selection_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("fallback")
    {
        "alert_window" => WindowSelectionReason::AlertWindow,
        "user_provided_range" => WindowSelectionReason::UserProvidedRange,
        "inferred_onset" => WindowSelectionReason::InferredOnset,
        _ => WindowSelectionReason::Fallback,
    };
    InvestigationWindow::new(
        incident_start,
        incident_end,
        baseline_start,
        baseline_end,
        reason,
    )
    .ok()
}

fn service_from_args(args: &serde_json::Value) -> String {
    args.get("service")
        .or_else(|| args.get("service_name"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Parse an exact incident/baseline contract for causal tool arguments.
pub fn require_window_from_args(args: &serde_json::Value) -> Result<InvestigationWindow, String> {
    try_window_from_args(args).ok_or_else(|| {
        "exact incident_start, incident_end, baseline_start, and baseline_end UTC RFC3339 bounds are required".to_string()
    })
}

fn source_family_for_tool(tool_name: &str) -> SourceFamily {
    match tool_name {
        "search_logs" => SourceFamily::Logs,
        "get_argocd_app"
        | "get_flux_resource"
        | "kube_describe"
        | "kube_events"
        | "search_kubernetes_access" => SourceFamily::Kubernetes,
        "list_deploys" | "get_anomaly_context" => SourceFamily::Deploys,
        "list_repo_files" | "search_repo" | "read_repo_file" => SourceFamily::Repository,
        "inspect_postgresql" | "inspect_mysql" => SourceFamily::Database,
        // Service RED metrics are currently calculated from spans in the
        // built-in implementation, so they intentionally remain traces.
        _ => SourceFamily::Traces,
    }
}

/// Serialize a machine-readable causal result while preserving the common
/// envelope at the top level. `data` is deliberately caller-defined but must
/// remain bounded by the tool implementation.
pub fn serialize_tool_output(
    envelope: &ToolResultEnvelope,
    data: serde_json::Value,
) -> Result<String, serde_json::Error> {
    let mut object = match serde_json::to_value(envelope)? {
        serde_json::Value::Object(object) => object,
        _ => unreachable!("tool result envelope serializes as an object"),
    };
    object.insert("data".to_string(), data);
    serde_json::to_string(&serde_json::Value::Object(object))
}

fn source_tables_for_tool(tool_name: &str) -> Vec<String> {
    if tool_name == "search_kubernetes_access" {
        return vec!["config_kubernetes_access_events".into()];
    }
    match source_family_for_tool(tool_name) {
        SourceFamily::Logs => vec!["logs".into()],
        SourceFamily::Traces => vec!["spans".into()],
        SourceFamily::Kubernetes => vec!["kubernetes_api".into()],
        SourceFamily::Deploys => vec!["config_deploys".into()],
        SourceFamily::Repository => vec!["repository_api".into()],
        SourceFamily::OTelMetrics => vec!["otel_metrics".into()],
        SourceFamily::Database => vec![
            "spans".into(),
            "logs".into(),
            "metrics_gauge".into(),
            "metrics_sum".into(),
        ],
    }
}

fn looks_like_no_data(lower: &str) -> bool {
    [
        "no matching",
        "no data",
        "not found",
        "no spans found",
        "no logs found",
        "no service traffic",
        "no cross-service calls",
        "no deploys",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn sanitize_summary(value: &str) -> String {
    let lines: Vec<String> = value
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line
                    .chars()
                    .all(|c| matches!(c, '-' | '=' | '_' | ' ' | '|'))
                && !matches!(*line, "Header" | "Results" | "Details" | "Summary")
        })
        .take(3)
        .map(|line| truncate_summary(&redact_sensitive_text(line), 360))
        .collect();
    lines.join(" ")
}

fn redact_sensitive_text(value: &str) -> String {
    value
        .split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            let sensitive_key = [
                "authorization:",
                "token=",
                "password=",
                "secret=",
                "api_key=",
                "apikey=",
                "x-api-key:",
            ]
            .iter()
            .find(|key| lower.starts_with(**key));
            if let Some(key) = sensitive_key {
                format!("{}<redacted>", &token[..key.len()])
            } else if token.contains("://") && token.contains('@') {
                "<redacted-uri>".to_string()
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_summary(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value.chars().take(max).collect::<String>() + "…"
}

fn fingerprint_args(args: &serde_json::Value) -> String {
    fn redact(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => serde_json::Value::Object(
                map.iter()
                    .map(|(key, value)| {
                        let lower = key.to_ascii_lowercase();
                        let sensitive = [
                            "token",
                            "password",
                            "secret",
                            "api_key",
                            "apikey",
                            "authorization",
                            "credential",
                            "conn",
                            "dsn",
                            "header",
                            "url",
                        ]
                        .iter()
                        .any(|marker| lower.contains(marker));
                        (
                            key.clone(),
                            if sensitive {
                                serde_json::Value::String("<redacted>".into())
                            } else {
                                redact(value)
                            },
                        )
                    })
                    .collect(),
            ),
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.iter().map(redact).collect())
            }
            other => other.clone(),
        }
    }
    let canonical = serde_json::to_vec(&redact(args)).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    // Format the digest byte-wise rather than with `{:x}`. sha2 0.11 returns
    // hybrid-array `Array`, which does not implement LowerHex the way 0.10's
    // GenericArray did. This idiom (already used in repository.rs) produces
    // byte-identical output and compiles against both versions.
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn ts(hour: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, hour as u32, 0, 0)
            .single()
            .unwrap()
    }

    #[test]
    fn centered_window_is_utc_and_has_equal_adjacent_baseline() {
        let window = InvestigationWindow::centered_on(
            ts(12),
            Duration::hours(2),
            ts(13),
            WindowSelectionReason::InferredOnset,
        )
        .unwrap();
        assert_eq!(window.incident_start, ts(11));
        assert_eq!(window.incident_end, ts(13));
        assert_eq!(window.baseline_start, ts(9));
        assert_eq!(window.baseline_end, ts(11));
        assert_eq!(window.incident_duration(), window.baseline_duration());
        assert_eq!(window.timezone, "UTC");
    }

    #[test]
    fn recent_window_is_deterministic_without_wall_clock() {
        let now = ts(12);
        let first =
            InvestigationWindow::recent(now, Duration::hours(1), WindowSelectionReason::Fallback)
                .unwrap();
        let second =
            InvestigationWindow::recent(now, Duration::hours(1), WindowSelectionReason::Fallback)
                .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn empty_and_unequal_windows_are_rejected() {
        assert_eq!(
            InvestigationWindow::new(
                ts(10),
                ts(10),
                ts(8),
                ts(10),
                WindowSelectionReason::Fallback
            ),
            Err(WindowError::EmptyIncident)
        );
        assert_eq!(
            InvestigationWindow::new(
                ts(10),
                ts(12),
                ts(8),
                ts(9),
                WindowSelectionReason::Fallback
            ),
            Err(WindowError::UnequalDurations)
        );
    }

    #[test]
    fn future_anomaly_is_rejected_against_explicit_as_of() {
        assert!(matches!(
            InvestigationWindow::centered_on(
                ts(14),
                Duration::hours(1),
                ts(13),
                WindowSelectionReason::AlertWindow
            ),
            Err(WindowError::FutureTimestamp { .. })
        ));
    }

    #[test]
    fn no_data_never_contributes_positive_evidence() {
        let envelope = ToolResultEnvelope::from_legacy(
            "query_traces",
            &json!({"service": "api"}),
            "No spans found.",
            None,
        );
        assert_eq!(envelope.status, ResultStatus::NoData);
        assert!(!envelope.is_positive_evidence());
    }

    #[test]
    fn legacy_envelope_repeats_an_explicit_effective_window() {
        let args = json!({
            "incident_start": "2026-08-01T10:00:00-07:00",
            "incident_end": "2026-08-01T11:00:00-07:00",
            "baseline_start": "2026-08-01T09:00:00-07:00",
            "baseline_end": "2026-08-01T10:00:00-07:00",
            "selection_reason": "user_provided_range"
        });
        let envelope = ToolResultEnvelope::from_legacy("query_traces", &args, "Found 1 span", None);
        let window = envelope.window.unwrap();
        assert_eq!(window.timezone, "UTC");
        assert_eq!(window.incident_start, ts(17));
        assert_eq!(window.incident_end, ts(18));
        assert_eq!(
            window.selection_reason,
            WindowSelectionReason::UserProvidedRange
        );
    }

    #[test]
    fn provenance_rejects_same_table_as_independent_signal() {
        let trace =
            ToolResultEnvelope::from_legacy("query_traces", &json!({}), "Found 1 span", None);
        let service_red =
            ToolResultEnvelope::from_legacy("query_metrics", &json!({}), "Latest=2", None);
        assert_eq!(trace.source_family, SourceFamily::Traces);
        assert_eq!(service_red.source_family, SourceFamily::Traces);
        assert!(!trace.is_independent_from(&service_red));
    }

    #[test]
    fn fingerprint_args_encoding_is_stable() {
        // Independently computed: printf '{"service":"api"}' | shasum -a 256
        assert_eq!(
            fingerprint_args(&json!({"service": "api"})),
            "sha256:e464c14d19356fee859c8dea5549a0453bdbf38530f3754c8bf6fcfc3b403679"
        );
    }

    #[test]
    fn fingerprints_redact_secret_values() {
        let a = fingerprint_args(&json!({"service": "api", "token": "one"}));
        let b = fingerprint_args(&json!({"service": "api", "token": "two"}));
        assert_eq!(a, b);
        assert!(!a.contains("one"));
        assert!(!a.contains("two"));
    }

    #[test]
    fn different_physical_sources_can_be_independent() {
        let trace =
            ToolResultEnvelope::from_legacy("query_traces", &json!({}), "Found 1 span", None);
        let logs = ToolResultEnvelope::from_legacy("search_logs", &json!({}), "Found 1 log", None);
        assert!(trace.is_independent_from(&logs));
    }

    #[test]
    fn kubernetes_access_uses_its_recorded_event_provenance() {
        let access = ToolResultEnvelope::from_legacy(
            "search_kubernetes_access",
            &json!({}),
            "Found 1 recorded action",
            None,
        );
        assert_eq!(access.source_family, SourceFamily::Kubernetes);
        assert_eq!(
            access.source_tables,
            vec!["config_kubernetes_access_events"]
        );
    }

    #[test]
    fn summary_drops_headers_and_separators() {
        let envelope = ToolResultEnvelope::from_causal_result(
            ResultStatus::Ok,
            SourceFamily::Logs,
            vec!["logs".into()],
            InvestigationWindow::recent(
                ts(12),
                Duration::hours(1),
                WindowSelectionReason::Fallback,
            )
            .unwrap(),
            "Results\n------\nFound 2 errors",
        );
        assert_eq!(envelope.summary, "Found 2 errors");
    }

    #[test]
    fn evidence_summary_redacts_credentials_and_connection_strings() {
        let envelope = ToolResultEnvelope::from_causal_result(
            ResultStatus::Ok,
            SourceFamily::Logs,
            vec!["logs".into()],
            InvestigationWindow::recent(
                ts(12),
                Duration::hours(1),
                WindowSelectionReason::Fallback,
            )
            .unwrap(),
            "password=secret authorization:Bearer-abc postgres://user:pw@db/app",
        );
        assert!(!envelope.summary.contains("secret"));
        assert!(!envelope.summary.contains("Bearer-abc"));
        assert!(!envelope.summary.contains("postgres://"));
        assert!(envelope.summary.contains("<redacted>"));
    }

    #[test]
    fn structured_tool_output_round_trips_with_provenance() {
        let window = InvestigationWindow::recent(
            ts(12),
            Duration::hours(1),
            WindowSelectionReason::Fallback,
        )
        .unwrap();
        let envelope = ToolResultEnvelope::from_causal_result(
            ResultStatus::Ok,
            SourceFamily::Traces,
            vec!["spans".into()],
            window.clone(),
            "server p99 increased",
        );
        let output = serialize_tool_output(&envelope, json!({"p99_delta_ms": 240.0})).unwrap();
        let parsed =
            ToolResultEnvelope::from_legacy("compare_service_windows", &json!({}), &output, None);
        assert_eq!(parsed.status, ResultStatus::Ok);
        assert_eq!(parsed.window, Some(window));
        assert_eq!(parsed.source_tables, vec!["spans"]);
        assert!(parsed.is_positive_evidence());
    }
}
