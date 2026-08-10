//! PR 2 comparative service and dependency analysis.
//!
//! The query shapes intentionally mirror query-api's service definitions:
//! service RED uses `SPAN_KIND_SERVER`, endpoint mode groups server spans by
//! HTTP method/path, and dependency latency uses the downstream server span.
//! Aggregates are computed in ClickHouse before the bounded result is returned.

use crate::agent::contracts::{
    InvestigationWindow, QualityBand, ResultQuality, ResultStatus, ToolResultEnvelope,
    require_window_from_args, serialize_tool_output,
};
use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};

const SERVER_SPAN_KIND: &str = "SPAN_KIND_SERVER";
const MAX_SERVICES: usize = 20;
const MAX_ENDPOINTS: usize = 50;
const MAX_DEPENDENCIES: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedStats {
    request_count: u64,
    request_rate_per_second: f64,
    error_count: u64,
    error_rate_pct: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceComparison {
    service: String,
    incident: Option<RedStats>,
    baseline: Option<RedStats>,
    request_rate_delta: Option<f64>,
    error_rate_delta_pct: Option<f64>,
    p95_delta_ms: Option<f64>,
    p99_delta_ms: Option<f64>,
    impact_score: f64,
    missing_instrumentation: bool,
}

#[derive(Debug, Clone, Serialize)]
struct EndpointComparison {
    service: String,
    endpoint: String,
    incident: Option<RedStats>,
    baseline: Option<RedStats>,
    error_rate_delta_pct: Option<f64>,
    p95_delta_ms: Option<f64>,
    p99_delta_ms: Option<f64>,
    impact_score: f64,
    missing_instrumentation: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ClientWaitComparison {
    service: String,
    incident: Option<WaitStats>,
    baseline: Option<WaitStats>,
    p95_delta_ms: Option<f64>,
    p99_delta_ms: Option<f64>,
    missing_instrumentation: bool,
}

#[derive(Debug, Clone, Serialize)]
struct WaitStats {
    request_count: u64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Serialize)]
struct ComparePayload {
    services: Vec<ServiceComparison>,
    endpoints: Vec<EndpointComparison>,
    client_wait: Vec<ClientWaitComparison>,
    warnings: Vec<String>,
}

#[derive(Debug, Row, Deserialize)]
struct ServicePeriodRow {
    service_name: String,
    period: String,
    request_count: u64,
    request_rate_per_second: f64,
    error_count: u64,
    error_rate_pct: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Row, Deserialize)]
struct EndpointPeriodRow {
    service_name: String,
    endpoint: String,
    period: String,
    request_count: u64,
    request_rate_per_second: f64,
    error_count: u64,
    error_rate_pct: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Row, Deserialize)]
struct ClientWaitPeriodRow {
    service_name: String,
    period: String,
    request_count: u64,
    p95_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Row, Deserialize)]
struct DependencyPeriodRow {
    caller: String,
    callee: String,
    operation: String,
    period: String,
    request_count: u64,
    request_rate_per_second: f64,
    error_count: u64,
    error_rate_pct: f64,
    child_p95_ms: f64,
    child_p99_ms: f64,
    caller_time_attributable_pct: f64,
}

fn sql_timestamp(value: chrono::DateTime<chrono::Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S.%f").to_string()
}

fn sql_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn service_list(args: &Value) -> Vec<String> {
    let mut services = Vec::new();
    if let Some(values) = args.get("services").and_then(Value::as_array) {
        services.extend(
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        );
    }
    if let Some(service) = args.get("service").and_then(Value::as_str)
        && !service.is_empty()
    {
        services.push(service.to_string());
    }
    services.sort();
    services.dedup();
    services.truncate(MAX_SERVICES);
    services
}

fn service_filter(services: &[String]) -> String {
    services
        .iter()
        .map(|service| format!("'{}'", sql_quote(service)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn period_predicate(window: &InvestigationWindow, period: &str, column: &str) -> String {
    let (start, end) = if period == "incident" {
        (window.incident_start, window.incident_end)
    } else {
        (window.baseline_start, window.baseline_end)
    };
    format!(
        "{column} >= toDateTime64('{}', 9, 'UTC') AND {column} < toDateTime64('{}', 9, 'UTC')",
        sql_timestamp(start),
        sql_timestamp(end)
    )
}

fn duration_seconds(window: &InvestigationWindow) -> f64 {
    (window.incident_duration().num_milliseconds() as f64 / 1_000.0).max(0.001)
}

fn red_select(
    period: &str,
    window: &InvestigationWindow,
    group_by: &str,
    select_group: &str,
) -> String {
    let predicate = period_predicate(window, period, "timestamp");
    let seconds = duration_seconds(window);
    format!(
        "SELECT {select_group}, '{period}' AS period, \
                count() AS request_count, \
                count() / {seconds} AS request_rate_per_second, \
                countIf(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500) AS error_count, \
                if(count() = 0, 0.0, 100.0 * countIf(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500) / count()) AS error_rate_pct, \
                quantile(0.50)(duration_ns) / 1000000.0 AS p50_ms, \
                quantile(0.95)(duration_ns) / 1000000.0 AS p95_ms, \
                quantile(0.99)(duration_ns) / 1000000.0 AS p99_ms \
         FROM spans \
         PREWHERE tenant_id = '{{tenant}}' \
             AND kind = '{SERVER_SPAN_KIND}' \
             AND {{service_filter}} \
             AND {predicate} \
         GROUP BY {group_by}"
    )
}

/// Exact-window service aggregate query. Quantiles are calculated before any
/// result limiting and both incident/baseline predicates are half-open.
pub(crate) fn build_compare_service_sql(
    services: &[String],
    window: &InvestigationWindow,
    tenant_id: &str,
) -> String {
    let filter = service_filter(services);
    let template = red_select("incident", window, "service_name", "service_name");
    let incident = template
        .replace("{tenant}", &sql_quote(tenant_id))
        .replace("{service_filter}", &format!("service_name IN ({filter})"));
    let template = red_select("baseline", window, "service_name", "service_name");
    let baseline = template
        .replace("{tenant}", &sql_quote(tenant_id))
        .replace("{service_filter}", &format!("service_name IN ({filter})"));
    format!("{incident} UNION ALL {baseline}")
}

pub(crate) fn build_compare_endpoint_sql(
    services: &[String],
    window: &InvestigationWindow,
    tenant_id: &str,
) -> String {
    let filter = service_filter(services);
    let group = "service_name, concat(http_method, ' ', http_path)";
    let select_group = "service_name, concat(http_method, ' ', http_path) AS endpoint";
    let incident = red_select("incident", window, group, select_group)
        .replace("{tenant}", &sql_quote(tenant_id))
        .replace("{service_filter}", &format!("service_name IN ({filter})"));
    let baseline = red_select("baseline", window, group, select_group)
        .replace("{tenant}", &sql_quote(tenant_id))
        .replace("{service_filter}", &format!("service_name IN ({filter})"));
    format!(
        "SELECT service_name, endpoint, period, request_count, request_rate_per_second, \
                error_count, error_rate_pct, p50_ms, p95_ms, p99_ms \
         FROM (({incident}) UNION ALL ({baseline})) \
         ORDER BY request_count DESC LIMIT 2000"
    )
}

/// Compare non-server client/producer/consumer spans separately from the
/// service's own server-span RED. This is the dependency-wait view used to
/// distinguish caller self-time from downstream waiting.
pub(crate) fn build_compare_client_wait_sql(
    services: &[String],
    window: &InvestigationWindow,
    tenant_id: &str,
) -> String {
    let filter = service_filter(services);
    let make_period = |period: &str| {
        let predicate = period_predicate(window, period, "timestamp");
        format!(
            "SELECT service_name, '{period}' AS period, count() AS request_count, \
                    quantile(0.95)(duration_ns) / 1000000.0 AS p95_ms, \
                    quantile(0.99)(duration_ns) / 1000000.0 AS p99_ms \
             FROM spans \
             PREWHERE tenant_id = '{tenant}' \
                 AND kind IN ('SPAN_KIND_CLIENT', 'SPAN_KIND_PRODUCER', 'SPAN_KIND_CONSUMER') \
                 AND service_name IN ({filter}) \
                 AND {predicate} \
             GROUP BY service_name",
            tenant = sql_quote(tenant_id),
        )
    };
    format!(
        "{} UNION ALL {}",
        make_period("incident"),
        make_period("baseline")
    )
}

fn as_red_stats(
    request_count: u64,
    request_rate_per_second: f64,
    error_count: u64,
    error_rate_pct: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
) -> RedStats {
    RedStats {
        request_count,
        request_rate_per_second,
        error_count,
        error_rate_pct,
        p50_ms,
        p95_ms,
        p99_ms,
    }
}

fn red_map(
    rows: impl IntoIterator<Item = ServicePeriodRow>,
) -> HashMap<String, (Option<RedStats>, Option<RedStats>)> {
    let mut map = HashMap::new();
    for row in rows {
        let stats = as_red_stats(
            row.request_count,
            row.request_rate_per_second,
            row.error_count,
            row.error_rate_pct,
            row.p50_ms,
            row.p95_ms,
            row.p99_ms,
        );
        let entry = map.entry(row.service_name).or_insert((None, None));
        if row.period == "incident" {
            entry.0 = Some(stats);
        } else {
            entry.1 = Some(stats);
        }
    }
    map
}

fn endpoint_map(
    rows: impl IntoIterator<Item = EndpointPeriodRow>,
) -> HashMap<(String, String), (Option<RedStats>, Option<RedStats>)> {
    let mut map = HashMap::new();
    for row in rows {
        let stats = as_red_stats(
            row.request_count,
            row.request_rate_per_second,
            row.error_count,
            row.error_rate_pct,
            row.p50_ms,
            row.p95_ms,
            row.p99_ms,
        );
        let entry = map
            .entry((row.service_name, row.endpoint))
            .or_insert((None, None));
        if row.period == "incident" {
            entry.0 = Some(stats);
        } else {
            entry.1 = Some(stats);
        }
    }
    map
}

fn client_wait_map(
    rows: impl IntoIterator<Item = ClientWaitPeriodRow>,
) -> HashMap<String, (Option<WaitStats>, Option<WaitStats>)> {
    let mut map = HashMap::new();
    for row in rows {
        let stats = WaitStats {
            request_count: row.request_count,
            p95_ms: row.p95_ms,
            p99_ms: row.p99_ms,
        };
        let entry = map.entry(row.service_name).or_insert((None, None));
        if row.period == "incident" {
            entry.0 = Some(stats);
        } else {
            entry.1 = Some(stats);
        }
    }
    map
}

fn delta_pair(
    incident: &Option<RedStats>,
    baseline: &Option<RedStats>,
    field: fn(&RedStats) -> f64,
) -> Option<f64> {
    Some(field(incident.as_ref()?) - field(baseline.as_ref()?))
}

fn impact_score(incident: &Option<RedStats>, baseline: &Option<RedStats>) -> f64 {
    let Some(incident) = incident else { return 0.0 };
    let Some(baseline) = baseline else { return 0.0 };
    let p99_delta = (incident.p99_ms - baseline.p99_ms).max(0.0);
    let error_delta = (incident.error_rate_pct - baseline.error_rate_pct).max(0.0);
    (p99_delta * ((incident.request_count + 1) as f64).ln()) + error_delta * 10.0
}

struct CompareEnvelopeParams<'a> {
    tool_name: &'a str,
    args: &'a Value,
    window: InvestigationWindow,
    status: ResultStatus,
    summary: String,
    sample_count: u64,
    incident_value: Value,
    baseline_value: Value,
    delta: Value,
    warnings: Vec<String>,
    service: String,
    operation: String,
    data: Value,
}

fn compare_envelope(params: CompareEnvelopeParams<'_>) -> Result<String, serde_json::Error> {
    let mut envelope = ToolResultEnvelope::from_legacy(
        params.tool_name,
        params.args,
        &params.summary,
        Some(&params.summary),
    );
    envelope.status = params.status.clone();
    envelope.window = Some(params.window);
    envelope.service = params.service;
    envelope.operation = params.operation;
    envelope.sample_count = params.sample_count;
    envelope.incident_value = Some(params.incident_value);
    envelope.baseline_value = Some(params.baseline_value);
    envelope.absolute_delta = Some(params.delta);
    envelope.quality = ResultQuality {
        band: match params.status {
            ResultStatus::Ok => QualityBand::High,
            ResultStatus::Partial => QualityBand::Medium,
            _ => QualityBand::Low,
        },
        reasons: params.warnings,
    };
    serialize_tool_output(&envelope, params.data)
}

fn access_denied_output(tool_name: &str, args: &Value) -> Result<String, serde_json::Error> {
    let mut envelope = ToolResultEnvelope::from_legacy(
        tool_name,
        args,
        "Access denied: trace scope is required",
        Some("trace scope is required"),
    );
    envelope.status = ResultStatus::AccessDenied;
    envelope.quality = ResultQuality {
        band: QualityBand::Low,
        reasons: vec!["caller lacks the traces scope".into()],
    };
    serialize_tool_output(&envelope, json!({}))
}

pub struct CompareServiceWindows;

#[async_trait::async_trait]
impl Tool for CompareServiceWindows {
    fn name(&self) -> &str {
        "compare_service_windows"
    }

    fn description(&self) -> &str {
        "Compare server-span RED behavior for one or more services between an exact incident window and equal-duration baseline. Includes endpoint changes and missing-instrumentation warnings. Always provide all four UTC window bounds."
    }

    fn parameters(&self) -> Value {
        json!({
            "type":"object",
            "required":["incident_start","incident_end","baseline_start","baseline_end"],
            "properties": {
                "services":{"type":"array","items":{"type":"string"},"maxItems":20},
                "service":{"type":"string","description":"Single service (alternative to services)"},
                "incident_start":{"type":"string","description":"Inclusive UTC RFC3339 bound"},
                "incident_end":{"type":"string","description":"Exclusive UTC RFC3339 bound"},
                "baseline_start":{"type":"string","description":"Inclusive UTC RFC3339 bound"},
                "baseline_end":{"type":"string","description":"Exclusive UTC RFC3339 bound"},
                "selection_reason":{"type":"string","enum":["alert_window","user_provided_range","inferred_onset","fallback"]}
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") {
            return Ok(access_denied_output(self.name(), &args)?);
        }
        let services = service_list(&args);
        if services.is_empty() {
            return Ok("Tool error: at least one service is required".into());
        }
        let window = match require_window_from_args(&args) {
            Ok(window) => window,
            Err(message) => return Ok(format!("Tool error: {message}")),
        };
        let service_sql = build_compare_service_sql(&services, &window, &ctx.tenant_id);
        let endpoint_sql = build_compare_endpoint_sql(&services, &window, &ctx.tenant_id);
        let client_wait_sql = build_compare_client_wait_sql(&services, &window, &ctx.tenant_id);
        let (service_result, endpoint_result, client_wait_result) = tokio::join!(
            crate::state::tenant_query(&ctx.state.ch, &service_sql, &ctx.tenant_id)
                .fetch_all::<ServicePeriodRow>(),
            crate::state::tenant_query(&ctx.state.ch, &endpoint_sql, &ctx.tenant_id)
                .fetch_all::<EndpointPeriodRow>(),
            crate::state::tenant_query(&ctx.state.ch, &client_wait_sql, &ctx.tenant_id)
                .fetch_all::<ClientWaitPeriodRow>()
        );
        let service_rows = service_result?;
        let endpoint_rows = endpoint_result?;
        let client_wait_rows = client_wait_result?;
        let service_data = red_map(service_rows);
        let endpoint_data = endpoint_map(endpoint_rows);
        let client_wait_data = client_wait_map(client_wait_rows);

        if service_data.is_empty() {
            return compare_envelope(CompareEnvelopeParams {
                tool_name: self.name(),
                args: &args,
                window,
                status: ResultStatus::NoData,
                summary: "No server-span data was found in either window.".into(),
                sample_count: 0,
                incident_value: json!([]),
                baseline_value: json!([]),
                delta: json!([]),
                warnings: vec!["no server spans in the requested windows".into()],
                service: services.join(", "),
                operation: "server_red".into(),
                data: json!(ComparePayload {
                    services: vec![],
                    endpoints: vec![],
                    client_wait: vec![],
                    warnings: vec!["no server spans in the requested windows".into()]
                }),
            })
            .map_err(Into::into);
        }

        let mut comparisons = Vec::new();
        let mut warnings = Vec::new();
        for (service, (incident, baseline)) in service_data {
            let missing = incident.is_none() || baseline.is_none();
            if missing {
                warnings.push(format!(
                    "{service}: missing incident or baseline server-span data"
                ));
            }
            comparisons.push(ServiceComparison {
                service,
                request_rate_delta: delta_pair(&incident, &baseline, |s| s.request_rate_per_second),
                error_rate_delta_pct: delta_pair(&incident, &baseline, |s| s.error_rate_pct),
                p95_delta_ms: delta_pair(&incident, &baseline, |s| s.p95_ms),
                p99_delta_ms: delta_pair(&incident, &baseline, |s| s.p99_ms),
                impact_score: impact_score(&incident, &baseline),
                incident,
                baseline,
                missing_instrumentation: missing,
            });
        }
        comparisons.sort_by(|a, b| b.impact_score.total_cmp(&a.impact_score));

        let mut endpoints = Vec::new();
        for ((service, endpoint), (incident, baseline)) in endpoint_data {
            endpoints.push(EndpointComparison {
                service,
                endpoint,
                error_rate_delta_pct: delta_pair(&incident, &baseline, |s| s.error_rate_pct),
                p95_delta_ms: delta_pair(&incident, &baseline, |s| s.p95_ms),
                p99_delta_ms: delta_pair(&incident, &baseline, |s| s.p99_ms),
                impact_score: impact_score(&incident, &baseline),
                missing_instrumentation: incident.is_none() || baseline.is_none(),
                incident,
                baseline,
            });
        }
        endpoints.sort_by(|a, b| b.impact_score.total_cmp(&a.impact_score));
        endpoints.truncate(MAX_ENDPOINTS);
        let mut client_wait = Vec::new();
        for (service, (incident, baseline)) in client_wait_data {
            let p95_delta_ms = match (&incident, &baseline) {
                (Some(incident), Some(baseline)) => Some(incident.p95_ms - baseline.p95_ms),
                _ => None,
            };
            let p99_delta_ms = match (&incident, &baseline) {
                (Some(incident), Some(baseline)) => Some(incident.p99_ms - baseline.p99_ms),
                _ => None,
            };
            client_wait.push(ClientWaitComparison {
                service,
                incident,
                baseline,
                p95_delta_ms,
                p99_delta_ms,
                missing_instrumentation: p95_delta_ms.is_none(),
            });
        }
        client_wait.sort_by(|a, b| {
            b.p95_delta_ms
                .unwrap_or(0.0)
                .total_cmp(&a.p95_delta_ms.unwrap_or(0.0))
        });
        let sample_count = comparisons
            .iter()
            .filter_map(|row| row.incident.as_ref())
            .map(|stats| stats.request_count)
            .sum();
        let status = if warnings.is_empty() {
            ResultStatus::Ok
        } else {
            ResultStatus::Partial
        };
        let summary = format!(
            "Compared {} services and {} changed endpoint views; top impact is {}.",
            comparisons.len(),
            endpoints.len(),
            comparisons
                .first()
                .map(|row| row.service.as_str())
                .unwrap_or("none")
        );
        let payload = ComparePayload {
            services: comparisons,
            endpoints,
            client_wait,
            warnings: warnings.clone(),
        };
        let data = serde_json::to_value(&payload)?;
        compare_envelope(CompareEnvelopeParams {
            tool_name: self.name(),
            args: &args,
            window,
            status,
            summary,
            sample_count,
            incident_value: data.clone(),
            baseline_value: data.clone(),
            delta: data,
            warnings,
            service: services.join(", "),
            operation: "server_red_and_endpoints".into(),
            data: serde_json::to_value(payload)?,
        })
        .map_err(Into::into)
    }
}

#[derive(Debug, Clone, Serialize)]
struct DependencyComparison {
    caller: String,
    callee: String,
    operation: String,
    incident: Option<DependencyStats>,
    baseline: Option<DependencyStats>,
    request_rate_delta: Option<f64>,
    error_rate_delta_pct: Option<f64>,
    child_p95_delta_ms: Option<f64>,
    child_p99_delta_ms: Option<f64>,
    caller_time_attributable_delta_pct: Option<f64>,
    impact_score: f64,
    missing_response_or_telemetry: bool,
    onset_alignment: String,
}

#[derive(Debug, Clone, Serialize)]
struct DependencyStats {
    request_count: u64,
    request_rate_per_second: f64,
    error_count: u64,
    error_rate_pct: f64,
    child_p95_ms: f64,
    child_p99_ms: f64,
    caller_time_attributable_pct: f64,
}

type DependencyKey = (String, String, String);
type DependencyPeriodPair = (Option<DependencyStats>, Option<DependencyStats>);
type DependencyMap = BTreeMap<DependencyKey, DependencyPeriodPair>;

#[derive(Debug, Serialize)]
struct DependencyPayload {
    dependencies: Vec<DependencyComparison>,
    warnings: Vec<String>,
}

fn build_dependency_period_sql(
    period: &str,
    window: &InvestigationWindow,
    tenant_id: &str,
) -> String {
    let predicate = period_predicate(window, period, "child.timestamp");
    let parent_predicate = period_predicate(window, period, "parent.timestamp");
    let seconds = duration_seconds(window);
    format!(
        "SELECT parent.service_name AS caller, child.service_name AS callee, child.span_name AS operation, \
                '{period}' AS period, count() AS request_count, count() / {seconds} AS request_rate_per_second, \
                countIf(child.status IN ('STATUS_CODE_ERROR', 'ERROR') OR child.http_status_code >= 500) AS error_count, \
                if(count() = 0, 0.0, 100.0 * countIf(child.status IN ('STATUS_CODE_ERROR', 'ERROR') OR child.http_status_code >= 500) / count()) AS error_rate_pct, \
                quantile(0.95)(child.duration_ns) / 1000000.0 AS child_p95_ms, \
                quantile(0.99)(child.duration_ns) / 1000000.0 AS child_p99_ms, \
                avg(toFloat64(child.duration_ns) / greatest(toFloat64(parent.duration_ns), 1.0)) * 100.0 AS caller_time_attributable_pct \
         FROM spans AS child \
         INNER JOIN spans AS parent ON child.trace_id = parent.trace_id \
             AND child.parent_span_id = parent.span_id \
         WHERE child.tenant_id = '{tenant}' \
             AND parent.tenant_id = '{tenant}' \
             AND child.kind = '{SERVER_SPAN_KIND}' \
             AND child.service_name != parent.service_name \
             AND {predicate} \
             AND {parent_predicate} \
         GROUP BY caller, callee, operation",
        tenant = sql_quote(tenant_id),
    )
}

pub(crate) fn build_rank_dependencies_sql(window: &InvestigationWindow, tenant_id: &str) -> String {
    let incident = build_dependency_period_sql("incident", window, tenant_id);
    let baseline = build_dependency_period_sql("baseline", window, tenant_id);
    format!("{incident} UNION ALL {baseline}")
}

fn dependency_map(rows: impl IntoIterator<Item = DependencyPeriodRow>) -> DependencyMap {
    let mut map = BTreeMap::new();
    for row in rows {
        let stats = DependencyStats {
            request_count: row.request_count,
            request_rate_per_second: row.request_rate_per_second,
            error_count: row.error_count,
            error_rate_pct: row.error_rate_pct,
            child_p95_ms: row.child_p95_ms,
            child_p99_ms: row.child_p99_ms,
            caller_time_attributable_pct: row.caller_time_attributable_pct,
        };
        let entry = map
            .entry((row.caller, row.callee, row.operation))
            .or_insert((None, None));
        if row.period == "incident" {
            entry.0 = Some(stats);
        } else {
            entry.1 = Some(stats);
        }
    }
    map
}

fn dependency_delta(
    incident: &Option<DependencyStats>,
    baseline: &Option<DependencyStats>,
    field: fn(&DependencyStats) -> f64,
) -> Option<f64> {
    Some(field(incident.as_ref()?) - field(baseline.as_ref()?))
}

fn dependency_impact_score(
    incident: &Option<DependencyStats>,
    baseline: &Option<DependencyStats>,
) -> f64 {
    let Some(incident) = incident else { return 0.0 };
    let Some(baseline) = baseline else { return 0.0 };
    let latency_delta = (incident.child_p95_ms - baseline.child_p95_ms).max(0.0);
    let error_delta = (incident.error_rate_pct - baseline.error_rate_pct).max(0.0);
    let volume = ((incident.request_count + 1) as f64).ln();
    latency_delta * volume + error_delta * 10.0
}

pub struct RankSlowDependencies;

#[async_trait::async_trait]
impl Tool for RankSlowDependencies {
    fn name(&self) -> &str {
        "rank_slow_dependencies"
    }

    fn description(&self) -> &str {
        "Rank cross-service dependency edges by incident-versus-baseline change. Uses downstream server spans, child p95/p99, error deltas, and caller time attributable to the child. Always provide exact UTC incident and baseline bounds."
    }

    fn parameters(&self) -> Value {
        json!({
            "type":"object",
            "required":["incident_start","incident_end","baseline_start","baseline_end"],
            "properties": {
                "incident_start":{"type":"string"},"incident_end":{"type":"string"},
                "baseline_start":{"type":"string"},"baseline_end":{"type":"string"},
                "selection_reason":{"type":"string","enum":["alert_window","user_provided_range","inferred_onset","fallback"]}
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") {
            return Ok(access_denied_output(self.name(), &args)?);
        }
        let window = match require_window_from_args(&args) {
            Ok(window) => window,
            Err(message) => return Ok(format!("Tool error: {message}")),
        };
        let sql = build_rank_dependencies_sql(&window, &ctx.tenant_id);
        let rows = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
            .fetch_all::<DependencyPeriodRow>()
            .await?;
        let grouped = dependency_map(rows);
        if grouped.is_empty() {
            let warning = "no cross-service downstream server spans in either window".to_string();
            let payload = DependencyPayload {
                dependencies: vec![],
                warnings: vec![warning.clone()],
            };
            return compare_envelope(CompareEnvelopeParams {
                tool_name: self.name(),
                args: &args,
                window,
                status: ResultStatus::NoData,
                summary: "No cross-service dependency data was found in either window.".into(),
                sample_count: 0,
                incident_value: json!([]),
                baseline_value: json!([]),
                delta: json!([]),
                warnings: vec![warning],
                service: String::new(),
                operation: "dependency_edges".into(),
                data: serde_json::to_value(payload)?,
            })
            .map_err(Into::into);
        }

        let mut dependencies = Vec::new();
        let mut warnings = Vec::new();
        for ((caller, callee, operation), (incident, baseline)) in grouped {
            let missing = incident.is_none() || baseline.is_none();
            if missing {
                warnings.push(format!(
                    "{caller} -> {callee} ({operation}): missing comparison window"
                ));
            }
            dependencies.push(DependencyComparison {
                caller,
                callee,
                operation,
                request_rate_delta: dependency_delta(&incident, &baseline, |s| {
                    s.request_rate_per_second
                }),
                error_rate_delta_pct: dependency_delta(&incident, &baseline, |s| s.error_rate_pct),
                child_p95_delta_ms: dependency_delta(&incident, &baseline, |s| s.child_p95_ms),
                child_p99_delta_ms: dependency_delta(&incident, &baseline, |s| s.child_p99_ms),
                caller_time_attributable_delta_pct: dependency_delta(&incident, &baseline, |s| {
                    s.caller_time_attributable_pct
                }),
                impact_score: dependency_impact_score(&incident, &baseline),
                missing_response_or_telemetry: missing,
                onset_alignment: if missing {
                    "not established".into()
                } else {
                    "changed within the incident window; exact onset requires bucketed analysis"
                        .into()
                },
                incident,
                baseline,
            });
        }
        dependencies.sort_by(|a, b| b.impact_score.total_cmp(&a.impact_score));
        dependencies.truncate(MAX_DEPENDENCIES);
        let sample_count = dependencies
            .iter()
            .filter_map(|edge| edge.incident.as_ref())
            .map(|stats| stats.request_count)
            .sum();
        let status = if warnings.is_empty() {
            ResultStatus::Ok
        } else {
            ResultStatus::Partial
        };
        let summary = format!(
            "Ranked {} dependency edges by incident change; top edge is {} -> {}.",
            dependencies.len(),
            dependencies
                .first()
                .map(|edge| edge.caller.as_str())
                .unwrap_or("none"),
            dependencies
                .first()
                .map(|edge| edge.callee.as_str())
                .unwrap_or("none")
        );
        let payload = DependencyPayload {
            dependencies,
            warnings: warnings.clone(),
        };
        let data = serde_json::to_value(&payload)?;
        compare_envelope(CompareEnvelopeParams {
            tool_name: self.name(),
            args: &args,
            window,
            status,
            summary,
            sample_count,
            incident_value: data.clone(),
            baseline_value: data.clone(),
            delta: data.clone(),
            warnings,
            service: String::new(),
            operation: "dependency_edges".into(),
            data,
        })
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::contracts::WindowSelectionReason;
    use chrono::{Duration, TimeZone, Utc};

    fn window() -> InvestigationWindow {
        InvestigationWindow::new(
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 11, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 10, 0, 0).unwrap(),
            WindowSelectionReason::UserProvidedRange,
        )
        .unwrap()
    }

    #[test]
    fn compare_service_query_uses_exact_half_open_windows_and_server_spans() {
        let sql = build_compare_service_sql(&["gateway".into()], &window(), "tenant-a");
        assert!(sql.contains("kind = 'SPAN_KIND_SERVER'"), "{sql}");
        assert!(
            sql.contains("timestamp >= toDateTime64('2026-08-01 10:00:00.000000000', 9, 'UTC')"),
            "{sql}"
        );
        assert!(
            sql.contains("timestamp < toDateTime64('2026-08-01 11:00:00.000000000', 9, 'UTC')"),
            "{sql}"
        );
        assert!(
            sql.contains("timestamp >= toDateTime64('2026-08-01 09:00:00.000000000', 9, 'UTC')"),
            "{sql}"
        );
        assert!(sql.contains("tenant_id = 'tenant-a'"), "{sql}");
        assert!(
            !sql.contains("now()"),
            "replayable SQL must not use wall clock: {sql}"
        );
    }

    #[test]
    fn endpoint_query_groups_server_http_endpoints_and_aggregates_before_limit() {
        let sql = build_compare_endpoint_sql(&["api".into()], &window(), "tenant-a");
        assert!(
            sql.contains("concat(http_method, ' ', http_path) AS endpoint"),
            "{sql}"
        );
        assert!(sql.contains("kind = 'SPAN_KIND_SERVER'"), "{sql}");
        assert!(sql.contains("quantile(0.95)(duration_ns)"), "{sql}");
        assert!(sql.contains("LIMIT 2000"), "{sql}");
        assert!(sql.contains("tenant_id = 'tenant-a'"), "{sql}");
    }

    #[test]
    fn client_wait_query_is_separate_from_server_red() {
        let sql = build_compare_client_wait_sql(&["gateway".into()], &window(), "tenant-a");
        assert!(
            sql.contains(
                "kind IN ('SPAN_KIND_CLIENT', 'SPAN_KIND_PRODUCER', 'SPAN_KIND_CONSUMER')"
            ),
            "{sql}"
        );
        assert!(!sql.contains("kind = 'SPAN_KIND_SERVER'"), "{sql}");
        assert!(sql.contains("quantile(0.95)(duration_ns)"), "{sql}");
        assert!(!sql.contains("now()"), "{sql}");
    }

    #[test]
    fn dependency_query_uses_downstream_server_span_and_tenant_on_both_sides() {
        let sql = build_rank_dependencies_sql(&window(), "ten'ant");
        assert!(
            sql.matches("child.kind = 'SPAN_KIND_SERVER'").count() == 2,
            "{sql}"
        );
        assert!(
            sql.matches("child.tenant_id = 'ten''ant'").count() == 2,
            "{sql}"
        );
        assert!(
            sql.matches("parent.tenant_id = 'ten''ant'").count() == 2,
            "{sql}"
        );
        assert!(
            sql.contains("child.service_name != parent.service_name"),
            "{sql}"
        );
        assert!(sql.contains("child_p95_ms"), "{sql}");
        assert!(!sql.contains("now()"), "{sql}");
    }

    #[test]
    fn impact_score_prioritizes_changed_edges_over_unchanged_absolute_latency() {
        let incident = Some(DependencyStats {
            request_count: 100,
            request_rate_per_second: 1.0,
            error_count: 0,
            error_rate_pct: 0.0,
            child_p95_ms: 800.0,
            child_p99_ms: 900.0,
            caller_time_attributable_pct: 80.0,
        });
        let baseline_changed = Some(DependencyStats {
            child_p95_ms: 100.0,
            ..incident.clone().unwrap()
        });
        let baseline_unchanged = Some(DependencyStats {
            child_p95_ms: 800.0,
            ..incident.clone().unwrap()
        });
        assert!(
            dependency_impact_score(&incident, &baseline_changed)
                > dependency_impact_score(&incident, &baseline_unchanged)
        );
    }

    #[test]
    fn service_list_is_bounded_and_deduplicated() {
        let mut args = json!({"services":["api","api","media"]});
        assert_eq!(service_list(&args), vec!["api", "media"]);
        args["service"] = json!("gateway");
        assert_eq!(service_list(&args), vec!["api", "gateway", "media"]);
        let _ = Duration::seconds(1); // keep chrono import explicit for contract parity
    }
}
