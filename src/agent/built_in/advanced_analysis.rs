//! PR3 causal analysis tools.
//!
//! These tools deliberately query the same ClickHouse tables used by the
//! existing trace and metric tools. They return bounded structured data inside
//! the PR1 provenance envelope and never mutate configuration or telemetry.

use crate::agent::contracts::{
    InvestigationWindow, QualityBand, ResultQuality, ResultStatus, SourceFamily,
    ToolResultEnvelope, require_window_from_args, serialize_tool_output,
};
use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_METRIC_ROWS: usize = 100;
const MAX_SILENCE_SERVICES: usize = 20;
const MAX_TRACE_SPANS: usize = 5000;

fn sql_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn sql_timestamp(value: chrono::DateTime<chrono::Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S.%f").to_string()
}

fn period_bounds(
    window: &InvestigationWindow,
    period: &str,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    if period == "incident" {
        (window.incident_start, window.incident_end)
    } else {
        (window.baseline_start, window.baseline_end)
    }
}

fn time_predicate(window: &InvestigationWindow, period: &str, column: &str) -> String {
    let (start, end) = period_bounds(window, period);
    format!(
        "{column} >= toDateTime64('{}', 9, 'UTC') AND {column} < toDateTime64('{}', 9, 'UTC')",
        sql_timestamp(start),
        sql_timestamp(end)
    )
}

struct EnvelopeParams<'a> {
    tool_name: &'a str,
    args: &'a Value,
    source_family: SourceFamily,
    source_tables: Vec<String>,
    window: InvestigationWindow,
    status: ResultStatus,
    summary: String,
    sample_count: u64,
    service: String,
    operation: String,
    warnings: Vec<String>,
    incident_value: Value,
    baseline_value: Value,
    delta: Value,
    data: Value,
}

fn envelope(params: EnvelopeParams<'_>) -> Result<String, serde_json::Error> {
    let mut result = ToolResultEnvelope::from_legacy(
        params.tool_name,
        params.args,
        &params.summary,
        Some(&params.summary),
    );
    result.status = params.status.clone();
    result.source_family = params.source_family;
    result.source_tables = params.source_tables;
    result.window = Some(params.window);
    result.service = params.service;
    result.operation = params.operation;
    result.sample_count = params.sample_count;
    result.incident_value = Some(params.incident_value);
    result.baseline_value = Some(params.baseline_value);
    result.absolute_delta = Some(params.delta);
    result.quality = ResultQuality {
        band: match params.status {
            ResultStatus::Ok => QualityBand::High,
            ResultStatus::Partial => QualityBand::Medium,
            _ => QualityBand::Low,
        },
        reasons: params.warnings,
    };
    serialize_tool_output(&result, params.data)
}

fn denied(
    tool_name: &str,
    args: &Value,
    family: SourceFamily,
    tables: Vec<String>,
) -> Result<String, serde_json::Error> {
    let mut result = ToolResultEnvelope::from_legacy(
        tool_name,
        args,
        "Access denied: the required telemetry scope is not available",
        Some("The required telemetry scope is not available"),
    );
    result.status = ResultStatus::AccessDenied;
    result.source_family = family;
    result.source_tables = tables;
    result.quality = ResultQuality {
        band: QualityBand::Low,
        reasons: vec!["caller lacks the required telemetry scope".into()],
    };
    serialize_tool_output(&result, json!({}))
}

// ── Critical path ──────────────────────────────────────────────────────────

#[derive(Debug, Row, Deserialize)]
struct CriticalSpanRow {
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    service_name: String,
    span_name: String,
    kind: String,
    start_ns: i64,
    duration_ns: u64,
    status: String,
}

#[derive(Debug, Clone)]
struct SpanNode {
    span_id: String,
    parent_span_id: String,
    service_name: String,
    span_name: String,
    kind: String,
    start_ns: i64,
    end_ns: i64,
    duration_ns: u64,
    status: String,
    children: Vec<String>,
}

fn build_critical_path_sql(
    trace_id: &str,
    window: &InvestigationWindow,
    tenant_id: &str,
) -> String {
    format!(
        "SELECT trace_id, span_id, parent_span_id, service_name, span_name, kind, \
                toInt64(toUnixTimestamp64Nano(timestamp)) AS start_ns, duration_ns, status \
         FROM spans \
         WHERE tenant_id = '{tenant}' \
           AND trace_id = '{trace}' \
           AND {window} \
         ORDER BY timestamp ASC \
         LIMIT {limit}",
        tenant = sql_quote(tenant_id),
        trace = sql_quote(trace_id),
        window = time_predicate(window, "incident", "timestamp"),
        limit = MAX_TRACE_SPANS,
    )
}

fn union_duration<'a>(node: &SpanNode, children: impl Iterator<Item = &'a SpanNode>) -> u64 {
    let mut ranges: Vec<(i64, i64)> = children
        .map(|child| {
            (
                child.start_ns.max(node.start_ns),
                child.end_ns.min(node.end_ns),
            )
        })
        .filter(|(start, end)| end > start)
        .collect();
    ranges.sort_unstable();
    let mut total = 0i64;
    let mut current: Option<(i64, i64)> = None;
    for (start, end) in ranges {
        match current {
            Some((current_start, current_end)) if start <= current_end => {
                current = Some((current_start, current_end.max(end)));
            }
            Some((current_start, current_end)) => {
                total += current_end - current_start;
                current = Some((start, end));
            }
            None => current = Some((start, end)),
        }
    }
    if let Some((start, end)) = current {
        total += end - start;
    }
    total.max(0) as u64
}

fn longest_child_path(
    id: &str,
    nodes: &HashMap<String, SpanNode>,
    memo: &mut HashMap<String, Vec<String>>,
    visiting: &mut HashSet<String>,
) -> Vec<String> {
    if let Some(path) = memo.get(id) {
        return path.clone();
    }
    if !visiting.insert(id.to_string()) {
        return Vec::new();
    }
    let Some(node) = nodes.get(id) else {
        visiting.remove(id);
        return Vec::new();
    };
    let mut best = Vec::new();
    for child_id in &node.children {
        let child_path = longest_child_path(child_id, nodes, memo, visiting);
        if child_path.len() > best.len() {
            best = child_path;
        }
    }
    let mut path = vec![id.to_string()];
    path.extend(best);
    visiting.remove(id);
    memo.insert(id.to_string(), path.clone());
    path
}

fn critical_path_data(rows: Vec<CriticalSpanRow>) -> (Value, Vec<String>, u64) {
    let mut warnings = Vec::new();
    let mut nodes = HashMap::new();
    let trace_id = rows
        .first()
        .map(|row| row.trace_id.clone())
        .unwrap_or_default();
    for row in rows {
        let end_ns = row
            .start_ns
            .saturating_add(row.duration_ns.min(i64::MAX as u64) as i64);
        nodes.insert(
            row.span_id.clone(),
            SpanNode {
                span_id: row.span_id,
                parent_span_id: row.parent_span_id,
                service_name: row.service_name,
                span_name: row.span_name,
                kind: row.kind,
                start_ns: row.start_ns,
                end_ns,
                duration_ns: row.duration_ns,
                status: row.status,
                children: Vec::new(),
            },
        );
    }
    let ids: Vec<String> = nodes.keys().cloned().collect();
    let mut roots = Vec::new();
    for id in ids {
        let parent = nodes
            .get(&id)
            .map(|node| node.parent_span_id.clone())
            .unwrap_or_default();
        if parent.is_empty() {
            roots.push(id);
        } else if let Some(parent_node) = nodes.get_mut(&parent) {
            parent_node.children.push(id);
        } else {
            warnings.push(format!("span {id} references missing parent {parent}"));
            roots.push(id);
        }
    }
    if roots.is_empty() && !nodes.is_empty() {
        warnings.push("no root span was found; trace may contain a parent cycle".into());
        roots.push(nodes.keys().next().cloned().unwrap_or_default());
    }

    let mut memo = HashMap::new();
    let mut visiting = HashSet::new();
    roots.sort_by_key(|id| {
        std::cmp::Reverse(nodes.get(id).map(|node| node.duration_ns).unwrap_or(0))
    });
    let root_id = roots.first().cloned().unwrap_or_default();
    let path = longest_child_path(&root_id, &nodes, &mut memo, &mut visiting);
    let root = nodes.get(&root_id);
    let mut child_wait: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut error_spans = 0u64;
    for node in nodes.values() {
        if node.status == "STATUS_CODE_ERROR" || node.status == "ERROR" {
            error_spans += 1;
        }
        for child_id in &node.children {
            if let Some(child) = nodes.get(child_id) {
                let entry = child_wait.entry(child.service_name.clone()).or_default();
                entry.0 = entry.0.saturating_add(child.duration_ns);
                entry.1 = entry.1.saturating_add(1);
            }
        }
    }
    let child_wait: Vec<Value> = child_wait
        .into_iter()
        .map(|(service, (duration_ns, calls))| {
            json!({"service":service,"calls":calls,"child_wait_ms":duration_ns as f64 / 1e6})
        })
        .collect();
    let (wall_ns, self_ns) = root
        .map(|node| {
            let child_ns =
                union_duration(node, node.children.iter().filter_map(|id| nodes.get(id)));
            (node.duration_ns, node.duration_ns.saturating_sub(child_ns))
        })
        .unwrap_or((0, 0));
    let path_details: Vec<Value> = path
        .iter()
        .filter_map(|id| nodes.get(id))
        .map(|node| {
            json!({
                "span_id": node.span_id,
                "service": node.service_name,
                "operation": node.span_name,
                "kind": node.kind,
                "duration_ms": node.duration_ns as f64 / 1e6,
            })
        })
        .collect();
    let warning_copy = warnings.clone();
    let data = json!({
        "trace_id": trace_id,
        "root_span_id": root_id,
        "critical_path": path_details,
        "wall_time_ms": wall_ns as f64 / 1e6,
        "self_time_ms": self_ns as f64 / 1e6,
        "child_wait_ms": wall_ns.saturating_sub(self_ns) as f64 / 1e6,
        "child_wait": child_wait,
        "error_spans": error_spans,
        "warnings": warnings,
    });
    (data, warning_copy, nodes.len() as u64)
}

pub struct AnalyzeTraceCriticalPath;

#[async_trait::async_trait]
impl Tool for AnalyzeTraceCriticalPath {
    fn name(&self) -> &str {
        "analyze_trace_critical_path"
    }

    fn description(&self) -> &str {
        "Reconstruct a trace tree and separate root request wall time, application self-time, child wait, critical-path services, and malformed or incomplete spans. Requires an exact incident window and trace_id."
    }

    fn parameters(&self) -> Value {
        json!({
            "type":"object",
            "required":["trace_id","incident_start","incident_end","baseline_start","baseline_end"],
            "properties": {
                "trace_id":{"type":"string"},
                "incident_start":{"type":"string","description":"Inclusive UTC RFC3339 bound"},
                "incident_end":{"type":"string","description":"Exclusive UTC RFC3339 bound"},
                "baseline_start":{"type":"string"},"baseline_end":{"type":"string"},
                "selection_reason":{"type":"string","enum":["alert_window","user_provided_range","inferred_onset","fallback"]}
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") {
            return Ok(denied(
                self.name(),
                &args,
                SourceFamily::Traces,
                vec!["spans".into()],
            )?);
        }
        let trace_id = args.get("trace_id").and_then(Value::as_str).unwrap_or("");
        if trace_id.is_empty() {
            return Ok("Tool error: trace_id is required".into());
        }
        let window = match require_window_from_args(&args) {
            Ok(window) => window,
            Err(message) => return Ok(format!("Tool error: {message}")),
        };
        let sql = build_critical_path_sql(trace_id, &window, &ctx.tenant_id);
        let rows = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
            .fetch_all::<CriticalSpanRow>()
            .await?;
        if rows.is_empty() {
            return Ok(envelope(EnvelopeParams {
                tool_name: self.name(),
                args: &args,
                source_family: SourceFamily::Traces,
                source_tables: vec!["spans".into()],
                window,
                status: ResultStatus::NoData,
                summary: "No spans were found for this trace in the incident window.".into(),
                sample_count: 0,
                service: trace_id.into(),
                operation: "critical_path".into(),
                warnings: vec!["trace is absent or outside the requested window".into()],
                incident_value: json!({}),
                baseline_value: json!({}),
                delta: json!({}),
                data: json!({"trace_id":trace_id,"critical_path":[],"warnings":["no spans"]}),
            })?);
        }
        let (data, warnings, sample_count) = critical_path_data(rows);
        let status = if data["warnings"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            ResultStatus::Partial
        } else {
            ResultStatus::Ok
        };
        let summary = format!(
            "Reconstructed trace {trace_id}; application self-time and downstream child wait are separated."
        );
        Ok(envelope(EnvelopeParams {
            tool_name: self.name(),
            args: &args,
            source_family: SourceFamily::Traces,
            source_tables: vec!["spans".into()],
            window,
            status,
            summary,
            sample_count,
            service: trace_id.into(),
            operation: "critical_path".into(),
            warnings,
            incident_value: data.clone(),
            baseline_value: json!({}),
            delta: data.clone(),
            data,
        })?)
    }
}

// ── Resource saturation ────────────────────────────────────────────────────

#[derive(Debug, Row, Deserialize)]
struct ResourceMetricRow {
    metric_name: String,
    metric_type: String,
    period: String,
    sample_count: u64,
    latest: f64,
    average: f64,
    maximum: f64,
}

fn resource_metric_predicate() -> &'static str {
    "(lower(MetricName) LIKE '%cpu%' OR lower(MetricName) LIKE '%memory%' OR lower(MetricName) LIKE '%mem%' OR lower(MetricName) LIKE '%throttl%' OR lower(MetricName) LIKE '%oom%' OR lower(MetricName) LIKE '%restart%' OR lower(MetricName) LIKE '%evict%' OR lower(MetricName) LIKE '%gc%' OR lower(MetricName) LIKE '%queue%' OR lower(MetricName) LIKE '%connection%')"
}

pub(crate) fn build_resource_saturation_sql(
    service: &str,
    window: &InvestigationWindow,
    tenant_id: &str,
) -> String {
    let service_filter = if service.is_empty() {
        String::new()
    } else {
        format!(" AND ServiceName = '{}'", sql_quote(service))
    };
    let make = |table: &str, kind: &str, period: &str| {
        format!(
            "SELECT MetricName AS metric_name, '{kind}' AS metric_type, '{period}' AS period, \
                    count() AS sample_count, argMax(Value, TimeUnix) AS latest, avg(Value) AS average, max(Value) AS maximum \
             FROM {table} \
             WHERE tenant_id = '{tenant}'{service_filter} \
               AND {time} AND {predicate} \
             GROUP BY MetricName",
            tenant = sql_quote(tenant_id),
            time = time_predicate(window, period, "TimeUnix"),
            predicate = resource_metric_predicate(),
        )
    };
    [
        make("metrics_gauge", "gauge", "incident"),
        make("metrics_gauge", "gauge", "baseline"),
        make("metrics_sum", "sum", "incident"),
        make("metrics_sum", "sum", "baseline"),
    ]
    .join(" UNION ALL ")
}

fn resource_status(
    metric: &str,
    incident: Option<&ResourceMetricRow>,
    baseline: Option<&ResourceMetricRow>,
) -> &'static str {
    let Some(incident) = incident else {
        return "not_instrumented";
    };
    let baseline = baseline.map(|row| row.latest).unwrap_or(0.0);
    let lower = metric.to_ascii_lowercase();
    let delta = incident.latest - baseline;
    if (lower.contains("oom")
        || lower.contains("restart")
        || lower.contains("evict")
        || lower.contains("throttl"))
        && incident.latest > baseline
        && incident.latest > 0.0
    {
        "elevated"
    } else if lower.contains("usage")
        || lower.contains("memory")
        || lower.contains("cpu")
        || lower.contains("gc")
        || lower.contains("queue")
        || lower.contains("connection")
    {
        if delta > baseline.abs().max(1.0) * 0.25 {
            "elevated"
        } else {
            "instrumented"
        }
    } else {
        "instrumented"
    }
}

pub struct GetResourceSaturation;

#[async_trait::async_trait]
impl Tool for GetResourceSaturation {
    fn name(&self) -> &str {
        "get_resource_saturation"
    }
    fn description(&self) -> &str {
        "Compare resource and saturation metrics for a service between exact incident and baseline windows. Reports CPU, memory, throttling, OOM, restart, eviction, GC, queue, and connection signals, distinguishing missing instrumentation from normal data."
    }
    fn parameters(&self) -> Value {
        json!({
            "type":"object",
            "required":["service","incident_start","incident_end","baseline_start","baseline_end"],
            "properties": {"service":{"type":"string"},"incident_start":{"type":"string"},"incident_end":{"type":"string"},"baseline_start":{"type":"string"},"baseline_end":{"type":"string"},"selection_reason":{"type":"string","enum":["alert_window","user_provided_range","inferred_onset","fallback"]}}
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("metrics") {
            return Ok(denied(
                self.name(),
                &args,
                SourceFamily::OTelMetrics,
                vec!["metrics_gauge".into(), "metrics_sum".into()],
            )?);
        }
        let service = args.get("service").and_then(Value::as_str).unwrap_or("");
        if service.is_empty() {
            return Ok("Tool error: service is required".into());
        }
        let window = match require_window_from_args(&args) {
            Ok(value) => value,
            Err(message) => return Ok(format!("Tool error: {message}")),
        };
        let sql = build_resource_saturation_sql(service, &window, &ctx.tenant_id);
        let rows = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
            .fetch_all::<ResourceMetricRow>()
            .await?;
        let mut grouped: BTreeMap<
            (String, String),
            (Option<ResourceMetricRow>, Option<ResourceMetricRow>),
        > = BTreeMap::new();
        for row in rows {
            let entry = grouped
                .entry((row.metric_name.clone(), row.metric_type.clone()))
                .or_default();
            if row.period == "incident" {
                entry.0 = Some(row);
            } else {
                entry.1 = Some(row);
            }
        }
        if grouped.is_empty() {
            return Ok(envelope(EnvelopeParams {
                tool_name: self.name(),
                args: &args,
                source_family: SourceFamily::OTelMetrics,
                source_tables: vec!["metrics_gauge".into(), "metrics_sum".into()],
                window,
                status: ResultStatus::NoData,
                summary: format!("No resource metrics were found for service {service}."),
                sample_count: 0,
                service: service.into(),
                operation: "resource_saturation".into(),
                warnings: vec![
                    "resource telemetry is not instrumented or was not emitted in either window"
                        .into(),
                ],
                incident_value: json!([]),
                baseline_value: json!([]),
                delta: json!([]),
                data: json!({"service":service,"signals":[],"warnings":["not instrumented"]}),
            })?);
        }
        let mut signals = Vec::new();
        let mut warnings = Vec::new();
        let mut sample_count = 0u64;
        for ((metric_name, metric_type), (incident, baseline)) in grouped {
            if let Some(row) = &incident {
                sample_count = sample_count.saturating_add(row.sample_count);
            }
            if incident.is_none() || baseline.is_none() {
                warnings.push(format!(
                    "{metric_name}: missing incident or baseline sample"
                ));
            }
            let delta = match (&incident, &baseline) {
                (Some(i), Some(b)) => Some(i.latest - b.latest),
                _ => None,
            };
            signals.push(json!({
                "metric_name":metric_name,
                "metric_type":metric_type,
                "status":resource_status(&metric_name, incident.as_ref(), baseline.as_ref()),
                "incident":incident.as_ref().map(|row| json!({"sample_count":row.sample_count,"latest":row.latest,"average":row.average,"maximum":row.maximum})),
                "baseline":baseline.as_ref().map(|row| json!({"sample_count":row.sample_count,"latest":row.latest,"average":row.average,"maximum":row.maximum})),
                "delta":delta,
            }));
        }
        let status = if warnings.is_empty() {
            ResultStatus::Ok
        } else {
            ResultStatus::Partial
        };
        let data = json!({"service":service,"signals":signals,"warnings":warnings});
        Ok(envelope(EnvelopeParams {
            tool_name: self.name(),
            args: &args,
            source_family: SourceFamily::OTelMetrics,
            source_tables: vec!["metrics_gauge".into(), "metrics_sum".into()],
            window,
            status,
            summary: format!("Compared resource saturation signals for {service}."),
            sample_count,
            service: service.into(),
            operation: "resource_saturation".into(),
            warnings: Vec::new(),
            incident_value: data.clone(),
            baseline_value: json!({}),
            delta: data.clone(),
            data,
        })?)
    }
}

// ── Metric catalog ──────────────────────────────────────────────────────────

#[derive(Debug, Row, Deserialize)]
struct MetricCatalogRow {
    metric_name: String,
    metric_type: String,
    description: String,
    unit: String,
    observed_services: Vec<String>,
    label_names: Vec<String>,
    series_count: u64,
    label_count: u64,
    sample_count: u64,
    last_seen: String,
}

pub(crate) fn build_metric_catalog_sql(
    window: &InvestigationWindow,
    tenant_id: &str,
    prefix: &str,
) -> String {
    let prefix_filter = if prefix.is_empty() {
        String::new()
    } else {
        format!(" AND MetricName LIKE '{}%'", sql_quote(prefix))
    };
    let make = |table: &str, kind: &str| {
        format!(
            "SELECT MetricName AS metric_name, '{kind}' AS metric_type, any(MetricDescription) AS description, any(MetricUnit) AS unit, \
                    arraySlice(groupUniqArray(20)(ServiceName), 1, 20) AS observed_services, \
                    arraySort(arrayDistinct(arrayFlatten(groupArray(mapKeys(Attributes))))) AS label_names, \
                    uniqExact(ServiceName, Attributes) AS series_count, max(length(mapKeys(Attributes))) AS label_count, \
                    count() AS sample_count, toString(max(TimeUnix)) AS last_seen \
             FROM {table} \
             WHERE tenant_id = '{tenant}' AND {time}{prefix_filter} \
             GROUP BY MetricName \
             ORDER BY series_count DESC \
             LIMIT {limit}",
            tenant = sql_quote(tenant_id),
            time = time_predicate(window, "incident", "TimeUnix"),
            limit = MAX_METRIC_ROWS,
        )
    };
    format!(
        "{} UNION ALL {}",
        make("metrics_gauge", "gauge"),
        make("metrics_sum", "sum")
    )
}

pub struct ListMetricCatalog;

#[async_trait::async_trait]
impl Tool for ListMetricCatalog {
    fn name(&self) -> &str {
        "list_metric_catalog"
    }
    fn description(&self) -> &str {
        "Discover metric names, type, unit, observed services, label names, sample count, last-seen time, and bounded series-cardinality hints in an exact incident window. Never returns label values."
    }
    fn parameters(&self) -> Value {
        json!({"type":"object","required":["incident_start","incident_end","baseline_start","baseline_end"],"properties":{"prefix":{"type":"string","description":"Optional metric-name prefix"},"incident_start":{"type":"string"},"incident_end":{"type":"string"},"baseline_start":{"type":"string"},"baseline_end":{"type":"string"},"selection_reason":{"type":"string","enum":["alert_window","user_provided_range","inferred_onset","fallback"]}}})
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("metrics") {
            return Ok(denied(
                self.name(),
                &args,
                SourceFamily::OTelMetrics,
                vec!["metrics_gauge".into(), "metrics_sum".into()],
            )?);
        }
        let window = match require_window_from_args(&args) {
            Ok(value) => value,
            Err(message) => return Ok(format!("Tool error: {message}")),
        };
        let prefix = args.get("prefix").and_then(Value::as_str).unwrap_or("");
        let sql = build_metric_catalog_sql(&window, &ctx.tenant_id, prefix);
        let rows = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
            .fetch_all::<MetricCatalogRow>()
            .await?;
        if rows.is_empty() {
            return Ok(envelope(EnvelopeParams {
                tool_name: self.name(),
                args: &args,
                source_family: SourceFamily::OTelMetrics,
                source_tables: vec!["metrics_gauge".into(), "metrics_sum".into()],
                window,
                status: ResultStatus::NoData,
                summary: "No metrics were observed in the requested window.".into(),
                sample_count: 0,
                service: String::new(),
                operation: "metric_catalog".into(),
                warnings: vec!["metric catalog is empty for this tenant and window".into()],
                incident_value: json!([]),
                baseline_value: json!([]),
                delta: json!([]),
                data: json!({"metrics":[]}),
            })?);
        }
        let sample_count = rows.iter().map(|row| row.sample_count).sum();
        let metrics: Vec<Value> = rows.into_iter().map(|row| json!({
            "metric_name":row.metric_name,"metric_type":row.metric_type,"description":row.description,"unit":row.unit,
            "observed_services":row.observed_services,"label_names":row.label_names,"series_count":row.series_count,
            "label_count":row.label_count,"sample_count":row.sample_count,"last_seen":row.last_seen,
        })).collect();
        let data = json!({"metrics":metrics,"warnings":[]});
        Ok(envelope(EnvelopeParams {
            tool_name: self.name(),
            args: &args,
            source_family: SourceFamily::OTelMetrics,
            source_tables: vec!["metrics_gauge".into(), "metrics_sum".into()],
            window,
            status: ResultStatus::Ok,
            summary: format!(
                "Cataloged {} metric definitions without returning label values.",
                data["metrics"].as_array().map_or(0, Vec::len)
            ),
            sample_count,
            service: String::new(),
            operation: "metric_catalog".into(),
            warnings: Vec::new(),
            incident_value: data.clone(),
            baseline_value: json!({}),
            delta: data.clone(),
            data,
        })?)
    }
}

// ── Service silence ─────────────────────────────────────────────────────────

#[derive(Debug, Row, Deserialize)]
struct SilenceRow {
    service: String,
    period: String,
    server_count: u64,
    expected_calls: u64,
    caller_count: u64,
}

fn service_values(args: &Value) -> Vec<String> {
    let mut services: Vec<String> = args
        .get("services")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if let Some(service) = args
        .get("service")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        services.push(service.to_string());
    }
    services.sort();
    services.dedup();
    services.truncate(MAX_SILENCE_SERVICES);
    services
}

pub(crate) fn build_service_silence_sql(
    services: &[String],
    window: &InvestigationWindow,
    tenant_id: &str,
) -> String {
    let mut queries = Vec::new();
    for service in services {
        let target = sql_quote(service);
        for period in ["incident", "baseline"] {
            let predicate = time_predicate(window, period, "timestamp");
            queries.push(format!(
                "SELECT '{target}' AS service, '{period}' AS period, \
                        countIf(kind = 'SPAN_KIND_SERVER' AND service_name = '{target}') AS server_count, \
                        countIf(kind IN ('SPAN_KIND_CLIENT', 'SPAN_KIND_PRODUCER', 'SPAN_KIND_CONSUMER') AND \
                            (JSONExtractString(attributes, 'peer.service') = '{target}' OR JSONExtractString(attributes, 'server.address') = '{target}')) AS expected_calls, \
                        uniqIf(service_name, kind IN ('SPAN_KIND_CLIENT', 'SPAN_KIND_PRODUCER', 'SPAN_KIND_CONSUMER') AND \
                            (JSONExtractString(attributes, 'peer.service') = '{target}' OR JSONExtractString(attributes, 'server.address') = '{target}')) AS caller_count \
                 FROM spans WHERE tenant_id = '{tenant}' AND {predicate} \
                   AND ((kind = 'SPAN_KIND_SERVER' AND service_name = '{target}') OR \
                        (kind IN ('SPAN_KIND_CLIENT', 'SPAN_KIND_PRODUCER', 'SPAN_KIND_CONSUMER') AND \
                         (JSONExtractString(attributes, 'peer.service') = '{target}' OR JSONExtractString(attributes, 'server.address') = '{target}')))",
                tenant = sql_quote(tenant_id),
            ));
        }
    }
    queries.join(" UNION ALL ")
}

fn silence_status(baseline_server: u64, incident_server: u64, expected_calls: u64) -> &'static str {
    if baseline_server == 0 {
        return "no_baseline";
    }
    let relative = incident_server as f64 / baseline_server as f64;
    if relative <= 0.10 && expected_calls > 0 {
        "silence_candidate"
    } else if relative <= 0.10 {
        "telemetry_uncertain"
    } else {
        "not_silent"
    }
}

pub struct DetectServiceSilence;

#[async_trait::async_trait]
impl Tool for DetectServiceSilence {
    fn name(&self) -> &str {
        "detect_service_silence"
    }
    fn description(&self) -> &str {
        "Detect services whose server-span volume disappears or drops sharply in an exact incident window despite caller-side client spans indicating expected traffic. Distinguishes no baseline, silence candidates, and telemetry uncertainty."
    }
    fn parameters(&self) -> Value {
        json!({"type":"object","required":["services","incident_start","incident_end","baseline_start","baseline_end"],"properties":{"services":{"type":"array","items":{"type":"string"},"maxItems":20},"service":{"type":"string"},"incident_start":{"type":"string"},"incident_end":{"type":"string"},"baseline_start":{"type":"string"},"baseline_end":{"type":"string"},"selection_reason":{"type":"string","enum":["alert_window","user_provided_range","inferred_onset","fallback"]}}})
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") {
            return Ok(denied(
                self.name(),
                &args,
                SourceFamily::Traces,
                vec!["spans".into()],
            )?);
        }
        let services = service_values(&args);
        if services.is_empty() {
            return Ok("Tool error: at least one service is required".into());
        }
        let window = match require_window_from_args(&args) {
            Ok(value) => value,
            Err(message) => return Ok(format!("Tool error: {message}")),
        };
        let sql = build_service_silence_sql(&services, &window, &ctx.tenant_id);
        let rows = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
            .fetch_all::<SilenceRow>()
            .await?;
        let mut grouped: BTreeMap<String, (Option<SilenceRow>, Option<SilenceRow>)> =
            BTreeMap::new();
        for row in rows {
            let entry = grouped.entry(row.service.clone()).or_default();
            if row.period == "incident" {
                entry.0 = Some(row);
            } else {
                entry.1 = Some(row);
            }
        }
        let mut results = Vec::new();
        let mut warnings = Vec::new();
        let mut sample_count = 0u64;
        for service in &services {
            let (incident, baseline) = grouped.remove(service).unwrap_or((None, None));
            let baseline_server = baseline.as_ref().map_or(0, |row| row.server_count);
            let incident_server = incident.as_ref().map_or(0, |row| row.server_count);
            let expected_calls = incident.as_ref().map_or(0, |row| row.expected_calls);
            let caller_count = incident.as_ref().map_or(0, |row| row.caller_count);
            let status = silence_status(baseline_server, incident_server, expected_calls);
            if status == "telemetry_uncertain" {
                warnings.push(format!("{service}: server spans dropped but no caller-side expected-traffic evidence was found"));
            }
            if let Some(row) = &incident {
                sample_count = sample_count.saturating_add(row.server_count);
            }
            results.push(json!({
                "service":service,
                "status":status,
                "incident_server_spans":incident_server,
                "baseline_server_spans":baseline_server,
                "incident_expected_calls":expected_calls,
                "incident_callers":caller_count,
                "relative_volume":if baseline_server == 0 { Value::Null } else { json!(incident_server as f64 / baseline_server as f64) },
                "warning":if status == "telemetry_uncertain" { Some("absence may be telemetry-pipeline failure or sampling") } else { None::<&str> },
            }));
        }
        let has_candidate = results
            .iter()
            .any(|row| row["status"] == "silence_candidate");
        let status = if warnings.is_empty() {
            ResultStatus::Ok
        } else {
            ResultStatus::Partial
        };
        let data = json!({"services":results,"warnings":warnings});
        Ok(envelope(EnvelopeParams {
            tool_name: self.name(),
            args: &args,
            source_family: SourceFamily::Traces,
            source_tables: vec!["spans".into()],
            window,
            status,
            summary: if has_candidate {
                "Detected one or more services with sharply reduced server-span volume and caller-side expected traffic.".into()
            } else {
                "No confirmed service silence was found in the requested comparison.".into()
            },
            sample_count,
            service: services.join(", "),
            operation: "service_silence".into(),
            warnings: Vec::new(),
            incident_value: data.clone(),
            baseline_value: json!({}),
            delta: data.clone(),
            data,
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::contracts::WindowSelectionReason;
    use chrono::{TimeZone, Utc};

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
    fn critical_path_query_is_tenant_scoped_and_bounded_to_incident_window() {
        let sql = build_critical_path_sql("trace'1", &window(), "tenant'a");
        assert!(sql.contains("tenant_id = 'tenant''a'"), "{sql}");
        assert!(sql.contains("trace_id = 'trace''1'"), "{sql}");
        assert!(sql.contains("kind"), "{sql}");
        assert!(
            sql.contains("timestamp >= toDateTime64('2026-08-01 10:00:00.000000000'"),
            "{sql}"
        );
        assert!(
            sql.contains("timestamp < toDateTime64('2026-08-01 11:00:00.000000000'"),
            "{sql}"
        );
        assert!(sql.contains("LIMIT 5000"), "{sql}");
        assert!(!sql.contains("now()"), "{sql}");
    }

    #[test]
    fn critical_path_separates_overlapping_child_wait_and_flags_orphans() {
        let rows = vec![
            CriticalSpanRow {
                trace_id: "t1".into(),
                span_id: "root".into(),
                parent_span_id: String::new(),
                service_name: "gateway".into(),
                span_name: "GET /".into(),
                kind: "SPAN_KIND_SERVER".into(),
                start_ns: 0,
                duration_ns: 1_000_000_000,
                status: "STATUS_CODE_OK".into(),
            },
            CriticalSpanRow {
                trace_id: "t1".into(),
                span_id: "db".into(),
                parent_span_id: "root".into(),
                service_name: "postgres".into(),
                span_name: "SELECT".into(),
                kind: "SPAN_KIND_CLIENT".into(),
                start_ns: 100_000_000,
                duration_ns: 500_000_000,
                status: "STATUS_CODE_OK".into(),
            },
            CriticalSpanRow {
                trace_id: "t1".into(),
                span_id: "orphan".into(),
                parent_span_id: "missing".into(),
                service_name: "worker".into(),
                span_name: "job".into(),
                kind: "SPAN_KIND_INTERNAL".into(),
                start_ns: 200_000_000,
                duration_ns: 100_000_000,
                status: "STATUS_CODE_ERROR".into(),
            },
        ];
        let (data, _warnings, sample_count) = critical_path_data(rows);
        assert_eq!(sample_count, 3);
        assert_eq!(data["wall_time_ms"], 1000.0);
        assert_eq!(data["self_time_ms"], 500.0);
        assert_eq!(data["child_wait_ms"], 500.0);
        assert_eq!(data["critical_path"][0]["service"], "gateway");
        assert!(!data["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn critical_path_handles_parent_cycles_without_recursing_forever() {
        let rows = vec![
            CriticalSpanRow {
                trace_id: "t1".into(),
                span_id: "a".into(),
                parent_span_id: "b".into(),
                service_name: "a".into(),
                span_name: "a".into(),
                kind: "SPAN_KIND_INTERNAL".into(),
                start_ns: 0,
                duration_ns: 10,
                status: "STATUS_CODE_OK".into(),
            },
            CriticalSpanRow {
                trace_id: "t1".into(),
                span_id: "b".into(),
                parent_span_id: "a".into(),
                service_name: "b".into(),
                span_name: "b".into(),
                kind: "SPAN_KIND_INTERNAL".into(),
                start_ns: 0,
                duration_ns: 10,
                status: "STATUS_CODE_OK".into(),
            },
        ];
        let (data, _, _) = critical_path_data(rows);
        assert!(!data["warnings"].as_array().unwrap().is_empty());
        assert!(data["critical_path"].is_array());
    }

    #[test]
    fn resource_query_covers_incident_and_baseline_and_known_saturation_families() {
        let sql = build_resource_saturation_sql("api", &window(), "tenant-a");
        assert!(sql.matches("tenant_id = 'tenant-a'").count() == 4, "{sql}");
        assert!(sql.contains("ServiceName = 'api'"), "{sql}");
        assert!(
            sql.contains("%throttl%") && sql.contains("%oom%") && sql.contains("%memory%"),
            "{sql}"
        );
        assert!(sql.contains("period"), "{sql}");
        assert!(!sql.contains("now()"), "{sql}");
    }

    #[test]
    fn metric_catalog_exposes_label_names_without_label_values() {
        let sql = build_metric_catalog_sql(&window(), "tenant-a", "http_");
        assert!(sql.contains("mapKeys(Attributes)"), "{sql}");
        assert!(sql.contains("groupUniqArray"), "{sql}");
        assert!(sql.contains("MetricName LIKE 'http_%'"), "{sql}");
        assert!(sql.contains("uniqExact(ServiceName, Attributes)"), "{sql}");
        assert!(sql.matches("tenant_id = 'tenant-a'").count() == 2, "{sql}");
        assert!(
            !sql.contains("mapValues(Attributes)"),
            "label values must not be returned: {sql}"
        );
    }

    #[test]
    fn silence_query_checks_server_span_kind_and_caller_expectations() {
        let sql = build_service_silence_sql(&["payments".into()], &window(), "tenant-a");
        assert!(sql.contains("kind = 'SPAN_KIND_SERVER'"), "{sql}");
        assert!(
            sql.contains(
                "kind IN ('SPAN_KIND_CLIENT', 'SPAN_KIND_PRODUCER', 'SPAN_KIND_CONSUMER')"
            ),
            "{sql}"
        );
        assert!(sql.contains("peer.service"), "{sql}");
        assert!(sql.contains("tenant_id = 'tenant-a'"), "{sql}");
        assert!(!sql.contains("now()"), "{sql}");
    }

    #[test]
    fn silence_requires_baseline_and_caller_evidence() {
        assert_eq!(silence_status(0, 0, 10), "no_baseline");
        assert_eq!(silence_status(100, 0, 10), "silence_candidate");
        assert_eq!(silence_status(100, 0, 0), "telemetry_uncertain");
        assert_eq!(silence_status(100, 80, 0), "not_silent");
    }
}
