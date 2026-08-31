//! Read-only MySQL diagnostics from the MySQL add-on's existing telemetry.
use crate::agent::contracts::{
    InvestigationWindow, QualityBand, ResultQuality, ResultStatus, SourceFamily,
    ToolResultEnvelope, WindowSelectionReason, serialize_tool_output,
};
use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use chrono::{Duration, Utc};
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

const MYSQL_METRICS: &[&str] = &[
    "mysql_threads_connected",
    "mysql_threads_running",
    "mysql_max_connections",
    "mysql_oldest_transaction_age_seconds",
    "mysql_lock_wait_edges",
    "mysql_metadata_lock_waiters",
    "mysql_innodb_history_list_length",
    "mysql_innodb_log_waits_total",
    "mysql_innodb_deadlocks_total",
    "mysql_replication_lag_seconds",
    "mysql_replication_io_running",
    "mysql_replication_sql_running",
    "mysql_collector_up",
];

pub struct InspectMysql;

#[derive(Debug, Row, Deserialize)]
struct CallRow {
    target: String,
    database: String,
    operation: String,
    calls: u64,
    errors: u64,
    total_ms: f64,
    p95_ms: f64,
}

#[derive(Debug, Row, Deserialize)]
struct EvidenceRow {
    timestamp: String,
    event: String,
    body: String,
    host: String,
    db: String,
    digest: String,
    calls: String,
    total_ms: String,
    mean_ms: String,
    lock_ms: String,
    waiting_pid: String,
    blocking_pid: String,
    check: String,
    severity: String,
    recommendation: String,
    error_code: String,
}

#[derive(Debug, Row, Deserialize)]
struct MetricRow {
    name: String,
    value: f64,
    timestamp: String,
}

fn quote(value: &str) -> String {
    value.replace('\'', "''")
}
fn number(value: &str) -> f64 {
    value.parse().unwrap_or(0.0)
}
fn compact(value: &str, max: usize) -> String {
    crate::agent::memory::truncate_at_char_boundary(value, max).to_string()
}

fn time_window(args: &Value) -> Result<(String, Option<InvestigationWindow>, String)> {
    if args.get("incident_start").is_some() {
        let window =
            crate::agent::contracts::require_window_from_args(args).map_err(anyhow::Error::msg)?;
        return Ok((
            format!(
                "timestamp >= toDateTime64('{}', 9, 'UTC') AND timestamp < toDateTime64('{}', 9, 'UTC')",
                window.incident_start.format("%Y-%m-%d %H:%M:%S%.f"),
                window.incident_end.format("%Y-%m-%d %H:%M:%S%.f")
            ),
            Some(window),
            "incident window".into(),
        ));
    }
    let minutes = args
        .get("minutes")
        .and_then(Value::as_u64)
        .unwrap_or(30)
        .clamp(1, 1440);
    let window = InvestigationWindow::recent(
        Utc::now(),
        Duration::minutes(minutes as i64),
        WindowSelectionReason::Fallback,
    )
    .ok();
    Ok((
        format!("timestamp >= now() - INTERVAL {minutes} MINUTE"),
        window,
        format!("last {minutes}m"),
    ))
}

fn calls_sql(service: &str, time: &str, tenant: &str) -> String {
    format!(
        "SELECT multiIf(JSONExtractString(attributes, 'server.address') != '', JSONExtractString(attributes, 'server.address'), JSONExtractString(attributes, 'net.peer.name') != '', JSONExtractString(attributes, 'net.peer.name'), 'database') AS target, \
         if(JSONExtractString(attributes, 'db.name') != '', JSONExtractString(attributes, 'db.name'), JSONExtractString(attributes, 'db.namespace')) AS database, \
         if(JSONExtractString(attributes, 'db.operation.name') != '', JSONExtractString(attributes, 'db.operation.name'), JSONExtractString(attributes, 'db.operation')) AS operation, \
         count() AS calls, countIf(status IN ('STATUS_CODE_ERROR','ERROR') OR http_status_code >= 500) AS errors, \
         sum(duration_ns) / 1000000.0 AS total_ms, quantile(0.95)(duration_ns) / 1000000.0 AS p95_ms \
         FROM spans PREWHERE tenant_id='{}' AND service_name='{}' AND {} \
         WHERE JSONExtractString(attributes, 'db.system') IN ('mysql','mariadb') OR JSONExtractString(attributes, 'db.system.name') IN ('mysql','mariadb') \
         GROUP BY target, database, operation ORDER BY total_ms DESC LIMIT 20",
        quote(tenant),
        quote(service),
        time,
    )
}

fn selectors(targets: &[String], host: &str, db: &str, map: &str, service: &str) -> Vec<String> {
    let mut out = Vec::new();
    for target in targets {
        let target = quote(target);
        if !target.is_empty() && target != "database" {
            out.push(format!(
                "({service} = '{target}' OR {map}['host'] = '{target}' OR {map}['db'] = '{target}')"
            ));
        }
    }
    if !host.is_empty() {
        let host = quote(host);
        out.push(format!("({service}='{host}' OR {map}['host']='{host}')"));
    }
    if !db.is_empty() {
        out.push(format!("{map}['db']='{}'", quote(db)));
    }
    out
}

fn logs_sql(targets: &[String], host: &str, db: &str, time: &str, tenant: &str) -> Option<String> {
    let selectors = selectors(targets, host, db, "LogAttributes", "ServiceName");
    if selectors.is_empty() {
        return None;
    }
    Some(format!(
        "SELECT toString(Timestamp) AS timestamp, LogAttributes['event'] AS event, Body AS body, \
         LogAttributes['host'] AS host, LogAttributes['db'] AS db, LogAttributes['digest'] AS digest, \
         LogAttributes['calls'] AS calls, LogAttributes['total_ms'] AS total_ms, LogAttributes['mean_ms'] AS mean_ms, \
         LogAttributes['lock_ms'] AS lock_ms, LogAttributes['waiting_pid'] AS waiting_pid, \
         LogAttributes['blocking_pid'] AS blocking_pid, LogAttributes['check'] AS check, \
         LogAttributes['severity'] AS severity, LogAttributes['recommendation'] AS recommendation, \
         LogAttributes['error_code'] AS error_code FROM logs \
         PREWHERE tenant_id='{}' AND {} WHERE LogAttributes['event'] IN \
         ('mysql.query_stats','mysql.wait_stats','mysql.lock_wait','mysql.metadata_lock_wait','mysql.advisor','mysql.replication','mysql.replication_error','mysql.error') \
         AND ({}) ORDER BY Timestamp DESC LIMIT 200",
        quote(tenant),
        time.replace("timestamp", "Timestamp"),
        selectors.join(" OR "),
    ))
}

fn metrics_sql(
    targets: &[String],
    host: &str,
    db: &str,
    time: &str,
    tenant: &str,
) -> Option<String> {
    let selectors = selectors(targets, host, db, "Attributes", "ServiceName");
    if selectors.is_empty() {
        return None;
    }
    let names = MYSQL_METRICS
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(",");
    let selection = selectors.join(" OR ");
    let time = time.replace("timestamp", "TimeUnix");
    Some(format!(
        "SELECT MetricName AS name, argMax(Value, TimeUnix) AS value, toString(max(TimeUnix)) AS timestamp FROM metrics_gauge \
         PREWHERE tenant_id='{}' AND {} WHERE MetricName IN ({}) AND ({}) GROUP BY MetricName \
         UNION ALL SELECT MetricName AS name, argMax(Value, TimeUnix) AS value, toString(max(TimeUnix)) AS timestamp FROM metrics_sum \
         PREWHERE tenant_id='{}' AND {} WHERE MetricName IN ({}) AND ({}) GROUP BY MetricName LIMIT {}",
        quote(tenant),
        time,
        names,
        selection,
        quote(tenant),
        time,
        names,
        selection,
        MYSQL_METRICS.len() * 2,
    ))
}

fn envelope(
    args: &Value,
    service: &str,
    window: Option<InvestigationWindow>,
    status: ResultStatus,
    summary: String,
    count: u64,
    data: Value,
) -> Result<String, serde_json::Error> {
    let mut out = ToolResultEnvelope::from_legacy("inspect_mysql", args, &summary, Some(&summary));
    out.status = status.clone();
    out.source_family = SourceFamily::Database;
    out.source_tables = vec![
        "spans".into(),
        "logs".into(),
        "metrics_gauge".into(),
        "metrics_sum".into(),
    ];
    out.window = window;
    out.service = service.into();
    out.operation = "mysql_diagnostics".into();
    out.sample_count = count;
    out.quality = ResultQuality {
        band: if status == ResultStatus::Ok {
            QualityBand::High
        } else if status == ResultStatus::Partial {
            QualityBand::Medium
        } else {
            QualityBand::Low
        },
        reasons: vec![
            "database evidence came from the MySQL collector".into(),
            "query evidence uses normalized digest text".into(),
        ],
    };
    serialize_tool_output(&out, data)
}

#[async_trait::async_trait]
impl Tool for InspectMysql {
    fn name(&self) -> &str {
        "inspect_mysql"
    }
    fn description(&self) -> &str {
        "Correlate an application's db.system=mysql spans with normalized query, wait, lock, index/advisor, replication, error, and health evidence from the existing read-only MySQL collector. Never accepts a DSN or changes MySQL."
    }
    fn parameters(&self) -> Value {
        json!({"type":"object","properties":{
            "service":{"type":"string","description":"Application service whose MySQL spans should be correlated"},
            "database_host":{"type":"string","description":"Known MySQL host or integration target"},
            "database":{"type":"string","description":"Known MySQL database"},
            "minutes":{"type":"integer","description":"Recent lookback, default 30 and maximum 1440"},
            "incident_start":{"type":"string"},"incident_end":{"type":"string"},
            "baseline_start":{"type":"string"},"baseline_end":{"type":"string"}
        }})
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") && !ctx.has_scope("logs") && !ctx.has_scope("metrics") {
            return envelope(
                &args,
                "",
                None,
                ResultStatus::AccessDenied,
                "MySQL diagnostics require trace, log, or metrics access.".into(),
                0,
                json!({"warnings":["no database telemetry scope"]}),
            )
            .map_err(Into::into);
        }
        let service = args
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let host = args
            .get("database_host")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let db = args
            .get("database")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let (time, window, time_label) = time_window(&args)?;
        let mut calls = Vec::<CallRow>::new();
        if ctx.has_scope("traces") && !service.is_empty() {
            calls = crate::state::tenant_query(
                &ctx.state.ch,
                &calls_sql(service, &time, &ctx.tenant_id),
                &ctx.tenant_id,
            )
            .fetch_all()
            .await?;
        }
        let mut targets = Vec::new();
        for row in &calls {
            targets.push(row.target.clone());
            targets.push(row.database.clone());
        }
        let evidence = if ctx.has_scope("logs") {
            match logs_sql(&targets, host, db, &time, &ctx.tenant_id) {
                Some(sql) => {
                    crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
                        .fetch_all::<EvidenceRow>()
                        .await?
                }
                None => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let metrics = if ctx.has_scope("metrics") {
            match metrics_sql(&targets, host, db, &time, &ctx.tenant_id) {
                Some(sql) => {
                    crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
                        .fetch_all::<MetricRow>()
                        .await?
                }
                None => Vec::new(),
            }
        } else {
            Vec::new()
        };
        if calls.is_empty() && evidence.is_empty() && metrics.is_empty() {
            return envelope(&args, service, window, ResultStatus::NoData, format!("No MySQL dependency or collector evidence matched {time_label}."), 0, json!({"warnings":["No db.system=mysql spans or matching MySQL collector telemetry were found."]})).map_err(Into::into);
        }

        let call_data = calls.iter().map(|row| json!({"target":row.target,"database":row.database,"operation":row.operation,"calls":row.calls,"errors":row.errors,"total_ms":row.total_ms,"p95_ms":row.p95_ms})).collect::<Vec<_>>();
        let mut queries = Vec::new();
        let mut waits = Vec::new();
        let mut locks = Vec::new();
        let mut findings = Vec::new();
        let mut other = Vec::new();
        for row in &evidence {
            let base = json!({"timestamp":row.timestamp,"host":row.host,"db":row.db});
            match row.event.as_str() {
                "mysql.query_stats" => queries.push(json!({"timestamp":row.timestamp,"host":row.host,"db":row.db,"digest":row.digest,"query":compact(&row.body,320),"calls":number(&row.calls),"db_time_ms":number(&row.total_ms),"mean_ms":number(&row.mean_ms),"lock_ms":number(&row.lock_ms)})),
                "mysql.wait_stats" => waits.push(json!({"context":base,"wait":compact(&row.body,200)})),
                "mysql.lock_wait" | "mysql.metadata_lock_wait" => locks.push(json!({"context":base,"waiting_pid":row.waiting_pid,"blocking_pid":row.blocking_pid,"detail":compact(&row.body,240)})),
                "mysql.advisor" => findings.push(json!({"context":base,"severity":row.severity,"check":row.check,"recommendation":compact(&row.recommendation,260),"evidence":compact(&row.body,240)})),
                _ => other.push(json!({"context":base,"event":row.event,"error_code":row.error_code,"detail":compact(&row.body,240)})),
            }
        }
        queries.sort_by(|a, b| {
            b["db_time_ms"]
                .as_f64()
                .unwrap_or(0.0)
                .partial_cmp(&a["db_time_ms"].as_f64().unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let metric_data = metrics
            .iter()
            .map(|row| json!({"name":row.name,"value":row.value,"timestamp":row.timestamp}))
            .collect::<Vec<_>>();
        let status = if calls.is_empty() || (evidence.is_empty() && metrics.is_empty()) {
            ResultStatus::Partial
        } else {
            ResultStatus::Ok
        };
        let summary = format!(
            "MySQL diagnostics ({time_label}): {} application call groups, {} query digests, {} waits, {} lock events, and {} findings.",
            calls.len(),
            queries.len(),
            waits.len(),
            locks.len(),
            findings.len()
        );
        envelope(&args, service, window, status, summary, (calls.len()+evidence.len()+metrics.len()) as u64, json!({
            "dependencies":call_data,"queries":queries.into_iter().take(12).collect::<Vec<_>>(),
            "waits":waits.into_iter().take(12).collect::<Vec<_>>(),"locks":locks.into_iter().take(12).collect::<Vec<_>>(),
            "findings":findings.into_iter().take(12).collect::<Vec<_>>(),"replication_and_errors":other.into_iter().take(12).collect::<Vec<_>>(),
            "metrics":metric_data.into_iter().take(20).collect::<Vec<_>>(),"collector":"mysql","read_only":true,"normalized_queries":true
        })).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn span_query_is_mysql_and_tenant_scoped() {
        let sql = calls_sql("checkout", "timestamp >= now()", "tenant-a");
        assert!(sql.contains("service_name='checkout'"));
        assert!(sql.contains("tenant_id='tenant-a'"));
        assert!(sql.contains("db.system"));
    }
    #[test]
    fn collector_query_is_bounded_and_normalized() {
        let sql = logs_sql(
            &["mysql.internal".into()],
            "",
            "",
            "timestamp >= now()",
            "tenant-a",
        )
        .unwrap();
        assert!(sql.contains("mysql.query_stats"));
        assert!(sql.contains("LIMIT 200"));
    }
}
