//! Read-only PostgreSQL diagnostics backed by the PostgreSQL integration.
//!
//! The agent never receives a DSN and never opens a second database connection.
//! It correlates application database spans with the metrics and logs emitted by
//! the PostgreSQL collector, whose existing connection is the read-only one.

use crate::agent::contracts::{
    InvestigationWindow, QualityBand, ResultQuality, ResultStatus, SourceFamily,
    ToolResultEnvelope, WindowSelectionReason, serialize_tool_output,
};
use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

const MAX_DEPENDENCIES: usize = 20;
const MAX_LOG_ROWS: u64 = 200;
const MAX_OUTPUT_ROWS: usize = 12;
const POSTGRES_METRICS: &[&str] = &[
    "postgresql_backends",
    "postgresql_max_connections",
    "postgresql_connection_count",
    "postgresql_oldest_transaction_age",
    "postgresql_lock_waiters",
    "postgresql_lock_wait_age",
    "postgresql_deadlocks",
    "postgresql_autovacuum_workers",
    "postgresql_database_xid_age",
    "postgresql_recovery",
    "postgresql_recovery_replay_age",
    "postgresql_replication_replay_lag",
    "postgresql_archiver_failed_total",
    "postgresql_archiver_last_failure_age",
    "postgresql_table_dead_bytes_estimate",
];

pub struct InspectPostgresql;

#[derive(Debug, Row, Deserialize)]
struct DatabaseCallRow {
    system: String,
    target: String,
    database: String,
    operation: String,
    calls: u64,
    errors: u64,
    total_ms: f64,
    p95_ms: f64,
}

#[derive(Debug, Row, Deserialize)]
struct DatabaseLogRow {
    timestamp: String,
    event: String,
    body: String,
    host: String,
    db: String,
    severity: String,
    queryid: String,
    mean_ms: String,
    total_ms: String,
    calls: String,
    plan_ms: String,
    max_age_s: String,
    waiting: String,
    severity_attr: String,
    check: String,
    current: String,
    recommendation: String,
}

#[derive(Debug, Row, Deserialize)]
struct DatabaseMetricRow {
    name: String,
    value: f64,
    timestamp: String,
}

fn sql_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn window_sql(args: &Value) -> Result<(String, Option<InvestigationWindow>, String)> {
    if args.get("incident_start").is_some() {
        let window =
            crate::agent::contracts::require_window_from_args(args).map_err(anyhow::Error::msg)?;
        let (start, end) = (window.incident_start, window.incident_end);
        return Ok((
            format!(
                "timestamp >= toDateTime64('{}', 9, 'UTC') AND timestamp < toDateTime64('{}', 9, 'UTC')",
                start.format("%Y-%m-%d %H:%M:%S%.f"),
                end.format("%Y-%m-%d %H:%M:%S%.f"),
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
    let around_minutes = args
        .get("around_minutes")
        .and_then(Value::as_u64)
        .unwrap_or(5)
        .clamp(1, 720);
    let around = args
        .get("around")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();

    if !around.is_empty() {
        let timestamp = DateTime::parse_from_rfc3339(around)
            .map_err(|_| anyhow::anyhow!("around must be a UTC RFC3339 timestamp"))?
            .with_timezone(&Utc);
        let duration = Duration::minutes((around_minutes * 2) as i64);
        let window = InvestigationWindow::centered_on(
            timestamp,
            duration,
            Utc::now(),
            WindowSelectionReason::UserProvidedRange,
        )
        .ok();
        return Ok((
            format!(
                "timestamp >= toDateTime64('{}', 9, 'UTC') - INTERVAL {} MINUTE AND timestamp < toDateTime64('{}', 9, 'UTC') + INTERVAL {} MINUTE",
                timestamp.format("%Y-%m-%d %H:%M:%S%.f"),
                around_minutes,
                timestamp.format("%Y-%m-%d %H:%M:%S%.f"),
                around_minutes,
            ),
            window,
            format!("±{around_minutes}m around {around}"),
        ));
    }

    let now = Utc::now();
    let window = InvestigationWindow::recent(
        now,
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

fn database_span_predicate() -> &'static str {
    "(JSONExtractString(attributes, 'db.system') IN ('postgresql', 'postgres') \
        OR JSONExtractString(attributes, 'db.system.name') IN ('postgresql', 'postgres') \
        OR JSONExtractString(attributes, 'db.operation.name') != '' \
        OR JSONExtractString(attributes, 'db.operation') != '' \
        OR JSONExtractString(attributes, 'db.statement') != '')"
}

fn build_database_calls_sql(
    service: &str,
    time_predicate: &str,
    tenant_id: &str,
    limit: usize,
) -> String {
    let service = sql_quote(service);
    let tenant_id = sql_quote(tenant_id);
    format!(
        "SELECT \
            if(JSONExtractString(attributes, 'db.system') != '', JSONExtractString(attributes, 'db.system'), \
                if(JSONExtractString(attributes, 'db.system.name') != '', JSONExtractString(attributes, 'db.system.name'), 'postgresql')) AS system, \
            multiIf( \
                JSONExtractString(attributes, 'server.address') != '', JSONExtractString(attributes, 'server.address'), \
                JSONExtractString(attributes, 'net.peer.name') != '', JSONExtractString(attributes, 'net.peer.name'), \
                JSONExtractString(attributes, 'db.namespace') != '', JSONExtractString(attributes, 'db.namespace'), \
                JSONExtractString(attributes, 'db.name') != '', JSONExtractString(attributes, 'db.name'), \
                'database') AS target, \
            if(JSONExtractString(attributes, 'db.name') != '', JSONExtractString(attributes, 'db.name'), JSONExtractString(attributes, 'db.namespace')) AS database, \
            if(JSONExtractString(attributes, 'db.operation.name') != '', JSONExtractString(attributes, 'db.operation.name'), JSONExtractString(attributes, 'db.operation')) AS operation, \
            count() AS calls, \
            countIf(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500) AS errors, \
            sum(duration_ns) / 1000000.0 AS total_ms, \
            quantile(0.95)(duration_ns) / 1000000.0 AS p95_ms \
         FROM spans \
         PREWHERE tenant_id = '{tenant_id}' \
             AND service_name = '{service}' \
             AND {time_predicate} \
         WHERE {database_predicate} \
         GROUP BY system, target, database, operation \
         ORDER BY total_ms DESC \
         LIMIT {limit}",
        database_predicate = database_span_predicate(),
    )
}

fn build_database_logs_sql(
    targets: &[String],
    database_host: &str,
    database: &str,
    time_predicate: &str,
    tenant_id: &str,
) -> Option<String> {
    let mut selectors = Vec::new();
    for target in targets {
        let value = sql_quote(target);
        if !value.is_empty() && value != "database" && value != "postgresql" {
            selectors.push(format!(
                "(LogAttributes['host'] = '{value}' OR LogAttributes['db'] = '{value}')"
            ));
        }
    }
    if !database_host.trim().is_empty() {
        selectors.push(format!(
            "LogAttributes['host'] = '{}'",
            sql_quote(database_host.trim())
        ));
    }
    if !database.trim().is_empty() {
        selectors.push(format!(
            "LogAttributes['db'] = '{}'",
            sql_quote(database.trim())
        ));
    }
    if selectors.is_empty() {
        return None;
    }

    let tenant_id = sql_quote(tenant_id);
    let log_time_predicate = time_predicate.replace("timestamp", "Timestamp");
    Some(format!(
        "SELECT toString(Timestamp) AS timestamp, \
                LogAttributes['event'] AS event, Body AS body, \
                LogAttributes['host'] AS host, LogAttributes['db'] AS db, \
                SeverityText AS severity, LogAttributes['queryid'] AS queryid, \
                LogAttributes['mean_ms'] AS mean_ms, LogAttributes['total_ms'] AS total_ms, \
                LogAttributes['calls'] AS calls, LogAttributes['plan_ms'] AS plan_ms, \
                LogAttributes['max_age_s'] AS max_age_s, LogAttributes['waiting'] AS waiting, \
                LogAttributes['severity'] AS severity_attr, LogAttributes['check'] AS check, \
                LogAttributes['current'] AS current, LogAttributes['recommendation'] AS recommendation \
         FROM logs \
         PREWHERE tenant_id = '{tenant_id}' AND {log_time_predicate} \
         WHERE LogAttributes['event'] IN ( \
             'postgresql.query_stats', 'postgresql.lock_wait', 'postgresql.advisor', \
             'postgresql.logical_subscription', 'postgresql.recovery') \
           AND ({}) \
         ORDER BY Timestamp DESC \
         LIMIT {}",
        selectors.join(" OR "),
        MAX_LOG_ROWS,
    ))
}

fn build_database_metrics_sql(
    targets: &[String],
    database_host: &str,
    database: &str,
    time_predicate: &str,
    tenant_id: &str,
) -> Option<String> {
    let mut selectors = Vec::new();
    for target in targets {
        let value = sql_quote(target);
        if !value.is_empty() && value != "database" && value != "postgresql" {
            selectors.push(format!(
                "(ServiceName = '{value}' OR Attributes['host'] = '{value}' OR Attributes['db'] = '{value}')"
            ));
        }
    }
    if !database_host.trim().is_empty() {
        let value = sql_quote(database_host.trim());
        selectors.push(format!(
            "(ServiceName = '{value}' OR Attributes['host'] = '{value}')"
        ));
    }
    if !database.trim().is_empty() {
        selectors.push(format!(
            "Attributes['db'] = '{}'",
            sql_quote(database.trim())
        ));
    }
    if selectors.is_empty() {
        return None;
    }

    let tenant_id = sql_quote(tenant_id);
    let metric_time_predicate = time_predicate.replace("timestamp", "TimeUnix");
    let metric_names = POSTGRES_METRICS
        .iter()
        .map(|name| format!("'{}'", sql_quote(name)))
        .collect::<Vec<_>>()
        .join(", ");
    let selector = selectors.join(" OR ");
    Some(format!(
        "SELECT MetricName AS name, argMax(Value, TimeUnix) AS value, toString(max(TimeUnix)) AS timestamp \
         FROM metrics_gauge \
         PREWHERE tenant_id = '{tenant_id}' AND {metric_time_predicate} \
         WHERE MetricName IN ({metric_names}) AND ({selector}) \
         GROUP BY MetricName \
         UNION ALL \
         SELECT MetricName AS name, argMax(Value, TimeUnix) AS value, toString(max(TimeUnix)) AS timestamp \
         FROM metrics_sum \
         PREWHERE tenant_id = '{tenant_id}' AND {metric_time_predicate} \
         WHERE MetricName IN ({metric_names}) AND ({selector}) \
         GROUP BY MetricName \
         LIMIT {}",
        POSTGRES_METRICS.len() * 2,
    ))
}

fn number(value: &str) -> f64 {
    value.parse::<f64>().unwrap_or(0.0)
}

fn compact(value: &str, max: usize) -> String {
    crate::agent::memory::truncate_at_char_boundary(value, max).to_string()
}

fn make_envelope(
    args: &Value,
    service: &str,
    window: Option<InvestigationWindow>,
    status: ResultStatus,
    summary: String,
    sample_count: u64,
    data: Value,
) -> Result<String, serde_json::Error> {
    let mut envelope =
        ToolResultEnvelope::from_legacy("inspect_postgresql", args, &summary, Some(&summary));
    envelope.status = status.clone();
    envelope.source_family = SourceFamily::Database;
    envelope.source_tables = vec![
        "spans".into(),
        "logs".into(),
        "metrics_gauge".into(),
        "metrics_sum".into(),
    ];
    envelope.window = window;
    envelope.service = service.to_string();
    envelope.operation = "postgresql_diagnostics".into();
    envelope.sample_count = sample_count;
    envelope.quality = ResultQuality {
        band: match status {
            ResultStatus::Ok => QualityBand::High,
            ResultStatus::Partial => QualityBand::Medium,
            _ => QualityBand::Low,
        },
        reasons: vec![
            "database evidence came from PostgreSQL collector telemetry".into(),
            "the collector uses the configured read-only PostgreSQL connection".into(),
        ],
    };
    serialize_tool_output(&envelope, data)
}

#[async_trait::async_trait]
impl Tool for InspectPostgresql {
    fn name(&self) -> &str {
        "inspect_postgresql"
    }

    fn description(&self) -> &str {
        "Inspect PostgreSQL health for an application that uses PostgreSQL. \
         First correlate the app's db.system=postgresql spans to a host/database, \
         then read slow query, planning, lock, advisor, recovery, and replication \
         evidence emitted by the PostgreSQL integration's existing read-only collector. \
         This tool never accepts a DSN and never changes the database."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Application service whose database spans should be correlated"
                },
                "database_host": {
                    "type": "string",
                    "description": "Known PostgreSQL host or integration target name, when the user supplied one"
                },
                "database": {
                    "type": "string",
                    "description": "Known PostgreSQL database name, when the user supplied one"
                },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 UTC timestamp to center the diagnostic window on"
                },
                "around_minutes": {
                    "type": "integer",
                    "description": "Minutes on each side of around (default 5, max 720)"
                },
                "minutes": {
                    "type": "integer",
                    "description": "Recent lookback when around is absent (default 30, max 1440)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") && !ctx.has_scope("logs") && !ctx.has_scope("metrics") {
            return make_envelope(
                &args,
                "",
                None,
                ResultStatus::AccessDenied,
                "PostgreSQL diagnostics require trace, log, or metrics access.".into(),
                0,
                json!({"warnings":["caller lacks traces, logs, and metrics scope"]}),
            )
            .map_err(Into::into);
        }

        let service = args
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let database_host = args
            .get("database_host")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let database = args
            .get("database")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let (time_predicate, window, time_desc) = window_sql(&args)?;
        let mut dependencies: Vec<DatabaseCallRow> = Vec::new();
        let mut log_rows: Vec<DatabaseLogRow> = Vec::new();
        let mut metric_rows: Vec<DatabaseMetricRow> = Vec::new();

        if ctx.has_scope("traces") && !service.is_empty() {
            let sql = build_database_calls_sql(
                service,
                &time_predicate,
                &ctx.tenant_id,
                MAX_DEPENDENCIES,
            );
            dependencies = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
                .fetch_all()
                .await?;
        }

        let mut targets = Vec::new();
        for row in &dependencies {
            targets.push(row.target.clone());
            if !row.database.is_empty() {
                targets.push(row.database.clone());
            }
        }
        if ctx.has_scope("logs") {
            if let Some(sql) = build_database_logs_sql(
                &targets,
                database_host,
                database,
                &time_predicate,
                &ctx.tenant_id,
            ) {
                log_rows = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
                    .fetch_all()
                    .await?;
            }
        }
        if ctx.has_scope("metrics") {
            if let Some(sql) = build_database_metrics_sql(
                &targets,
                database_host,
                database,
                &time_predicate,
                &ctx.tenant_id,
            ) {
                metric_rows = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
                    .fetch_all()
                    .await?;
            }
        }

        if dependencies.is_empty() && log_rows.is_empty() && metric_rows.is_empty() {
            let summary = if service.is_empty() && database_host.is_empty() && database.is_empty() {
                format!("No PostgreSQL dependency or integration evidence found in {time_desc}.")
            } else {
                format!(
                    "No PostgreSQL evidence matched the requested application/database in {time_desc}."
                )
            };
            return make_envelope(
                &args,
                service,
                window,
                ResultStatus::NoData,
                summary,
                0,
                json!({
                    "dependencies": [],
                    "slow_queries": [],
                    "lock_waits": [],
                    "advisors": [],
                    "metrics": [],
                    "warnings": ["No db.system=postgresql spans or matching PostgreSQL collector events were found."]
                }),
            )
            .map_err(Into::into);
        }

        let mut out = format!(
            "PostgreSQL diagnostics ({time_desc}) using the integration's read-only collector evidence.\n"
        );
        if !service.is_empty() {
            out.push_str(&format!("Application service: {service}\n"));
        }

        let dependency_data: Vec<Value> = dependencies
            .iter()
            .map(|row| {
                json!({
                    "system": row.system,
                    "target": row.target,
                    "database": row.database,
                    "operation": row.operation,
                    "calls": row.calls,
                    "errors": row.errors,
                    "total_ms": row.total_ms,
                    "p95_ms": row.p95_ms,
                })
            })
            .collect();
        if !dependencies.is_empty() {
            out.push_str("\nApplication database calls:\n");
            for row in dependencies.iter().take(MAX_OUTPUT_ROWS) {
                out.push_str(&format!(
                    "  {} {} / {} — {} calls, {:.1}ms total, p95 {:.1}ms, {} errors\n",
                    row.system,
                    row.target,
                    if row.database.is_empty() {
                        "database"
                    } else {
                        &row.database
                    },
                    row.calls,
                    row.total_ms,
                    row.p95_ms,
                    row.errors
                ));
            }
        }

        let mut slow_queries = Vec::new();
        let mut lock_waits = Vec::new();
        let mut advisors = Vec::new();
        let current_metrics: Vec<Value> = metric_rows
            .iter()
            .map(|row| json!({"name": row.name, "value": row.value, "timestamp": row.timestamp}))
            .collect();
        for row in &log_rows {
            match row.event.as_str() {
                "postgresql.query_stats" => slow_queries.push(json!({
                    "timestamp": row.timestamp,
                    "host": row.host,
                    "db": row.db,
                    "queryid": row.queryid,
                    "mean_ms": number(&row.mean_ms),
                    "total_ms": number(&row.total_ms),
                    "calls": number(&row.calls),
                    "plan_ms": number(&row.plan_ms),
                    "query": compact(&row.body, 320),
                })),
                "postgresql.lock_wait" => lock_waits.push(json!({
                    "timestamp": row.timestamp,
                    "host": row.host,
                    "waiting": number(&row.waiting),
                    "max_age_s": number(&row.max_age_s),
                    "detail": compact(&row.body, 240),
                })),
                "postgresql.advisor" => advisors.push(json!({
                    "timestamp": row.timestamp,
                    "host": row.host,
                    "db": row.db,
                    "severity": if row.severity_attr.is_empty() { &row.severity } else { &row.severity_attr },
                    "check": row.check,
                    "current": compact(&row.current, 180),
                    "recommendation": compact(&row.recommendation, 260),
                })),
                _ => {}
            }
        }
        slow_queries.sort_by(|a, b| {
            b.get("mean_ms")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .partial_cmp(&a.get("mean_ms").and_then(Value::as_f64).unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if !slow_queries.is_empty() {
            out.push_str("\nSlowest PostgreSQL query samples:\n");
            for row in slow_queries.iter().take(MAX_OUTPUT_ROWS) {
                out.push_str(&format!(
                    "  mean={:.1}ms plan={:.1}ms calls={} db={} query={}\n",
                    row["mean_ms"].as_f64().unwrap_or(0.0),
                    row["plan_ms"].as_f64().unwrap_or(0.0),
                    row["calls"].as_f64().unwrap_or(0.0),
                    row["db"].as_str().unwrap_or(""),
                    row["query"].as_str().unwrap_or(""),
                ));
            }
        }
        if !lock_waits.is_empty() {
            out.push_str("\nLock contention:\n");
            for row in lock_waits.iter().take(MAX_OUTPUT_ROWS) {
                out.push_str(&format!(
                    "  waiting={} oldest_wait={:.1}s {}\n",
                    row["waiting"].as_f64().unwrap_or(0.0),
                    row["max_age_s"].as_f64().unwrap_or(0.0),
                    row["detail"].as_str().unwrap_or(""),
                ));
            }
        }
        if !advisors.is_empty() {
            out.push_str("\nPostgreSQL advisor findings:\n");
            for row in advisors.iter().take(MAX_OUTPUT_ROWS) {
                out.push_str(&format!(
                    "  [{}] {}: {} — {}\n",
                    row["severity"].as_str().unwrap_or("info"),
                    row["check"].as_str().unwrap_or("finding"),
                    row["current"].as_str().unwrap_or(""),
                    row["recommendation"].as_str().unwrap_or(""),
                ));
            }
        }
        if !current_metrics.is_empty() {
            out.push_str("\nCurrent PostgreSQL health signals:\n");
            for row in current_metrics.iter().take(MAX_OUTPUT_ROWS) {
                out.push_str(&format!(
                    "  {} = {:.2}\n",
                    row["name"].as_str().unwrap_or("metric"),
                    row["value"].as_f64().unwrap_or(0.0),
                ));
            }
        }

        let status = if dependencies.is_empty() || (log_rows.is_empty() && metric_rows.is_empty()) {
            ResultStatus::Partial
        } else {
            ResultStatus::Ok
        };
        make_envelope(
            &args,
            service,
            window,
            status,
            out,
            (dependencies.len() + log_rows.len() + metric_rows.len()) as u64,
            json!({
                "dependencies": dependency_data,
                "slow_queries": slow_queries.into_iter().take(MAX_OUTPUT_ROWS).collect::<Vec<_>>(),
                "lock_waits": lock_waits.into_iter().take(MAX_OUTPUT_ROWS).collect::<Vec<_>>(),
                "advisors": advisors.into_iter().take(MAX_OUTPUT_ROWS).collect::<Vec<_>>(),
                "metrics": current_metrics.into_iter().take(MAX_OUTPUT_ROWS).collect::<Vec<_>>(),
                "collector": "postgresql",
                "read_only": true,
            }),
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_database_calls_sql, build_database_logs_sql, build_database_metrics_sql};

    #[test]
    fn app_query_sql_requires_postgresql_attributes_and_tenant() {
        let sql = build_database_calls_sql("payments", "timestamp >= now()", "tenant", 20);
        assert!(sql.contains("service_name = 'payments'"));
        assert!(sql.contains("tenant_id = 'tenant'"));
        assert!(sql.contains("db.system"));
        assert!(sql.contains("LIMIT 20"));
    }

    #[test]
    fn database_log_sql_is_bounded_to_matched_targets() {
        let sql = build_database_logs_sql(
            &["db.internal".into()],
            "",
            "",
            "Timestamp >= now()",
            "tenant",
        )
        .unwrap();
        assert!(sql.contains("LogAttributes['host'] = 'db.internal'"));
        assert!(sql.contains("postgresql.query_stats"));
        assert!(sql.contains("LIMIT 200"));
    }

    #[test]
    fn database_log_sql_requires_a_target() {
        assert!(build_database_logs_sql(&[], "", "", "Timestamp >= now()", "tenant").is_none());
    }

    #[test]
    fn database_metrics_sql_is_tenant_scoped_and_bounded() {
        let sql = build_database_metrics_sql(
            &["db.internal".into()],
            "",
            "",
            "timestamp >= now()",
            "tenant",
        )
        .unwrap();
        assert!(sql.contains("FROM metrics_gauge"));
        assert!(sql.contains("FROM metrics_sum"));
        assert!(sql.contains("tenant_id = 'tenant'"));
        assert!(sql.contains("ServiceName = 'db.internal'"));
    }
}
