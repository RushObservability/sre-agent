use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct ListServices;

#[derive(Debug, Row, Deserialize)]
struct ServiceRow {
    service_name: String,
    total: u64,
    errors: u64,
    p50_ms: f64,
    p99_ms: f64,
}

#[async_trait::async_trait]
impl Tool for ListServices {
    fn name(&self) -> &str { "list_services" }

    fn description(&self) -> &str {
        "List all services with their request count, error count, and latency. \
         Use this to get an overview of which services are healthy or degraded."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "minutes": {
                    "type": "integer",
                    "description": "Look back this many minutes (default 15)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let minutes = args.get("minutes").and_then(|v| v.as_u64()).unwrap_or(15);

        let query = format!(
            "SELECT service_name, \
                    count() AS total, \
                    countIf(status = 'STATUS_CODE_ERROR') AS errors, \
                    quantile(0.5)(duration_ns) / 1e6 AS p50_ms, \
                    quantile(0.99)(duration_ns) / 1e6 AS p99_ms \
             FROM wide_events \
             WHERE timestamp >= now() - INTERVAL {minutes} MINUTE \
               AND service_name != '' \
             GROUP BY service_name \
             ORDER BY total DESC"
        );

        let rows: Vec<ServiceRow> = ctx.state.ch.query(&query).fetch_all().await?;

        if rows.is_empty() {
            return Ok(format!("No service traffic in last {minutes}m."));
        }

        let mut out = format!("Services in last {minutes}m:\n\n");
        out.push_str(&format!("{:<25} {:>8} {:>8} {:>6} {:>10} {:>10}\n",
            "Service", "Requests", "Errors", "Err%", "p50(ms)", "p99(ms)"));
        out.push_str(&"-".repeat(75));
        out.push('\n');

        for r in &rows {
            let err_pct = if r.total > 0 { (r.errors as f64 / r.total as f64) * 100.0 } else { 0.0 };
            out.push_str(&format!(
                "{:<25} {:>8} {:>8} {:>5.1}% {:>10.1} {:>10.1}\n",
                r.service_name, r.total, r.errors, err_pct, r.p50_ms, r.p99_ms
            ));
        }

        Ok(out)
    }
}

pub struct ServiceDependencies;

#[derive(Debug, Row, Deserialize)]
struct DepRow {
    caller: String,
    callee: String,
    call_count: u64,
}

#[async_trait::async_trait]
impl Tool for ServiceDependencies {
    fn name(&self) -> &str { "service_dependencies" }

    fn description(&self) -> &str {
        "Get the dependency graph showing which services call which other services. \
         Use this to understand upstream/downstream impact of an incident."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Show dependencies for this service (optional — shows all if omitted)"
                },
                "minutes": {
                    "type": "integer",
                    "description": "Look back this many minutes (default 30)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let minutes = args.get("minutes").and_then(|v| v.as_u64()).unwrap_or(30);

        let mut conditions = vec![
            format!("timestamp >= now() - INTERVAL {minutes} MINUTE"),
            "parent_span_id != ''".to_string(),
        ];
        if !service.is_empty() {
            let safe = service.replace('\'', "''");
            conditions.push(format!(
                "(caller = '{safe}' OR callee = '{safe}')"
            ));
        }

        // Join wide_events with itself on parent_span_id to find cross-service calls
        let query = format!(
            "SELECT parent.service_name AS caller, child.service_name AS callee, \
                    count() AS call_count \
             FROM wide_events AS child \
             INNER JOIN wide_events AS parent ON child.parent_span_id = parent.span_id \
                AND parent.trace_id = child.trace_id \
             WHERE child.timestamp >= now() - INTERVAL {minutes} MINUTE \
               AND parent.timestamp >= now() - INTERVAL {minutes} MINUTE \
               AND parent.service_name != child.service_name \
             GROUP BY caller, callee \
             ORDER BY call_count DESC \
             LIMIT 50"
        );

        let rows: Vec<DepRow> = ctx.state.ch.query(&query).fetch_all().await?;

        if rows.is_empty() {
            return Ok(format!("No cross-service calls found in last {minutes}m."));
        }

        let mut out = format!("Service dependencies (last {minutes}m):\n\n");
        for r in &rows {
            out.push_str(&format!("  {} → {} ({} calls)\n", r.caller, r.callee, r.call_count));
        }
        Ok(out)
    }
}
