use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct ListServices;

/// Pure SQL builder for `list_services`. The only interpolated string value
/// (`tenant_id`) is escaped with the ClickHouse-standard doubled single
/// quote (`''`); the model-supplied `minutes` is clamped here so a hostile
/// value can never widen the scan window.
#[cfg(test)]
pub(crate) fn build_list_services_sql(minutes: u64, tenant_id: &str) -> String {
    // Clamp the model-supplied window to at most 24h so the LLM can't
    // request a months-long full scan.
    let minutes = minutes.clamp(1, 1440);
    let tenant_id = tenant_id.replace('\'', "''");

    format!(
        "SELECT service_name, \
                count() AS total, \
                countIf(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500) AS errors, \
                if(count() = 0, 0, 100.0 * countIf(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500) / count()) AS error_pct, \
                quantile(0.5)(duration_ns) / 1e6 AS p50_ms, \
                quantile(0.99)(duration_ns) / 1e6 AS p99_ms \
         FROM spans \
         WHERE tenant_id = '{tenant_id}' \
           AND timestamp >= now() - INTERVAL {minutes} MINUTE \
           AND service_name != '' \
         GROUP BY service_name \
         ORDER BY error_pct DESC, total DESC \
         LIMIT 100"
    )
}

/// Pure SQL builder for `service_dependencies`. Every interpolated string
/// value (`tenant_id`, `service`) is escaped with the ClickHouse-standard
/// doubled single quote (`''`); the model-supplied `minutes` is clamped here
/// so a hostile value can never widen the self-join window.
#[cfg(test)]
pub(crate) fn build_service_dependencies_sql(
    service: &str,
    minutes: u64,
    tenant_id: &str,
) -> String {
    // Clamp the model-supplied window to at most 24h so the LLM can't
    // request a months-long full-table self-join.
    let minutes = minutes.clamp(1, 1440);
    let tenant_id = tenant_id.replace('\'', "''");

    // Restrict the join to the requested service's edges (either side).
    // Empty/absent service keeps the global dependency graph behavior.
    let service_filter = if service.is_empty() {
        String::new()
    } else {
        let safe = service.replace('\'', "''");
        format!("AND (parent.service_name = '{safe}' OR child.service_name = '{safe}') ")
    };

    // Join spans with itself on parent_span_id to find cross-service calls
    format!(
        "SELECT parent.service_name AS caller, child.service_name AS callee, \
                count() AS call_count, \
                countIf(child.status IN ('STATUS_CODE_ERROR', 'ERROR') OR child.http_status_code >= 500) AS errors, \
                if(count() = 0, 0, 100.0 * countIf(child.status IN ('STATUS_CODE_ERROR', 'ERROR') OR child.http_status_code >= 500) / count()) AS error_pct, \
                quantile(0.99)(child.duration_ns) / 1e6 AS p99_ms \
         FROM spans AS child \
         INNER JOIN spans AS parent ON child.parent_span_id = parent.span_id \
            AND parent.trace_id = child.trace_id \
         WHERE child.tenant_id = '{tenant_id}' \
           AND parent.tenant_id = '{tenant_id}' \
           AND child.timestamp >= now() - INTERVAL {minutes} MINUTE \
           AND parent.timestamp >= now() - INTERVAL {minutes} MINUTE \
           AND parent.service_name != child.service_name \
         {service_filter}\
         GROUP BY caller, callee \
         ORDER BY error_pct DESC, call_count DESC \
         LIMIT 50"
    )
}

#[derive(Debug, Deserialize)]
struct ServiceRow {
    service_name: String,
    #[serde(rename = "request_count")]
    total: u64,
    #[serde(rename = "error_count")]
    errors: u64,
    p50_ms: f64,
    p99_ms: f64,
}

#[derive(Debug, Deserialize)]
struct ServiceGraphResponse {
    nodes: Vec<ServiceRow>,
    edges: Vec<DepRow>,
}

#[async_trait::async_trait]
impl Tool for ListServices {
    fn name(&self) -> &str {
        "list_services"
    }

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
        if !ctx.has_scope("traces") {
            return Ok("Access denied: your account does not have permission to list services (service data is derived from traces). Try a different investigation approach using tools you have access to.".to_string());
        }
        // Clamp the model-supplied window to at most 24h so the LLM can't
        // request a months-long full scan.
        let minutes = args
            .get("minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(15)
            .clamp(1, 1440);
        let rows = ctx
            .state
            .query_api
            .service_graph::<ServiceGraphResponse>(&ctx.tenant_id, minutes)
            .await?
            .nodes;

        if rows.is_empty() {
            return Ok(format!("No service traffic in last {minutes}m."));
        }

        let mut out = format!("Services in last {minutes}m:\n\n");
        out.push_str(&format!(
            "{:<25} {:>8} {:>8} {:>7} {:>10} {:>10}\n",
            "Service", "Requests", "Errors", "Err%", "p50(ms)", "p99(ms)"
        ));
        out.push_str(&"-".repeat(75));
        out.push('\n');

        for r in &rows {
            let err_pct = if r.total > 0 {
                (r.errors as f64 / r.total as f64) * 100.0
            } else {
                0.0
            };
            out.push_str(&format!(
                "{:<25} {:>8} {:>8} {:>6.1}% {:>10.1} {:>10.1}\n",
                r.service_name, r.total, r.errors, err_pct, r.p50_ms, r.p99_ms
            ));
        }

        Ok(out)
    }
}

pub struct ServiceDependencies;

#[derive(Debug, Deserialize)]
struct DepRow {
    #[serde(rename = "source")]
    caller: String,
    #[serde(rename = "target")]
    callee: String,
    #[serde(rename = "request_count")]
    call_count: u64,
    #[serde(rename = "error_count")]
    errors: u64,
    avg_duration_ms: f64,
}

#[async_trait::async_trait]
impl Tool for ServiceDependencies {
    fn name(&self) -> &str {
        "service_dependencies"
    }

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
        if !ctx.has_scope("traces") {
            return Ok("Access denied: your account does not have permission to query service dependencies (service data is derived from traces). Try a different investigation approach using tools you have access to.".to_string());
        }
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        // Clamp the model-supplied window to at most 24h so the LLM can't
        // request a months-long full-table self-join.
        let minutes = args
            .get("minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(30)
            .clamp(1, 1440);
        let mut rows = ctx
            .state
            .query_api
            .service_graph::<ServiceGraphResponse>(&ctx.tenant_id, minutes)
            .await?
            .edges;
        if !service.is_empty() {
            rows.retain(|row| row.caller == service || row.callee == service);
        }

        if rows.is_empty() {
            return Ok(format!("No cross-service calls found in last {minutes}m."));
        }

        let mut out = format!("Service dependencies (last {minutes}m):\n\n");
        for r in &rows {
            out.push_str(&format!(
                "  {} → {} ({} calls, {} errors, {:.1}% error, avg={:.1}ms)\n",
                r.caller,
                r.callee,
                r.call_count,
                r.errors,
                if r.call_count > 0 {
                    r.errors as f64 * 100.0 / r.call_count as f64
                } else {
                    0.0
                },
                r.avg_duration_ms
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_list_services_sql, build_service_dependencies_sql};

    #[test]
    fn list_services_has_limit_100_and_tenant_scope() {
        let sql = build_list_services_sql(15, "default");
        assert!(sql.contains("LIMIT 100"), "{sql}");
        assert!(sql.contains("tenant_id = 'default'"), "{sql}");
    }

    #[test]
    fn list_services_clamps_minutes_and_doubles_quotes() {
        let sql = build_list_services_sql(999_999, "ten'ant");
        assert!(sql.contains("INTERVAL 1440 MINUTE"), "{sql}");
        assert!(sql.contains("tenant_id = 'ten''ant'"), "{sql}");
        assert!(
            !sql.contains("\\'"),
            "no backslash quote escaping anywhere: {sql}"
        );
    }

    #[test]
    fn dependencies_service_predicate_present_when_set_absent_when_empty() {
        let with = build_service_dependencies_sql("api", 30, "default");
        assert!(
            with.contains("(parent.service_name = 'api' OR child.service_name = 'api')"),
            "{with}"
        );

        let without = build_service_dependencies_sql("", 30, "default");
        assert!(!without.contains("parent.service_name = '"), "{without}");
        assert!(without.contains("LIMIT 50"), "{without}");
    }

    #[test]
    fn dependencies_clamps_minutes_and_doubles_quotes() {
        let sql = build_service_dependencies_sql("O'Brien", 999_999, "ten'ant");
        assert!(sql.contains("INTERVAL 1440 MINUTE"), "{sql}");
        assert!(sql.contains("parent.service_name = 'O''Brien'"), "{sql}");
        assert!(sql.contains("child.tenant_id = 'ten''ant'"), "{sql}");
        assert!(
            !sql.contains("\\'"),
            "no backslash quote escaping anywhere: {sql}"
        );
    }
}
