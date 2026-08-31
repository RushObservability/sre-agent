use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct QueryTraces;

/// Pure SQL builder for `query_traces`. Every interpolated string value is
/// escaped with the ClickHouse-standard doubled single quote (`''`); the
/// model-supplied `minutes`/`limit` are clamped here so a hostile value can
/// never widen the scan window or row count.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_query_traces_sql(
    service: &str,
    status: &str,
    span_name: &str,
    min_duration_ms: u64,
    order_by: &str,
    around: &str,
    around_minutes: u64,
    minutes: u64,
    limit: u64,
    tenant_id: &str,
) -> String {
    // Clamp the model-supplied window to at most 24h so the LLM can't
    // request a months-long full scan.
    let minutes = minutes.clamp(1, 1440);
    let around_minutes = around_minutes.clamp(1, 720);
    let limit = limit.min(100);
    let tenant_id = tenant_id.replace('\'', "''");

    let mut conditions = if !around.is_empty() {
        let ts = around
            .replace('\'', "''")
            .replace('T', " ")
            .trim_end_matches('Z')
            .to_string();
        vec![
            format!("timestamp >= toDateTime64('{ts}', 9) - INTERVAL {around_minutes} MINUTE"),
            format!("timestamp <= toDateTime64('{ts}', 9) + INTERVAL {around_minutes} MINUTE"),
        ]
    } else {
        vec![format!("timestamp >= now() - INTERVAL {minutes} MINUTE")]
    };
    conditions.push(format!("tenant_id = '{tenant_id}'"));
    if !service.is_empty() {
        conditions.push(format!("service_name = '{}'", service.replace('\'', "''")));
    }
    if !span_name.is_empty() {
        conditions.push(format!("span_name = '{}'", span_name.replace('\'', "''")));
    }
    if min_duration_ms > 0 {
        conditions.push(format!(
            "duration_ns >= {}",
            min_duration_ms.saturating_mul(1_000_000)
        ));
    }
    if status == "error" {
        conditions.push(
            "(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500)".to_string(),
        );
    } else if status == "ok" {
        conditions
            .push("status IN ('STATUS_CODE_OK', 'OK') AND http_status_code < 500".to_string());
    }

    let where_clause = conditions.join(" AND ");
    let order = if order_by == "duration" {
        "duration_ns DESC"
    } else {
        "timestamp DESC"
    };
    format!(
        "SELECT trace_id, span_id, parent_span_id, service_name, span_name, http_method, http_path, \
                http_status_code, status, duration_ns, \
                toString(timestamp) AS ts_str \
         FROM spans \
         WHERE {where_clause} \
         ORDER BY {order} \
         LIMIT {limit}"
    )
}

/// Pure SQL builder for `get_trace`. Both interpolated values (`trace_id`,
/// `tenant_id`) are escaped with the ClickHouse-standard doubled single
/// quote (`''`).
pub(crate) fn build_get_trace_sql(trace_id: &str, tenant_id: &str) -> String {
    let tenant_id = tenant_id.replace('\'', "''");
    format!(
        "SELECT span_id, parent_span_id, service_name, http_method, http_path, \
                http_status_code, status, duration_ns, attributes, \
                toString(timestamp) AS ts_str \
         FROM spans \
         WHERE trace_id = '{}' \
           AND tenant_id = '{tenant_id}' \
         ORDER BY timestamp ASC",
        trace_id.replace('\'', "''")
    )
}

#[derive(Debug, Row, Deserialize)]
#[allow(dead_code)] // fields populated by ClickHouse row deserialization
struct TraceRow {
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    service_name: String,
    span_name: String,
    http_method: String,
    http_path: String,
    http_status_code: u16,
    status: String,
    duration_ns: u64,
    ts_str: String,
}

#[async_trait::async_trait]
impl Tool for QueryTraces {
    fn name(&self) -> &str {
        "query_traces"
    }

    fn description(&self) -> &str {
        "Search recent traces/spans. Returns matching spans with service, status, duration, and path. \
         Use this to find errors, slow requests, or traffic patterns for a service."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Filter by service name"
                },
                "status": {
                    "type": "string",
                    "enum": ["error", "ok"],
                    "description": "Filter by span status (error or ok)"
                },
                "span_name": {
                    "type": "string",
                    "description": "Filter by operation/span name"
                },
                "min_duration_ms": {
                    "type": "integer",
                    "description": "Only return spans at least this slow (milliseconds)"
                },
                "order_by": {
                    "type": "string",
                    "enum": ["time", "duration"],
                    "description": "Return newest spans or slowest spans first (default time)"
                },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 timestamp to center the search on (e.g. '2025-01-15T10:30:00Z'). Searches ±5 minutes around this time. Overrides 'minutes'."
                },
                "around_minutes": {
                    "type": "integer",
                    "description": "Window on each side of 'around' in minutes (default 5, max 720)"
                },
                "minutes": {
                    "type": "integer",
                    "description": "Look back this many minutes from now (default 15). Ignored if 'around' is set."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max spans to return (default 20, max 100)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") {
            return Ok("Access denied: your account does not have permission to query traces. Try a different investigation approach using tools you have access to.".to_string());
        }
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let status = args.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let span_name = args.get("span_name").and_then(|v| v.as_str()).unwrap_or("");
        let min_duration_ms = args
            .get("min_duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .min(86_400_000);
        let order_by = args
            .get("order_by")
            .and_then(|v| v.as_str())
            .unwrap_or("time");
        let around = args.get("around").and_then(|v| v.as_str()).unwrap_or("");
        let around_minutes = args
            .get("around_minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(5)
            .clamp(1, 720);
        // Clamp the model-supplied window to at most 24h so the LLM can't
        // request a months-long full scan.
        let minutes = args
            .get("minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(15)
            .clamp(1, 1440);
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(100);

        let query = build_query_traces_sql(
            service,
            status,
            span_name,
            min_duration_ms,
            order_by,
            around,
            around_minutes,
            minutes,
            limit,
            &ctx.tenant_id,
        );

        let rows: Vec<TraceRow> = crate::state::tenant_query(&ctx.state.ch, &query, &ctx.tenant_id)
            .fetch_all()
            .await?;

        if rows.is_empty() {
            return Ok("No matching spans found.".to_string());
        }

        // Summarize
        let total = rows.len();
        let errors = rows
            .iter()
            .filter(|r| is_error(r.status.as_str(), r.http_status_code))
            .count();
        let mut svc_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut path_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut durations: Vec<u64> = Vec::new();

        for r in &rows {
            *svc_counts.entry(r.service_name.clone()).or_default() += 1;
            if !r.http_path.is_empty() {
                *path_counts
                    .entry(format!("{} {}", r.http_method, r.http_path))
                    .or_default() += 1;
            }
            durations.push(r.duration_ns);
        }
        durations.sort();
        let p50 = durations.get(durations.len() / 2).copied().unwrap_or(0);
        let p99 = durations
            .get(durations.len() * 99 / 100)
            .copied()
            .unwrap_or(0);

        let time_desc = if !around.is_empty() {
            format!("±{around_minutes}m around {around}")
        } else {
            format!("last {minutes}m")
        };
        let mut out = format!("Found {total} spans ({errors} errors) ({time_desc}).\n");
        out.push_str(&format!(
            "Latency: p50={:.1}ms p99={:.1}ms\n",
            p50 as f64 / 1e6,
            p99 as f64 / 1e6
        ));

        if !path_counts.is_empty() {
            out.push_str("\nTop paths:\n");
            let mut sorted: Vec<_> = path_counts.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            for (path, count) in sorted.iter().take(10) {
                out.push_str(&format!("  {path}: {count} spans\n"));
            }
        }

        // Show a few sample error spans
        let error_samples: Vec<&TraceRow> = rows
            .iter()
            .filter(|r| is_error(r.status.as_str(), r.http_status_code))
            .take(5)
            .collect();
        if !error_samples.is_empty() {
            out.push_str("\nSample error spans:\n");
            for s in error_samples {
                out.push_str(&format!(
                    "  [{ts}] {svc} {span} {method} {path} → {code} ({dur:.1}ms) trace={tid} span={sid} parent={pid}\n",
                    ts = s.ts_str,
                    svc = s.service_name,
                    span = s.span_name,
                    method = s.http_method,
                    path = s.http_path,
                    code = s.http_status_code,
                    dur = s.duration_ns as f64 / 1e6,
                    tid = s.trace_id,
                    sid = s.span_id,
                    pid = if s.parent_span_id.is_empty() { "-" } else { &s.parent_span_id },
                ));
            }
        }

        Ok(out)
    }
}

fn is_error(status: &str, http_status_code: u16) -> bool {
    matches!(status, "STATUS_CODE_ERROR" | "ERROR") || http_status_code >= 500
}

pub struct GetTrace;

#[derive(Debug, Row, Deserialize)]
#[allow(dead_code)] // fields populated by ClickHouse row deserialization
struct SpanRow {
    span_id: String,
    parent_span_id: String,
    service_name: String,
    http_method: String,
    http_path: String,
    http_status_code: u16,
    status: String,
    duration_ns: u64,
    attributes: String,
    ts_str: String,
}

#[async_trait::async_trait]
impl Tool for GetTrace {
    fn name(&self) -> &str {
        "get_trace"
    }

    fn description(&self) -> &str {
        "Get all spans for a specific trace ID. Shows the full request flow across services."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "required": ["trace_id"],
            "properties": {
                "trace_id": {
                    "type": "string",
                    "description": "The trace ID to look up"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("traces") {
            return Ok("Access denied: your account does not have permission to query traces. Try a different investigation approach using tools you have access to.".to_string());
        }
        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("trace_id is required"))?;

        let query = build_get_trace_sql(trace_id, &ctx.tenant_id);

        let rows: Vec<SpanRow> = crate::state::tenant_query(&ctx.state.ch, &query, &ctx.tenant_id)
            .fetch_all()
            .await?;

        if rows.is_empty() {
            return Ok(format!("No spans found for trace {trace_id}"));
        }

        let mut out = format!("Trace {trace_id}: {} spans\n\n", rows.len());
        for s in &rows {
            let indent = if s.parent_span_id.is_empty() {
                ""
            } else {
                "  "
            };
            out.push_str(&format!(
                "{indent}[{ts}] {svc} {method} {path} → {status} {code} ({dur:.1}ms)\n",
                ts = s.ts_str,
                svc = s.service_name,
                method = s.http_method,
                path = s.http_path,
                status = if is_error(&s.status, s.http_status_code) {
                    "ERROR"
                } else {
                    "OK"
                },
                code = s.http_status_code,
                dur = s.duration_ns as f64 / 1e6,
            ));
            if !s.attributes.is_empty() && s.attributes != "{}" {
                out.push_str(&format!(
                    "    span={} parent={} attributes={}\n",
                    s.span_id,
                    if s.parent_span_id.is_empty() {
                        "-"
                    } else {
                        &s.parent_span_id
                    },
                    crate::agent::memory::truncate_at_char_boundary(&s.attributes, 500)
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_get_trace_sql, build_query_traces_sql};

    #[test]
    fn service_filter_present_when_set_absent_when_empty() {
        let with = build_query_traces_sql("api", "", "", 0, "time", "", 5, 15, 20, "default");
        assert!(with.contains("service_name = 'api'"));

        let without = build_query_traces_sql("", "", "", 0, "time", "", 5, 15, 20, "default");
        assert!(!without.contains("service_name = '"));
    }

    #[test]
    fn single_quotes_are_doubled_never_backslash_escaped() {
        let sql =
            build_query_traces_sql("O'Brien", "error", "", 0, "time", "", 5, 15, 20, "ten'ant");
        assert!(sql.contains("service_name = 'O''Brien'"), "{sql}");
        assert!(sql.contains("tenant_id = 'ten''ant'"), "{sql}");
        assert!(
            !sql.contains("\\'"),
            "no backslash quote escaping anywhere: {sql}"
        );
    }

    #[test]
    fn status_filter_maps_to_status_codes() {
        let err = build_query_traces_sql("", "error", "", 0, "time", "", 5, 15, 20, "default");
        assert!(err.contains("http_status_code >= 500"));
        let ok = build_query_traces_sql("", "ok", "", 0, "time", "", 5, 15, 20, "default");
        assert!(ok.contains("http_status_code < 500"));
        let none = build_query_traces_sql("", "", "", 0, "time", "", 5, 15, 20, "default");
        assert!(!none.contains("status = 'STATUS_CODE"));
    }

    #[test]
    fn minutes_clamp_to_1440_and_limit_present() {
        let sql = build_query_traces_sql("", "", "", 0, "time", "", 5, 999_999, 20, "default");
        assert!(sql.contains("INTERVAL 1440 MINUTE"), "{sql}");
        assert!(sql.contains("LIMIT 20"), "{sql}");

        let capped = build_query_traces_sql("", "", "", 0, "time", "", 5, 15, 9_999, "default");
        assert!(
            capped.contains("LIMIT 100"),
            "limit capped at 100: {capped}"
        );
    }

    #[test]
    fn get_trace_escapes_trace_id_and_tenant() {
        let sql = build_get_trace_sql("ab'cd", "ten'ant");
        assert!(sql.contains("trace_id = 'ab''cd'"), "{sql}");
        assert!(sql.contains("tenant_id = 'ten''ant'"), "{sql}");
        assert!(!sql.contains("\\'"), "{sql}");
    }

    #[test]
    fn filters_slow_operations_and_can_order_by_duration() {
        let sql = build_query_traces_sql(
            "api",
            "",
            "GET /checkout",
            250,
            "duration",
            "",
            5,
            15,
            20,
            "default",
        );
        assert!(sql.contains("span_name = 'GET /checkout'"), "{sql}");
        assert!(sql.contains("duration_ns >= 250000000"), "{sql}");
        assert!(sql.contains("ORDER BY duration_ns DESC"), "{sql}");
    }
}
