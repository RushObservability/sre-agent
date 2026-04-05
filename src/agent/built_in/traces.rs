use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct QueryTraces;

#[derive(Debug, Row, Deserialize)]
#[allow(dead_code)] // fields populated by ClickHouse row deserialization
struct TraceRow {
    trace_id: String,
    span_id: String,
    service_name: String,
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
                "around": {
                    "type": "string",
                    "description": "ISO 8601 timestamp to center the search on (e.g. '2025-01-15T10:30:00Z'). Searches ±5 minutes around this time. Overrides 'minutes'."
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
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let status = args.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let around = args.get("around").and_then(|v| v.as_str()).unwrap_or("");
        let minutes = args.get("minutes").and_then(|v| v.as_u64()).unwrap_or(15);
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(100);

        let mut conditions = if !around.is_empty() {
            let ts = around
                .replace('\'', "''")
                .replace('T', " ")
                .trim_end_matches('Z')
                .to_string();
            vec![
                format!("timestamp >= toDateTime64('{ts}', 9) - INTERVAL 5 MINUTE"),
                format!("timestamp <= toDateTime64('{ts}', 9) + INTERVAL 5 MINUTE"),
            ]
        } else {
            vec![format!("timestamp >= now() - INTERVAL {minutes} MINUTE")]
        };
        if !service.is_empty() {
            conditions.push(format!("service_name = '{}'", service.replace('\'', "''")));
        }
        if status == "error" {
            conditions.push("status = 'STATUS_CODE_ERROR'".to_string());
        } else if status == "ok" {
            conditions.push("status = 'STATUS_CODE_OK'".to_string());
        }

        let where_clause = conditions.join(" AND ");
        let query = format!(
            "SELECT trace_id, span_id, service_name, http_method, http_path, \
                    http_status_code, status, duration_ns, \
                    toString(timestamp) AS ts_str \
             FROM wide_events \
             WHERE {where_clause} \
             ORDER BY timestamp DESC \
             LIMIT {limit}"
        );

        let rows: Vec<TraceRow> = ctx.state.ch.query(&query).fetch_all().await?;

        if rows.is_empty() {
            return Ok("No matching spans found.".to_string());
        }

        // Summarize
        let total = rows.len();
        let errors = rows
            .iter()
            .filter(|r| r.status == "STATUS_CODE_ERROR")
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
            format!("±5m around {around}")
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
            .filter(|r| r.status == "STATUS_CODE_ERROR")
            .take(5)
            .collect();
        if !error_samples.is_empty() {
            out.push_str("\nSample error spans:\n");
            for s in error_samples {
                out.push_str(&format!(
                    "  [{ts}] {svc} {method} {path} → {code} ({dur:.1}ms) trace={tid}\n",
                    ts = s.ts_str,
                    svc = s.service_name,
                    method = s.http_method,
                    path = s.http_path,
                    code = s.http_status_code,
                    dur = s.duration_ns as f64 / 1e6,
                    tid = s.trace_id,
                ));
            }
        }

        Ok(out)
    }
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
        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("trace_id is required"))?;

        let query = format!(
            "SELECT span_id, parent_span_id, service_name, http_method, http_path, \
                    http_status_code, status, duration_ns, attributes, \
                    toString(timestamp) AS ts_str \
             FROM wide_events \
             WHERE trace_id = '{}' \
             ORDER BY timestamp ASC",
            trace_id.replace('\'', "''")
        );

        let rows: Vec<SpanRow> = ctx.state.ch.query(&query).fetch_all().await?;

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
                status = if s.status == "STATUS_CODE_ERROR" {
                    "ERROR"
                } else {
                    "OK"
                },
                code = s.http_status_code,
                dur = s.duration_ns as f64 / 1e6,
            ));
        }
        Ok(out)
    }
}
