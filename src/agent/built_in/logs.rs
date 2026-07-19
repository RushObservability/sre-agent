use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct SearchLogs;

/// Pure SQL builder for `search_logs`. Every interpolated string value is
/// escaped with the ClickHouse-standard doubled single quote (`''`); the
/// model-supplied `minutes`/`limit` are clamped here so a hostile value can
/// never widen the scan window or row count.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_search_logs_sql(
    service: &str,
    severity: &str,
    query_text: &str,
    trace_id: &str,
    span_id: &str,
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
    let limit = limit.min(200);
    let tenant_id = tenant_id.replace('\'', "''");

    let mut conditions = if !around.is_empty() {
        // ClickHouse expects 'YYYY-MM-DD hh:mm:ss' — strip trailing Z and replace T with space
        let ts = around
            .replace('\'', "''")
            .replace('T', " ")
            .trim_end_matches('Z')
            .to_string();
        vec![
            format!("Timestamp >= toDateTime64('{ts}', 9) - INTERVAL {around_minutes} MINUTE"),
            format!("Timestamp <= toDateTime64('{ts}', 9) + INTERVAL {around_minutes} MINUTE"),
        ]
    } else {
        vec![format!("Timestamp >= now() - INTERVAL {minutes} MINUTE")]
    };
    conditions.push(format!("tenant_id = '{tenant_id}'"));
    if !service.is_empty() {
        conditions.push(format!("ServiceName = '{}'", service.replace('\'', "''")));
    }
    if !severity.is_empty() {
        // Map severity to include that level and above
        let levels = match severity.to_uppercase().as_str() {
            "ERROR" => vec!["ERROR", "FATAL", "CRITICAL"],
            "WARN" => vec!["WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"],
            "INFO" => vec!["INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"],
            _ => vec![severity],
        };
        let in_list: String = levels
            .iter()
            .map(|l| format!("'{}'", l.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        conditions.push(format!("SeverityText IN ({in_list})"));
    }
    if !query_text.is_empty() {
        let q = query_text
            .to_lowercase()
            .replace('\'', "''")
            .replace('%', "\\%");
        conditions.push(format!(
            "(lower(Body) LIKE '%{q}%' OR lower(toString(LogAttributes)) LIKE '%{q}%' OR lower(toString(ResourceAttributes)) LIKE '%{q}%')"
        ));
    }
    if !trace_id.is_empty() {
        conditions.push(format!("TraceId = '{}'", trace_id.replace('\'', "''")));
    }
    if !span_id.is_empty() {
        conditions.push(format!("SpanId = '{}'", span_id.replace('\'', "''")));
    }

    let where_clause = conditions.join(" AND ");
    format!(
        "SELECT toString(Timestamp) AS timestamp, \
                ServiceName AS service_name, \
                SeverityText AS severity, \
                Body AS body, \
                TraceId AS trace_id, \
                SpanId AS span_id, \
                toString(LogAttributes) AS log_attributes, \
                toString(ResourceAttributes) AS resource_attributes \
         FROM logs \
         WHERE {where_clause} \
         ORDER BY Timestamp DESC \
         LIMIT {limit}"
    )
}

#[derive(Debug, Row, Deserialize)]
#[allow(dead_code)] // fields populated by ClickHouse row deserialization
struct LogRow {
    timestamp: String,
    service_name: String,
    severity: String,
    body: String,
    trace_id: String,
    span_id: String,
    log_attributes: String,
    resource_attributes: String,
}

#[async_trait::async_trait]
impl Tool for SearchLogs {
    fn name(&self) -> &str {
        "search_logs"
    }

    fn description(&self) -> &str {
        "Search application logs. Returns matching log entries with timestamp, service, severity, and message. \
         Use this to find error messages, stack traces, and application-level details."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Filter by service name"
                },
                "severity": {
                    "type": "string",
                    "enum": ["ERROR", "WARN", "INFO", "DEBUG"],
                    "description": "Minimum severity level"
                },
                "query": {
                    "type": "string",
                    "description": "Text search across the log body and structured attributes (case-insensitive substring match)"
                },
                "trace_id": {
                    "type": "string",
                    "description": "Filter to logs correlated with this trace ID"
                },
                "span_id": {
                    "type": "string",
                    "description": "Filter to logs correlated with this span ID"
                },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 timestamp to center the search on (e.g. '2025-01-15T10:30:00Z'). Searches ±5 minutes around this time. Use this when investigating a specific event. Overrides 'minutes'."
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
                    "description": "Max logs to return (default 50, max 200)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("logs") {
            return Ok("Access denied: your account does not have permission to search logs. Try a different investigation approach using tools you have access to.".to_string());
        }
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let severity = args.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        let query_text = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
        let trace_id = args.get("trace_id").and_then(|v| v.as_str()).unwrap_or("");
        let span_id = args.get("span_id").and_then(|v| v.as_str()).unwrap_or("");
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
            .unwrap_or(50)
            .min(200);

        let sql = build_search_logs_sql(
            service,
            severity,
            query_text,
            trace_id,
            span_id,
            around,
            around_minutes,
            minutes,
            limit,
            &ctx.tenant_id,
        );

        let rows: Vec<LogRow> = crate::state::tenant_query(&ctx.state.ch, &sql, &ctx.tenant_id)
            .fetch_all()
            .await?;

        if rows.is_empty() {
            return Ok("No matching logs found.".to_string());
        }

        // Group by message pattern to avoid repeating the same error 100 times
        let mut pattern_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for r in &rows {
            // Use first 120 chars as pattern key
            let key = crate::agent::memory::truncate_at_char_boundary(&r.body, 120);
            *pattern_counts.entry(key.to_string()).or_default() += 1;
        }

        let total = rows.len();
        let time_desc = if !around.is_empty() {
            format!("±{around_minutes}m around {around}")
        } else {
            format!("last {minutes}m")
        };
        let mut out = format!("Found {total} log entries ({time_desc}).\n");

        // Show top patterns
        let mut sorted_patterns: Vec<_> = pattern_counts.into_iter().collect();
        sorted_patterns.sort_by(|a, b| b.1.cmp(&a.1));
        if sorted_patterns.len() > 1 {
            out.push_str("\nTop message patterns:\n");
            for (pattern, count) in sorted_patterns.iter().take(10) {
                out.push_str(&format!("  ({count}x) {pattern}\n"));
            }
        }

        // Show individual entries (deduplicated to unique messages)
        out.push_str("\nRecent entries:\n");
        let mut seen = std::collections::HashSet::new();
        let mut shown = 0;
        for r in &rows {
            let key = crate::agent::memory::truncate_at_char_boundary(&r.body, 120);
            if seen.insert(key.to_string()) {
                out.push_str(&format!(
                    "  [{ts}] [{sev}] {svc}: {body}{correlation}{attrs}\n",
                    ts = r.timestamp,
                    sev = r.severity,
                    svc = r.service_name,
                    body = if r.body.len() > 300 {
                        format!(
                            "{}...",
                            crate::agent::memory::truncate_at_char_boundary(&r.body, 300)
                        )
                    } else {
                        r.body.clone()
                    },
                    correlation = if r.trace_id.is_empty() {
                        String::new()
                    } else {
                        format!(" [trace={} span={}]", r.trace_id, r.span_id)
                    },
                    attrs = if r.log_attributes.is_empty() || r.log_attributes == "{}" {
                        String::new()
                    } else {
                        format!(
                            " attrs={}",
                            crate::agent::memory::truncate_at_char_boundary(&r.log_attributes, 240)
                        )
                    },
                ));
                shown += 1;
                if shown >= 20 {
                    break;
                }
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::build_search_logs_sql;

    #[test]
    fn service_filter_present_when_set_absent_when_empty() {
        let with = build_search_logs_sql("api", "", "", "", "", "", 5, 15, 50, "default");
        assert!(with.contains("ServiceName = 'api'"));

        let without = build_search_logs_sql("", "", "", "", "", "", 5, 15, 50, "default");
        assert!(!without.contains("ServiceName ="));
    }

    #[test]
    fn single_quotes_are_doubled_never_backslash_escaped() {
        let sql = build_search_logs_sql("O'Brien", "", "o'clock", "", "", "", 5, 15, 50, "ten'ant");
        assert!(sql.contains("ServiceName = 'O''Brien'"), "{sql}");
        assert!(sql.contains("tenant_id = 'ten''ant'"), "{sql}");
        assert!(sql.contains("'%o''clock%'"), "{sql}");
        assert!(
            !sql.contains("\\'"),
            "no backslash quote escaping anywhere: {sql}"
        );
    }

    #[test]
    fn severity_fallthrough_value_is_escaped() {
        let sql = build_search_logs_sql("", "bo'gus", "", "", "", "", 5, 15, 50, "default");
        assert!(sql.contains("SeverityText IN ('bo''gus')"), "{sql}");
        assert!(!sql.contains("\\'"), "{sql}");
    }

    #[test]
    fn minutes_clamp_to_1440_and_limit_present() {
        let sql = build_search_logs_sql("", "", "", "", "", "", 5, 999_999, 50, "default");
        assert!(sql.contains("INTERVAL 1440 MINUTE"), "{sql}");
        assert!(sql.contains("LIMIT 50"), "{sql}");

        let capped = build_search_logs_sql("", "", "", "", "", "", 5, 15, 9_999, "default");
        assert!(
            capped.contains("LIMIT 200"),
            "limit capped at 200: {capped}"
        );
    }

    #[test]
    fn around_replaces_relative_window() {
        let sql = build_search_logs_sql(
            "",
            "",
            "",
            "",
            "",
            "2025-01-15T10:30:00Z",
            5,
            15,
            50,
            "default",
        );
        assert!(
            sql.contains("toDateTime64('2025-01-15 10:30:00', 9)"),
            "{sql}"
        );
        assert!(!sql.contains("now() - INTERVAL"), "{sql}");
    }

    #[test]
    fn correlation_filters_and_attribute_search_are_present() {
        let sql = build_search_logs_sql(
            "", "", "timeout", "trace-1", "span-2", "", 5, 15, 50, "default",
        );
        assert!(sql.contains("TraceId = 'trace-1'"), "{sql}");
        assert!(sql.contains("SpanId = 'span-2'"), "{sql}");
        assert!(sql.contains("LogAttributes"), "{sql}");
    }
}
