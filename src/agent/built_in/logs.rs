use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct SearchLogs;

#[derive(Debug, Row, Deserialize)]
struct LogRow {
    timestamp: String,
    service_name: String,
    severity: String,
    body: String,
    trace_id: String,
}

#[async_trait::async_trait]
impl Tool for SearchLogs {
    fn name(&self) -> &str { "search_logs" }

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
                    "description": "Text search in log body (case-insensitive substring match)"
                },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 timestamp to center the search on (e.g. '2025-01-15T10:30:00Z'). Searches ±5 minutes around this time. Use this when investigating a specific event. Overrides 'minutes'."
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
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let severity = args.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        let query_text = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
        let around = args.get("around").and_then(|v| v.as_str()).unwrap_or("");
        let minutes = args.get("minutes").and_then(|v| v.as_u64()).unwrap_or(15);
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(200);

        let mut conditions = if !around.is_empty() {
            // ClickHouse expects 'YYYY-MM-DD hh:mm:ss' — strip trailing Z and replace T with space
            let ts = around.replace('\'', "''").replace('T', " ").trim_end_matches('Z').to_string();
            vec![
                format!("Timestamp >= toDateTime64('{ts}', 9) - INTERVAL 5 MINUTE"),
                format!("Timestamp <= toDateTime64('{ts}', 9) + INTERVAL 5 MINUTE"),
            ]
        } else {
            vec![
                format!("Timestamp >= now() - INTERVAL {minutes} MINUTE"),
            ]
        };
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
            let in_list: String = levels.iter().map(|l| format!("'{l}'")).collect::<Vec<_>>().join(",");
            conditions.push(format!("SeverityText IN ({in_list})"));
        }
        if !query_text.is_empty() {
            conditions.push(format!(
                "lower(Body) LIKE '%{}%'",
                query_text.to_lowercase().replace('\'', "''").replace('%', "\\%")
            ));
        }

        let where_clause = conditions.join(" AND ");
        let sql = format!(
            "SELECT toString(Timestamp) AS timestamp, \
                    ServiceName AS service_name, \
                    SeverityText AS severity, \
                    Body AS body, \
                    TraceId AS trace_id \
             FROM otel_logs \
             WHERE {where_clause} \
             ORDER BY Timestamp DESC \
             LIMIT {limit}"
        );

        let rows: Vec<LogRow> = ctx.state.ch.query(&sql).fetch_all().await?;

        if rows.is_empty() {
            return Ok("No matching logs found.".to_string());
        }

        // Group by message pattern to avoid repeating the same error 100 times
        let mut pattern_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for r in &rows {
            // Use first 120 chars as pattern key
            let key = if r.body.len() > 120 { &r.body[..120] } else { &r.body };
            *pattern_counts.entry(key.to_string()).or_default() += 1;
        }

        let total = rows.len();
        let time_desc = if !around.is_empty() {
            format!("±5m around {around}")
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
            let key = if r.body.len() > 120 { &r.body[..120] } else { &r.body };
            if seen.insert(key.to_string()) {
                out.push_str(&format!(
                    "  [{ts}] [{sev}] {svc}: {body}\n",
                    ts = r.timestamp,
                    sev = r.severity,
                    svc = r.service_name,
                    body = if r.body.len() > 300 { format!("{}...", &r.body[..300]) } else { r.body.clone() },
                ));
                shown += 1;
                if shown >= 20 { break; }
            }
        }

        Ok(out)
    }
}
