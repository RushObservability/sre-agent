use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct QueryMetrics;

#[derive(Debug, Row, Deserialize)]
struct MetricRow {
    bucket: String,
    value: f64,
}

#[async_trait::async_trait]
impl Tool for QueryMetrics {
    fn name(&self) -> &str {
        "query_metrics"
    }

    fn description(&self) -> &str {
        "Query time-series metrics. Can query request rates, error rates, and latency percentiles \
         for a service, or run a raw PromQL-style metric name query."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name to query APM metrics for"
                },
                "metric": {
                    "type": "string",
                    "enum": ["request_rate", "error_rate", "p50_latency", "p99_latency"],
                    "description": "APM metric type (used with service)"
                },
                "metric_name": {
                    "type": "string",
                    "description": "Raw metric name to query from otel_metrics tables (alternative to service+metric)"
                },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 timestamp to center the query on (e.g. '2025-01-15T10:30:00Z'). Queries ±5 minutes around this time. Overrides 'minutes'."
                },
                "minutes": {
                    "type": "integer",
                    "description": "Look back this many minutes from now (default 30). Ignored if 'around' is set."
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let metric = args
            .get("metric")
            .and_then(|v| v.as_str())
            .unwrap_or("request_rate");
        let metric_name = args
            .get("metric_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let around = args.get("around").and_then(|v| v.as_str()).unwrap_or("");
        let minutes = args.get("minutes").and_then(|v| v.as_u64()).unwrap_or(30);

        // Normalize ISO timestamp for ClickHouse: strip Z, replace T with space
        let ch_ts = if !around.is_empty() {
            around
                .replace('\'', "''")
                .replace('T', " ")
                .trim_end_matches('Z')
                .to_string()
        } else {
            String::new()
        };

        // Build time filter for wide_events (DateTime64 timestamp column)
        let time_filter = if !around.is_empty() {
            format!(
                "timestamp >= toDateTime64('{ch_ts}', 9) - INTERVAL 5 MINUTE AND timestamp <= toDateTime64('{ch_ts}', 9) + INTERVAL 5 MINUTE"
            )
        } else {
            format!("timestamp >= now() - INTERVAL {minutes} MINUTE")
        };

        // Build time filter for otel_metrics tables (TimeUnix column)
        let otel_time_filter = if !around.is_empty() {
            format!(
                "TimeUnix >= toDateTime64('{ch_ts}', 9) - INTERVAL 5 MINUTE AND TimeUnix <= toDateTime64('{ch_ts}', 9) + INTERVAL 5 MINUTE"
            )
        } else {
            format!("TimeUnix >= now() - INTERVAL {minutes} MINUTE")
        };

        let time_desc = if !around.is_empty() {
            format!("±5m around {around}")
        } else {
            format!("last {minutes}m")
        };

        let (query, label) = if !metric_name.is_empty() {
            let sql = format!(
                "SELECT toString(toStartOfInterval(TimeUnix, INTERVAL 1 MINUTE)) AS bucket, \
                        avg(Value) AS value \
                 FROM otel_metrics_gauge \
                 WHERE MetricName = '{}' \
                   AND {otel_time_filter} \
                 GROUP BY bucket \
                 ORDER BY bucket",
                metric_name.replace('\'', "''")
            );
            (sql, metric_name.to_string())
        } else if !service.is_empty() {
            let safe_svc = service.replace('\'', "''");
            match metric {
                "error_rate" => {
                    let sql = format!(
                        "SELECT toString(toStartOfInterval(timestamp, INTERVAL 1 MINUTE)) AS bucket, \
                                countIf(status = 'STATUS_CODE_ERROR') AS value \
                         FROM wide_events \
                         WHERE service_name = '{safe_svc}' \
                           AND {time_filter} \
                         GROUP BY bucket ORDER BY bucket"
                    );
                    (sql, format!("{service} error_rate"))
                }
                "p50_latency" => {
                    let sql = format!(
                        "SELECT toString(toStartOfInterval(timestamp, INTERVAL 1 MINUTE)) AS bucket, \
                                quantile(0.5)(duration_ns) / 1e6 AS value \
                         FROM wide_events \
                         WHERE service_name = '{safe_svc}' \
                           AND {time_filter} \
                         GROUP BY bucket ORDER BY bucket"
                    );
                    (sql, format!("{service} p50 latency (ms)"))
                }
                "p99_latency" => {
                    let sql = format!(
                        "SELECT toString(toStartOfInterval(timestamp, INTERVAL 1 MINUTE)) AS bucket, \
                                quantile(0.99)(duration_ns) / 1e6 AS value \
                         FROM wide_events \
                         WHERE service_name = '{safe_svc}' \
                           AND {time_filter} \
                         GROUP BY bucket ORDER BY bucket"
                    );
                    (sql, format!("{service} p99 latency (ms)"))
                }
                _ => {
                    let sql = format!(
                        "SELECT toString(toStartOfInterval(timestamp, INTERVAL 1 MINUTE)) AS bucket, \
                                count() AS value \
                         FROM wide_events \
                         WHERE service_name = '{safe_svc}' \
                           AND {time_filter} \
                         GROUP BY bucket ORDER BY bucket"
                    );
                    (sql, format!("{service} request_rate"))
                }
            }
        } else {
            return Ok("Provide either 'service' + 'metric' or 'metric_name'.".to_string());
        };

        let rows: Vec<MetricRow> = ctx.state.ch.query(&query).fetch_all().await?;

        if rows.is_empty() {
            return Ok(format!("No data for {label} ({time_desc})."));
        }

        let values: Vec<f64> = rows.iter().map(|r| r.value).collect();
        let avg = values.iter().sum::<f64>() / values.len() as f64;
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let latest = values.last().copied().unwrap_or(0.0);

        let mut out = format!(
            "{label} ({time_desc}, {} data points):\n\
             Latest={latest:.2}  Avg={avg:.2}  Min={min:.2}  Max={max:.2}\n\nTimeline:\n",
            rows.len()
        );

        // Show the time series
        for r in &rows {
            out.push_str(&format!("  {}: {:.2}\n", r.bucket, r.value));
        }

        Ok(out)
    }
}
