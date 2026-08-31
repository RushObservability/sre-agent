use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use clickhouse::Row;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct QueryMetrics;

/// Pure SQL builder for `query_metrics`. Returns `(sql, label)` for the
/// selected query mode, or `None` when neither `metric_name` nor `service`
/// is provided. Every interpolated string value (`tenant_id`, `around`,
/// `metric_name`, `service`) is escaped with the ClickHouse-standard doubled
/// single quote (`''`); the model-supplied `minutes` is clamped here so a
/// hostile value can never widen the scan window.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_query_metrics_sql(
    service: &str,
    metric: &str,
    metric_name: &str,
    metric_type: &str,
    around: &str,
    around_minutes: u64,
    minutes: u64,
    tenant_id: &str,
) -> Option<(String, String)> {
    // Clamp the model-supplied window to at most 24h so the LLM can't
    // request a months-long full scan.
    let minutes = minutes.clamp(1, 1440);
    let around_minutes = around_minutes.clamp(1, 720);
    let tenant_id = tenant_id.replace('\'', "''");

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

    // Build time filter for spans (DateTime64 timestamp column)
    let time_filter = if !around.is_empty() {
        format!(
            "tenant_id = '{tenant_id}' AND timestamp >= toDateTime64('{ch_ts}', 9) - INTERVAL {around_minutes} MINUTE AND timestamp <= toDateTime64('{ch_ts}', 9) + INTERVAL {around_minutes} MINUTE"
        )
    } else {
        format!("tenant_id = '{tenant_id}' AND timestamp >= now() - INTERVAL {minutes} MINUTE")
    };

    // Build time filter for metrics_ tables (TimeUnix column)
    let otel_time_filter = if !around.is_empty() {
        format!(
            "tenant_id = '{tenant_id}' AND TimeUnix >= toDateTime64('{ch_ts}', 9) - INTERVAL {around_minutes} MINUTE AND TimeUnix <= toDateTime64('{ch_ts}', 9) + INTERVAL {around_minutes} MINUTE"
        )
    } else {
        format!("tenant_id = '{tenant_id}' AND TimeUnix >= now() - INTERVAL {minutes} MINUTE")
    };

    if !metric_name.is_empty() {
        let service_filter = if service.is_empty() {
            String::new()
        } else {
            format!(" AND ServiceName = '{}'", service.replace('\'', "''"))
        };
        let (table, value_expr, label_suffix) = match metric_type {
            "sum" => ("metrics_sum", "max(Value)", "sum"),
            "histogram" => (
                "metrics_histogram",
                "if(sum(Count) = 0, 0, sum(Sum) / sum(Count))",
                "histogram_avg",
            ),
            _ => ("metrics_gauge", "avg(Value)", "gauge_avg"),
        };
        let sql = format!(
            "SELECT toString(toStartOfInterval(TimeUnix, INTERVAL 1 MINUTE)) AS bucket, \
                    {value_expr} AS value \
             FROM {table} \
             WHERE MetricName = '{}' \
               {service_filter} \
               AND {otel_time_filter} \
             GROUP BY bucket \
             ORDER BY bucket",
            metric_name.replace('\'', "''")
        );
        let label = if service.is_empty() {
            format!("{metric_name} {label_suffix}")
        } else {
            format!("{service} {metric_name} {label_suffix}")
        };
        Some((sql, label))
    } else if !service.is_empty() {
        let safe_svc = service.replace('\'', "''");
        let pair = match metric {
            "error_rate" => {
                let sql = format!(
                    "SELECT toString(toStartOfInterval(timestamp, INTERVAL 1 MINUTE)) AS bucket, \
                            if(count() = 0, 0, 100.0 * countIf(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500) / count()) AS value \
                     FROM spans \
                     WHERE service_name = '{safe_svc}' \
                       AND {time_filter} \
                     GROUP BY bucket ORDER BY bucket"
                );
                (sql, format!("{service} error_rate_pct"))
            }
            "p50_latency" => {
                let sql = format!(
                    "SELECT toString(toStartOfInterval(timestamp, INTERVAL 1 MINUTE)) AS bucket, \
                            quantile(0.5)(duration_ns) / 1e6 AS value \
                     FROM spans \
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
                     FROM spans \
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
                     FROM spans \
                     WHERE service_name = '{safe_svc}' \
                       AND {time_filter} \
                     GROUP BY bucket ORDER BY bucket"
                );
                (sql, format!("{service} request_rate"))
            }
        };
        Some(pair)
    } else {
        None
    }
}

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
                    "description": "Raw metric name to query from an OTel metrics table (alternative to service+metric)"
                },
                "metric_type": {
                    "type": "string",
                    "enum": ["gauge", "sum", "histogram"],
                    "description": "OTel metric table for metric_name (default gauge). Histogram returns the average sample value."
                },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 timestamp to center the query on (e.g. '2025-01-15T10:30:00Z'). Queries ±5 minutes around this time. Overrides 'minutes'."
                },
                "around_minutes": {
                    "type": "integer",
                    "description": "Window on each side of 'around' in minutes (default 5, max 720)"
                },
                "minutes": {
                    "type": "integer",
                    "description": "Look back this many minutes from now (default 30). Ignored if 'around' is set."
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("metrics") {
            return Ok("Access denied: your account does not have permission to query metrics. Try a different investigation approach using tools you have access to.".to_string());
        }
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let metric = args
            .get("metric")
            .and_then(|v| v.as_str())
            .unwrap_or("request_rate");
        let metric_name = args
            .get("metric_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let metric_type = args
            .get("metric_type")
            .and_then(|v| v.as_str())
            .unwrap_or("gauge");
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
            .unwrap_or(30)
            .clamp(1, 1440);

        let time_desc = if !around.is_empty() {
            format!("±{around_minutes}m around {around}")
        } else {
            format!("last {minutes}m")
        };

        let Some((query, label)) = build_query_metrics_sql(
            service,
            metric,
            metric_name,
            metric_type,
            around,
            around_minutes,
            minutes,
            &ctx.tenant_id,
        ) else {
            return Ok("Provide either 'service' + 'metric' or 'metric_name'.".to_string());
        };

        let rows: Vec<MetricRow> =
            crate::state::tenant_query(&ctx.state.ch, &query, &ctx.tenant_id)
                .fetch_all()
                .await?;

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

#[cfg(test)]
mod tests {
    use super::build_query_metrics_sql;

    #[test]
    fn returns_none_without_service_or_metric_name() {
        assert!(
            build_query_metrics_sql("", "request_rate", "", "gauge", "", 5, 30, "default")
                .is_none()
        );
    }

    #[test]
    fn service_mode_builds_each_metric_with_filter() {
        for (metric, marker) in [
            (
                "error_rate",
                "countIf(status IN ('STATUS_CODE_ERROR', 'ERROR') OR http_status_code >= 500)",
            ),
            ("p50_latency", "quantile(0.5)(duration_ns)"),
            ("p99_latency", "quantile(0.99)(duration_ns)"),
            ("request_rate", "count() AS value"),
        ] {
            let (sql, label) =
                build_query_metrics_sql("api", metric, "", "gauge", "", 5, 30, "default").unwrap();
            assert!(sql.contains("service_name = 'api'"), "{metric}: {sql}");
            assert!(sql.contains(marker), "{metric}: {sql}");
            assert!(label.starts_with("api "), "{metric}: {label}");
        }
    }

    #[test]
    fn metric_name_mode_escapes_and_targets_gauge_table() {
        let (sql, label) = build_query_metrics_sql(
            "",
            "request_rate",
            "cpu's_usage",
            "gauge",
            "",
            5,
            30,
            "default",
        )
        .unwrap();
        assert!(sql.contains("FROM metrics_gauge"), "{sql}");
        assert!(sql.contains("MetricName = 'cpu''s_usage'"), "{sql}");
        assert_eq!(label, "cpu's_usage gauge_avg");
    }

    #[test]
    fn single_quotes_are_doubled_never_backslash_escaped() {
        let (sql, _) =
            build_query_metrics_sql("O'Brien", "error_rate", "", "gauge", "", 5, 30, "ten'ant")
                .unwrap();
        assert!(sql.contains("service_name = 'O''Brien'"), "{sql}");
        assert!(sql.contains("tenant_id = 'ten''ant'"), "{sql}");
        assert!(
            !sql.contains("\\'"),
            "no backslash quote escaping anywhere: {sql}"
        );
    }

    #[test]
    fn minutes_clamp_to_1440() {
        let (sql, _) = build_query_metrics_sql(
            "api",
            "request_rate",
            "",
            "gauge",
            "",
            5,
            999_999,
            "default",
        )
        .unwrap();
        assert!(sql.contains("INTERVAL 1440 MINUTE"), "{sql}");
    }

    #[test]
    fn around_uses_normalized_timestamp_window() {
        let (sql, _) = build_query_metrics_sql(
            "api",
            "request_rate",
            "",
            "gauge",
            "2025-01-15T10:30:00Z",
            5,
            30,
            "default",
        )
        .unwrap();
        assert!(
            sql.contains("toDateTime64('2025-01-15 10:30:00', 9)"),
            "{sql}"
        );
        assert!(!sql.contains("now() - INTERVAL"), "{sql}");
    }

    #[test]
    fn raw_metric_type_selects_the_matching_otel_table() {
        for (kind, table) in [("sum", "metrics_sum"), ("histogram", "metrics_histogram")] {
            let (sql, label) = build_query_metrics_sql(
                "api",
                "request_rate",
                "requests",
                kind,
                "",
                5,
                30,
                "default",
            )
            .unwrap();
            assert!(sql.contains(&format!("FROM {table}")), "{kind}: {sql}");
            assert!(label.contains(kind), "{kind}: {label}");
        }
    }
}
