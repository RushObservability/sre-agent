use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};

pub struct GetInsights;

#[derive(Debug, Deserialize)]
struct Insights {
    summary: String,
    #[serde(default)]
    anomalies: Vec<InsightAnomaly>,
    #[serde(default)]
    log_patterns: Vec<LogPattern>,
}

#[derive(Debug, Deserialize)]
struct InsightAnomaly {
    name: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    metric: String,
    #[serde(default)]
    value: f64,
    #[serde(default)]
    expected: f64,
    #[serde(default)]
    deviation: f64,
    #[serde(default)]
    since: String,
    #[serde(default = "still_open")]
    open_at_end: bool,
}

fn still_open() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct LogPattern {
    service: String,
    severity: String,
    template: String,
    count: u64,
    #[serde(default)]
    last_seen: String,
}

fn format_insights(insights: &Insights) -> String {
    let mut out = format!("{}\n", insights.summary);
    if !insights.anomalies.is_empty() {
        out.push_str("\nAnomalies:\n");
        for a in &insights.anomalies {
            out.push_str(&format!(
                "  {name} service={service} metric={metric} value={value:.4} expected={expected:.4} \
                 deviation={deviation:.1}σ since={since}{resolved}\n",
                name = a.name,
                service = a.service,
                metric = a.metric,
                value = a.value,
                expected = a.expected,
                deviation = a.deviation,
                since = a.since,
                resolved = if a.open_at_end {
                    ""
                } else {
                    " (resolved before window end)"
                },
            ));
        }
    }
    if !insights.log_patterns.is_empty() {
        out.push_str("\nRepeated WARN/ERROR log patterns:\n");
        for p in insights.log_patterns.iter().take(15) {
            out.push_str(&format!(
                "  ({count}x) [{sev}] {svc}: {template} (last {last})\n",
                count = p.count,
                sev = p.severity,
                svc = p.service,
                template = crate::agent::memory::truncate_at_char_boundary(&p.template, 200),
                last = p.last_seen,
            ));
        }
    }
    if insights.anomalies.is_empty() && insights.log_patterns.is_empty() {
        out.push_str("\nNo firing anomalies or repeated warning/error log patterns.\n");
    }
    out
}

#[async_trait::async_trait]
impl Tool for GetInsights {
    fn name(&self) -> &str {
        "get_insights"
    }

    fn description(&self) -> &str {
        "One cheap overview of what is wrong: anomalies firing in the window, repeated \
         WARN/ERROR log patterns, and a 0-100 health score. Call it early to pick which \
         service and signal to dig into, then confirm with the detailed tools."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "around": {
                    "type": "string",
                    "description": "ISO 8601 incident timestamp to center the window on (e.g. '2025-01-15T10:30:00Z'). Overrides 'minutes'."
                },
                "around_minutes": {
                    "type": "integer",
                    "description": "Window on each side of 'around' in minutes (default 15, max 720)"
                },
                "minutes": {
                    "type": "integer",
                    "description": "Look back this many minutes from now (default 15, max 1440). Ignored if 'around' is set."
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("logs") {
            return Ok("Access denied: get_insights reads log patterns, which your account cannot access. Use get_anomaly_context for anomalies instead.".to_string());
        }
        let around = args.get("around").and_then(|v| v.as_str()).unwrap_or("");
        let around_minutes = args
            .get("around_minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(15);
        let minutes = args
            .get("minutes")
            .and_then(|v| v.as_u64())
            .unwrap_or(15)
            .clamp(1, 1440);
        // "Now" keeps query-api's live rule state; a past window reads event history.
        let insights: Insights = if around.trim().is_empty() {
            ctx.state
                .query_api
                .get_insights(&ctx.tenant_id, Some(minutes), None, None)
                .await
        } else {
            let (from, to) = crate::query_api::bounded_time_range(around, around_minutes, minutes)?;
            ctx.state
                .query_api
                .get_insights(&ctx.tenant_id, None, Some(&from), Some(&to))
                .await
        }
        .map_err(|e| anyhow::anyhow!("failed to get insights: {e}"))?;
        Ok(format_insights(&insights))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_lists_anomalies_and_patterns() {
        let insights: Insights = serde_json::from_value(json!({
            "health_score": 70,
            "summary": "health 70/100 over the last 15m",
            "anomalies": [
                {"name": "checkout p99", "service": "checkout", "metric": "p99",
                 "value": 2.5, "expected": 0.4, "deviation": 6.2,
                 "since": "2026-11-07 10:00:00", "open_at_end": false}
            ],
            "log_patterns": [
                {"service": "checkout", "severity": "ERROR",
                 "template": "order N failed", "example": "order 42 failed",
                 "count": 12, "last_seen": "2026-11-07 10:05:00"}
            ]
        }))
        .unwrap();
        let out = format_insights(&insights);
        assert!(out.contains("checkout p99"), "{out}");
        assert!(out.contains("resolved before window end"), "{out}");
        assert!(
            out.contains("(12x) [ERROR] checkout: order N failed"),
            "{out}"
        );
        assert!(!out.contains("No firing anomalies"), "{out}");
    }

    #[test]
    fn healthy_result_says_so_and_old_responses_parse() {
        // Older query-api responses lack open_at_end; anomalies then count as open.
        let insights: Insights = serde_json::from_value(json!({
            "health_score": 100,
            "summary": "health 100/100",
        }))
        .unwrap();
        assert!(format_insights(&insights).contains("No firing anomalies"));

        // A pattern below the scoring threshold leaves the score at 100 but is still listed.
        let quiet: Insights = serde_json::from_value(json!({
            "health_score": 100,
            "summary": "health 100/100",
            "log_patterns": [{"service": "checkout", "severity": "ERROR",
                              "template": "order N failed", "count": 5}]
        }))
        .unwrap();
        let out = format_insights(&quiet);
        assert!(out.contains("order N failed"), "{out}");
        assert!(!out.contains("No firing anomalies"), "{out}");
    }
}
