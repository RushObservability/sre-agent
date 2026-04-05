use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use serde_json::{Value, json};

pub struct GetAnomalyContext;

#[async_trait::async_trait]
impl Tool for GetAnomalyContext {
    fn name(&self) -> &str { "get_anomaly_context" }

    fn description(&self) -> &str {
        "Get anomaly detection rules and recent anomaly events. \
         Use this to understand what monitoring rules exist and recent anomalous behavior."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "Get details for a specific rule (optional — lists all if omitted)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let rule_id = args.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");

        if !rule_id.is_empty() {
            let rule = ctx.state.config_db.get_anomaly_rule(rule_id)
                .map_err(|e| anyhow::anyhow!("failed to get rule: {e}"))?
                .ok_or_else(|| anyhow::anyhow!("anomaly rule not found: {rule_id}"))?;

            let events = ctx.state.config_db.list_anomaly_events(rule_id, 10)
                .map_err(|e| anyhow::anyhow!("failed to get events: {e}"))?;

            let mut out = format!(
                "Anomaly Rule: {}\n\
                 - Source: {}\n\
                 - Pattern: {}\n\
                 - Service: {}\n\
                 - Sensitivity: {:.1}σ\n\
                 - State: {}\n\
                 - Last triggered: {}\n\n",
                rule.name, rule.source, rule.pattern,
                rule.service_name, rule.sensitivity, rule.state,
                rule.last_triggered_at.as_deref().unwrap_or("never"),
            );

            if events.is_empty() {
                out.push_str("No recent events.\n");
            } else {
                out.push_str(&format!("Recent events ({}):\n", events.len()));
                for e in &events {
                    out.push_str(&format!(
                        "  [{ts}] {state} metric={metric} value={val:.4} expected={exp:.4} deviation={dev:.1}σ\n",
                        ts = e.created_at, state = e.state, metric = e.metric,
                        val = e.value, exp = e.expected, dev = e.deviation,
                    ));
                }
            }
            Ok(out)
        } else {
            let rules = ctx.state.config_db.list_anomaly_rules()
                .map_err(|e| anyhow::anyhow!("failed to list rules: {e}"))?;

            if rules.is_empty() {
                return Ok("No anomaly rules configured.".to_string());
            }

            let mut out = format!("Anomaly rules ({}):\n\n", rules.len());
            for r in &rules {
                let state_icon = match r.state.as_str() {
                    "anomalous" => "!",
                    "no_data" => "?",
                    _ => " ",
                };
                out.push_str(&format!(
                    "  [{state_icon}] {name} ({source}/{pattern}) state={state} sensitivity={sens:.1}σ\n",
                    name = r.name, source = r.source, pattern = r.pattern,
                    state = r.state, sens = r.sensitivity,
                ));
            }
            Ok(out)
        }
    }
}
