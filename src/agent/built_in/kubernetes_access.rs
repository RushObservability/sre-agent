//! Read-only Kubernetes access metadata for incident correlation.
//!
//! This tool is deliberately separate from the live Kubernetes tools. It uses
//! query-api's tenant and license boundary, and query-api returns only request
//! metadata plus a reconstructed kubectl command. Session output, command
//! arguments, device details, and network evidence never enter the LLM context.

use crate::agent::tools::{Tool, ToolContext};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

const MAX_RESPONSE_BYTES: usize = 512 * 1024;

pub struct SearchKubernetesAccess;

fn required_timestamp(args: &Value, name: &str) -> Result<String> {
    let raw = args
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is required"))?;
    DateTime::parse_from_rfc3339(raw)
        .map_err(|_| anyhow::anyhow!("{name} must be an RFC3339 timestamp"))?;
    Ok(raw.to_string())
}

fn optional_string(args: &Value, name: &str, max_bytes: usize) -> Result<Option<String>> {
    let Some(raw) = args.get(name).and_then(Value::as_str) else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > max_bytes {
        bail!("{name} exceeds its {max_bytes}-byte limit")
    }
    Ok(Some(value.to_string()))
}

fn unavailable(reason: &str) -> String {
    json!({
        "available": false,
        "reason": reason,
        "investigation_guidance": "Continue with deploys, logs, traces, metrics, and Kubernetes events. Do not treat unavailable access history as evidence that no operator action occurred."
    })
    .to_string()
}

#[async_trait::async_trait]
impl Tool for SearchKubernetesAccess {
    fn name(&self) -> &str {
        "search_kubernetes_access"
    }

    fn description(&self) -> &str {
        "Search recorded Kubernetes API actions for the incident window. Call this only when evidence makes a manual kubectl action plausible: an unexplained workload/config/RBAC change, an exec or attach session, a resource deletion, or timing that does not match known deploy automation. This is a discriminating check, not a routine first step. The add-on must be enabled, and only reconstructed command metadata is returned."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "from": {
                    "type": "string",
                    "description": "Inclusive UTC RFC3339 start of the suspected action window"
                },
                "to": {
                    "type": "string",
                    "description": "Inclusive UTC RFC3339 end of the suspected action window"
                },
                "actor": { "type": "string", "description": "Optional actor name or ID" },
                "cluster": { "type": "string", "description": "Optional exact cluster ID" },
                "namespace": { "type": "string", "description": "Optional exact namespace" },
                "verb": { "type": "string", "description": "Optional Kubernetes API verb such as create, patch, update, or delete" },
                "resource": { "type": "string", "description": "Optional Kubernetes resource such as deployments, pods, or configmaps" },
                "status": { "type": "string", "description": "Optional HTTP status code or class: 2xx, 4xx, or 5xx" },
                "limit": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum rows, default 25" }
            },
            "required": ["from", "to"]
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        if !ctx.has_scope("kube_cluster") {
            bail!("kube_cluster scope is required for Kubernetes access history")
        }
        let from = required_timestamp(&args, "from")?;
        let to = required_timestamp(&args, "to")?;
        let from_time = DateTime::parse_from_rfc3339(&from)?.with_timezone(&Utc);
        let to_time = DateTime::parse_from_rfc3339(&to)?.with_timezone(&Utc);
        if to_time <= from_time {
            bail!("to must be later than from")
        }
        if to_time.signed_duration_since(from_time) > chrono::Duration::days(7) {
            bail!("Kubernetes access searches are limited to a seven-day window")
        }

        let mut query = vec![
            ("tenant_id".to_string(), ctx.tenant_id.clone()),
            ("from".to_string(), from),
            ("to".to_string(), to),
            (
                "limit".to_string(),
                args.get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(25)
                    .clamp(1, 50)
                    .to_string(),
            ),
        ];
        for (argument, parameter, max_bytes) in [
            ("actor", "actor", 256),
            ("cluster", "cluster", 256),
            ("namespace", "namespace", 253),
            ("verb", "verb", 64),
            ("resource", "resource", 128),
            ("status", "status", 16),
        ] {
            if let Some(value) = optional_string(&args, argument, max_bytes)? {
                query.push((parameter.to_string(), value));
            }
        }

        let response = match ctx
            .state
            .query_api
            .get_kubernetes_access(&ctx.tenant_id, &query, MAX_RESPONSE_BYTES)
            .await
        {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(unavailable("Kubernetes access logging is not enabled")),
            Err(error) => {
                tracing::warn!(%error, "Kubernetes access history request failed");
                return Ok(unavailable(
                    "Kubernetes access history is temporarily unavailable",
                ));
            }
        };

        Ok(serde_json::to_string_pretty(&response)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_requires_a_bounded_incident_window() {
        let schema = SearchKubernetesAccess.parameters();
        assert_eq!(schema["required"], json!(["from", "to"]));
        assert_eq!(schema["properties"]["limit"]["maximum"], 50);
    }

    #[test]
    fn description_keeps_access_history_on_demand() {
        let description = SearchKubernetesAccess.description();
        assert!(description.contains("only when evidence"));
        assert!(description.contains("not a routine first step"));
    }

    #[test]
    fn timestamps_must_be_rfc3339() {
        assert!(required_timestamp(&json!({"from": "yesterday"}), "from").is_err());
        assert_eq!(
            required_timestamp(&json!({"from": "2026-08-23T10:00:00Z"}), "from").unwrap(),
            "2026-08-23T10:00:00Z"
        );
    }
}
