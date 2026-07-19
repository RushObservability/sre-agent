use crate::agent::tools::{Tool, ToolContext};
use anyhow::Result;
use serde_json::{Value, json};

pub struct ListDeploys;

#[async_trait::async_trait]
impl Tool for ListDeploys {
    fn name(&self) -> &str {
        "list_deploys"
    }

    fn description(&self) -> &str {
        "List recent deploys/releases. Use this to check if a deploy correlates with the incident timing."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Filter deploys by service name (optional)"
                },
                "hours": {
                    "type": "integer",
                    "description": "Look back this many hours (default 6)"
                },
                "around": {
                    "type": "string",
                    "description": "ISO 8601 incident timestamp. When set, list deploys in the preceding 'hours' window around that event instead of relative to now."
                }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let hours = args.get("hours").and_then(|v| v.as_u64()).unwrap_or(6);
        let around = args.get("around").and_then(|v| v.as_str()).unwrap_or("");

        let end = if around.is_empty() {
            chrono::Utc::now()
        } else {
            chrono::DateTime::parse_from_rfc3339(around)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now())
        };
        let cutoff = end - chrono::Duration::hours(hours.min(24 * 30) as i64);
        let from_str = cutoff.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let until_str = if around.is_empty() {
            None
        } else {
            Some(end.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        };

        let svc_filter = if service.is_empty() {
            None
        } else {
            Some(service.to_string())
        };

        let deploys = ctx
            .state
            .config_db
            .list_deploy_markers(svc_filter.as_deref(), Some(&from_str), until_str.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("failed to list deploys: {e}"))?;

        if deploys.is_empty() {
            let scope = if service.is_empty() {
                "any service".to_string()
            } else {
                service.to_string()
            };
            return Ok(format!("No deploys for {scope} in last {hours}h."));
        }

        let mut out = if around.is_empty() {
            format!("Deploys in last {hours}h:\n\n")
        } else {
            format!("Deploys in the {hours}h before {around}:\n\n")
        };
        for d in &deploys {
            out.push_str(&format!(
                "  [{ts}] {svc} → {ver}",
                ts = d.deployed_at,
                svc = d.service_name,
                ver = d.version,
            ));
            if !d.commit_sha.is_empty() {
                out.push_str(&format!(
                    " ({})",
                    &d.commit_sha[..d.commit_sha.len().min(8)]
                ));
            }
            if !d.description.is_empty() {
                out.push_str(&format!("  — {}", d.description));
            }
            out.push('\n');
        }
        Ok(out)
    }
}
