use anyhow::Result;
use serde_json::Value;

use crate::agent::skills;
use crate::agent::tools::{Tool, ToolContext};

/// Tool that loads an investigation skill/playbook on demand.
pub struct LoadSkill;

#[async_trait::async_trait]
impl Tool for LoadSkill {
    fn name(&self) -> &str {
        "load_skill"
    }

    fn description(&self) -> &str {
        "Load an investigation playbook for a specific incident type. \
         Returns a detailed checklist and heuristics to guide your investigation. \
         Call with no arguments to list available skills."
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "skill": {
                    "type": "string",
                    "description": "Name of the skill to load. Options: error_rate_spike, latency_degradation, deploy_regression, dependency_failure, throughput_anomaly. Omit to list all available skills."
                }
            },
            "required": []
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> Result<String> {
        let skill_name = args
            .get("skill")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if skill_name.is_empty() {
            return Ok(skills::list_skills_summary());
        }

        let all = skills::all_skills();
        match all.get(skill_name) {
            Some(skill) => Ok(format!("{}\n\nUse this playbook to guide your next investigation steps.", skill.content)),
            None => {
                let summary = skills::list_skills_summary();
                Ok(format!("Unknown skill: '{}'\n\n{}", skill_name, summary))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_db::ConfigDb;
    use std::sync::Arc;

    fn test_ctx() -> ToolContext {
        let ch = clickhouse::Client::default().with_url("http://localhost:8123");
        let config_db = Arc::new(ConfigDb::open(":memory:").unwrap());
        ToolContext {
            state: crate::AppState { ch, config_db },
        }
    }

    #[tokio::test]
    async fn load_skill_with_no_args_lists_all() {
        let tool = LoadSkill;
        let ctx = test_ctx();
        let out = tool.execute(serde_json::json!({}), &ctx).await.unwrap();
        assert!(out.contains("Available investigation skills"));
        assert!(out.contains("error_rate_spike"));
        assert!(out.contains("argocd_unhealthy"));
    }

    #[tokio::test]
    async fn load_skill_with_known_name_returns_content() {
        let tool = LoadSkill;
        let ctx = test_ctx();
        let out = tool
            .execute(serde_json::json!({"skill": "error_rate_spike"}), &ctx)
            .await
            .unwrap();
        assert!(out.contains("Error Rate Spike"));
        assert!(out.contains("Use this playbook"));
    }

    #[tokio::test]
    async fn load_skill_with_unknown_name_returns_summary_with_error() {
        let tool = LoadSkill;
        let ctx = test_ctx();
        let out = tool
            .execute(serde_json::json!({"skill": "does_not_exist"}), &ctx)
            .await
            .unwrap();
        assert!(out.contains("Unknown skill"));
        assert!(out.contains("Available investigation skills"));
    }

    #[test]
    fn parameters_schema_is_valid() {
        let params = LoadSkill.parameters();
        assert_eq!(params["type"], "object");
        assert!(params["properties"]["skill"].is_object());
    }
}
