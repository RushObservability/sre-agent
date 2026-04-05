use anyhow::Result;
use serde_json::Value;

use crate::agent::skill_store::SkillSource;
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
         Call with no arguments to list every available skill (built-in and custom)."
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "skill": {
                    "type": "string",
                    "description": "The skill id to load. Pick an id from the AVAILABLE SKILLS list in your system prompt. \
                                   Built-in skills use bare ids (e.g. `error_rate_spike`). Custom skills use the `custom:` \
                                   prefix (e.g. `custom:kafka_lag`). Omit this argument to list all available skills."
                }
            },
            "required": []
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let skill_name = args.get("skill").and_then(|v| v.as_str()).unwrap_or("");

        if skill_name.is_empty() {
            return Ok(list_skills_grouped(ctx));
        }

        // Try exact id first (built-ins use bare names, custom uses "custom:" prefix).
        if let Some(body) = ctx.skill_store.render_body(skill_name) {
            return Ok(body);
        }

        // Helpful fallback: if the user dropped the `custom:` prefix, try adding it.
        let with_prefix = format!("custom:{skill_name}");
        if let Some(body) = ctx.skill_store.render_body(&with_prefix) {
            return Ok(body);
        }

        // Unknown skill — list the valid ids so the model can retry correctly.
        Ok(format!(
            "Unknown skill: '{}'\n\n{}",
            skill_name,
            list_skills_grouped(ctx)
        ))
    }
}

/// Format all skills available in the store as a grouped listing (Built-in / Custom).
fn list_skills_grouped(ctx: &ToolContext) -> String {
    let mut built_in_lines: Vec<String> = Vec::new();
    let mut custom_lines: Vec<String> = Vec::new();

    for entry in ctx.skill_store.all() {
        let line = format!("- `{}`: {}", entry.id, entry.description);
        match &entry.source {
            SkillSource::BuiltIn => built_in_lines.push(line),
            SkillSource::Custom { .. } => custom_lines.push(line),
        }
    }

    let mut out = String::from("Available investigation skills:\n");
    if !built_in_lines.is_empty() {
        out.push_str("\n**Built-in:**\n");
        out.push_str(&built_in_lines.join("\n"));
        out.push('\n');
    }
    if !custom_lines.is_empty() {
        out.push_str("\n**Custom:**\n");
        out.push_str(&custom_lines.join("\n"));
        out.push('\n');
    }
    if built_in_lines.is_empty() && custom_lines.is_empty() {
        out.push_str("(no skills registered)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::skill_store::SkillStore;
    use crate::config_db::ConfigDb;
    use std::sync::Arc;

    fn test_ctx() -> ToolContext {
        let ch = clickhouse::Client::default().with_url("http://localhost:8123");
        let config_db = Arc::new(ConfigDb::open(":memory:").unwrap());
        let skill_store = Arc::new(SkillStore::load(&config_db));
        ToolContext {
            state: crate::AppState {
                ch,
                config_db,
                query_api_url: None,
            },
            skill_store,
        }
    }

    #[tokio::test]
    async fn load_skill_with_no_args_lists_all() {
        let tool = LoadSkill;
        let ctx = test_ctx();
        let out = tool.execute(serde_json::json!({}), &ctx).await.unwrap();
        assert!(out.contains("Available investigation skills"));
        assert!(out.contains("Built-in"));
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
