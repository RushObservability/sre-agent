use crate::AppState;
use crate::agent::skill_store::SkillStore;
use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Context passed to every tool execution.
pub struct ToolContext {
    pub state: AppState,
    /// Unified view of built-in and custom investigation skills for this run.
    /// Built fresh per investigation so edits to custom skills are picked up
    /// on the next invocation.
    pub skill_store: Arc<SkillStore>,
}

/// A tool the agent can invoke.
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameters(&self) -> Value;
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String>;
}

/// Registry of available tools.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
    order: Vec<String>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        let name = tool.name().to_string();
        self.tools.insert(name.clone(), tool);
        self.order.push(name);
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.get(name)
    }

    /// Build the tool definitions array for the LLM API.
    pub fn definitions(&self) -> Vec<Value> {
        self.order
            .iter()
            .filter_map(|name| self.tools.get(name))
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name(),
                        "description": t.description(),
                        "parameters": t.parameters(),
                    }
                })
            })
            .collect()
    }

    /// Execute a tool by name.
    pub async fn execute(&self, name: &str, args: Value, ctx: &ToolContext) -> Result<String> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown tool: {name}"))?;
        tool.execute(args, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_db::ConfigDb;
    use async_trait::async_trait;
    use serde_json::json;

    /// A fake tool for exercising the registry.
    struct FakeTool {
        name_s: &'static str,
        description_s: &'static str,
        returns: String,
    }

    #[async_trait]
    impl Tool for FakeTool {
        fn name(&self) -> &str {
            self.name_s
        }
        fn description(&self) -> &str {
            self.description_s
        }
        fn parameters(&self) -> Value {
            json!({"type": "object", "properties": {}})
        }
        async fn execute(&self, _args: Value, _ctx: &ToolContext) -> Result<String> {
            Ok(self.returns.clone())
        }
    }

    fn test_ctx() -> ToolContext {
        let ch = clickhouse::Client::default().with_url("http://localhost:8123");
        let config_db = Arc::new(ConfigDb::open(":memory:").unwrap());
        let skill_store = Arc::new(crate::agent::skill_store::SkillStore::load(&config_db));
        ToolContext {
            state: crate::AppState { ch, config_db, query_api_url: None },
            skill_store,
        }
    }

    #[test]
    fn empty_registry_has_no_tools() {
        let r = ToolRegistry::new();
        assert!(r.get("anything").is_none());
        assert!(r.definitions().is_empty());
    }

    #[test]
    fn register_and_lookup() {
        let mut r = ToolRegistry::new();
        r.register(Arc::new(FakeTool {
            name_s: "foo",
            description_s: "does foo",
            returns: "ok".into(),
        }));
        assert!(r.get("foo").is_some());
        assert!(r.get("bar").is_none());
    }

    #[test]
    fn definitions_include_name_desc_params() {
        let mut r = ToolRegistry::new();
        r.register(Arc::new(FakeTool {
            name_s: "search",
            description_s: "search tool",
            returns: String::new(),
        }));
        let defs = r.definitions();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0]["type"], "function");
        assert_eq!(defs[0]["function"]["name"], "search");
        assert_eq!(defs[0]["function"]["description"], "search tool");
        assert!(defs[0]["function"]["parameters"].is_object());
    }

    #[test]
    fn definitions_preserve_registration_order() {
        let mut r = ToolRegistry::new();
        r.register(Arc::new(FakeTool {
            name_s: "a",
            description_s: "",
            returns: "".into(),
        }));
        r.register(Arc::new(FakeTool {
            name_s: "b",
            description_s: "",
            returns: "".into(),
        }));
        r.register(Arc::new(FakeTool {
            name_s: "c",
            description_s: "",
            returns: "".into(),
        }));
        let defs = r.definitions();
        assert_eq!(defs[0]["function"]["name"], "a");
        assert_eq!(defs[1]["function"]["name"], "b");
        assert_eq!(defs[2]["function"]["name"], "c");
    }

    #[tokio::test]
    async fn execute_known_tool_returns_result() {
        let mut r = ToolRegistry::new();
        r.register(Arc::new(FakeTool {
            name_s: "echo",
            description_s: "echo",
            returns: "hello".into(),
        }));
        let ctx = test_ctx();
        let out = r.execute("echo", json!({}), &ctx).await.unwrap();
        assert_eq!(out, "hello");
    }

    #[tokio::test]
    async fn execute_unknown_tool_errors() {
        let r = ToolRegistry::new();
        let ctx = test_ctx();
        let err = r.execute("nope", json!({}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("unknown tool"));
    }

    #[tokio::test]
    async fn register_all_built_ins_works() {
        // Make sure the full production set of tools can be registered
        let mut r = ToolRegistry::new();
        crate::agent::built_in::register_all(&mut r);
        let defs = r.definitions();
        assert!(!defs.is_empty());
        // Spot-check known tools
        let names: Vec<String> = defs
            .iter()
            .map(|d| d["function"]["name"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(names.contains(&"search_logs".to_string()));
        assert!(names.contains(&"query_traces".to_string()));
        assert!(names.contains(&"query_metrics".to_string()));
        assert!(names.contains(&"load_skill".to_string()));
        assert!(names.contains(&"get_argocd_app".to_string()));
    }
}
