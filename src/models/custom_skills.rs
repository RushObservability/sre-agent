use serde::{Deserialize, Serialize};

/// User-defined investigation skill. The sre-agent reads these from the
/// shared `rush_config.db` (owned and written by query-api) and exposes them
/// via the `load_skill` tool to LLM investigation loops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSkill {
    pub id: String,
    pub name: String,
    pub title: String,
    pub description: String,
    pub content: String,
    /// JSON-decoded list of tool names this skill is allowed to suggest.
    pub allowed_tools: Vec<String>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}
