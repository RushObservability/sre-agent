use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub source: String,
    pub pattern: String,
    pub query: String,
    pub service_name: String,
    pub apm_metric: String,
    pub sensitivity: f64,
    pub alpha: f64,
    pub eval_interval_secs: i64,
    pub window_secs: i64,
    pub split_labels: String,
    pub notification_channel_ids: String,
    pub state: String,
    pub last_eval_at: Option<String>,
    pub last_triggered_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub id: String,
    pub rule_id: String,
    pub state: String,
    pub metric: String,
    pub value: f64,
    pub expected: f64,
    pub deviation: f64,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployMarker {
    pub id: String,
    pub service_name: String,
    pub version: String,
    pub commit_sha: String,
    pub description: String,
    pub environment: String,
    pub deployed_by: String,
    pub deployed_at: String,
}
