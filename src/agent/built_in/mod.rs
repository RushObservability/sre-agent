mod traces;
mod logs;
mod metrics;
mod services;
mod deploys;
mod anomalies;
mod skills_tool;
mod argocd_tool;
mod kube_tool;

use crate::agent::tools::{ToolRegistry, Tool};
use std::sync::Arc;

/// Register all built-in tools.
pub fn register_all(registry: &mut ToolRegistry) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(traces::QueryTraces),
        Arc::new(traces::GetTrace),
        Arc::new(logs::SearchLogs),
        Arc::new(metrics::QueryMetrics),
        Arc::new(services::ListServices),
        Arc::new(services::ServiceDependencies),
        Arc::new(deploys::ListDeploys),
        Arc::new(anomalies::GetAnomalyContext),
        Arc::new(skills_tool::LoadSkill),
        Arc::new(argocd_tool::GetArgocdApp),
        Arc::new(kube_tool::KubeDescribe),
        Arc::new(kube_tool::KubeEvents),
    ];
    for tool in tools {
        registry.register(tool);
    }
}
