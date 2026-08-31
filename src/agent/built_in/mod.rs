mod advanced_analysis;
mod anomalies;
mod argocd_tool;
mod deploys;
mod flux_tool;
mod kube_tool;
mod kubernetes_access;
mod logs;
mod metrics;
mod mysql;
mod past_incidents;
mod postgres;
mod repository_tools;
mod service_analysis;
mod services;
mod skills_tool;
mod traces;

use crate::agent::tools::{Tool, ToolRegistry};
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
        Arc::new(service_analysis::CompareServiceWindows),
        Arc::new(service_analysis::RankSlowDependencies),
        Arc::new(advanced_analysis::AnalyzeTraceCriticalPath),
        Arc::new(advanced_analysis::GetResourceSaturation),
        Arc::new(advanced_analysis::ListMetricCatalog),
        Arc::new(advanced_analysis::DetectServiceSilence),
        Arc::new(deploys::ListDeploys),
        Arc::new(anomalies::GetAnomalyContext),
        Arc::new(past_incidents::SearchPastIncidents),
        Arc::new(postgres::InspectPostgresql),
        Arc::new(mysql::InspectMysql),
        Arc::new(repository_tools::ListRepositoryFiles),
        Arc::new(repository_tools::SearchRepository),
        Arc::new(repository_tools::ReadRepositoryFile),
        Arc::new(skills_tool::LoadSkill),
        Arc::new(argocd_tool::GetArgocdApp),
        Arc::new(flux_tool::GetFluxResource),
        Arc::new(kube_tool::KubeDescribe),
        Arc::new(kube_tool::KubeEvents),
        Arc::new(kubernetes_access::SearchKubernetesAccess),
    ];
    for tool in tools {
        registry.register(tool);
    }
}
