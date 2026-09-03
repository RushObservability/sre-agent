#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServiceLink {
    pub tenant_id: String,
    pub service_name: String,
    pub github_repo: String,
    pub github_installation_id: u64,
    pub github_repository_id: u64,
    pub default_branch: String,
    pub root_path: String,
    #[serde(default)]
    pub updated_at: String,
}
