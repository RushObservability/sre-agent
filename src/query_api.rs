use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::time::Duration;

use crate::models::anomaly::{AnomalyEvent, AnomalyRule, DeployMarker};
use crate::models::custom_skills::CustomSkill;
use crate::models::service_link::ServiceLink;

#[derive(Clone)]
pub struct QueryApiClient {
    base_url: Url,
    internal_token: String,
    http: reqwest::Client,
}

impl QueryApiClient {
    pub fn new(base_url: &str, internal_token: String) -> Result<Self> {
        if internal_token.trim().is_empty() {
            bail!("SRE_AGENT_INTERNAL_TOKEN must not be empty");
        }
        let mut base_url = Url::parse(base_url).context("QUERY_API_URL must be a valid URL")?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            bail!(
                "QUERY_API_URL must be an HTTP(S) origin without credentials, query, or fragment"
            );
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(35))
            .build()
            .context("failed to build query-api client")?;
        Ok(Self {
            base_url,
            internal_token,
            http,
        })
    }

    #[doc(hidden)]
    pub fn new_disconnected_for_tests() -> Self {
        Self::new("http://127.0.0.1:1", "test-internal-token".into()).unwrap()
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    fn url(&self, path: &str) -> Result<Url> {
        let path = path.strip_prefix('/').unwrap_or(path);
        self.base_url
            .join(path)
            .context("failed to build query-api URL")
    }

    fn request(
        &self,
        method: Method,
        tenant_id: &str,
        path: &str,
    ) -> Result<reqwest::RequestBuilder> {
        validate_tenant(tenant_id)?;
        let url = Url::parse(path)
            .or_else(|_| self.url(path))
            .context("failed to build query-api request URL")?;
        if url.origin() != self.base_url.origin() {
            bail!("query-api request URL escaped the configured origin");
        }
        Ok(self
            .http
            .request(method, url)
            .header("x-rush-internal-token", &self.internal_token)
            .header("x-rush-tenant", tenant_id))
    }

    async fn send_json<T: DeserializeOwned>(&self, request: reqwest::RequestBuilder) -> Result<T> {
        let response = request.send().await.context("query-api request failed")?;
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            let message = crate::agent::memory::truncate_at_char_boundary(&message, 512);
            bail!("query-api returned {status}: {message}");
        }
        response
            .json::<T>()
            .await
            .context("query-api returned invalid JSON")
    }

    async fn send_empty(&self, request: reqwest::RequestBuilder) -> Result<()> {
        let response = request.send().await.context("query-api request failed")?;
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            let message = crate::agent::memory::truncate_at_char_boundary(&message, 512);
            bail!("query-api returned {status}: {message}");
        }
        Ok(())
    }

    pub async fn ready(&self, tenant_id: &str) -> Result<()> {
        validate_tenant(tenant_id)?;
        let response: Value = self.send_json(self.http.get(self.url("healthz")?)).await?;
        if response
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status != "ok")
        {
            bail!("query-api health check did not report ok");
        }
        Ok(())
    }

    pub async fn llm_ready(&self, tenant_id: &str) -> Result<bool> {
        let response: Value = self
            .send_json(self.request(Method::GET, tenant_id, "api/v1/internal/sre/llm/ready")?)
            .await?;
        Ok(response
            .get("configured")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    pub async fn query_spans<T: DeserializeOwned>(
        &self,
        tenant_id: &str,
        body: &Value,
    ) -> Result<T> {
        self.send_json(
            self.request(Method::POST, tenant_id, "api/v1/query")?
                .json(body),
        )
        .await
    }

    pub async fn query_span_timeseries<T: DeserializeOwned>(
        &self,
        tenant_id: &str,
        body: &Value,
    ) -> Result<T> {
        self.send_json(
            self.request(Method::POST, tenant_id, "api/v1/query/timeseries")?
                .json(body),
        )
        .await
    }

    pub async fn query_logs<T: DeserializeOwned>(
        &self,
        tenant_id: &str,
        body: &Value,
    ) -> Result<T> {
        self.send_json(
            self.request(Method::POST, tenant_id, "api/v1/logs")?
                .json(body),
        )
        .await
    }

    pub async fn get_trace<T: DeserializeOwned>(
        &self,
        tenant_id: &str,
        trace_id: &str,
    ) -> Result<Option<T>> {
        if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("trace_id must be a 32-character hex string");
        }
        let response = self
            .request(Method::GET, tenant_id, &format!("api/v1/traces/{trace_id}"))?
            .send()
            .await
            .context("query-api request failed")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = response.status();
        if !status.is_success() {
            bail!("query-api returned {status}");
        }
        Ok(Some(
            response
                .json()
                .await
                .context("query-api returned invalid trace JSON")?,
        ))
    }

    pub async fn service_graph<T: DeserializeOwned>(
        &self,
        tenant_id: &str,
        minutes: u64,
    ) -> Result<T> {
        let mut url = self.url("api/v1/services/graph")?;
        url.query_pairs_mut()
            .append_pair("minutes", &minutes.clamp(1, 1440).to_string());
        self.send_json(self.request(Method::GET, tenant_id, url.as_str())?)
            .await
    }

    pub async fn prom_query_range<T: DeserializeOwned>(
        &self,
        tenant_id: &str,
        query: &str,
        start: i64,
        end: i64,
        step: u64,
    ) -> Result<T> {
        if query.len() > 4096 || start > end {
            bail!("invalid PromQL range query");
        }
        let mut url = self.url("prom/api/v1/query_range")?;
        url.query_pairs_mut()
            .append_pair("query", query)
            .append_pair("start", &start.to_string())
            .append_pair("end", &end.to_string())
            .append_pair("step", &step.clamp(1, 3600).to_string());
        self.send_json(self.request(Method::GET, tenant_id, url.as_str())?)
            .await
    }

    pub async fn prom_label_values(
        &self,
        tenant_id: &str,
        label: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<String>> {
        if label.is_empty()
            || label.len() > 128
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || start > end
        {
            bail!("invalid Prometheus label query");
        }
        #[derive(Deserialize)]
        struct Response {
            data: Vec<String>,
        }
        let mut url = self.url(&format!("prom/api/v1/label/{label}/values"))?;
        url.query_pairs_mut()
            .append_pair("start", &start.to_string())
            .append_pair("end", &end.to_string());
        Ok(self
            .send_json::<Response>(self.request(Method::GET, tenant_id, url.as_str())?)
            .await?
            .data)
    }

    async fn context<T: DeserializeOwned>(&self, tenant_id: &str, body: Value) -> Result<T> {
        #[derive(Deserialize)]
        struct Envelope<T> {
            data: T,
        }
        let response: Envelope<T> = self
            .send_json(
                self.request(Method::POST, tenant_id, "api/v1/internal/sre/context")?
                    .json(&body),
            )
            .await?;
        Ok(response.data)
    }

    pub async fn list_deploy_markers(
        &self,
        tenant_id: &str,
        service: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Vec<DeployMarker>> {
        self.context(
            tenant_id,
            json!({"operation":"list_deploys","service":service,"from":from,"to":to}),
        )
        .await
    }
    pub async fn list_anomaly_rules(&self, tenant_id: &str) -> Result<Vec<AnomalyRule>> {
        self.context(tenant_id, json!({"operation":"list_anomaly_rules"}))
            .await
    }
    pub async fn get_anomaly_rule(&self, tenant_id: &str, id: &str) -> Result<Option<AnomalyRule>> {
        self.context(tenant_id, json!({"operation":"get_anomaly_rule","id":id}))
            .await
    }
    pub async fn get_anomaly_event(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<AnomalyEvent>> {
        self.context(tenant_id, json!({"operation":"get_anomaly_event","id":id}))
            .await
    }
    pub async fn list_anomaly_events(
        &self,
        tenant_id: &str,
        rule_id: &str,
        limit: i64,
    ) -> Result<Vec<AnomalyEvent>> {
        self.context(
            tenant_id,
            json!({"operation":"list_anomaly_events","rule_id":rule_id,"limit":limit.clamp(1,100)}),
        )
        .await
    }
    pub async fn get_setting(&self, tenant_id: &str, key: &str) -> Result<Option<String>> {
        self.context(tenant_id, json!({"operation":"get_setting","key":key}))
            .await
    }
    pub async fn list_enabled_custom_skills(&self, tenant_id: &str) -> Result<Vec<CustomSkill>> {
        self.context(tenant_id, json!({"operation":"list_enabled_custom_skills"}))
            .await
    }
    pub async fn get_custom_skill_by_name(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<Option<CustomSkill>> {
        self.context(
            tenant_id,
            json!({"operation":"get_custom_skill","name":name}),
        )
        .await
    }
    pub async fn get_service_link(
        &self,
        tenant_id: &str,
        service: &str,
    ) -> Result<Option<ServiceLink>> {
        self.context(
            tenant_id,
            json!({"operation":"get_service_link","service":service}),
        )
        .await
    }

    pub async fn audit_repository_access(
        &self,
        tenant_id: &str,
        service_name: &str,
        repository: &str,
        action: &str,
        path: &str,
    ) -> Result<()> {
        self.send_empty(
            self.request(
                Method::POST,
                tenant_id,
                "api/v1/internal/repository-access-audit",
            )?
            .json(&json!({
                "tenant_id": tenant_id,
                "service_name": service_name,
                "repository": repository,
                "action": action,
                "path": path,
                "outcome": "success"
            })),
        )
        .await
    }

    pub async fn get_kubernetes_access(
        &self,
        tenant_id: &str,
        parameters: &[(String, String)],
        max_bytes: usize,
    ) -> Result<Option<Value>> {
        let mut url = self.url("api/v1/internal/kubernetes-access-events")?;
        url.query_pairs_mut().extend_pairs(
            parameters
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
        let response = self
            .request(Method::GET, tenant_id, url.as_str())?
            .send()
            .await
            .context("query-api request failed")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = response.status();
        if !status.is_success() {
            bail!("query-api returned {status}");
        }
        if response
            .content_length()
            .is_some_and(|bytes| bytes > max_bytes as u64)
        {
            bail!("query-api response exceeds its size limit");
        }
        let body = response
            .bytes()
            .await
            .context("failed to read query-api response")?;
        if body.len() > max_bytes {
            bail!("query-api response exceeds its size limit");
        }
        Ok(Some(
            serde_json::from_slice(&body).context("query-api returned invalid JSON")?,
        ))
    }

    pub async fn create_session(
        &self,
        id: &str,
        tenant_id: &str,
        title: &str,
        created_by: &str,
        template_id: &str,
    ) -> Result<()> {
        self.send_empty(self.request(Method::POST, tenant_id, "api/v1/internal/sre/sessions")?.json(&json!({"id":id,"title":title,"created_by":created_by,"template_id":template_id}))).await
    }
    pub async fn get_session(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<InvestigationSession>> {
        let response = self
            .request(
                Method::GET,
                tenant_id,
                &format!("api/v1/internal/sre/sessions/{id}"),
            )?
            .send()
            .await
            .context("query-api request failed")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = response.status();
        if !status.is_success() {
            bail!("query-api returned {status}");
        }
        Ok(Some(
            response
                .json()
                .await
                .context("query-api returned invalid session JSON")?,
        ))
    }
    pub async fn list_sessions(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<InvestigationSession>> {
        #[derive(Deserialize)]
        struct Response {
            sessions: Vec<InvestigationSession>,
        }
        let mut url = self.url("api/v1/internal/sre/sessions")?;
        url.query_pairs_mut()
            .append_pair("limit", &limit.clamp(1, 200).to_string());
        Ok(self
            .send_json::<Response>(self.request(Method::GET, tenant_id, url.as_str())?)
            .await?
            .sessions)
    }
    pub async fn update_session_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> Result<()> {
        self.patch_session(tenant_id, id, json!({"status":status}))
            .await
    }
    pub async fn update_session_title(&self, tenant_id: &str, id: &str, title: &str) -> Result<()> {
        self.patch_session(tenant_id, id, json!({"title":title}))
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn update_session_after_turn(
        &self,
        tenant_id: &str,
        id: &str,
        memory: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        model: &str,
        status: Option<&str>,
    ) -> Result<()> {
        self.patch_session(tenant_id, id, json!({"working_memory":memory,"prompt_tokens_delta":prompt_tokens,"completion_tokens_delta":completion_tokens,"llm_model":model,"status":status})).await
    }
    async fn patch_session(&self, tenant_id: &str, id: &str, body: Value) -> Result<()> {
        self.send_empty(
            self.request(
                Method::PATCH,
                tenant_id,
                &format!("api/v1/internal/sre/sessions/{id}"),
            )?
            .json(&body),
        )
        .await
    }
    pub async fn delete_session(&self, tenant_id: &str, id: &str) -> Result<()> {
        self.send_empty(self.request(
            Method::DELETE,
            tenant_id,
            &format!("api/v1/internal/sre/sessions/{id}"),
        )?)
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn add_turn(
        &self,
        tenant_id: &str,
        id: &str,
        session_id: &str,
        turn_index: i64,
        role: &str,
        content: &str,
        tool_calls: &str,
        report_kind: &str,
    ) -> Result<()> {
        self.send_empty(self.request(Method::POST, tenant_id, &format!("api/v1/internal/sre/sessions/{session_id}/turns"))?.json(&json!({"id":id,"turn_index":turn_index,"role":role,"content":content,"tool_calls":tool_calls,"report_kind":report_kind}))).await
    }
    pub async fn get_turns(
        &self,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<Vec<InvestigationTurn>> {
        self.fetch_turns(tenant_id, session_id, None).await
    }
    pub async fn get_recent_turns(
        &self,
        tenant_id: &str,
        session_id: &str,
        limit: i64,
    ) -> Result<Vec<InvestigationTurn>> {
        self.fetch_turns(tenant_id, session_id, Some(limit.clamp(1, 200)))
            .await
    }
    async fn fetch_turns(
        &self,
        tenant_id: &str,
        session_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<InvestigationTurn>> {
        #[derive(Deserialize)]
        struct Response {
            turns: Vec<InvestigationTurn>,
        }
        let mut url = self.url(&format!("api/v1/internal/sre/sessions/{session_id}/turns"))?;
        if let Some(limit) = limit {
            url.query_pairs_mut()
                .append_pair("limit", &limit.to_string());
        }
        Ok(self
            .send_json::<Response>(self.request(Method::GET, tenant_id, url.as_str())?)
            .await?
            .turns)
    }
    pub async fn count_turns(&self, tenant_id: &str, session_id: &str) -> Result<i64> {
        #[derive(Deserialize)]
        struct Response {
            count: i64,
        }
        let mut url = self.url(&format!("api/v1/internal/sre/sessions/{session_id}/turns"))?;
        url.query_pairs_mut().append_pair("count_only", "true");
        Ok(self
            .send_json::<Response>(self.request(Method::GET, tenant_id, url.as_str())?)
            .await?
            .count)
    }
}

fn validate_tenant(tenant_id: &str) -> Result<()> {
    if tenant_id.is_empty()
        || tenant_id.len() > 128
        || tenant_id.eq_ignore_ascii_case("_audit")
        || tenant_id.chars().any(|c| c.is_control())
    {
        bail!("invalid tenant scope");
    }
    Ok(())
}

pub fn bounded_time_range(
    around: &str,
    around_minutes: u64,
    minutes: u64,
) -> Result<(String, String)> {
    let to = if around.trim().is_empty() {
        chrono::Utc::now()
    } else {
        chrono::DateTime::parse_from_rfc3339(around)
            .context("around must be an RFC3339 timestamp")?
            .with_timezone(&chrono::Utc)
    };
    let from = if around.trim().is_empty() {
        to - chrono::Duration::minutes(minutes.clamp(1, 1440) as i64)
    } else {
        to - chrono::Duration::minutes(around_minutes.clamp(1, 720) as i64)
    };
    let to = if around.trim().is_empty() {
        to
    } else {
        to + chrono::Duration::minutes(around_minutes.clamp(1, 720) as i64)
    };
    Ok((from.to_rfc3339(), to.to_rfc3339()))
}

pub fn format_nanos_timestamp(nanos: i64) -> String {
    let seconds = nanos.div_euclid(1_000_000_000);
    let subsecond = nanos.rem_euclid(1_000_000_000) as u32;
    chrono::DateTime::from_timestamp(seconds, subsecond)
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| nanos.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSession {
    pub id: String,
    pub tenant_id: String,
    pub title: String,
    pub status: String,
    pub template_id: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub working_memory: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub llm_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationTurn {
    pub id: String,
    pub session_id: String,
    pub turn_index: i64,
    pub role: String,
    pub content: String,
    pub tool_calls: String,
    pub report_kind: String,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_rejects_credentials_and_non_http_schemes() {
        assert!(QueryApiClient::new("file:///tmp/query-api", "token".into()).is_err());
        assert!(QueryApiClient::new("http://user:pass@localhost:8080", "token".into()).is_err());
        assert!(QueryApiClient::new("http://localhost:8080", "token".into()).is_ok());
    }

    #[test]
    fn tenant_scope_rejects_reserved_tenant() {
        assert!(validate_tenant("customer-a").is_ok());
        assert!(validate_tenant("_audit").is_err());
    }

    #[test]
    fn internal_requests_are_tenant_scoped_and_authenticated() {
        let client = QueryApiClient::new("http://query-api:8080", "shared-secret".into()).unwrap();
        let request = client
            .request(Method::POST, "customer-a", "api/v1/query")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.url().as_str(), "http://query-api:8080/api/v1/query");
        assert_eq!(request.headers()["x-rush-tenant"], "customer-a");
        assert_eq!(request.headers()["x-rush-internal-token"], "shared-secret");
    }

    #[test]
    fn requests_cannot_escape_the_configured_origin() {
        let client = QueryApiClient::new("http://query-api:8080", "shared-secret".into()).unwrap();
        assert!(
            client
                .request(
                    Method::GET,
                    "customer-a",
                    "http://attacker.invalid/api/v1/query"
                )
                .is_err()
        );
    }
}
