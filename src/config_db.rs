//! ClickHouse adapter over the shared `observability` config tables.
//!
//! For shared tables (anomaly_rules, deploy_markers, custom_skills, settings)
//! the agent reads from `config_*` tables owned and created by query-api. For
//! investigation sessions and turns, the agent owns the schema and reads/writes
//! directly — it runs `CREATE TABLE IF NOT EXISTS` for those two tables only,
//! for standalone/first-boot safety (idempotent; query-api also creates them).
//!
//! Mutable tables use the ReplacingMergeTree pattern (mirror query-api's
//! `clickhouse_config.rs`):
//!   - INSERT rows with a monotonic `version` and `is_deleted = 0`.
//!   - READ latest with `... FINAL WHERE is_deleted = 0 AND ...`.
//!   - UPDATE = re-INSERT the full row with a higher `version`.
//!   - DELETE = re-INSERT with `is_deleted = 1` and a higher `version`.

use clickhouse::Client;

use crate::models::anomaly::{AnomalyEvent, AnomalyRule, DeployMarker};
use crate::models::custom_skills::CustomSkill;
use crate::models::service_link::ServiceLink;

pub struct ConfigDb {
    pub client: Client,
}

// ── Intermediate ClickHouse row structs ────────────────────────────────────

#[derive(clickhouse::Row, serde::Deserialize)]
struct DeployMarkerRow {
    id: String,
    service_name: String,
    version: String,
    commit_sha: String,
    description: String,
    environment: String,
    deployed_by: String,
    deployed_at: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct AnomalyRuleRow {
    id: String,
    name: String,
    description: String,
    enabled: u8,
    source: String,
    pattern: String,
    query: String,
    service_name: String,
    apm_metric: String,
    sensitivity: f64,
    alpha: f64,
    eval_interval_secs: i64,
    window_secs: i64,
    split_labels: String,
    notification_channel_ids: String,
    state: String,
    last_eval_at: String,
    last_triggered_at: String,
    created_at: String,
    updated_at: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct AnomalyEventRow {
    id: String,
    rule_id: String,
    state: String,
    metric: String,
    value: f64,
    expected: f64,
    deviation: f64,
    message: String,
    created_at: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct CustomSkillRow {
    id: String,
    name: String,
    title: String,
    description: String,
    content: String,
    allowed_tools: String,
    enabled: u8,
    created_by: String,
    created_at: String,
    updated_at: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct InvestigationSessionRow {
    id: String,
    tenant_id: String,
    title: String,
    status: String,
    template_id: String,
    created_by: String,
    created_at: String,
    updated_at: String,
    working_memory: String,
    prompt_tokens: i64,
    completion_tokens: i64,
    llm_model: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct InvestigationTurnRow {
    id: String,
    session_id: String,
    turn_index: i64,
    role: String,
    content: String,
    tool_calls: String,
    report_kind: String,
    created_at: String,
}

impl ConfigDb {
    /// Resolve a repository link inside the caller's tenant. Repository links
    /// live in query-api's tenant-safe v2 table; the agent is read-only here.
    pub async fn get_service_link(
        &self,
        tenant_id: &str,
        service_name: &str,
    ) -> anyhow::Result<Option<ServiceLink>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            tenant_id: String,
            service_name: String,
            github_repo: String,
            github_installation_id: u64,
            github_repository_id: u64,
            default_branch: String,
            root_path: String,
        }

        let result = self.client
            .query("SELECT tenant_id, service_name, github_repo, github_installation_id, github_repository_id, default_branch, root_path FROM config_service_links_v2 FINAL WHERE tenant_id = ? AND service_name = ? AND is_deleted = 0 LIMIT 1")
            .bind(tenant_id)
            .bind(service_name)
            .fetch_one::<Row>()
            .await;
        match result {
            Ok(row) => Ok(Some(ServiceLink {
                tenant_id: row.tenant_id,
                service_name: row.service_name,
                github_repo: row.github_repo,
                github_installation_id: row.github_installation_id,
                github_repository_id: row.github_repository_id,
                default_branch: row.default_branch,
                root_path: row.root_path,
            })),
            Err(clickhouse::error::Error::RowNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Build the ClickHouse client and ensure the two agent-owned tables exist.
    ///
    /// The 5 shared tables (deploy_markers, anomaly_rules, anomaly_events,
    /// settings, custom_skills) are owned by query-api and are NOT created here.
    /// NOTE: no `.with_database()` — config_* tables live in the ClickHouse session
    /// default database (`default`), exactly like query-api's ConfigDb. The telemetry
    /// data tables (spans, logs, …) live in `observability`, but config does
    /// NOT. Setting a database here would point the agent at empty/wrong tables.
    pub async fn open(url: &str, user: &str, password: &str) -> anyhow::Result<Self> {
        let client = Client::default()
            .with_url(url)
            .with_user(user)
            .with_password(password);
        let db = Self { client };
        db.run_owned_migrations().await?;
        Ok(db)
    }

    /// TEST-ONLY constructor: build a ConfigDb whose client points at an
    /// unroutable localhost port, WITHOUT connecting or running migrations.
    ///
    /// The `clickhouse` crate client is lazy — no I/O happens until a query
    /// is executed — so this is synchronous and infallible. Any query made
    /// through it fails fast with a connection error.
    ///
    /// Exists so integration tests (e.g. `tests/loop_runner_mock.rs`) can
    /// build a `ToolContext` without a live ClickHouse. NEVER use this in
    /// production code paths: it is deliberately disconnected and skips the
    /// owned-table migrations that `open` guarantees.
    pub fn new_disconnected_for_tests() -> Self {
        Self {
            // Port 1 (tcpmux) is unroutable/closed on any sane dev box —
            // queries error out immediately instead of hanging.
            client: Client::default().with_url("http://127.0.0.1:1"),
        }
    }

    /// Create the two sre-agent-owned tables if they do not already exist.
    /// Idempotent — for standalone/first-boot safety. Schemas match query-api.
    async fn run_owned_migrations(&self) -> anyhow::Result<()> {
        let ddls = [
            // Investigation sessions (owned by sre-agent; mutable → ReplacingMergeTree)
            "CREATE TABLE IF NOT EXISTS config_investigation_sessions (
                id                String,
                tenant_id         String DEFAULT 'default',
                title             String DEFAULT '',
                status            String DEFAULT 'active',
                template_id       String DEFAULT '',
                created_by        String DEFAULT '',
                created_at        String DEFAULT toString(now()),
                updated_at        String DEFAULT toString(now()),
                working_memory    String DEFAULT '{}',
                prompt_tokens     Int64 DEFAULT 0,
                completion_tokens Int64 DEFAULT 0,
                llm_model         String DEFAULT '',
                version           UInt64,
                is_deleted        UInt8 DEFAULT 0
            ) ENGINE = ReplacingMergeTree(version)
            ORDER BY (id)",
            // Investigation turns (owned by sre-agent; append-only)
            "CREATE TABLE IF NOT EXISTS config_investigation_turns (
                id          String,
                session_id  String,
                turn_index  Int64,
                role        String,
                content     String,
                tool_calls  String DEFAULT '[]',
                report_kind String DEFAULT '',
                created_at  String DEFAULT toString(now())
            ) ENGINE = MergeTree()
            ORDER BY (session_id, turn_index)",
        ];

        for ddl in ddls {
            self.client
                .query(ddl)
                .execute()
                .await
                .map_err(|e| anyhow::anyhow!("DDL failed: {e}\nSQL: {ddl}"))?;
        }
        Ok(())
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn now_str() -> String {
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    fn next_version() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    fn map_anomaly_rule(r: AnomalyRuleRow) -> AnomalyRule {
        AnomalyRule {
            id: r.id,
            name: r.name,
            description: r.description,
            enabled: r.enabled != 0,
            source: r.source,
            pattern: r.pattern,
            query: r.query,
            service_name: r.service_name,
            apm_metric: r.apm_metric,
            sensitivity: r.sensitivity,
            alpha: r.alpha,
            eval_interval_secs: r.eval_interval_secs,
            window_secs: r.window_secs,
            split_labels: r.split_labels,
            notification_channel_ids: r.notification_channel_ids,
            state: r.state,
            last_eval_at: if r.last_eval_at.is_empty() {
                None
            } else {
                Some(r.last_eval_at)
            },
            last_triggered_at: if r.last_triggered_at.is_empty() {
                None
            } else {
                Some(r.last_triggered_at)
            },
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }

    fn map_session(r: InvestigationSessionRow) -> InvestigationSession {
        InvestigationSession {
            id: r.id,
            tenant_id: r.tenant_id,
            title: r.title,
            status: r.status,
            template_id: r.template_id,
            created_by: r.created_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
            working_memory: r.working_memory,
            prompt_tokens: r.prompt_tokens,
            completion_tokens: r.completion_tokens,
            llm_model: r.llm_model,
        }
    }

    fn map_turn(r: InvestigationTurnRow) -> InvestigationTurn {
        InvestigationTurn {
            id: r.id,
            session_id: r.session_id,
            turn_index: r.turn_index,
            role: r.role,
            content: r.content,
            tool_calls: r.tool_calls,
            report_kind: r.report_kind,
            created_at: r.created_at,
        }
    }

    // ── Deploy markers (read-only; shared, owned by query-api) ──

    pub async fn list_deploy_markers(
        &self,
        service_name: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> anyhow::Result<Vec<DeployMarker>> {
        // ClickHouse doesn't support optional parameters; build SQL dynamically.
        let sql = {
            let mut s = "SELECT id, service_name, version, commit_sha, description, environment, deployed_by, deployed_at FROM config_deploy_markers WHERE 1=1".to_string();
            if service_name.is_some() {
                s.push_str(" AND service_name = ?");
            }
            if from.is_some() {
                s.push_str(" AND deployed_at >= ?");
            }
            if to.is_some() {
                s.push_str(" AND deployed_at <= ?");
            }
            s.push_str(" ORDER BY deployed_at DESC LIMIT 100");
            s
        };
        let mut q = self.client.query(&sql);
        if let Some(sn) = service_name {
            q = q.bind(sn);
        }
        if let Some(f) = from {
            q = q.bind(f);
        }
        if let Some(t) = to {
            q = q.bind(t);
        }
        let rows = q.fetch_all::<DeployMarkerRow>().await?;
        Ok(rows
            .into_iter()
            .map(|r| DeployMarker {
                id: r.id,
                service_name: r.service_name,
                version: r.version,
                commit_sha: r.commit_sha,
                description: r.description,
                environment: r.environment,
                deployed_by: r.deployed_by,
                deployed_at: r.deployed_at,
            })
            .collect())
    }

    // ── Anomaly rules (read-only; shared, owned by query-api) ──

    pub async fn list_anomaly_rules(&self) -> anyhow::Result<Vec<AnomalyRule>> {
        let rows = self.client
            .query("SELECT id, name, description, enabled, source, pattern, query, service_name, apm_metric, sensitivity, alpha, eval_interval_secs, window_secs, split_labels, notification_channel_ids, state, last_eval_at, last_triggered_at, created_at, updated_at FROM config_anomaly_rules FINAL WHERE is_deleted = 0 ORDER BY created_at DESC")
            .fetch_all::<AnomalyRuleRow>()
            .await?;
        Ok(rows.into_iter().map(Self::map_anomaly_rule).collect())
    }

    pub async fn get_anomaly_rule(&self, id: &str) -> anyhow::Result<Option<AnomalyRule>> {
        let result = self.client
            .query("SELECT id, name, description, enabled, source, pattern, query, service_name, apm_metric, sensitivity, alpha, eval_interval_secs, window_secs, split_labels, notification_channel_ids, state, last_eval_at, last_triggered_at, created_at, updated_at FROM config_anomaly_rules FINAL WHERE id = ? AND is_deleted = 0 LIMIT 1")
            .bind(id)
            .fetch_one::<AnomalyRuleRow>()
            .await;
        match result {
            Ok(r) => Ok(Some(Self::map_anomaly_rule(r))),
            Err(clickhouse::error::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ── Anomaly events (read-only; shared, owned by query-api) ──

    pub async fn get_anomaly_event(&self, id: &str) -> anyhow::Result<Option<AnomalyEvent>> {
        let result = self.client
            .query("SELECT id, rule_id, state, metric, value, expected, deviation, message, created_at FROM config_anomaly_events WHERE id = ? LIMIT 1")
            .bind(id)
            .fetch_one::<AnomalyEventRow>()
            .await;
        match result {
            Ok(r) => Ok(Some(AnomalyEvent {
                id: r.id,
                rule_id: r.rule_id,
                state: r.state,
                metric: r.metric,
                value: r.value,
                expected: r.expected,
                deviation: r.deviation,
                message: r.message,
                created_at: r.created_at,
            })),
            Err(clickhouse::error::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn list_anomaly_events(
        &self,
        rule_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<AnomalyEvent>> {
        let rows = self.client
            .query("SELECT id, rule_id, state, metric, value, expected, deviation, message, created_at FROM config_anomaly_events WHERE rule_id = ? ORDER BY created_at DESC LIMIT ?")
            .bind(rule_id)
            .bind(limit as u64)
            .fetch_all::<AnomalyEventRow>()
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| AnomalyEvent {
                id: r.id,
                rule_id: r.rule_id,
                state: r.state,
                metric: r.metric,
                value: r.value,
                expected: r.expected,
                deviation: r.deviation,
                message: r.message,
                created_at: r.created_at,
            })
            .collect())
    }

    // ── Settings (read-only; shared, owned by query-api) ──

    pub async fn get_setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            value: String,
        }
        let result = self
            .client
            .query(
                "SELECT value FROM config_settings FINAL WHERE key = ? AND is_deleted = 0 LIMIT 1",
            )
            .bind(key)
            .fetch_one::<Row>()
            .await;
        match result {
            Ok(r) => Ok(Some(r.value)),
            Err(clickhouse::error::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ── Custom skills (read-only; shared, owned by query-api) ──

    /// List only enabled custom skills, ordered by name.
    pub async fn list_enabled_custom_skills(&self) -> anyhow::Result<Vec<CustomSkill>> {
        let rows = self.client
            .query("SELECT id, name, title, description, content, allowed_tools, enabled, created_by, created_at, updated_at FROM config_custom_skills FINAL WHERE is_deleted = 0 AND enabled = 1 ORDER BY name ASC")
            .fetch_all::<CustomSkillRow>()
            .await?;
        Ok(rows.into_iter().map(Self::map_custom_skill).collect())
    }

    /// Fetch a single custom skill by its unique `name`. Returns regardless of
    /// `enabled` status so callers can surface a clear error when an explicitly
    /// requested skill has been disabled.
    pub async fn get_custom_skill_by_name(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<CustomSkill>> {
        let result = self.client
            .query("SELECT id, name, title, description, content, allowed_tools, enabled, created_by, created_at, updated_at FROM config_custom_skills FINAL WHERE name = ? AND is_deleted = 0 LIMIT 1")
            .bind(name)
            .fetch_one::<CustomSkillRow>()
            .await;
        match result {
            Ok(r) => Ok(Some(Self::map_custom_skill(r))),
            Err(clickhouse::error::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn map_custom_skill(r: CustomSkillRow) -> CustomSkill {
        CustomSkill {
            id: r.id,
            name: r.name,
            title: r.title,
            description: r.description,
            content: r.content,
            allowed_tools: serde_json::from_str(&r.allowed_tools).unwrap_or_default(),
            enabled: r.enabled != 0,
            created_by: r.created_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }

    // ── Investigation sessions (owned by sre-agent) ──

    /// Create a new investigation session.
    pub async fn create_session(
        &self,
        id: &str,
        tenant_id: &str,
        title: &str,
        created_by: &str,
        template_id: &str,
    ) -> anyhow::Result<()> {
        let now = Self::now_str();
        let ver = Self::next_version();
        self.client
            .query("INSERT INTO config_investigation_sessions (id, tenant_id, title, status, template_id, created_by, created_at, updated_at, working_memory, prompt_tokens, completion_tokens, llm_model, version, is_deleted) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, '{}', 0, 0, '', ?, 0)")
            .bind(id)
            .bind(tenant_id)
            .bind(title)
            .bind(template_id)
            .bind(created_by)
            .bind(&now)
            .bind(&now)
            .bind(ver)
            .execute()
            .await?;
        Ok(())
    }

    /// Get a session by ID.
    pub async fn get_session(&self, id: &str) -> anyhow::Result<Option<InvestigationSession>> {
        let result = self.client
            .query("SELECT id, tenant_id, title, status, template_id, created_by, created_at, updated_at, working_memory, prompt_tokens, completion_tokens, llm_model FROM config_investigation_sessions FINAL WHERE id = ? AND is_deleted = 0 LIMIT 1")
            .bind(id)
            .fetch_one::<InvestigationSessionRow>()
            .await;
        match result {
            Ok(r) => Ok(Some(Self::map_session(r))),
            Err(clickhouse::error::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update the status of a session (active, completed, archived).
    pub async fn update_session_status(&self, id: &str, status: &str) -> anyhow::Result<()> {
        let existing = match self.get_session(id).await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let now = Self::now_str();
        let ver = Self::next_version();
        self.client
            .query("INSERT INTO config_investigation_sessions (id, tenant_id, title, status, template_id, created_by, created_at, updated_at, working_memory, prompt_tokens, completion_tokens, llm_model, version, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)")
            .bind(&existing.id)
            .bind(&existing.tenant_id)
            .bind(&existing.title)
            .bind(status)
            .bind(&existing.template_id)
            .bind(&existing.created_by)
            .bind(&existing.created_at)
            .bind(&now)
            .bind(&existing.working_memory)
            .bind(existing.prompt_tokens)
            .bind(existing.completion_tokens)
            .bind(&existing.llm_model)
            .bind(ver)
            .execute()
            .await?;
        Ok(())
    }

    /// Update the title of a session.
    pub async fn update_session_title(&self, id: &str, title: &str) -> anyhow::Result<()> {
        let existing = match self.get_session(id).await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let now = Self::now_str();
        let ver = Self::next_version();
        self.client
            .query("INSERT INTO config_investigation_sessions (id, tenant_id, title, status, template_id, created_by, created_at, updated_at, working_memory, prompt_tokens, completion_tokens, llm_model, version, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)")
            .bind(&existing.id)
            .bind(&existing.tenant_id)
            .bind(title)
            .bind(&existing.status)
            .bind(&existing.template_id)
            .bind(&existing.created_by)
            .bind(&existing.created_at)
            .bind(&now)
            .bind(&existing.working_memory)
            .bind(existing.prompt_tokens)
            .bind(existing.completion_tokens)
            .bind(&existing.llm_model)
            .bind(ver)
            .execute()
            .await?;
        Ok(())
    }

    /// End-of-turn finalization in a single read + single versioned insert.
    ///
    /// Replaces the old `update_session_memory` + `update_session_tokens`
    /// (+ `update_session_status`) sequence, which performed one
    /// `SELECT … FINAL` and one full-row INSERT *each* (3–4 FINAL scans and
    /// row versions per turn, with clobber races between them). Token counts
    /// are additive; `status: None` keeps the existing status.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_session_after_turn(
        &self,
        session_id: &str,
        memory_json: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        model: &str,
        status: Option<&str>,
    ) -> anyhow::Result<()> {
        let existing = match self.get_session(session_id).await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let now = Self::now_str();
        let ver = Self::next_version();
        let new_prompt = existing.prompt_tokens + prompt_tokens as i64;
        let new_completion = existing.completion_tokens + completion_tokens as i64;
        let status = status.unwrap_or(&existing.status);
        self.client
            .query("INSERT INTO config_investigation_sessions (id, tenant_id, title, status, template_id, created_by, created_at, updated_at, working_memory, prompt_tokens, completion_tokens, llm_model, version, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)")
            .bind(&existing.id)
            .bind(&existing.tenant_id)
            .bind(&existing.title)
            .bind(status)
            .bind(&existing.template_id)
            .bind(&existing.created_by)
            .bind(&existing.created_at)
            .bind(&now)
            .bind(memory_json)
            .bind(new_prompt)
            .bind(new_completion)
            .bind(model)
            .bind(ver)
            .execute()
            .await?;
        Ok(())
    }

    /// List recent sessions for a tenant.
    pub async fn list_sessions(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<InvestigationSession>> {
        let rows = self.client
            .query("SELECT id, tenant_id, title, status, template_id, created_by, created_at, updated_at, working_memory, prompt_tokens, completion_tokens, llm_model FROM config_investigation_sessions FINAL WHERE tenant_id = ? AND is_deleted = 0 AND status != 'archived' ORDER BY updated_at DESC LIMIT ?")
            .bind(tenant_id)
            .bind(limit as u64)
            .fetch_all::<InvestigationSessionRow>()
            .await?;
        Ok(rows.into_iter().map(Self::map_session).collect())
    }

    /// Delete a session (soft-delete via tombstone).
    pub async fn delete_session(&self, id: &str) -> anyhow::Result<()> {
        let existing = match self.get_session(id).await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let now = Self::now_str();
        let ver = Self::next_version();
        self.client
            .query("INSERT INTO config_investigation_sessions (id, tenant_id, title, status, template_id, created_by, created_at, updated_at, working_memory, prompt_tokens, completion_tokens, llm_model, version, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)")
            .bind(&existing.id)
            .bind(&existing.tenant_id)
            .bind(&existing.title)
            .bind(&existing.status)
            .bind(&existing.template_id)
            .bind(&existing.created_by)
            .bind(&existing.created_at)
            .bind(&now)
            .bind(&existing.working_memory)
            .bind(existing.prompt_tokens)
            .bind(existing.completion_tokens)
            .bind(&existing.llm_model)
            .bind(ver)
            .execute()
            .await?;
        Ok(())
    }

    // ── Investigation turns (owned by sre-agent; append-only) ──

    /// Append a turn to a session.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_turn(
        &self,
        id: &str,
        session_id: &str,
        turn_index: i64,
        role: &str,
        content: &str,
        tool_calls: &str,
        report_kind: &str,
    ) -> anyhow::Result<()> {
        let now = Self::now_str();
        self.client
            .query("INSERT INTO config_investigation_turns (id, session_id, turn_index, role, content, tool_calls, report_kind, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(session_id)
            .bind(turn_index)
            .bind(role)
            .bind(content)
            .bind(tool_calls)
            .bind(report_kind)
            .bind(&now)
            .execute()
            .await?;
        Ok(())
    }

    /// Get all turns for a session, ordered by turn_index.
    pub async fn get_turns(&self, session_id: &str) -> anyhow::Result<Vec<InvestigationTurn>> {
        let rows = self.client
            .query("SELECT id, session_id, turn_index, role, content, tool_calls, report_kind, created_at FROM config_investigation_turns WHERE session_id = ? ORDER BY turn_index ASC")
            .bind(session_id)
            .fetch_all::<InvestigationTurnRow>()
            .await?;
        Ok(rows.into_iter().map(Self::map_turn).collect())
    }

    /// Get the last N turns for a session (for context window reconstruction).
    pub async fn get_recent_turns(
        &self,
        session_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<InvestigationTurn>> {
        // Sub-query to get latest N in DESC, then re-sort ASC for message ordering.
        let rows = self.client
            .query("SELECT id, session_id, turn_index, role, content, tool_calls, report_kind, created_at FROM (SELECT id, session_id, turn_index, role, content, tool_calls, report_kind, created_at FROM config_investigation_turns WHERE session_id = ? ORDER BY turn_index DESC LIMIT ?) ORDER BY turn_index ASC")
            .bind(session_id)
            .bind(limit as u64)
            .fetch_all::<InvestigationTurnRow>()
            .await?;
        Ok(rows.into_iter().map(Self::map_turn).collect())
    }

    /// Count turns in a session (for determining next turn_index).
    pub async fn count_turns(&self, session_id: &str) -> anyhow::Result<i64> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Count {
            n: u64,
        }
        let row = self
            .client
            .query("SELECT count() AS n FROM config_investigation_turns WHERE session_id = ?")
            .bind(session_id)
            .fetch_one::<Count>()
            .await?;
        Ok(row.n as i64)
    }
}

/// Row struct for `investigation_sessions`.
#[derive(Debug, Clone, serde::Serialize)]
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

/// Row struct for `investigation_turns`.
#[derive(Debug, Clone, serde::Serialize)]
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

    /// Build a ConfigDb against a live ClickHouse for integration testing.
    /// Reads connection params from env, defaulting to localhost. All tests in
    /// this module are `#[ignore]`d because they require a running ClickHouse
    /// with query-api's `config_*` schema present; run with
    /// `cargo test -- --ignored` against a live instance.
    async fn live_db() -> ConfigDb {
        let url =
            std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".to_string());
        let password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
        ConfigDb::open(&url, &user, &password).await.unwrap()
    }

    #[tokio::test]
    #[ignore = "requires a live ClickHouse with query-api config schema"]
    async fn open_succeeds_and_lists_are_queryable() {
        let db = live_db().await;
        // Should be able to query the shared tables without errors.
        db.list_anomaly_rules().await.unwrap();
        db.list_deploy_markers(None, None, None).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live ClickHouse with query-api config schema"]
    async fn get_missing_anomaly_rule_returns_none() {
        let db = live_db().await;
        assert!(db.get_anomaly_rule("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live ClickHouse with query-api config schema"]
    async fn get_missing_setting_returns_none() {
        let db = live_db().await;
        assert!(db.get_setting("unknown_key").await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live ClickHouse with query-api config schema"]
    async fn session_roundtrip() {
        let db = live_db().await;
        let id = uuid::Uuid::new_v4().to_string();
        db.create_session(&id, "tenant-a", "My investigation", "alice", "")
            .await
            .unwrap();
        let s = db.get_session(&id).await.unwrap().unwrap();
        assert_eq!(s.tenant_id, "tenant-a");
        assert_eq!(s.title, "My investigation");
        assert_eq!(s.status, "active");
        db.delete_session(&id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live ClickHouse with query-api config schema"]
    async fn turn_roundtrip_and_count() {
        let db = live_db().await;
        let sid = uuid::Uuid::new_v4().to_string();
        db.create_session(&sid, "t", "", "", "").await.unwrap();
        assert_eq!(db.count_turns(&sid).await.unwrap(), 0);
        db.add_turn(
            &uuid::Uuid::new_v4().to_string(),
            &sid,
            0,
            "user",
            "q",
            "[]",
            "",
        )
        .await
        .unwrap();
        db.add_turn(
            &uuid::Uuid::new_v4().to_string(),
            &sid,
            1,
            "assistant",
            "a",
            "[]",
            "final",
        )
        .await
        .unwrap();
        assert_eq!(db.count_turns(&sid).await.unwrap(), 2);
        let turns = db.get_turns(&sid).await.unwrap();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, "user");
        assert_eq!(turns[1].report_kind, "final");
        db.delete_session(&sid).await.unwrap();
    }
}
