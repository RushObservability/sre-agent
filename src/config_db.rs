//! SQLite adapter over the shared `rush_config.db` file.
//!
//! For shared tables (anomaly_rules, deploy_markers, custom_skills, settings)
//! the agent reads from tables owned by query-api. For investigation sessions
//! and turns, the agent owns the schema and reads/writes directly.

use rusqlite::{Connection, params};
use std::sync::Mutex;

use crate::models::anomaly::{AnomalyEvent, AnomalyRule, DeployMarker};
use crate::models::custom_skills::CustomSkill;

pub struct ConfigDb {
    conn: Mutex<Connection>,
}

impl ConfigDb {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let _ = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");

        // Ensure the tables the agent reads from exist. If the database is
        // shared with query-api, these are no-ops (CREATE IF NOT EXISTS). If
        // the agent is running standalone with a fresh file, this gives us
        // stub tables so queries return empty results instead of "no such
        // table" errors.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS deploy_markers (
                id TEXT PRIMARY KEY,
                service_name TEXT NOT NULL,
                version TEXT NOT NULL,
                commit_sha TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                environment TEXT NOT NULL DEFAULT '',
                deployed_by TEXT NOT NULL DEFAULT '',
                deployed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anomaly_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL DEFAULT '',
                pattern TEXT NOT NULL DEFAULT '',
                query TEXT NOT NULL DEFAULT '',
                service_name TEXT NOT NULL DEFAULT '',
                apm_metric TEXT NOT NULL DEFAULT '',
                sensitivity REAL NOT NULL DEFAULT 3.0,
                alpha REAL NOT NULL DEFAULT 0.25,
                eval_interval_secs INTEGER NOT NULL DEFAULT 300,
                window_secs INTEGER NOT NULL DEFAULT 3600,
                split_labels TEXT NOT NULL DEFAULT '[]',
                notification_channel_ids TEXT NOT NULL DEFAULT '[]',
                state TEXT NOT NULL DEFAULT 'normal',
                last_eval_at TEXT,
                last_triggered_at TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            CREATE TABLE IF NOT EXISTS anomaly_events (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                state TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                expected REAL NOT NULL,
                deviation REAL NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS custom_skills (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                content TEXT NOT NULL,
                allowed_tools TEXT NOT NULL DEFAULT '[]',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            -- Investigation sessions (owned by sre-agent)
            CREATE TABLE IF NOT EXISTS investigation_sessions (
                id              TEXT PRIMARY KEY,
                tenant_id       TEXT NOT NULL DEFAULT 'default',
                title           TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'active',
                template_id     TEXT NOT NULL DEFAULT '',
                created_by      TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                working_memory  TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_tenant
                ON investigation_sessions(tenant_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_status
                ON investigation_sessions(tenant_id, status);

            -- Investigation turns (owned by sre-agent)
            CREATE TABLE IF NOT EXISTS investigation_turns (
                id          TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL REFERENCES investigation_sessions(id) ON DELETE CASCADE,
                turn_index  INTEGER NOT NULL,
                role        TEXT NOT NULL,
                content     TEXT NOT NULL,
                tool_calls  TEXT NOT NULL DEFAULT '[]',
                report_kind TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_turns_session
                ON investigation_turns(session_id, turn_index);
            "#,
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // ── Deploy markers ──

    pub fn list_deploy_markers(
        &self,
        service_name: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> anyhow::Result<Vec<DeployMarker>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = "SELECT id, service_name, version, commit_sha, description, environment, deployed_by, deployed_at FROM deploy_markers WHERE 1=1".to_string();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(sn) = service_name {
            sql.push_str(&format!(" AND service_name = ?{}", param_values.len() + 1));
            param_values.push(Box::new(sn.to_string()));
        }
        if let Some(f) = from {
            sql.push_str(&format!(" AND deployed_at >= ?{}", param_values.len() + 1));
            param_values.push(Box::new(f.to_string()));
        }
        if let Some(t) = to {
            sql.push_str(&format!(" AND deployed_at <= ?{}", param_values.len() + 1));
            param_values.push(Box::new(t.to_string()));
        }
        sql.push_str(" ORDER BY deployed_at DESC LIMIT 100");

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_ref.as_slice(), |row| {
                Ok(DeployMarker {
                    id: row.get(0)?,
                    service_name: row.get(1)?,
                    version: row.get(2)?,
                    commit_sha: row.get(3)?,
                    description: row.get(4)?,
                    environment: row.get(5)?,
                    deployed_by: row.get(6)?,
                    deployed_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ── Anomaly rules ──

    pub fn list_anomaly_rules(&self) -> anyhow::Result<Vec<AnomalyRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, enabled, source, pattern, query, service_name, \
             apm_metric, sensitivity, alpha, eval_interval_secs, window_secs, \
             split_labels, notification_channel_ids, state, last_eval_at, last_triggered_at, \
             created_at, updated_at FROM anomaly_rules ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AnomalyRule {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    enabled: row.get(3)?,
                    source: row.get(4)?,
                    pattern: row.get(5)?,
                    query: row.get(6)?,
                    service_name: row.get(7)?,
                    apm_metric: row.get(8)?,
                    sensitivity: row.get(9)?,
                    alpha: row.get(10)?,
                    eval_interval_secs: row.get(11)?,
                    window_secs: row.get(12)?,
                    split_labels: row.get(13)?,
                    notification_channel_ids: row.get(14)?,
                    state: row.get(15)?,
                    last_eval_at: row.get(16)?,
                    last_triggered_at: row.get(17)?,
                    created_at: row.get(18)?,
                    updated_at: row.get(19)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_anomaly_rule(&self, id: &str) -> anyhow::Result<Option<AnomalyRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, enabled, source, pattern, query, service_name, \
             apm_metric, sensitivity, alpha, eval_interval_secs, window_secs, \
             split_labels, notification_channel_ids, state, last_eval_at, last_triggered_at, \
             created_at, updated_at FROM anomaly_rules WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(AnomalyRule {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                enabled: row.get(3)?,
                source: row.get(4)?,
                pattern: row.get(5)?,
                query: row.get(6)?,
                service_name: row.get(7)?,
                apm_metric: row.get(8)?,
                sensitivity: row.get(9)?,
                alpha: row.get(10)?,
                eval_interval_secs: row.get(11)?,
                window_secs: row.get(12)?,
                split_labels: row.get(13)?,
                notification_channel_ids: row.get(14)?,
                state: row.get(15)?,
                last_eval_at: row.get(16)?,
                last_triggered_at: row.get(17)?,
                created_at: row.get(18)?,
                updated_at: row.get(19)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    // ── Anomaly events ──

    pub fn get_anomaly_event(&self, id: &str) -> anyhow::Result<Option<AnomalyEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, rule_id, state, metric, value, expected, deviation, message, created_at \
             FROM anomaly_events WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(AnomalyEvent {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                state: row.get(2)?,
                metric: row.get(3)?,
                value: row.get(4)?,
                expected: row.get(5)?,
                deviation: row.get(6)?,
                message: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn list_anomaly_events(
        &self,
        rule_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<AnomalyEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, rule_id, state, metric, value, expected, deviation, message, created_at \
             FROM anomaly_events WHERE rule_id = ?1 ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![rule_id, limit], |row| {
                Ok(AnomalyEvent {
                    id: row.get(0)?,
                    rule_id: row.get(1)?,
                    state: row.get(2)?,
                    metric: row.get(3)?,
                    value: row.get(4)?,
                    expected: row.get(5)?,
                    deviation: row.get(6)?,
                    message: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ── Settings ──

    pub fn get_setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query_map(params![key], |row| row.get::<_, String>(0))?;
        Ok(rows.next().transpose()?)
    }

    // ── Custom skills (read-only) ──

    /// List only enabled custom skills, ordered by name.
    pub fn list_enabled_custom_skills(&self) -> anyhow::Result<Vec<CustomSkill>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, title, description, content, allowed_tools, enabled, \
             created_by, created_at, updated_at FROM custom_skills WHERE enabled = 1 \
             ORDER BY name ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let allowed_tools_json: String = row.get(5)?;
                let enabled_int: i64 = row.get(6)?;
                Ok(CustomSkill {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    title: row.get(2)?,
                    description: row.get(3)?,
                    content: row.get(4)?,
                    allowed_tools: serde_json::from_str(&allowed_tools_json)
                        .unwrap_or_else(|_| Vec::new()),
                    enabled: enabled_int != 0,
                    created_by: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Fetch a single custom skill by its unique `name`. Returns regardless
    /// of `enabled` status so callers can surface a clear error when an
    /// explicitly requested skill has been disabled.
    pub fn get_custom_skill_by_name(&self, name: &str) -> anyhow::Result<Option<CustomSkill>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, title, description, content, allowed_tools, enabled, \
             created_by, created_at, updated_at FROM custom_skills WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map(params![name], |row| {
            let allowed_tools_json: String = row.get(5)?;
            let enabled_int: i64 = row.get(6)?;
            Ok(CustomSkill {
                id: row.get(0)?,
                name: row.get(1)?,
                title: row.get(2)?,
                description: row.get(3)?,
                content: row.get(4)?,
                allowed_tools: serde_json::from_str(&allowed_tools_json)
                    .unwrap_or_else(|_| Vec::new()),
                enabled: enabled_int != 0,
                created_by: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    // ── Investigation sessions ──

    /// Create a new investigation session.
    pub fn create_session(
        &self,
        id: &str,
        tenant_id: &str,
        title: &str,
        created_by: &str,
        template_id: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO investigation_sessions (id, tenant_id, title, created_by, template_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, tenant_id, title, created_by, template_id],
        )?;
        Ok(())
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: &str) -> anyhow::Result<Option<InvestigationSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, tenant_id, title, status, template_id, created_by, \
             created_at, updated_at, working_memory FROM investigation_sessions WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(InvestigationSession {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                title: row.get(2)?,
                status: row.get(3)?,
                template_id: row.get(4)?,
                created_by: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
                working_memory: row.get(8)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Update the working memory JSON for a session.
    pub fn update_session_memory(&self, id: &str, working_memory_json: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE investigation_sessions SET working_memory = ?1, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?2",
            params![working_memory_json, id],
        )?;
        Ok(())
    }

    /// Update the status of a session (active, completed, archived).
    pub fn update_session_status(&self, id: &str, status: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE investigation_sessions SET status = ?1, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    /// Update the title of a session.
    pub fn update_session_title(&self, id: &str, title: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE investigation_sessions SET title = ?1, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?2",
            params![title, id],
        )?;
        Ok(())
    }

    /// List recent sessions for a tenant.
    pub fn list_sessions(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<InvestigationSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, tenant_id, title, status, template_id, created_by, \
             created_at, updated_at, working_memory FROM investigation_sessions \
             WHERE tenant_id = ?1 AND status != 'archived' \
             ORDER BY updated_at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![tenant_id, limit], |row| {
                Ok(InvestigationSession {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    title: row.get(2)?,
                    status: row.get(3)?,
                    template_id: row.get(4)?,
                    created_by: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    working_memory: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a session (cascade deletes turns).
    pub fn delete_session(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM investigation_sessions WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ── Investigation turns ──

    /// Append a turn to a session.
    pub fn add_turn(
        &self,
        id: &str,
        session_id: &str,
        turn_index: i64,
        role: &str,
        content: &str,
        tool_calls: &str,
        report_kind: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO investigation_turns (id, session_id, turn_index, role, content, tool_calls, report_kind) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, session_id, turn_index, role, content, tool_calls, report_kind],
        )?;
        Ok(())
    }

    /// Get all turns for a session, ordered by turn_index.
    pub fn get_turns(&self, session_id: &str) -> anyhow::Result<Vec<InvestigationTurn>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, turn_index, role, content, tool_calls, report_kind, created_at \
             FROM investigation_turns WHERE session_id = ?1 ORDER BY turn_index ASC",
        )?;
        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok(InvestigationTurn {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    turn_index: row.get(2)?,
                    role: row.get(3)?,
                    content: row.get(4)?,
                    tool_calls: row.get(5)?,
                    report_kind: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get the last N turns for a session (for context window reconstruction).
    pub fn get_recent_turns(
        &self,
        session_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<InvestigationTurn>> {
        let conn = self.conn.lock().unwrap();
        // Sub-query to get latest N in DESC, then re-sort ASC for message ordering.
        let mut stmt = conn.prepare(
            "SELECT id, session_id, turn_index, role, content, tool_calls, report_kind, created_at \
             FROM ( \
                 SELECT * FROM investigation_turns WHERE session_id = ?1 \
                 ORDER BY turn_index DESC LIMIT ?2 \
             ) ORDER BY turn_index ASC",
        )?;
        let rows = stmt
            .query_map(params![session_id, limit], |row| {
                Ok(InvestigationTurn {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    turn_index: row.get(2)?,
                    role: row.get(3)?,
                    content: row.get(4)?,
                    tool_calls: row.get(5)?,
                    report_kind: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Count turns in a session (for determining next turn_index).
    pub fn count_turns(&self, session_id: &str) -> anyhow::Result<i64> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT COUNT(*) FROM investigation_turns WHERE session_id = ?1")?;
        let count: i64 = stmt.query_row(params![session_id], |row| row.get(0))?;
        Ok(count)
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

    fn fresh_db() -> ConfigDb {
        ConfigDb::open(":memory:").unwrap()
    }

    #[test]
    fn open_in_memory_succeeds() {
        let db = fresh_db();
        // Should be able to query without errors even though tables are empty
        assert_eq!(db.list_anomaly_rules().unwrap().len(), 0);
        assert_eq!(db.list_deploy_markers(None, None, None).unwrap().len(), 0);
    }

    #[test]
    fn get_missing_anomaly_rule_returns_none() {
        let db = fresh_db();
        assert!(db.get_anomaly_rule("nonexistent").unwrap().is_none());
    }

    #[test]
    fn get_missing_anomaly_event_returns_none() {
        let db = fresh_db();
        assert!(db.get_anomaly_event("nonexistent").unwrap().is_none());
    }

    #[test]
    fn list_anomaly_events_empty_for_unknown_rule() {
        let db = fresh_db();
        assert_eq!(db.list_anomaly_events("rule-1", 10).unwrap().len(), 0);
    }

    #[test]
    fn get_missing_setting_returns_none() {
        let db = fresh_db();
        assert!(db.get_setting("unknown_key").unwrap().is_none());
    }

    #[test]
    fn setting_roundtrip() {
        let db = fresh_db();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                params!["argocd_enabled", "true"],
            )
            .unwrap();
        }
        assert_eq!(
            db.get_setting("argocd_enabled").unwrap(),
            Some("true".to_string())
        );
    }

    #[test]
    fn deploy_marker_roundtrip_and_service_filter() {
        let db = fresh_db();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO deploy_markers (id, service_name, version, commit_sha, description, environment, deployed_by, deployed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params!["d1", "checkout", "v1.2.3", "abc1234", "Hotfix", "prod", "alice", "2026-01-15T10:00:00Z"],
            )
            .unwrap();
        }

        let all = db.list_deploy_markers(None, None, None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].service_name, "checkout");
        assert_eq!(all[0].version, "v1.2.3");
        assert_eq!(all[0].commit_sha, "abc1234");

        let filtered = db
            .list_deploy_markers(Some("checkout"), None, None)
            .unwrap();
        assert_eq!(filtered.len(), 1);

        let none = db.list_deploy_markers(Some("other"), None, None).unwrap();
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn deploy_marker_time_window_filter() {
        let db = fresh_db();
        {
            let conn = db.conn.lock().unwrap();
            for (id, at) in [
                ("d1", "2026-01-01"),
                ("d2", "2026-01-15"),
                ("d3", "2026-02-01"),
            ] {
                conn.execute(
                    "INSERT INTO deploy_markers (id, service_name, version, deployed_at) VALUES (?1, 'svc', 'v1', ?2)",
                    params![id, at],
                )
                .unwrap();
            }
        }
        let january = db
            .list_deploy_markers(None, Some("2026-01-01"), Some("2026-01-31"))
            .unwrap();
        assert_eq!(january.len(), 2);
        let ids: Vec<_> = january.iter().map(|d| d.id.as_str()).collect();
        assert!(ids.contains(&"d1"));
        assert!(ids.contains(&"d2"));
    }

    // ── Investigation session tests ──

    #[test]
    fn session_roundtrip() {
        let db = fresh_db();
        db.create_session("s1", "tenant-a", "My investigation", "alice", "")
            .unwrap();
        let s = db.get_session("s1").unwrap().unwrap();
        assert_eq!(s.id, "s1");
        assert_eq!(s.tenant_id, "tenant-a");
        assert_eq!(s.title, "My investigation");
        assert_eq!(s.status, "active");
        assert_eq!(s.working_memory, "{}");
    }

    #[test]
    fn get_missing_session_returns_none() {
        let db = fresh_db();
        assert!(db.get_session("nonexistent").unwrap().is_none());
    }

    #[test]
    fn update_session_memory_roundtrip() {
        let db = fresh_db();
        db.create_session("s1", "t", "", "", "").unwrap();
        let mem = r#"{"task":"find bug","suspect_services":["checkout"]}"#;
        db.update_session_memory("s1", mem).unwrap();
        let s = db.get_session("s1").unwrap().unwrap();
        assert_eq!(s.working_memory, mem);
    }

    #[test]
    fn update_session_status() {
        let db = fresh_db();
        db.create_session("s1", "t", "", "", "").unwrap();
        db.update_session_status("s1", "completed").unwrap();
        let s = db.get_session("s1").unwrap().unwrap();
        assert_eq!(s.status, "completed");
    }

    #[test]
    fn update_session_title() {
        let db = fresh_db();
        db.create_session("s1", "t", "Old title", "", "").unwrap();
        db.update_session_title("s1", "New title").unwrap();
        let s = db.get_session("s1").unwrap().unwrap();
        assert_eq!(s.title, "New title");
    }

    #[test]
    fn list_sessions_filters_by_tenant() {
        let db = fresh_db();
        db.create_session("s1", "a", "", "", "").unwrap();
        db.create_session("s2", "b", "", "", "").unwrap();
        db.create_session("s3", "a", "", "", "").unwrap();
        let list = db.list_sessions("a", 50).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn list_sessions_excludes_archived() {
        let db = fresh_db();
        db.create_session("s1", "a", "", "", "").unwrap();
        db.create_session("s2", "a", "", "", "").unwrap();
        db.update_session_status("s2", "archived").unwrap();
        let list = db.list_sessions("a", 50).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "s1");
    }

    #[test]
    fn delete_session_cascades_to_turns() {
        let db = fresh_db();
        db.create_session("s1", "t", "", "", "").unwrap();
        db.add_turn("t1", "s1", 0, "user", "hello", "[]", "").unwrap();
        db.add_turn("t2", "s1", 1, "assistant", "hi", "[]", "final").unwrap();
        assert_eq!(db.get_turns("s1").unwrap().len(), 2);

        db.delete_session("s1").unwrap();
        assert!(db.get_session("s1").unwrap().is_none());
        assert_eq!(db.get_turns("s1").unwrap().len(), 0);
    }

    // ── Investigation turn tests ──

    #[test]
    fn turn_roundtrip() {
        let db = fresh_db();
        db.create_session("s1", "t", "", "", "").unwrap();
        db.add_turn("t1", "s1", 0, "user", "Why is checkout slow?", "[]", "").unwrap();
        db.add_turn("t2", "s1", 1, "assistant", "Root cause found.", "[{\"name\":\"search_logs\"}]", "final").unwrap();

        let turns = db.get_turns("s1").unwrap();
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].role, "user");
        assert_eq!(turns[0].content, "Why is checkout slow?");
        assert_eq!(turns[1].role, "assistant");
        assert_eq!(turns[1].report_kind, "final");
    }

    #[test]
    fn get_recent_turns_limits_correctly() {
        let db = fresh_db();
        db.create_session("s1", "t", "", "", "").unwrap();
        for i in 0..10 {
            db.add_turn(&format!("t{i}"), "s1", i, "user", &format!("msg {i}"), "[]", "").unwrap();
        }
        let recent = db.get_recent_turns("s1", 3).unwrap();
        assert_eq!(recent.len(), 3);
        // Should be the last 3 turns, in ascending order
        assert_eq!(recent[0].turn_index, 7);
        assert_eq!(recent[1].turn_index, 8);
        assert_eq!(recent[2].turn_index, 9);
    }

    #[test]
    fn count_turns_returns_correct_count() {
        let db = fresh_db();
        db.create_session("s1", "t", "", "", "").unwrap();
        assert_eq!(db.count_turns("s1").unwrap(), 0);
        db.add_turn("t1", "s1", 0, "user", "q", "[]", "").unwrap();
        db.add_turn("t2", "s1", 1, "assistant", "a", "[]", "").unwrap();
        assert_eq!(db.count_turns("s1").unwrap(), 2);
    }
}
