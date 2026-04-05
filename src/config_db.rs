//! Read-only SQLite adapter over the shared `wide_config.db` file.
//!
//! The agent does NOT migrate or write to this database — query-api owns the
//! schema. The agent opens the file read-only and exposes only the methods
//! needed by investigation tools: anomaly rules/events, deploy markers,
//! and settings lookup.

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
}
