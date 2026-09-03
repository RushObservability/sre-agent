use anyhow::Result;
use serde_json::Value;

use crate::agent::tools::{Tool, ToolContext};

/// Retrieval of similar past investigations, to ground the current one.
///
/// Mirrors the "past-incident retrieval (k≈3)" pattern that reduces hallucinated
/// root causes (Microsoft RCA agent): surface prior *resolved* investigations whose
/// title / working memory overlaps the current symptom, as priors to verify.
pub struct SearchPastIncidents;

const DEFAULT_LIMIT: usize = 3;
const SCAN_LIMIT: i64 = 60; // most-recent sessions to score
const EXCERPT_CHARS: usize = 600;

#[async_trait::async_trait]
impl Tool for SearchPastIncidents {
    fn name(&self) -> &str {
        "search_past_incidents"
    }

    fn description(&self) -> &str {
        "Find similar PAST resolved investigations (by service name and symptom keywords) to use \
         as priors for likely root causes. Returns up to a few prior incidents with their \
         recorded findings. Treat results as leads to verify with fresh evidence — NOT as facts; \
         the current incident may have a different cause."
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Affected service name and/or symptom keywords, e.g. \"checkout high latency 5xx\". Tokens are matched against past investigation titles and findings."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max number of past incidents to return (default 3).",
                    "minimum": 1,
                    "maximum": 10
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(DEFAULT_LIMIT)
            .clamp(1, 10);

        let sessions = ctx
            .state
            .query_api
            .list_sessions(&ctx.tenant_id, SCAN_LIMIT)
            .await?;

        // Only completed investigations are useful priors (skip active/in-progress).
        let q_tokens = tokenize(query);
        let mut scored: Vec<(u32, &crate::query_api::InvestigationSession)> = sessions
            .iter()
            .filter(|s| s.status == "completed")
            .map(|s| (score(&q_tokens, s), s))
            .filter(|(sc, _)| q_tokens.is_empty() || *sc > 0)
            .collect();

        // Highest overlap first; ties broken by recency (list is already recency-ordered,
        // and a stable sort preserves that for equal scores).
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        scored.truncate(limit);

        if scored.is_empty() {
            return Ok(
                "No similar resolved past investigations found. Proceed with a fresh investigation."
                    .to_string(),
            );
        }

        let mut out = String::from(
            "Similar PAST resolved investigations (priors — verify with fresh evidence, do not assume the same cause):\n\n",
        );
        for (sc, s) in &scored {
            out.push_str(&format!(
                "### {}\n- when: {}\n- match score: {}\n- recorded findings:\n{}\n\n",
                if s.title.is_empty() {
                    "(untitled investigation)"
                } else {
                    &s.title
                },
                s.created_at,
                sc,
                excerpt(&s.working_memory),
            ));
        }
        out.push_str(
            "Reminder: these are priors from prior incidents. Confirm against current telemetry before adopting any of them as the root cause.",
        );
        Ok(out)
    }
}

/// Lowercase alphanumeric tokens of length ≥ 3, minus a few stopwords.
fn tokenize(s: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "the",
        "and",
        "for",
        "with",
        "this",
        "that",
        "from",
        "high",
        "low",
        "error",
        "errors",
        "issue",
        "service",
        "investigation",
        "incident",
    ];
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3 && !STOP.contains(t))
        .map(|t| t.to_string())
        .collect()
}

/// Overlap score of query tokens against a session's title (weighted 2x) + working memory.
fn score(q_tokens: &[String], s: &crate::query_api::InvestigationSession) -> u32 {
    if q_tokens.is_empty() {
        return 0;
    }
    let title = s.title.to_lowercase();
    let mem = s.working_memory.to_lowercase();
    let mut score = 0u32;
    for t in q_tokens {
        if title.contains(t.as_str()) {
            score += 2;
        } else if mem.contains(t.as_str()) {
            score += 1;
        }
    }
    score
}

/// Trim the working-memory blob to a readable excerpt.
fn excerpt(mem: &str) -> String {
    let m = mem.trim();
    if m.is_empty() || m == "{}" {
        return "  (no recorded findings)".to_string();
    }
    let trimmed: String = m.chars().take(EXCERPT_CHARS).collect();
    let suffix = if m.chars().count() > EXCERPT_CHARS {
        "…"
    } else {
        ""
    };
    format!("```\n{trimmed}{suffix}\n```")
}
