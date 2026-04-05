use std::collections::HashSet;

/// Working memory — distilled facts that survive aggressive transcript compaction.
/// Based on Raschka's two-layer memory pattern: transcript is for prompt reconstruction,
/// working memory is for task continuity.
#[derive(Debug, Default)]
pub struct WorkingMemory {
    pub task: String,
    pub suspect_services: Vec<String>,     // LRU, max 8
    pub confirmed_facts: Vec<String>,      // max 10
    pub ruled_out: Vec<String>,            // max 10
    pub recent_tool_calls: Vec<CallSignature>, // for repeat detection
    pub consecutive_empty_results: u32,    // dead-end detection
    /// Hypotheses we explored and ruled out (LRU, max 5). Used to discourage
    /// re-exploring dead ends across escalation rounds.
    pub failed_hypotheses: Vec<String>,
    /// Dead-end escalation level.
    ///   0 = initial investigation
    ///   1 = nudged to try alternative tool categories
    ///   2 = nudged to check dependency graph / widen window
    ///   3+ = force preliminary report
    pub escalation_level: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallSignature {
    pub tool: String,
    pub args_normalized: String, // stable representation of args
}

impl WorkingMemory {
    pub fn new(task: String) -> Self {
        Self {
            task,
            ..Default::default()
        }
    }

    /// LRU insert: remove existing, push to end, cap size.
    fn remember<T: PartialEq + Clone>(bucket: &mut Vec<T>, item: T, limit: usize) {
        bucket.retain(|x| *x != item);
        bucket.push(item);
        if bucket.len() > limit {
            let drop = bucket.len() - limit;
            bucket.drain(..drop);
        }
    }

    pub fn add_suspect_service(&mut self, svc: String) {
        if svc.is_empty() {
            return;
        }
        Self::remember(&mut self.suspect_services, svc, 8);
    }

    pub fn add_fact(&mut self, fact: String) {
        if fact.is_empty() {
            return;
        }
        Self::remember(&mut self.confirmed_facts, fact, 10);
    }

    pub fn add_ruled_out(&mut self, item: String) {
        if item.is_empty() {
            return;
        }
        Self::remember(&mut self.ruled_out, item, 10);
    }

    /// Record a hypothesis that was explored but ruled out. LRU-capped at 5.
    pub fn add_failed_hypothesis(&mut self, item: String) {
        if item.is_empty() {
            return;
        }
        Self::remember(&mut self.failed_hypotheses, item, 5);
    }

    /// Check if this exact tool call was made recently (exact dup).
    pub fn is_repeat_call(&self, sig: &CallSignature) -> bool {
        self.recent_tool_calls.iter().any(|c| c == sig)
    }

    pub fn record_call(&mut self, sig: CallSignature) {
        self.recent_tool_calls.push(sig);
        // Keep only last 20 call signatures
        if self.recent_tool_calls.len() > 20 {
            let drop = self.recent_tool_calls.len() - 20;
            self.recent_tool_calls.drain(..drop);
        }
    }

    /// Render working memory as a compact string for prompt injection.
    pub fn to_prompt_block(&self) -> String {
        let mut out = String::from("## Working Memory\n");
        if !self.task.is_empty() {
            out.push_str(&format!("**Task**: {}\n", self.task));
        }
        if !self.suspect_services.is_empty() {
            out.push_str(&format!("**Suspect services**: {}\n", self.suspect_services.join(", ")));
        }
        if !self.confirmed_facts.is_empty() {
            out.push_str("**Confirmed facts**:\n");
            for f in &self.confirmed_facts {
                out.push_str(&format!("- {f}\n"));
            }
        }
        if !self.ruled_out.is_empty() {
            out.push_str("**Ruled out**:\n");
            for r in &self.ruled_out {
                out.push_str(&format!("- {r}\n"));
            }
        }
        if !self.failed_hypotheses.is_empty() {
            out.push_str("**Previously ruled out (don't revisit):**\n");
            for h in &self.failed_hypotheses {
                out.push_str(&format!("- {h}\n"));
            }
        }
        if self.escalation_level > 0 {
            let stage_hint = match self.escalation_level {
                1 => " (already tried alternative tool categories — now must check dependency graph)",
                2 => " (already widened scope — now must produce a preliminary report with open questions)",
                _ => " (must emit a preliminary report with explicit open questions)",
            };
            out.push_str(&format!(
                "**Escalation level:** {}{}\n",
                self.escalation_level, stage_hint
            ));
        }
        out
    }
}

/// Normalize args into a stable string for repeat detection.
/// Collapses equivalent queries (sorted keys, whitespace removed).
pub fn normalize_args(args: &serde_json::Value) -> String {
    fn walk(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(k);
                    out.push(':');
                    walk(&m[*k], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(arr) => {
                out.push('[');
                for (i, v) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    walk(v, out);
                }
                out.push(']');
            }
            serde_json::Value::String(s) => out.push_str(s),
            serde_json::Value::Number(n) => out.push_str(&n.to_string()),
            serde_json::Value::Bool(b) => out.push_str(&b.to_string()),
            serde_json::Value::Null => out.push_str("null"),
        }
    }
    let mut s = String::new();
    walk(args, &mut s);
    s
}

/// Extract signal-worthy facts from a tool result for working memory.
/// Returns (suspect_services, facts) tuples to add.
pub fn extract_facts_from_tool_result(tool_name: &str, args: &serde_json::Value, result: &str) -> ExtractedFacts {
    let mut out = ExtractedFacts::default();

    // Service extraction from args
    if let Some(svc) = args.get("service").and_then(|v| v.as_str()) {
        if !svc.is_empty() {
            out.services.insert(svc.to_string());
        }
    }
    if let Some(svc) = args.get("service_name").and_then(|v| v.as_str()) {
        if !svc.is_empty() {
            out.services.insert(svc.to_string());
        }
    }

    // Detect empty/no-data results
    let low = result.to_lowercase();
    if low.contains("no matching")
        || low.contains("no data")
        || low.contains("not found")
        || low.contains("no spans found")
        || low.contains("no logs found")
    {
        out.empty_result = true;
    }

    // Tool-specific summarization
    match tool_name {
        "search_logs" => {
            // Extract "Found N log entries" and top error patterns
            if let Some(first_line) = result.lines().next() {
                if first_line.contains("Found") {
                    out.summary = Some(first_line.to_string());
                }
            }
        }
        "query_traces" => {
            if let Some(first_line) = result.lines().next() {
                if first_line.contains("Found") {
                    out.summary = Some(first_line.to_string());
                }
            }
        }
        "query_metrics" => {
            // Metrics output has "Latest=X Avg=Y Min=Z Max=W"
            for line in result.lines().take(5) {
                if line.contains("Latest=") || line.contains("error_rate") || line.contains("latency") {
                    out.summary = Some(line.trim().to_string());
                    break;
                }
            }
        }
        "get_argocd_app" => {
            // Extract health status
            for line in result.lines().take(10) {
                if line.starts_with("Health:") || line.starts_with("Sync:") {
                    out.summary = Some(line.trim().to_string());
                    break;
                }
            }
        }
        "kube_describe" => {
            // Extract pod phase / container state
            for line in result.lines().take(20) {
                if line.contains("Phase:")
                    || line.contains("WAITING:")
                    || line.contains("TERMINATED:")
                    || line.contains("CrashLoop")
                    || line.contains("OOMKill")
                {
                    out.summary = Some(line.trim().to_string());
                    break;
                }
            }
        }
        _ => {}
    }

    out
}

#[derive(Debug, Default)]
pub struct ExtractedFacts {
    pub services: HashSet<String>,
    pub summary: Option<String>,
    pub empty_result: bool,
}

/// Clip a tool result to a budget specific to the tool type.
/// Based on Raschka's per-event clipping, but bucketed by signal type since
/// logs/traces/metrics have different information density.
pub fn clip_tool_result(tool_name: &str, result: &str) -> String {
    let limit = match tool_name {
        "search_logs" => 4000,
        "query_traces" => 3000,
        "get_trace" => 4000,
        "query_metrics" => 1500,
        "list_services" => 2000,
        "service_dependencies" => 1500,
        "list_deploys" => 2000,
        "get_anomaly_context" => 2000,
        "get_argocd_app" => 3000,
        "kube_describe" => 2500,
        "kube_events" => 2500,
        "load_skill" => 6000, // skills are intentional content
        _ => 2000,
    };

    if result.len() <= limit {
        return result.to_string();
    }
    format!(
        "{}\n...[truncated {} chars]",
        &result[..limit],
        result.len() - limit
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── normalize_args ──

    #[test]
    fn normalize_args_stable_across_key_order() {
        let a = json!({"service": "foo", "minutes": 15});
        let b = json!({"minutes": 15, "service": "foo"});
        assert_eq!(normalize_args(&a), normalize_args(&b));
    }

    #[test]
    fn normalize_args_distinguishes_different_values() {
        let a = json!({"service": "foo"});
        let b = json!({"service": "bar"});
        assert_ne!(normalize_args(&a), normalize_args(&b));
    }

    #[test]
    fn normalize_args_nested_objects() {
        let a = json!({"filter": {"x": 1, "y": 2}});
        let b = json!({"filter": {"y": 2, "x": 1}});
        assert_eq!(normalize_args(&a), normalize_args(&b));
    }

    #[test]
    fn normalize_args_handles_null() {
        assert_eq!(normalize_args(&json!(null)), "null");
    }

    // ── WorkingMemory LRU behavior ──

    #[test]
    fn suspect_services_lru_caps_at_8() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..15 {
            m.add_suspect_service(format!("svc{i}"));
        }
        assert_eq!(m.suspect_services.len(), 8);
        // Most recent 8 should be kept (svc7..svc14)
        assert!(m.suspect_services.contains(&"svc14".to_string()));
        assert!(m.suspect_services.contains(&"svc7".to_string()));
        assert!(!m.suspect_services.contains(&"svc0".to_string()));
    }

    #[test]
    fn suspect_services_reinsert_moves_to_end() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_suspect_service("a".to_string());
        m.add_suspect_service("b".to_string());
        m.add_suspect_service("c".to_string());
        m.add_suspect_service("a".to_string()); // should move to end
        assert_eq!(
            m.suspect_services,
            vec!["b".to_string(), "c".to_string(), "a".to_string()]
        );
    }

    #[test]
    fn empty_service_not_added() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_suspect_service(String::new());
        assert!(m.suspect_services.is_empty());
    }

    #[test]
    fn confirmed_facts_lru_caps_at_10() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..15 {
            m.add_fact(format!("fact-{i}"));
        }
        assert_eq!(m.confirmed_facts.len(), 10);
        assert!(m.confirmed_facts.contains(&"fact-14".to_string()));
        assert!(!m.confirmed_facts.contains(&"fact-0".to_string()));
    }

    #[test]
    fn failed_hypotheses_lru_caps_at_5() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..8 {
            m.add_failed_hypothesis(format!("h-{i}"));
        }
        assert_eq!(m.failed_hypotheses.len(), 5);
        assert!(m.failed_hypotheses.contains(&"h-7".to_string()));
        assert!(!m.failed_hypotheses.contains(&"h-0".to_string()));
    }

    #[test]
    fn empty_failed_hypothesis_not_added() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_failed_hypothesis(String::new());
        assert!(m.failed_hypotheses.is_empty());
    }

    #[test]
    fn prompt_block_renders_failed_hypotheses_when_present() {
        let mut m = WorkingMemory::new("t".to_string());
        m.add_failed_hypothesis("checkout db slow query".to_string());
        let block = m.to_prompt_block();
        assert!(block.contains("Previously ruled out"));
        assert!(block.contains("checkout db slow query"));
    }

    #[test]
    fn prompt_block_renders_escalation_level_when_non_zero() {
        let mut m = WorkingMemory::new("t".to_string());
        m.escalation_level = 2;
        let block = m.to_prompt_block();
        assert!(block.contains("Escalation level"));
        assert!(block.contains('2'));
    }

    #[test]
    fn prompt_block_omits_escalation_when_zero() {
        let m = WorkingMemory::new("t".to_string());
        let block = m.to_prompt_block();
        assert!(!block.contains("Escalation level"));
    }

    // ── Repeat call detection ──

    #[test]
    fn is_repeat_call_false_on_new_signature() {
        let m = WorkingMemory::new("t".to_string());
        let sig = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:foo}".to_string(),
        };
        assert!(!m.is_repeat_call(&sig));
    }

    #[test]
    fn is_repeat_call_true_after_record() {
        let mut m = WorkingMemory::new("t".to_string());
        let sig = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:foo}".to_string(),
        };
        m.record_call(sig.clone());
        assert!(m.is_repeat_call(&sig));
    }

    #[test]
    fn different_signatures_are_not_repeats() {
        let mut m = WorkingMemory::new("t".to_string());
        let s1 = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:foo}".to_string(),
        };
        let s2 = CallSignature {
            tool: "search_logs".to_string(),
            args_normalized: "{service:bar}".to_string(),
        };
        m.record_call(s1.clone());
        assert!(!m.is_repeat_call(&s2));
    }

    #[test]
    fn recent_tool_calls_capped_at_20() {
        let mut m = WorkingMemory::new("t".to_string());
        for i in 0..25 {
            m.record_call(CallSignature {
                tool: "t".to_string(),
                args_normalized: format!("arg{i}"),
            });
        }
        assert_eq!(m.recent_tool_calls.len(), 20);
    }

    // ── Prompt block rendering ──

    #[test]
    fn prompt_block_omits_empty_sections() {
        let m = WorkingMemory::new("find the bug".to_string());
        let block = m.to_prompt_block();
        assert!(block.contains("find the bug"));
        // Empty sections shouldn't render headers
        assert!(!block.contains("Suspect services"));
        assert!(!block.contains("Confirmed facts"));
    }

    #[test]
    fn prompt_block_includes_facts_and_services() {
        let mut m = WorkingMemory::new("task".to_string());
        m.add_suspect_service("checkout".to_string());
        m.add_fact("error rate is 5%".to_string());
        let block = m.to_prompt_block();
        assert!(block.contains("checkout"));
        assert!(block.contains("error rate is 5%"));
    }

    // ── extract_facts_from_tool_result ──

    #[test]
    fn extract_facts_search_logs() {
        let args = json!({"service": "checkout", "minutes": 15});
        let result = "Found 42 log entries (last 15m).\nTop message patterns:\n";
        let facts = extract_facts_from_tool_result("search_logs", &args, result);
        assert!(facts.services.contains("checkout"));
        assert_eq!(
            facts.summary,
            Some("Found 42 log entries (last 15m).".to_string())
        );
        assert!(!facts.empty_result);
    }

    #[test]
    fn extract_facts_empty_logs() {
        let args = json!({});
        let facts = extract_facts_from_tool_result("search_logs", &args, "No matching logs found.");
        assert!(facts.empty_result);
    }

    #[test]
    fn extract_facts_empty_traces() {
        let args = json!({});
        let facts = extract_facts_from_tool_result("query_traces", &args, "No spans found.");
        assert!(facts.empty_result);
    }

    #[test]
    fn extract_facts_metrics_summary() {
        let args = json!({"service": "api", "metric": "error_rate"});
        let result = "api error_rate (last 30m, 30 data points):\nLatest=0.05 Avg=0.03 Min=0.01 Max=0.08\n";
        let facts = extract_facts_from_tool_result("query_metrics", &args, result);
        assert!(facts.services.contains("api"));
        // Summary grabs the first matching line — either the header ("error_rate")
        // or the stats line ("Latest="). Both are informative.
        let summary = facts.summary.as_ref().unwrap();
        assert!(
            summary.contains("error_rate") || summary.contains("Latest="),
            "unexpected summary: {summary}"
        );
    }

    #[test]
    fn extract_facts_argocd_health() {
        let args = json!({"name": "my-app"});
        let result = "ArgoCD Application: my-app\nProject: default\nHealth: Degraded — pods not ready\nSync: Synced (revision: abc1234)\n";
        let facts = extract_facts_from_tool_result("get_argocd_app", &args, result);
        assert!(facts.summary.as_ref().unwrap().contains("Degraded"));
    }

    #[test]
    fn extract_facts_kube_describe_crashloop() {
        let args = json!({"kind": "pod", "name": "my-pod", "namespace": "default"});
        let result = "pod/my-pod\nPhase: Running\nContainers (1):\n  app: ready=false restarts=12\n    WAITING: CrashLoopBackOff — back-off 5m restarting\n";
        let facts = extract_facts_from_tool_result("kube_describe", &args, result);
        let summary = facts.summary.unwrap();
        assert!(summary.contains("Phase:") || summary.contains("CrashLoop") || summary.contains("WAITING"));
    }

    // ── clip_tool_result ──

    #[test]
    fn clip_respects_search_logs_budget() {
        let long = "x".repeat(10_000);
        let clipped = clip_tool_result("search_logs", &long);
        assert!(clipped.contains("[truncated"));
        // Budget is 4000
        assert!(clipped.len() < 5000);
    }

    #[test]
    fn clip_respects_metrics_budget() {
        let long = "x".repeat(10_000);
        let clipped = clip_tool_result("query_metrics", &long);
        // Budget is 1500 — should be much smaller than search_logs
        assert!(clipped.len() < 2000);
    }

    #[test]
    fn clip_short_input_unchanged() {
        let short = "Found 5 entries.";
        assert_eq!(clip_tool_result("search_logs", short), short);
    }

    #[test]
    fn clip_unknown_tool_uses_default_budget() {
        let long = "x".repeat(5_000);
        let clipped = clip_tool_result("mystery_tool", &long);
        assert!(clipped.contains("[truncated"));
    }
}
