//! Investigation templates -- pre-configured starting points that reduce
//! time-to-first-insight for common investigation types.
//!
//! Templates are static Rust structs (not user-editable in v3).

use serde::Serialize;

/// A pre-defined investigation template that primes the agent with
/// domain-specific context, a prompt modifier, and optional auto-tools.
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationTemplate {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// Appended to the system prompt for investigations using this template.
    pub prompt_modifier: &'static str,
    /// Tool names the agent should call automatically at the start.
    pub auto_tools: &'static [&'static str],
}

/// Return all built-in investigation templates.
pub fn built_in_templates() -> Vec<&'static InvestigationTemplate> {
    vec![
        &ALERT_INVESTIGATION,
        &POSTMORTEM,
        &CAPACITY_REVIEW,
        &DEPLOY_REVIEW,
        &SECURITY_REVIEW,
    ]
}

/// Look up a template by ID. Returns `None` for unknown IDs.
pub fn get_template(id: &str) -> Option<&'static InvestigationTemplate> {
    built_in_templates().into_iter().find(|t| t.id == id)
}

static ALERT_INVESTIGATION: InvestigationTemplate = InvestigationTemplate {
    id: "alert_investigation",
    name: "Investigate Alert",
    description: "Start from an anomaly event -- loads context and investigates root cause",
    prompt_modifier: "\
You are investigating a specific alert/anomaly event. Focus on the anomaly's metric, \
timestamp, and affected service. Start with the anomaly context, then broaden your \
investigation to upstream and downstream dependencies. Correlate with recent deploys.",
    auto_tools: &["get_anomaly_context"],
};

static POSTMORTEM: InvestigationTemplate = InvestigationTemplate {
    id: "postmortem",
    name: "Postmortem Mode",
    description: "Build a timeline and root cause analysis for a past incident",
    prompt_modifier: "\
You are helping write a postmortem. Focus on building a complete timeline, identifying \
the root cause, and documenting contributing factors. Structure your final output as: \
Timeline, Root Cause, Contributing Factors, Impact, Action Items. Be thorough with \
timestamps and specific evidence.",
    auto_tools: &["search_logs", "query_traces", "list_deploys"],
};

static CAPACITY_REVIEW: InvestigationTemplate = InvestigationTemplate {
    id: "capacity_review",
    name: "Capacity Review",
    description: "Analyze capacity trends and headroom for a service",
    prompt_modifier: "\
You are performing a capacity review. Focus on resource utilization trends (CPU, memory, \
request throughput, error budget). Identify services approaching capacity limits. Report \
on current headroom, growth trends, and recommendations for scaling.",
    auto_tools: &["query_metrics", "list_services"],
};

static DEPLOY_REVIEW: InvestigationTemplate = InvestigationTemplate {
    id: "deploy_review",
    name: "Deployment Review",
    description: "Correlate a recent deploy with any emerging issues",
    prompt_modifier: "\
You are reviewing a deployment for impact. Compare error rates, latency, and throughput \
before and after the deploy timestamp. Determine if the deploy caused any regression. \
Check both the deployed service and its downstream dependencies.",
    auto_tools: &["list_deploys", "query_traces", "search_logs"],
};

static SECURITY_REVIEW: InvestigationTemplate = InvestigationTemplate {
    id: "security_review",
    name: "Security Review",
    description: "Investigate a security event or suspicious activity",
    prompt_modifier: "\
You are investigating a security event. Focus on access patterns, authentication failures, \
unusual API calls, and data exfiltration indicators. Use SIEM-focused log queries. Look \
for 401/403 responses, brute-force patterns, and anomalous request volumes.",
    auto_tools: &["search_logs"],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_returns_five_templates() {
        assert_eq!(built_in_templates().len(), 5);
    }

    #[test]
    fn get_template_by_id() {
        let t = get_template("postmortem").unwrap();
        assert_eq!(t.name, "Postmortem Mode");
    }

    #[test]
    fn get_template_unknown_returns_none() {
        assert!(get_template("nonexistent").is_none());
    }

    #[test]
    fn all_templates_have_unique_ids() {
        let templates = built_in_templates();
        let mut ids = std::collections::HashSet::new();
        for t in &templates {
            assert!(ids.insert(t.id), "duplicate template id: {}", t.id);
        }
    }

    #[test]
    fn templates_serialize_to_json() {
        let t = get_template("alert_investigation").unwrap();
        let json = serde_json::to_string(t).unwrap();
        assert!(json.contains("alert_investigation"));
        assert!(json.contains("get_anomaly_context"));
    }
}
