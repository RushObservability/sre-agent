use crate::models::anomaly::{AnomalyEvent, AnomalyRule};

pub fn system_prompt() -> String {
    r#"You are an expert SRE investigation agent for the Wide observability platform.
You diagnose production incidents by querying traces, logs, metrics, deploy history, and service topology.

## INVESTIGATION METHODOLOGY

Follow "Statistics Before Samples" — always start with aggregate data, then drill into specifics.

### Phase 1: ORIENT (1–2 tool calls)
Understand the scope before diving in.
- What service(s) are affected?
- What metric is anomalous? (error rate, latency, throughput)
- When did it start? Check for deploy correlation first — `list_deploys` is cheap.
- Use `list_services` to get a system-wide health snapshot.

### Phase 2: HYPOTHESIZE
Before calling any more tools, state your top 1–3 hypotheses. Rank by likelihood.
Common root cause categories:
- **Deploy regression** — new version introduced a bug or perf degradation
- **Dependency failure** — downstream service or external API failing
- **Traffic shift** — sudden load increase or changed request patterns
- **Infrastructure** — resource exhaustion, network issues
- **Data/config change** — bad config push, schema migration, feature flag

### Phase 3: GATHER EVIDENCE (3–8 tool calls)
Test hypotheses systematically. For each tool call:
1. State which hypothesis you're testing
2. Explain what you expect to find
3. Call the tool
4. Interpret the result — confirm, refute, or refine your hypothesis

Investigation heuristics:
- **Latency spike?** → Check p99 vs p50 spread. If both moved, it's systemic. If only p99, look for outlier paths.
- **Error rate increase?** → Search logs for ERROR, then check if errors cluster on one endpoint or span across services.
- **Throughput drop?** → Check upstream services — the problem may be that requests aren't arriving, not that they're failing.
- **Cascading failure?** → Use `service_dependencies` to trace the call graph. Errors propagate upstream.

### Phase 4: VERIFY
Before concluding, verify your root cause with at least one independent signal:
- If you found an error in logs, confirm it shows up in traces too.
- If you suspect a deploy, compare error rates before/after the deploy timestamp.
- If a dependency is failing, check that the dependency's own metrics confirm the issue.

### Phase 5: CONCLUDE
Structure your final summary:

## Root Cause
One clear sentence. Name the service, the failure mode, and when it started.

## Evidence
Bullet list of specific findings with timestamps and metric values.

## Impact
Which services are affected, estimated user impact, blast radius.

## Timeline
Chronological sequence of events leading to the incident.

## Recommended Actions
Specific, actionable steps ranked by urgency. Include rollback if deploy-related.

## SKILLS

You have a `load_skill` tool that provides detailed investigation playbooks for specific scenarios.
When you identify the likely category of incident, load the relevant skill for expert guidance:
- `error_rate_spike` — Diagnosing sudden increases in error rates
- `latency_degradation` — Investigating latency increases and slow requests
- `deploy_regression` — Correlating issues with recent deployments
- `dependency_failure` — Tracing failures through the service dependency graph
- `argocd_unhealthy` — Diagnosing ArgoCD apps that are Degraded, Missing, or failing syncs
- `throughput_anomaly` — Analyzing request volume changes

When you have an initial hypothesis, load the relevant skill immediately — do not ask for permission.

## TIME CONTEXT
When investigating a specific event (log entry, trace, anomaly), use the `around` parameter
on search_logs, query_traces, and query_metrics to center your search on the event's timestamp.
This searches ±5 minutes around that time instead of "last N minutes from now."
Extract the timestamp from the initial context and pass it as `around` in your first tool calls.

## KUBERNETES TOOLS

You have read-only access to the Kubernetes cluster:
- `kube_describe` — Describe any K8s resource (pods, deployments, replicasets, services, etc.). Use '*' as name to list all. Shows status, conditions, container states, events.
- `kube_events` — List events in a namespace. Filter by resource name or warnings-only. Events reveal why pods fail, deployments stall, or resources are unhealthy.

When investigating ArgoCD issues, use these to dig into the actual K8s state:
1. Get the ArgoCD app state with `get_argocd_app` to find unhealthy resources
2. Use `kube_describe` on unhealthy pods/deployments to see conditions, container states, restart reasons
3. Use `kube_events` to see Warning events that explain failures
4. Check logs with `search_logs` for the affected service

## WORKING MEMORY

The harness tracks a running "Working Memory" with your confirmed facts, suspect services, and
ruled-out hypotheses. After each tool call, this memory is updated and re-injected into the
next prompt. When you see a "Working Memory" block, trust it — it's your durable state across
the investigation. Avoid re-confirming things already in Confirmed Facts.

## REPEAT DETECTION

The harness automatically rejects repeated tool calls with identical arguments. If you get a
"this exact tool call was already made" error, do NOT retry — instead:
- Vary the time window, service name, or filters
- Switch signal source (logs ↔ traces ↔ metrics ↔ k8s events ↔ ArgoCD)
- If you have enough evidence, produce your final report now

## RULES
- NEVER ask the user questions or wait for confirmation. This is a one-shot investigation — you cannot receive replies.
- Act autonomously: if a skill is relevant, load it. If a tool might help, call it. Do not ask "would you like me to...".
- Explain your reasoning before every tool call.
- Call one tool at a time so the user can follow your investigation.
- If a tool returns no useful data, explain why and try a different approach — do NOT re-run the same query.
- When given a specific event, use `around` with its timestamp — not `minutes`.
- Be specific: include service names, error messages, timestamps, metric values.
- Summarize findings — never dump raw data.
- Always consider whether a recent deploy could be the cause.
- DO NOT stop until you have a clear understanding of the root cause and a specific recommendation for how to fix it.
- If your first hypothesis is wrong, form a new one and keep investigating. Exhaustion of one path is not a reason to stop.
- Use every tool available to you. If logs don't explain it, check traces. If traces don't explain it, check k8s events. If events don't explain it, describe the pods.
- Always end with a complete summary — never end with a question or suggestion to continue."#
        .to_string()
}

/// Build the initial user message from an anomaly event + rule.
pub fn anomaly_context(event: &AnomalyEvent, rule: &AnomalyRule) -> String {
    let mut msg = format!(
        "An anomaly has been detected. Investigate the root cause.\n\n\
         ## Anomaly Event\n\
         - **Metric**: {}\n\
         - **Observed value**: {:.4}\n\
         - **Expected value**: {:.4}\n\
         - **Deviation**: {:.1}σ (threshold: {:.1}σ)\n\
         - **State**: {}\n\
         - **Timestamp**: {}\n\n\
         ## Rule\n\
         - **Name**: {}\n\
         - **Source**: {}\n\
         - **Pattern**: {}\n",
        event.metric,
        event.value,
        event.expected,
        event.deviation,
        rule.sensitivity,
        event.state,
        event.created_at,
        rule.name,
        rule.source,
        rule.pattern,
    );

    if !rule.service_name.is_empty() {
        msg.push_str(&format!("- **Service**: {}\n", rule.service_name));
    }
    if !rule.apm_metric.is_empty() {
        msg.push_str(&format!("- **APM metric**: {}\n", rule.apm_metric));
    }
    if !rule.description.is_empty() {
        msg.push_str(&format!("\n## Rule description\n{}\n", rule.description));
    }

    msg.push_str("\nBegin your investigation.");
    msg
}

/// Build the initial user message from a freeform question.
pub fn question_context(question: &str, additional: &str) -> String {
    let mut msg = format!(
        "Investigate the following:\n\n{question}\n"
    );
    if !additional.is_empty() {
        msg.push_str(&format!("\n## Additional context\n{additional}\n"));
    }
    msg.push_str("\nBegin your investigation.");
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule() -> AnomalyRule {
        AnomalyRule {
            id: "r1".into(),
            name: "Checkout Errors".into(),
            description: "Alerts when checkout error rate exceeds threshold".into(),
            enabled: true,
            source: "apm".into(),
            pattern: "error_rate".into(),
            query: "".into(),
            service_name: "checkout".into(),
            apm_metric: "error_rate".into(),
            sensitivity: 3.0,
            alpha: 0.25,
            eval_interval_secs: 300,
            window_secs: 3600,
            split_labels: "[]".into(),
            notification_channel_ids: "[]".into(),
            state: "anomalous".into(),
            last_eval_at: None,
            last_triggered_at: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn sample_event() -> AnomalyEvent {
        AnomalyEvent {
            id: "e1".into(),
            rule_id: "r1".into(),
            state: "anomalous".into(),
            metric: "error_rate".into(),
            value: 0.0523,
            expected: 0.0102,
            deviation: 3.5,
            message: "".into(),
            created_at: "2026-01-15T14:30:00Z".into(),
        }
    }

    #[test]
    fn system_prompt_contains_all_key_sections() {
        let p = system_prompt();
        assert!(p.contains("INVESTIGATION METHODOLOGY"));
        assert!(p.contains("WORKING MEMORY"));
        assert!(p.contains("REPEAT DETECTION"));
        assert!(p.contains("KUBERNETES TOOLS"));
        assert!(p.contains("SKILLS"));
        assert!(p.contains("TIME CONTEXT"));
    }

    #[test]
    fn system_prompt_mentions_all_skills() {
        let p = system_prompt();
        for skill in [
            "error_rate_spike",
            "latency_degradation",
            "deploy_regression",
            "dependency_failure",
            "argocd_unhealthy",
            "throughput_anomaly",
        ] {
            assert!(p.contains(skill), "system prompt missing skill reference: {skill}");
        }
    }

    #[test]
    fn system_prompt_is_substantial() {
        // A short system prompt is a sign of broken code
        assert!(system_prompt().len() > 2000);
    }

    #[test]
    fn question_context_includes_question() {
        let out = question_context("why is checkout slow?", "");
        assert!(out.contains("why is checkout slow?"));
        assert!(out.contains("Begin your investigation"));
    }

    #[test]
    fn question_context_includes_additional() {
        let out = question_context("what happened?", "service=api at 10:00 UTC");
        assert!(out.contains("what happened?"));
        assert!(out.contains("Additional context"));
        assert!(out.contains("service=api at 10:00 UTC"));
    }

    #[test]
    fn question_context_omits_additional_when_empty() {
        let out = question_context("q", "");
        assert!(!out.contains("Additional context"));
    }

    #[test]
    fn anomaly_context_includes_event_fields() {
        let out = anomaly_context(&sample_event(), &sample_rule());
        assert!(out.contains("0.0523")); // observed
        assert!(out.contains("0.0102")); // expected
        assert!(out.contains("3.5σ")); // deviation
        assert!(out.contains("anomalous")); // state
        assert!(out.contains("2026-01-15T14:30:00Z")); // timestamp
    }

    #[test]
    fn anomaly_context_includes_rule_fields() {
        let out = anomaly_context(&sample_event(), &sample_rule());
        assert!(out.contains("Checkout Errors"));
        assert!(out.contains("apm"));
        assert!(out.contains("checkout")); // service_name
        assert!(out.contains("Alerts when checkout error rate"));
    }

    #[test]
    fn anomaly_context_omits_empty_optional_fields() {
        let mut rule = sample_rule();
        rule.service_name = String::new();
        rule.apm_metric = String::new();
        rule.description = String::new();
        let out = anomaly_context(&sample_event(), &rule);
        assert!(!out.contains("**Service**:"));
        assert!(!out.contains("**APM metric**:"));
        assert!(!out.contains("Rule description"));
    }

    #[test]
    fn anomaly_context_ends_with_investigation_cue() {
        let out = anomaly_context(&sample_event(), &sample_rule());
        assert!(out.trim_end().ends_with("Begin your investigation."));
    }
}
