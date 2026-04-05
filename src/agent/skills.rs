use std::collections::HashMap;

/// A skill is a targeted investigation playbook that the agent can load on demand.
/// Each skill provides a focused checklist and heuristics for a specific incident type.
pub struct Skill {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub content: &'static str,
}

/// Return all available skills indexed by name.
pub fn all_skills() -> HashMap<&'static str, Skill> {
    let mut m = HashMap::new();

    m.insert("error_rate_spike", Skill {
        name: "error_rate_spike",
        title: "Error Rate Spike Investigation",
        description: "Playbook for diagnosing sudden increases in error rates",
        content: r#"# Error Rate Spike Investigation Playbook

## Quick Assessment
1. **Scope the blast radius** — Is this one service or many? Use `list_services` to compare error rates.
2. **Check deploy timing** — Use `list_deploys` and compare the error spike timestamp against recent deploys. A deploy within the last 30 minutes is the #1 suspect.
3. **Identify the error** — Use `search_logs` with severity=ERROR for the affected service. Look for the dominant error message.

## Diagnostic Checklist
- [ ] Which HTTP status codes are elevated? (5xx = server, 4xx = client/upstream)
- [ ] Is the error on all endpoints or a specific path? Check traces filtered by status=error.
- [ ] Are errors consistent or intermittent? Consistent = code bug. Intermittent = dependency or resource.
- [ ] Did traffic volume change? A spike in requests can cause errors if capacity is exceeded.

## Root Cause Patterns

### Pattern: All 5xx, started after deploy
→ **Deploy regression.** Compare error rate before/after deploy timestamp. Recommend rollback.

### Pattern: 5xx on one endpoint, other endpoints fine
→ **Code path bug.** Search logs for the specific endpoint, look for stack traces or panic messages.

### Pattern: 5xx intermittent, correlates with downstream errors
→ **Dependency failure.** Use `service_dependencies` to find downstream services, then check their error rates and logs.

### Pattern: 429 or 503, correlates with traffic increase
→ **Capacity exhaustion.** Check request_rate metrics for a traffic spike. Look for rate limiting or connection pool exhaustion in logs.

### Pattern: Errors across multiple services simultaneously
→ **Shared dependency failure.** Find the common downstream service using the dependency graph. Check infrastructure (database, cache, queue).

## Key Queries
- Error rate trend: `query_metrics` with metric=error_rate for the service, 30min window
- Error logs: `search_logs` with severity=ERROR, look for the top recurring message
- Error traces: `query_traces` with status=error to see which spans fail
- Full trace: Once you have an error trace ID, use `get_trace` to see the full call chain"#,
    });

    m.insert("latency_degradation", Skill {
        name: "latency_degradation",
        title: "Latency Degradation Investigation",
        description: "Playbook for investigating latency increases and slow requests",
        content: r#"# Latency Degradation Investigation Playbook

## Quick Assessment
1. **p50 vs p99** — Use `query_metrics` for both p50_latency and p99_latency.
   - Both elevated = systemic issue (database, shared resource)
   - Only p99 elevated = outlier paths or specific request types
2. **Which service?** — If a gateway is slow, the real problem is often a downstream dependency.
3. **When did it start?** — Check `list_deploys` for timing correlation.

## Diagnostic Checklist
- [ ] Is latency elevated on all endpoints or specific ones? Check traces.
- [ ] Are downstream services also slow? Use `service_dependencies` + check their latency.
- [ ] Is there a change in request volume? More traffic = higher latency under load.
- [ ] Any errors accompanying the latency? Retries cause latency spikes.

## Root Cause Patterns

### Pattern: p50 and p99 both elevated, started at specific time
→ **Systemic degradation.** Check for deploy, database slow queries, or resource exhaustion.

### Pattern: Only p99 elevated, p50 normal
→ **Outlier requests.** Use `query_traces` to find the slowest spans. Look for specific paths, large payloads, or cold cache misses.

### Pattern: Latency gradually increasing over hours
→ **Resource leak or accumulation.** Look for memory pressure, connection pool exhaustion, or growing queue depth. Check metrics for a steady climb.

### Pattern: Latency spikes periodically (every N minutes)
→ **Background job interference.** Look for cron jobs, garbage collection, or batch processing that competes for resources.

### Pattern: Gateway slow but downstream services have normal latency
→ **Network or serialization issue.** The time is spent between services, not within them. Check for large response payloads or DNS resolution delays.

## Key Queries
- Latency trend: `query_metrics` with p50_latency and p99_latency, 30min window
- Slow traces: `query_traces` for the service, sorted by duration — examine the slowest
- Dependency latency: `query_traces` for downstream services to isolate which hop is slow
- Deploy correlation: `list_deploys` — compare latency before/after recent deploys"#,
    });

    m.insert("deploy_regression", Skill {
        name: "deploy_regression",
        title: "Deploy Regression Investigation",
        description: "Playbook for correlating issues with recent deployments",
        content: r#"# Deploy Regression Investigation Playbook

## Quick Assessment
1. **List recent deploys** — Use `list_deploys` for the affected service and nearby services.
2. **Timeline match** — Does the anomaly start within minutes of a deploy? Strong correlation = high confidence.
3. **Version comparison** — Note the version/commit before and after. The diff is your suspect.

## Diagnostic Checklist
- [ ] Which service was deployed? Was it the affected service or an upstream/downstream?
- [ ] What changed? Check the commit SHA from deploy info.
- [ ] Are errors new (not seen before the deploy) or existing errors that got worse?
- [ ] Did multiple services deploy simultaneously? Check all deploys in the window.

## Investigation Steps

### Step 1: Establish the deploy timeline
Use `list_deploys` with a 6-hour window. Create a mental timeline of deploys vs anomaly onset.

### Step 2: Compare before/after metrics
Query error_rate and p99_latency for the service with a window that spans 15 minutes before and after the deploy timestamp. Look for a step change.

### Step 3: Identify new errors
Search logs for ERROR in the service AFTER the deploy timestamp. Look for error messages or stack traces that didn't appear before.

### Step 4: Check traces for new failure patterns
Query traces with status=error after the deploy. Look for spans that are failing in the new version that worked in the old version.

### Step 5: Verify with dependency check
If the deployed service is a dependency, check upstream services for correlated error increases.

## Confidence Assessment
- **High confidence:** Anomaly starts within 5 minutes of deploy, new error type appears, no other changes
- **Medium confidence:** Anomaly starts within 30 minutes, could be traffic or load related
- **Low confidence:** Anomaly timing is loose, multiple changes happened simultaneously

## Recommendation Template
If deploy regression confirmed:
1. **Immediate:** Recommend rollback to previous version [version]
2. **Short-term:** Identify the specific code change that caused the regression
3. **Long-term:** Add canary deployment or automated rollback for this service"#,
    });

    m.insert("dependency_failure", Skill {
        name: "dependency_failure",
        title: "Dependency Failure Investigation",
        description: "Playbook for tracing failures through the service dependency graph",
        content: r#"# Dependency Failure Investigation Playbook

## Quick Assessment
1. **Map the dependency graph** — Use `service_dependencies` to see who calls whom.
2. **Find the origin** — Errors propagate upstream. The root cause is the deepest failing service.
3. **Check all services** — Use `list_services` to find which services have elevated error rates.

## Diagnostic Checklist
- [ ] Which services have elevated error rates? Sort by severity.
- [ ] What's the call graph between affected services?
- [ ] Is there a single service that all failing services depend on?
- [ ] Is the dependency internal or external (third-party API, database)?

## Investigation Steps

### Step 1: Get the big picture
Use `list_services` to see error rates across all services. Identify the cluster of affected services.

### Step 2: Map dependencies
Use `service_dependencies` to draw the call graph. Focus on services with high error rates.

### Step 3: Find the deepest failure
Follow the dependency chain downstream. The service that's failing WITHOUT its OWN dependencies failing is likely the root cause.

### Step 4: Investigate the root service
Focus your investigation on the root service:
- `search_logs` for ERROR messages
- `query_metrics` for error_rate and latency
- `query_traces` with status=error for failure details
- `list_deploys` for recent changes

### Step 5: Verify the cascade
Get a trace that shows the full call chain through affected services. Use `get_trace` on an error trace to confirm the failure originates at the root service and propagates up.

## Common Patterns

### Database failure
Multiple services fail simultaneously because they share a database. Logs will show connection errors or query timeouts.

### External API down
Services calling a third-party API see timeouts. Other services fail because they depend on the data from those services.

### Circuit breaker tripped
A dependency was slow, circuit breaker opened, and now all calls to it fail fast with a circuit breaker error.

### DNS resolution failure
Services can't resolve hostnames. Errors are connection-level, not application-level."#,
    });

    m.insert("argocd_unhealthy", Skill {
        name: "argocd_unhealthy",
        title: "ArgoCD Unhealthy App Investigation",
        description: "Playbook for diagnosing ArgoCD applications that are Degraded, Missing, or have failed syncs",
        content: r#"# ArgoCD Unhealthy App Investigation Playbook

## Quick Assessment
1. Call `get_argocd_app` to get the full application state
2. Read the conditions — ArgoCD often tells you exactly what's wrong
3. Identify which resources are unhealthy from the resource list

## Diagnostic Checklist
- [ ] What is the health status? (Degraded, Missing, Progressing, Unknown)
- [ ] Are there conditions/warnings on the app?
- [ ] Which specific K8s resources are unhealthy?
- [ ] Was there a recent sync? Did it succeed or fail?
- [ ] Is the app OutOfSync? (desired state != live state)
- [ ] Are there error logs from unhealthy pods? (use search_logs for the service)
- [ ] Did a recent deploy correlate with the health change? (use list_deploys)
- [ ] What do the traces show for the affected service? (use query_traces)

## Root Cause Patterns

### Pattern: Deployment Degraded — pods not becoming ready
-> Search logs for the service around the time health changed
-> Look for: CrashLoopBackOff, OOMKilled, readiness probe failures, image pull errors
-> Check error rate and latency metrics for the service
-> Check if the container image exists

### Pattern: Sync Failed — manifests can't be applied
-> Read the operation state error message from get_argocd_app
-> Common causes: invalid manifest YAML, resource conflicts, admission webhook rejections
-> Check if another controller or manual edit is conflicting

### Pattern: OutOfSync but Healthy
-> App is running fine but live state doesn't match Git
-> Check if auto-sync is disabled on the app
-> May be intentional (manual override, sync window)

### Pattern: Missing resources
-> Resources expected by ArgoCD don't exist in the cluster
-> Check if resources were deleted manually
-> Check if pruning is enabled
-> Check cluster/namespace connectivity

### Pattern: Progressing for too long
-> A rollout is stuck and not completing
-> Check for: insufficient CPU/memory, pending PVCs, node scheduling issues
-> Search logs for startup failures in new pods
-> Check if old pods are being terminated correctly

## Key Queries
- App state: `get_argocd_app` with the app name
- Pod status: `kube_describe` with kind=pod and the pod name + namespace to see container states, restart reasons, OOMKill
- Deployment status: `kube_describe` with kind=deployment to see replica counts, rollout conditions
- K8s events: `kube_events` with namespace and warnings_only=true to find failure reasons
- List pods: `kube_describe` with kind=pod, name='*', namespace to see all pods and their states
- Service logs: `search_logs` with the service name, around the degradation time
- Service errors: `query_traces` with status=error for the service
- Recent deploys: `list_deploys` for the service
- Error rate: `query_metrics` with metric=error_rate for the service

## Investigation depth
Do NOT stop after just checking the ArgoCD app state. Always:
1. Identify the unhealthy resources from the app state
2. Describe the specific pods/deployments that are failing
3. Read the K8s events for the namespace
4. Check logs for error messages
5. Only then form your conclusion"#,
    });

    m.insert("throughput_anomaly", Skill {
        name: "throughput_anomaly",
        title: "Throughput Anomaly Investigation",
        description: "Playbook for analyzing request volume changes",
        content: r#"# Throughput Anomaly Investigation Playbook

## Quick Assessment
1. **Direction** — Is throughput higher or lower than expected?
   - Higher: Traffic spike, possible DDoS, viral event, or retry storm
   - Lower: Upstream failure, routing change, or client-side issue
2. **Scope** — All services or specific ones? Use `list_services` for the overview.
3. **Timing** — Sudden drop/spike or gradual change?

## Diagnostic Checklist
- [ ] Is the throughput change on all endpoints or specific routes?
- [ ] Did upstream services also see a change? Check the full call chain.
- [ ] Are there new error types appearing alongside the throughput change?
- [ ] Any deploys or config changes in the window?

## Throughput Drop Investigation

### Step 1: Check upstream
If service B's throughput dropped, check if service A (which calls B) also dropped. If A is fine but B is down, the issue is between A and B (routing, DNS, load balancer). If A also dropped, go further upstream.

### Step 2: Check for errors replacing successful requests
Sometimes throughput "drops" because requests are now failing before reaching the service. Check error logs on upstream services and load balancers.

### Step 3: Check client-side (if applicable)
If this is a user-facing service, check RUM data for client-side errors or connectivity issues.

## Throughput Spike Investigation

### Step 1: Identify the source
Use `query_traces` to see which paths have increased traffic. Is it organic or synthetic?

### Step 2: Look for retry storms
If errors are also elevated, clients may be retrying failed requests, amplifying load. Check for exponential traffic growth combined with error rate increase.

### Step 3: Check capacity impact
Is the throughput increase causing latency degradation or errors? Use `query_metrics` for latency alongside request_rate.

## Key Queries
- Request rate: `query_metrics` with metric=request_rate, compare 1-hour window
- Per-service breakdown: `list_services` to compare request counts
- Traffic patterns: `query_traces` to see which endpoints have changed volume"#,
    });

    m
}

/// List available skills as a formatted string (for the load_skill tool).
pub fn list_skills_summary() -> String {
    let skills = all_skills();
    let mut lines = Vec::new();
    lines.push("Available investigation skills:".to_string());
    // Sort for deterministic order
    let mut names: Vec<_> = skills.keys().collect();
    names.sort();
    for name in names {
        let s = &skills[name];
        lines.push(format!("- **{}**: {}", s.name, s.description));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_expected_skills_present() {
        let skills = all_skills();
        let expected = [
            "error_rate_spike",
            "latency_degradation",
            "deploy_regression",
            "dependency_failure",
            "argocd_unhealthy",
            "throughput_anomaly",
        ];
        for name in expected {
            assert!(skills.contains_key(name), "missing skill: {name}");
        }
    }

    #[test]
    fn skill_fields_non_empty() {
        for (key, skill) in all_skills() {
            assert!(!skill.name.is_empty(), "{key}: empty name");
            assert_eq!(skill.name, key, "{key}: name mismatch");
            assert!(!skill.title.is_empty(), "{key}: empty title");
            assert!(!skill.description.is_empty(), "{key}: empty description");
            assert!(
                skill.content.len() > 100,
                "{key}: content suspiciously short ({} chars)",
                skill.content.len()
            );
        }
    }

    #[test]
    fn skills_reference_agent_tools() {
        // Each skill should mention at least one agent tool by name
        let tool_names = [
            "search_logs",
            "query_traces",
            "query_metrics",
            "list_deploys",
            "get_argocd_app",
            "kube_describe",
            "kube_events",
            "list_services",
            "service_dependencies",
        ];
        for (key, skill) in all_skills() {
            let mentions_any = tool_names.iter().any(|t| skill.content.contains(t));
            assert!(mentions_any, "skill {key} does not reference any agent tool");
        }
    }

    #[test]
    fn list_skills_summary_includes_all() {
        let summary = list_skills_summary();
        for name in all_skills().keys() {
            assert!(summary.contains(name), "summary missing {name}");
        }
        assert!(summary.contains("Available investigation skills"));
    }

    #[test]
    fn argocd_skill_mentions_argocd() {
        let skills = all_skills();
        let s = skills.get("argocd_unhealthy").expect("skill missing");
        assert!(s.content.to_lowercase().contains("argocd"));
    }
}
