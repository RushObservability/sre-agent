use super::kube_tool::namespace_allowed_for;
use crate::agent::tools::ToolContext;
use anyhow::{Result, bail};
use kube::api::DynamicObject;
use serde_json::Value;

pub(super) struct GitOpsPolicy {
    pub controller_namespace: String,
    tenant_id: String,
    namespaces: Option<String>,
    cluster_reads: bool,
}

impl GitOpsPolicy {
    pub fn from_env(ctx: &ToolContext, controller: &str) -> Result<Self> {
        Self::new(
            &ctx.tenant_id,
            &ctx.scopes,
            std::env::var(controller).ok().as_deref(),
            std::env::var("SRE_AGENT_KUBE_TENANT_NAMESPACES")
                .ok()
                .as_deref(),
            std::env::var("SRE_AGENT_KUBE_ALLOW_CLUSTER_SCOPED")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
        )
    }

    pub fn new(
        tenant_id: &str,
        scopes: &[String],
        controller_namespace: Option<&str>,
        namespaces: Option<&str>,
        cluster_reads: bool,
    ) -> Result<Self> {
        let Some(controller_namespace) = controller_namespace.filter(|ns| !ns.trim().is_empty())
        else {
            bail!("GitOps controller is not enabled");
        };
        validate_namespace(controller_namespace)?;
        if !scopes
            .iter()
            .any(|scope| scope == "all" || scope == "kubernetes")
        {
            bail!("Kubernetes scope is required for GitOps reads");
        }
        Ok(Self {
            controller_namespace: controller_namespace.to_string(),
            tenant_id: tenant_id.to_string(),
            namespaces: namespaces.map(str::to_string),
            cluster_reads: cluster_reads && scopes.iter().any(|scope| scope == "kube_cluster"),
        })
    }

    pub fn namespace(&self, namespace: &str) -> Result<()> {
        validate_namespace(namespace)?;
        if !namespace_allowed_for(self.namespaces.as_deref(), &self.tenant_id, namespace) {
            bail!("GitOps resource is not authorized for this tenant");
        }
        Ok(())
    }

    fn resource_namespace(&self, namespace: &str) -> Result<()> {
        if namespace.is_empty() && self.cluster_reads {
            return Ok(());
        }
        self.namespace(namespace)
    }

    pub fn object(&self, object: &DynamicObject, namespace: &str, name: &str) -> Result<()> {
        if object.metadata.namespace.as_deref() != Some(namespace)
            || object.metadata.name.as_deref() != Some(name)
        {
            bail!("GitOps response does not match the authorized resource");
        }
        self.namespace(namespace)
    }

    pub fn argocd_destination(&self, data: &Value) -> Result<()> {
        let destination = &data["spec"]["destination"];
        // A namespace grant belongs to the agent's cluster, not every remote
        // cluster that happens to use the same namespace name.
        let server = destination["server"].as_str().unwrap_or("");
        let name = destination["name"].as_str().unwrap_or("");
        if !matches!(
            (server, name),
            ("https://kubernetes.default.svc", "") | ("", "in-cluster")
        ) {
            bail!("Remote or unresolved Argo CD destinations are not authorized");
        }
        self.namespace(destination["namespace"].as_str().unwrap_or(""))?;
        for path in [
            "/status/resources",
            "/status/operationState/syncResult/resources",
        ] {
            if let Some(resources) = data.pointer(path).and_then(Value::as_array) {
                for resource in resources {
                    self.resource_namespace(resource["namespace"].as_str().unwrap_or(""))?;
                }
            }
        }
        Ok(())
    }

    pub fn flux_destination(&self, data: &Value, kind: &str, namespace: &str) -> Result<()> {
        let spec = &data["spec"];
        if spec.get("kubeConfig").is_some_and(|value| !value.is_null()) {
            bail!("Remote Flux destinations are not authorized");
        }
        if let Some(target) = spec.get("targetNamespace") {
            self.namespace(target.as_str().unwrap_or(""))?;
        } else if kind == "Kustomization" {
            // Without a target namespace, a Kustomization can apply manifests
            // anywhere. Do not infer tenant ownership from its controller CR.
            bail!("Flux Kustomization requires an authorized targetNamespace");
        }
        for path in [
            "/spec/sourceRef",
            "/spec/chart/spec/sourceRef",
            "/spec/chartRef",
        ] {
            if let Some(reference) = data.pointer(path) {
                self.namespace(
                    reference
                        .get("namespace")
                        .map_or(Some(namespace), Value::as_str)
                        .unwrap_or(""),
                )?;
            }
        }
        if let Some(dependencies) = spec["dependsOn"].as_array() {
            for dependency in dependencies {
                self.namespace(
                    dependency
                        .get("namespace")
                        .map_or(Some(namespace), Value::as_str)
                        .unwrap_or(""),
                )?;
            }
        }
        if let Some(entries) = data
            .pointer("/status/inventory/entries")
            .and_then(Value::as_array)
        {
            for entry in entries {
                let parts: Vec<_> = entry["id"].as_str().unwrap_or("").split('_').collect();
                if parts.len() != 4 {
                    bail!("Flux inventory scope could not be verified");
                }
                self.resource_namespace(parts[0])?;
            }
        }
        Ok(())
    }
}

fn validate_namespace(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
    {
        bail!("A valid Kubernetes namespace is required for GitOps reads");
    }
    Ok(())
}

pub(super) fn resource_name(args: &Value) -> Result<&str> {
    let name = args["name"].as_str().unwrap_or("");
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        bail!("A valid GitOps resource name is required");
    }
    Ok(name)
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub const NAMESPACES: &str = r#"{"tenant-a":["argocd","flux-system","app-a"]}"#;

    pub fn policy(controller: &str, namespaces: Option<&str>) -> GitOpsPolicy {
        GitOpsPolicy::new(
            "tenant-a",
            &["all".into()],
            Some(controller),
            namespaces,
            false,
        )
        .unwrap()
    }

    pub async fn unexpected_client() -> Result<kube::Client, kube::Error> {
        panic!("a denied read must not initialize a Kubernetes client")
    }

    // In-memory transport exercises kube's request construction without TLS,
    // credentials, environment mutation, or access to a real cluster.
    pub fn client(status: u16, body: Value) -> (kube::Client, Arc<Mutex<Vec<String>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let service = tower::service_fn(move |request: axum::http::Request<kube::client::Body>| {
            captured
                .lock()
                .unwrap()
                .push(format!("{} {}", request.method(), request.uri()));
            let body = body.to_string();
            async move {
                Ok::<_, std::convert::Infallible>(
                    axum::http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
            }
        });
        (kube::Client::new(service, "default"), requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use test_support::{NAMESPACES, policy};

    #[test]
    fn disabled_controllers_and_missing_scope_are_rejected() {
        for controller in [None, Some(""), Some(" "), Some("../argocd")] {
            assert!(
                GitOpsPolicy::new(
                    "tenant-a",
                    &["all".into()],
                    controller,
                    Some(NAMESPACES),
                    false
                )
                .is_err()
            );
        }
        for scopes in [vec![], vec!["logs".into()], vec!["kube_cluster".into()]] {
            assert!(
                GitOpsPolicy::new("tenant-a", &scopes, Some("argocd"), Some(NAMESPACES), true)
                    .is_err()
            );
        }
    }

    #[test]
    fn namespace_grants_are_exact_fail_closed_and_shared_fallback_is_preserved() {
        for raw in [
            None,
            Some(""),
            Some("invalid"),
            Some("{}"),
            Some(r#"{"tenant-b":["app-a"]}"#),
        ] {
            assert!(policy("argocd", raw).namespace("app-a").is_err());
        }
        let shared = policy("argocd", Some(r#"{"*":["shared"],"tenant-a":[]}"#));
        assert!(shared.namespace("shared").is_err());
        let shared = policy("argocd", Some(r#"{"*":["shared"]}"#));
        assert!(shared.namespace("shared").is_ok());
        for namespace in ["", "*", "app-b", "../app-a", "app-a/../app-b"] {
            assert!(
                policy("argocd", Some(NAMESPACES))
                    .namespace(namespace)
                    .is_err()
            );
        }
    }

    #[test]
    fn argocd_requires_local_destination_and_authorized_managed_resources() {
        let policy = policy("argocd", Some(NAMESPACES));
        let base = json!({"spec":{"destination":{"server":"https://kubernetes.default.svc","namespace":"app-a"}}});
        assert!(policy.argocd_destination(&base).is_ok());
        let mut named = base.clone();
        named["spec"]["destination"] = json!({"name":"in-cluster","namespace":"app-a"});
        assert!(policy.argocd_destination(&named).is_ok());
        for destination in [
            json!({"server":"https://other-cluster","namespace":"app-a"}),
            json!({"name":"other-cluster","namespace":"app-a"}),
            json!({"server":"https://kubernetes.default.svc","namespace":"app-b"}),
            json!({"server":"https://kubernetes.default.svc"}),
            json!({"namespace":"app-a"}),
        ] {
            let mut data = base.clone();
            data["spec"]["destination"] = destination;
            assert!(policy.argocd_destination(&data).is_err());
        }
        for path in ["resources", "syncResult"] {
            let mut data = base.clone();
            data["status"] = if path == "resources" {
                json!({"resources":[{"namespace":"app-b"}]})
            } else {
                json!({"operationState":{"syncResult":{"resources":[{"namespace":"app-b"}]}}})
            };
            assert!(policy.argocd_destination(&data).is_err());
        }
    }

    #[test]
    fn cluster_resources_need_both_admin_scope_and_operator_switch_without_tenant_bypass() {
        for enabled in [false, true] {
            for admin in [false, true] {
                let scopes = if admin {
                    vec!["all".into(), "kube_cluster".into()]
                } else {
                    vec!["all".into()]
                };
                let policy = GitOpsPolicy::new(
                    "tenant-a",
                    &scopes,
                    Some("argocd"),
                    Some(NAMESPACES),
                    enabled,
                )
                .unwrap();
                assert_eq!(policy.resource_namespace("").is_ok(), enabled && admin);
                assert!(policy.resource_namespace("app-b").is_err());
            }
        }
    }

    #[test]
    fn flux_rejects_remote_targets_cross_namespace_refs_and_unscoped_inventory() {
        let policy = policy("flux-system", Some(NAMESPACES));
        let base = json!({"spec":{"targetNamespace":"app-a"}});
        assert!(
            policy
                .flux_destination(&base, "Kustomization", "flux-system")
                .is_ok()
        );
        assert!(
            policy
                .flux_destination(&json!({"spec":{}}), "Kustomization", "flux-system")
                .is_err()
        );
        assert!(
            policy
                .flux_destination(&json!({"spec":{}}), "HelmRelease", "app-a")
                .is_ok()
        );
        for spec in [
            json!({"targetNamespace":"app-b"}),
            json!({"targetNamespace":"app-a","kubeConfig":{"secretRef":{"name":"remote"}}}),
            json!({"targetNamespace":"app-a","sourceRef":{"namespace":"app-b"}}),
            json!({"targetNamespace":"app-a","chartRef":{"namespace":"app-b"}}),
            json!({"targetNamespace":"app-a","chart":{"spec":{"sourceRef":{"namespace":"app-b"}}}}),
            json!({"targetNamespace":"app-a","dependsOn":[{"name":"private","namespace":"app-b"}]}),
        ] {
            assert!(
                policy
                    .flux_destination(&json!({"spec":spec}), "Kustomization", "flux-system")
                    .is_err()
            );
        }
        for id in [
            "app-b_private_apps_Deployment",
            "_private__Namespace",
            "malformed",
        ] {
            let mut data = base.clone();
            data["status"] = json!({"inventory":{"entries":[{"id":id}]}});
            assert!(
                policy
                    .flux_destination(&data, "Kustomization", "flux-system")
                    .is_err()
            );
        }
        let mut data = base;
        data["status"] = json!({"inventory":{"entries":[{"id":"app-a_web_apps_Deployment"}]}});
        assert!(
            policy
                .flux_destination(&data, "Kustomization", "flux-system")
                .is_ok()
        );
    }
}
