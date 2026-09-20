# GitOps access during investigations

Argo CD and Flux tools use the same tenant namespace allowlist as the live Kubernetes tools. Kubernetes RBAC still applies to the agent's service account. A Rush tenant grant does not grant Kubernetes permissions.

## Configure access

Set the controller namespace to enable its tool. An unset, empty, or invalid namespace disables that controller's reads.

```sh
export ARGOCD_NAMESPACE=argocd
export FLUXCD_NAMESPACE=flux-system
export SRE_AGENT_KUBE_TENANT_NAMESPACES='{"tenant-a":["argocd","flux-system","payments"],"tenant-b":["argocd","orders"]}'
```

In this example, tenant A can inspect local Argo CD applications in `argocd` that deploy to `payments`, and Flux resources in `flux-system` or `payments` that target authorized namespaces. An application targeting `orders` is denied to tenant A even though both tenants can access the controller namespace.

Missing or malformed allowlists deny access. Namespaces are exact matches, not patterns. A `"*"` tenant entry is a fallback for tenants without their own entry. An explicit tenant entry replaces the fallback, including an empty list.

Normal investigation callers receive the `all` scope from query-api, which includes namespaced infrastructure reads. Restricted callers need `kubernetes` or `all`. The `kube_cluster` scope alone does not grant namespaced access.

## Argo CD

- Reads one Application by name in `ARGOCD_NAMESPACE`. A missing object or an API error never triggers a search in other namespaces.
- Requires the controller namespace and destination namespace to be in the tenant's allowlist.
- Accepts only the local destination `server: https://kubernetes.default.svc` or `name: in-cluster`. Remote and unresolved destinations are denied, including for administrators. Namespace grants do not identify remote clusters.
- Checks namespaces in current managed resources and the last sync result before returning application details. Cluster-scoped entries require both the `kube_cluster` scope and `SRE_AGENT_KUBE_ALLOW_CLUSTER_SCOPED=true`.

The Argo CD project name is not a Rush authorization grant. Configure Argo CD AppProject/RBAC restrictions separately. Controller metadata and repository configuration must remain under trusted platform administration.

See Argo CD's [application and project configuration](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/) for destination and project definitions.

## Flux

- Uses the requested namespace, or `FLUXCD_NAMESPACE` when the argument is omitted. An empty or invalid explicit namespace is denied. There is no all-namespace search.
- Checks the resource namespace, any explicit target namespace, source/chart references, dependencies, and Kustomization inventory namespaces.
- Requires an explicit authorized `spec.targetNamespace` on a Kustomization. Without one, its manifests may deploy into namespaces that cannot be inferred from the controller object's namespace.
- Denies resources using `spec.kubeConfig`, because their destination is another cluster.
- Requires the admin scope and cluster-read switch for cluster-scoped inventory entries. These do not override another tenant's namespace restrictions.

See Flux's [target namespace](https://fluxcd.io/flux/components/kustomize/kustomizations/#target-namespace) and [inventory](https://fluxcd.io/flux/components/kustomize/kustomizations/#inventory) documentation.

## Upgrade notes

Deployments that previously relied on unrestricted GitOps reads need namespace grants. Cross-namespace fallback and remote-cluster inspection are no longer supported by these tools. Flux Kustomizations without `targetNamespace` are denied until their scope is explicit.

Denied requests do not return the object's diagnostics to the model or activity log. The agent may fetch an Application from an authorized shared controller namespace to determine its destination, but it authorizes that destination before formatting any output.

The authorization tests inject an in-memory Kubernetes transport. They verify denial before client initialization, exact namespaced requests, authorized reads, blocked destinations, and no fallback after 403/404/500 responses. They do not need cluster credentials or TLS setup.
