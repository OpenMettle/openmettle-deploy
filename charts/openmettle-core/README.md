# openmettle-core chart

CPU-only packaging for the OpenMettle core API, worker and schema migration. Increment I1 of V1-32 is the **render contract**: templates, the values schema, security defaults and render-time tests. I2 adds a **kind install smoke test** ([`tests/kind`](../../tests/kind/README.md)). I3 adds **NetworkPolicies** (chart-scoped deny-all plus per-component allows) and live enforcement probes in the kind smoke test; the hosted kind run for I3 is pending pull-request CI execution. I4 adds optional, off-by-default **artifact storage, a database CA mount, an Ingress with TLS and an API PodDisruptionBudget**, plus a [synthetic example overlay](../../examples/values-synthetic.yaml). The I4 options are render-tested and kubeconform-validated only; none has been installed on a cluster. Neither a render nor a smoke run is application acceptance or qualification.

## What it renders

| Resource | Name | Notes |
| --- | --- | --- |
| Deployment | `<fullname>-api` | Port 8080 (`http`); liveness `/healthz`, readiness `/readyz` |
| Deployment | `<fullname>-worker` | Port 8081 (`http`); same probes; no Service |
| Service | `<fullname>-api` | ClusterIP; `api.service.port` → named port `http` |
| ServiceAccount | `<fullname>-api`, `<fullname>-worker` | One per component; no token mounted |
| ServiceAccount | `<fullname>-migrate` | Hook, weight `-10` |
| Job | `<fullname>-migrate` | Hook, weight `0`; see [Schema migration](#schema-migration) |
| NetworkPolicy | `<fullname>-deny-all` | Release-wide Ingress/Egress deny-all (`networkPolicy.enabled`, default `true`) |
| NetworkPolicy | `<fullname>-api`, `<fullname>-worker` | DNS and database egress; API ingress on TCP 8080 from `networkPolicy.api.ingressFrom` only |
| NetworkPolicy | `<fullname>-migrate` | Hook, weight `-10`; DNS and database egress for the migrate pod |
| PersistentVolumeClaim | `<fullname>-artifacts` | Optional (`storage.artifacts` with `size`); kept on uninstall. See [Artifact storage](#artifact-storage) |
| Ingress | `<fullname>-api` | Optional (`ingress.enabled`); HTTPS to the API Service. See [Ingress and TLS](#ingress-and-tls) |
| PodDisruptionBudget | `<fullname>-api` | Optional (`api.podDisruptionBudget.enabled`). See [API PodDisruptionBudget](#api-poddisruptionbudget) |

`<fullname>` is the release name if it already contains `openmettle-core`, otherwise `<release>-openmettle-core`, truncated to 52 characters. The chart creates no Namespace, Secret, ConfigMap, RBAC object, CRD, IngressClass, Traefik Middleware, device request or `resource.k8s.io` object. All resources are namespaced; set the namespace with `--namespace`.

## Values contract

[`values.schema.json`](values.schema.json) (JSON Schema draft 2020-12) rejects unknown keys at every level, so an unsupported key such as `oidc:` fails the render instead of being ignored. `affinity` is the only pass-through: its top-level keys are checked and Kubernetes validates the nested structure. Integer bounds copy core's (`src/lib.rs`, `src/migrate.rs`). The schema also rejects the `global` key that Helm passes to subcharts, so this chart cannot be used as a subchart. This is by design: core is installed as its own release.

The chart refuses to render until you supply:

- `images.{api,worker,migrate}.repository` and `.digest`. Images render as `[registry/]repository@sha256:<digest>`. Tags are not accepted in either field. `registry` is optional. The migrate image is not needed when `migration.enabled` is false.
- `database.{api,worker,migrate}.existingSecret`: names of existing Secrets. Each holds a full `postgres://` URL under `key` (default `url`). The migrate Secret is not needed when `migration.enabled` is false.
- `networkPolicy.database.to`: at least one Kubernetes `NetworkPolicyPeer` for PostgreSQL while `networkPolicy.enabled` is true. An empty list is rejected at render time because Kubernetes treats an empty `to` list as allowing every destination.

| Key | Default | Meaning |
| --- | --- | --- |
| `images.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `images.pullSecrets` | `[]` | Names of existing pull Secrets |
| `images.<component>.{registry,repository,digest}` | `""` | See above |
| `database.<component>.{existingSecret,key}` | `""`, `url` | See above |
| `database.connectionBudget` | `null` | Optional; see [Connection budget](#connection-budget) |
| `api.replicas`, `worker.replicas` | `1` | Independent |
| `api.resources`, `worker.resources` | requests `100m` CPU, `64Mi` | Core's contract examples, not qualified sizing. Only `cpu`, `memory` and `ephemeral-storage` are accepted. |
| `<component>.serviceAccount.{create,name,annotations}` | `true`, `""`, `{}` | `name` is required when `create` is false. Rendering fails if two components (including the migration, when enabled) resolve to the same name, or if any name is `default` |
| `<component>.settings.dbMaxConnections` | `4` | `OPENMETTLE_<ROLE>_DB_MAX_CONNECTIONS`, 1–64 |
| `<component>.settings.dbTimeoutMs` | `2000` | `OPENMETTLE_<ROLE>_DB_TIMEOUT_MS`, 1–30000 |
| `<component>.settings.shutdownTimeoutMs` | `5000` | `OPENMETTLE_<ROLE>_SHUTDOWN_TIMEOUT_MS`, 1–60000 |
| `<component>.terminationGracePeriodSeconds` | `15` | Must exceed `shutdownTimeoutMs`; rendering fails otherwise |
| `<component>.strategy.{maxSurge,maxUnavailable}` | `1`, `0` | Integers; both 0 is rejected |
| `api.service.port` | `8080` | Service port; container ports are fixed |
| `<component>.{podAnnotations,nodeSelector,tolerations,affinity}` | empty | Scheduling for api and worker |
| `migration.enabled` | `true` | Run the migration hook |
| `migration.settings.connectTimeoutMs` | `5000` | `OPENMETTLE_MIGRATE_CONNECT_TIMEOUT_MS`, 1–60000 |
| `migration.settings.lockTimeoutMs` | `15000` | `OPENMETTLE_MIGRATE_LOCK_TIMEOUT_MS`, 1–600000 |
| `migration.settings.statementTimeoutMs` | `300000` | `OPENMETTLE_MIGRATE_STATEMENT_TIMEOUT_MS`, 1–3600000 |
| `migration.activeDeadlineSeconds` | `900` | Job deadline. Must exceed `connectTimeoutMs + lockTimeoutMs + statementTimeoutMs`; rendering fails otherwise. Pass a Helm `--timeout` of at least this value; see [Schema migration](#schema-migration) |
| `migration.resources`, `migration.serviceAccount` | `{}`, created | As above |
| `migration.{podAnnotations,nodeSelector,tolerations,affinity}` | empty | Scheduling for the hook pod, for example on tainted nodes |
| `networkPolicy.enabled` | `true` | Render the release's deny-all and per-component NetworkPolicies; see [NetworkPolicy](#networkpolicy) |
| `networkPolicy.api.ingressFrom` | `[]` | `NetworkPolicyPeer` list allowed to connect to the API on TCP 8080. Empty denies all pod ingress |
| `networkPolicy.dns.to` | `kube-system` / `k8s-app: kube-dns` | `NetworkPolicyPeer` list for UDP and TCP 53 egress. Must be non-empty while enabled |
| `networkPolicy.database.to` | `[]` | Required while enabled: `NetworkPolicyPeer` list for PostgreSQL egress on `networkPolicy.database.port` |
| `networkPolicy.database.port` | `5432` | TCP port for database egress, 1–65535 |
| `database.caBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Mount one key of an existing ConfigMap at `/etc/openmettle/db-ca/ca.crt`; see [Database CA](#database-ca) |
| `storage.artifacts.enabled` | `false` | Mount an artifact volume in api and worker; see [Artifact storage](#artifact-storage) |
| `storage.artifacts.existingClaim` | `""` | Existing PVC to mount. Exactly one of `existingClaim` and `size` while enabled |
| `storage.artifacts.size` | `""` | Size of a chart-owned PVC, for example `20Gi` |
| `storage.artifacts.accessModes` | `[ReadWriteOnce]` | Chart-owned PVC only: `ReadWriteOnce` and/or `ReadWriteMany` |
| `storage.artifacts.storageClassName` | `null` | Chart-owned PVC only. `null`: cluster default; `""`: no class |
| `storage.artifacts.annotations` | `{}` | Chart-owned PVC only |
| `ingress.enabled` | `false` | Render an Ingress; see [Ingress and TLS](#ingress-and-tls) |
| `ingress.className` | `""` | Required while enabled: the IngressClass |
| `ingress.annotations` | `{}` | Controller annotations, passed through |
| `ingress.hosts` | `[]` | Required while enabled: dedicated lowercase hostnames; no wildcard, port or IP |
| `ingress.tls` | `[]` | Required while enabled: `{secretName, hosts}` entries naming existing TLS Secrets. Every host must be covered |
| `api.podDisruptionBudget.enabled` | `false` | See [API PodDisruptionBudget](#api-poddisruptionbudget) |
| `api.podDisruptionBudget.{minAvailable,maxUnavailable}` | `null` | Exactly one while enabled: an integer or `"<0–100>%"` |

`<component>` is `api` or `worker`; `<ROLE>` is `API` or `WORKER`.

Every process gets an explicit environment: `BIND` (`0.0.0.0:8080` or `0.0.0.0:8081`; core otherwise binds loopback), `DATABASE_URL` from its own Secret through `secretKeyRef`, and the settings above. The chart never uses `envFrom`. Each variable carries its own component prefix, as core ADR 0002 requires. Set `sslmode` explicitly in every URL, because SQLx defaults to `prefer`, which permits plaintext fallback. Readiness `timeoutSeconds` is `ceil(dbTimeoutMs / 1000) + 1`, because `/readyz` waits up to the database timeout.

Keep site values in a private overlay outside this repository and pass it with `-f`; see [Private overlays](#private-overlays). The synthetic files under `tests/chart/values/` use reserved `example.test` names and all-zero digests; they render but cannot be installed.

### Connection budget

Core ADR 0003 bounds PostgreSQL connections at the server. When `database.connectionBudget` is set, rendering fails unless

`(api.replicas + api.maxSurge) × api.dbMaxConnections + (worker.replicas + worker.maxSurge) × worker.dbMaxConnections + 1 (migrator) ≤ connectionBudget`.

Set it to the connections available to this release, after subtracting reserved and administrative or backup headroom. The check covers configured pools only. It also excludes Terminating pods: during a rollout, a replaced pod keeps its pool open while it drains, for up to `terminationGracePeriodSeconds`, so the actual peak can briefly exceed the computed one. Leave headroom for that. Enforce each role's share in PostgreSQL with `CONNECTION LIMIT`; the chart does not manage roles.

## Security defaults

These are fixed and are not values:

- Pod: `runAsNonRoot`, `runAsUser`/`runAsGroup` 65532 (the core image user), seccomp `RuntimeDefault`. `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch` is added only to api and worker pods that mount the artifact volume.
- Container: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, `privileged: false`. By default no volumes are mounted. The only optional volumes are the artifact claim (read-write, api and worker) and the database CA ConfigMap (read-only, every component). The root filesystem stays read-only either way.
- `automountServiceAccountToken: false` on every ServiceAccount and every pod, plus `enableServiceLinks: false`. The processes never call the Kubernetes API, so the chart creates no RBAC.
- Credentials come only from existing Secrets. The owner credential reaches only the migration Job. The chart never uses `lookup`.
- `/healthz` and `/readyz` are unauthenticated. The Service is ClusterIP only, `networkPolicy.api.ingressFrom` defaults to empty, and the Ingress is off by default.

## NetworkPolicy

`networkPolicy.enabled` defaults to `true`. When enabled, the chart renders a chart-scoped deny-all plus per-component allow policies:

- **`<fullname>-deny-all`** selects every pod of this release (`app.kubernetes.io/name` and `app.kubernetes.io/instance`) with `policyTypes: [Ingress, Egress]` and no rules.
- **`<fullname>-api`**, **`<fullname>-worker`** and **`<fullname>-migrate`** each select only their own component and declare `policyTypes: [Ingress, Egress]`:
  - **Egress** is restricted to `networkPolicy.dns.to` on UDP and TCP 53 and `networkPolicy.database.to` on TCP `networkPolicy.database.port` (default `5432`). Rendering fails if `dns.to` or `database.to` is empty while `networkPolicy.enabled` is true, because Kubernetes treats an empty `to` list as matching every destination.
  - The default `networkPolicy.dns.to` selects pods labelled `k8s-app: kube-dns` in the `kube-system` namespace, matching kubeadm (including kind) and K3s CoreDNS. Override it where cluster DNS uses different labels, namespace or IP blocks.
  - **Ingress** is allowed only on the API pod's container port (TCP `8080`) from `networkPolicy.api.ingressFrom`. It defaults to `[]` (no ingress rule rendered, so all pod-to-pod ingress is denied). Kubelet liveness/readiness probes and `kubectl port-forward` originate from the node or inside the pod's network namespace rather than from another pod peer, so they are unaffected. Worker and migrate pods never render an ingress rule.
- **Migrate hook policy.** `<fullname>-migrate` carries `helm.sh/hook: pre-install,pre-upgrade`, `helm.sh/hook-weight: "-10"` and `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded`, matching the migrate ServiceAccount. Hooks run before ordinary release resources, so on first install in a namespace that denies by default—and on upgrades while `<fullname>-deny-all` is in place—the hook policy gives the migrate Job DNS and database egress and is deleted once the hook succeeds. When `migration.enabled` is false, no migrate NetworkPolicy is rendered.
- **Cluster CNI requirement.** `NetworkPolicy` resources have no effect unless the target cluster's network plugin enforces them. K3s's embedded network policy controller (kube-router) enforces `NetworkPolicy` by default unless disabled (`--disable-network-policy`). Verify enforcement on the target cluster as part of qualification; setting `networkPolicy.enabled: false` disables all policy objects and waives the `networkPolicy.database.to` requirement.

## Private overlays

The chart ships no site values. Compose an install from the chart defaults plus one or more private overlays kept outside this public repository: an ignored `config/<site>.local.yaml` here, or a private configuration repository. Helm merges `-f` files left to right, so later files win. Lists such as `ingress.hosts` or `networkPolicy.database.to` are replaced, not merged.

[`examples/values-synthetic.yaml`](../../examples/values-synthetic.yaml) is a complete, clearly marked synthetic overlay that enables every I4 option. It uses the reserved `.example` domain, all-zero digests and placeholder Secret, ConfigMap and claim names. It renders, but cannot be installed. Copy it to a private location, replace every placeholder and review the render before any apply:

```sh
helm template openmettle charts/openmettle-core --namespace openmettle -f config/site.local.yaml > /tmp/openmettle.yaml
# review /tmp/openmettle.yaml, then (owner action) install with a timeout covering the migration:
helm upgrade --install openmettle charts/openmettle-core --namespace openmettle -f config/site.local.yaml --timeout 15m
```

The overlay references objects the chart never creates: the three database URL Secrets, the database CA ConfigMap, an existing artifact PVC (if used), the TLS Secret, the IngressClass and any Traefik Middleware. Create them in the release namespace first. OIDC and login settings are not accepted yet: they arrive in I5, after core V1-04 mounts its routes. The schema rejects an `oidc:` key.

## Database CA

`database.caBundle` mounts one key of an existing ConfigMap holding a PEM CA bundle. The chart never creates it:

```sh
kubectl --namespace openmettle create configmap openmettle-db-ca --from-file=ca.crt=<path to PEM bundle>
```

- **Mount.** When enabled, the api, worker and migrate pods each mount the key read-only at the fixed path `/etc/openmettle/db-ca/ca.crt` (volume `db-ca`, directory `/etc/openmettle/db-ca`). The key is projected under the fixed file name `ca.crt`, so it never becomes a path. The schema and a render guard also reject keys containing `/`, and the keys `.` and `..`.
- **No environment variable.** The chart sets no `PGSSLROOTCERT` or other `PG*` variable. Core ADR 0002 requires each process's environment to carry only its own `OPENMETTLE_<ROLE>_` prefix and forbids shared database defaults. SQLx reads TLS options from each URL instead. Reference the file in **every** URL Secret (api, worker and owner):

  `postgres://<role>:<password>@<host>:5432/openmettle?sslmode=verify-full&sslrootcert=/etc/openmettle/db-ca/ca.crt`

  `verify-full` checks the certificate chain and the host name. Without an explicit `sslmode`, SQLx uses `prefer`, which permits plaintext.
- **Missing ConfigMap.** The volume is not optional. If the ConfigMap or key is missing, pods stay in `ContainerCreating`, and the migration hook waits until the Helm timeout.
- **Rotation.** The kubelet refreshes ConfigMap volumes (not `subPath` mounts, which the chart does not use) after a delay. Whether SQLx reloads the file for new connections has not been verified. Restart the Deployments after changing the bundle.
- Not tested against a TLS-enabled PostgreSQL. The kind smoke fixture uses `sslmode=disable`.

## Artifact storage

`storage.artifacts` mounts one PersistentVolumeClaim read-write at `/var/lib/openmettle/artifacts` in the api and worker pods. The migration Job never mounts it. PostgreSQL stores artifact metadata and accounting (core ADR 0005); the volume is for payload bytes.

- **Core does not use the path yet.** Core has no artifact-directory setting today; filesystem storage is V1-15. Enabling the volume now only provisions and mounts it. The chart will pass the path once core defines a prefixed setting.
- **Exactly one source while enabled.** Set `existingClaim` to mount a PVC you manage, or `size` for a chart-owned PVC `<fullname>-artifacts`. Rendering fails if both or neither are set. `accessModes`, `storageClassName` and `annotations` describe the chart-owned PVC only. With `existingClaim`, a non-null `storageClassName` or non-empty `annotations` is rejected rather than ignored.
- **Access modes.** Both api and worker mount the claim, so only `ReadWriteOnce` and `ReadWriteMany` are accepted. `ReadWriteOnce` permits several pods on **one node** only: on a multi-node cluster, pods scheduled to another node stay `Pending`. Use `ReadWriteMany` (or co-locate with `nodeSelector`/`affinity`) for more than one node.
- **Ownership.** `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch` is added to the api and worker pods so that the non-root user can write a freshly provisioned volume. Whether a volume honours `fsGroup` depends on its CSI driver. `readOnlyRootFilesystem` and `runAsUser` stay unchanged.
- **Kept on uninstall.** The chart-owned PVC carries `helm.sh/resource-policy: keep`, which takes precedence over a user annotation with the same key. `helm uninstall` leaves it and its data in place. A later install with the same release name and `size` fails, because the PVC exists outside the release. Set `existingClaim: <fullname>-artifacts` to reuse it. Deleting the claim (and data) is a separate, deliberate owner action.
- **Backup and restore** are not provided by the chart (V1-30/V1-31). Not tested against any StorageClass.

## Ingress and TLS

`ingress.enabled` renders one `networking.k8s.io/v1` Ingress, `<fullname>-api`. It routes every path (`/`, `Prefix`) for each `ingress.hosts` entry to the API Service's `http` port, without rewriting. Rendering fails unless:

- `ingress.className` is set. Redaction and limits are controller-specific, so the controller must be explicit.
- `ingress.hosts` lists at least one lowercase DNS name with at least two labels. Wildcards, ports and IP addresses are rejected. Use a dedicated application hostname: core's host-only `__Host-` cookies are shared across all ports of a hostname (core ADR 0017).
- every host is covered by an `ingress.tls` entry, and every TLS host is routed. Each entry names an existing `kubernetes.io/tls` Secret, for example one issued by cert-manager. The chart routes HTTPS only and never creates Secrets.
- while `networkPolicy.enabled` is true, `networkPolicy.api.ingressFrom` is non-empty. Otherwise the controller could not reach the API.

**Why `networkPolicy.api.ingressFrom` must select only the ingress controller.** Every control below lives in the controller: TLS termination, body and header limits, and log redaction. The API serves unauthenticated `/healthz` and `/readyz`, and the staged login routes trust no forwarded header (core ADR 0018). Any other pod allowed to reach port 8080 would bypass all of these controls. List only the controller's pods (namespace and pod selectors), never a broad namespace or CIDR. Traffic from the controller to the API is plain HTTP inside the cluster, unless the CNI encrypts it.

### Mandatory before routing login traffic: no request targets, cookies or bodies in logs

Core ADRs 0017, 0019, 0022 and 0024 require that ingress and proxy telemetry never records:

- **request targets**: the path and query string. OIDC callbacks carry `code` and `state` in the query.
- **cookies**: the `__Host-openmettle-login` and `__Host-openmettle-session` credentials, and any `Cookie` or `Set-Cookie` header.
- **request bodies**: sign-in invitation codes travel in the form body of `POST` initiation (ADR 0022).

Core redacts its own process telemetry (ADR 0024), but the controller's access log, debug log and traces are outside core. The chart cannot configure them, because they are controller-wide static settings. They are mandatory deployment steps.

**Traefik (first target controller).** Traefik's access log does not record bodies. Its `RequestPath` field includes the query string, and request headers (including `Cookie`) are logged only if headers are kept. Configure static (install-time) options:

```text
--accesslog=true
--accesslog.format=json                       # field filtering below needs JSON; the CLF line carries the full request line
--accesslog.fields.defaultmode=keep
--accesslog.fields.names.RequestPath=drop     # path and query string (callback code and state)
--accesslog.fields.names.ClientUsername=drop
--accesslog.fields.headers.defaultmode=drop   # every request header, including Cookie and Authorization
--log.level=INFO                              # DEBUG may log request details
```

On K3s's bundled Traefik, pass them through a `HelmChartConfig` named `traefik` in `kube-system` (`spec.valuesContent` → `additionalArguments`). If your Traefik Helm values already configure `logs.access`, set the equivalent `logs.access.fields` values there instead of adding duplicate flags. If Traefik tracing or OpenTelemetry is enabled, do not list `Cookie`, `Set-Cookie` or `Authorization` in its captured headers. Also confirm that span URL attributes on your version do not carry query values; otherwise disable tracing. Do not add body-logging plugins or middlewares. Option names were checked against Traefik v3 documentation, not against a running Traefik. Verify them on your version.

**Body size, timeouts and TLS (Traefik).**

- **Body limit.** Core refuses initiation bodies over 256 bytes and every other login body that is not empty (ADR 0018). The ingress limit is defence in depth and must allow the routes you expose. A Traefik `Middleware` in the release namespace, created by the operator:

  ```yaml
  apiVersion: traefik.io/v1alpha1
  kind: Middleware
  metadata: {name: openmettle-request-limits, namespace: openmettle}
  spec:
    buffering:
      maxRequestBodyBytes: 65536   # synthetic value; size to the routes you mount
  ```

  Attach it with the annotation `traefik.ingress.kubernetes.io/router.middlewares: <namespace>-openmettle-request-limits@kubernetescrd`. Never attach `StripPrefix`, `ReplacePath` or `ReplacePathRegex`: the callback path must arrive exactly as the browser sent it (ADRs 0017 and 0018).
- **Timeouts and header limits** are entry-point settings, for example `entryPoints.websecure.transport.respondingTimeouts.readTimeout`. Core's router limits a request head after it is parsed. Slow or oversized heads and idle connections are the controller's job (ADR 0018).
- **TLS** terminates at Traefik. Annotate `traefik.ingress.kubernetes.io/router.entrypoints: websecure` and `traefik.ingress.kubernetes.io/router.tls: "true"`, and redirect the plain-HTTP entry point to HTTPS controller-wide.

**Acceptance check (owner action; not performed here).** After the route is live, send a request to `https://<host>/readyz?code=synthetic-code&state=synthetic-state` with a `Cookie: __Host-openmettle-session=synthetic-cookie` header. Then `POST` the body `invitation=synthetic-body`. Confirm that no controller log line or trace contains `synthetic-code`, `synthetic-state`, `synthetic-cookie` or `synthetic-body`. Record the result as qualification evidence.

## API PodDisruptionBudget

`api.podDisruptionBudget` renders a `policy/v1` PodDisruptionBudget `<fullname>-api` that selects only API pods. It is off by default so that a single-replica install never blocks a node drain. While enabled, rendering fails unless:

- exactly one of `minAvailable` and `maxUnavailable` is set. Each is a non-negative integer or a percentage string such as `"50%"`.
- `api.replicas` is at least 2.
- at least one voluntary eviction stays allowed. Kubernetes rounds percentages up, so `minAvailable: "51%"` on 2 replicas keeps both and is rejected, and `maxUnavailable: 0` or `"0%"` is rejected.

`unhealthyPodEvictionPolicy: AlwaysAllow` lets a drain evict API pods that are not Ready, so an unhealthy API never blocks maintenance. The budget counts current replicas only. Pair it with `api.affinity` (for example a preferred anti-affinity on `kubernetes.io/hostname`) to spread replicas across nodes. The worker has no PDB.

## Schema migration

Core runs migrations once per release, before new API and worker pods start (core ADR 0003). The chart does this with a Helm hook Job:

- `helm.sh/hook: pre-install,pre-upgrade`. Helm creates or updates the Deployments only after the Job succeeds. Hooks run before ordinary resources, so the migrate ServiceAccount and (when `networkPolicy.enabled` is true) the migrate egress NetworkPolicy are hooks too, at a lower weight (`-10`).
- `before-hook-creation,hook-succeeded` delete policy on all migration hooks. A successful run leaves nothing behind. When the Job fails, Helm 4.3 still deletes the hooks that completed before it and carry `hook-succeeded` (`pkg/action/hooks.go`). The migrate ServiceAccount and migrate NetworkPolicy are therefore removed, and only the failed Job and its pods stay for diagnosis. The next install or upgrade recreates them and replaces the Job.
- `restartPolicy: Never`, `backoffLimit: 2`, `activeDeadlineSeconds` from values. A `podFailurePolicy` fails the Job immediately on exit 78 (invalid configuration). Exit 1, for example a lock timeout, may retry.
- `activeDeadlineSeconds` must exceed `connectTimeoutMs + lockTimeoutMs + statementTimeoutMs`, or rendering fails. One attempt connects, waits for locks and then runs statements, so a smaller deadline would end a long statement before its configured timeout. This is a lower bound only: migrations with several long statements, and retries, need more.
- `migration.{nodeSelector,tolerations,affinity,podAnnotations}` schedule the hook pod independently of api and worker.
- **No rollback hook.** Migrations are forward-only, and `helm rollback` runs no migration. Only the migrator refuses a database at a newer schema version. The API and worker do not check the schema version; core ADR 0003 lists a schema-compatibility readiness gate as not yet covered. A rollback to the previous release therefore relies on ADR 0003's rule that each migration stays compatible with the previous release's API and worker. Nothing guarantees compatibility further back. Recovery from a bad release is a corrective forward release or a restore (V1-30/V1-31).

**Helm timeout.** Helm waits for each hook only for `--timeout`, which defaults to 300 s, while the Job deadline defaults to 900 s. Give `helm install` and `helm upgrade` a `--timeout` of at least `migration.activeDeadlineSeconds` (for the defaults, `--timeout 15m`). If Helm's timeout expires first, Helm marks the release failed and deletes the migrate ServiceAccount and (when `networkPolicy.enabled` is true) the migrate NetworkPolicy as described above, while the Job keeps running. Without its ServiceAccount the Job cannot create a retry pod, and under default-deny the running pod loses its chart egress allowance for any new DNS lookup or database connection (and depending on CNI conntrack behavior, in-flight traffic may be disrupted). Re-running the install or upgrade deletes and replaces the Job, which stops any pod still running. This is recoverable: each migration runs in one transaction, so an interrupted run leaves no partial migration, and the next run continues from the last committed version.

**Sidecar injection.** If a service mesh or another admission webhook injects a long-running sidecar into the hook pod, the pod does not finish when the migrate container exits. The Job then never completes and Helm waits until its timeout. Exclude the hook pod from injection, for example with `migration.podAnnotations` if your mesh supports an opt-out annotation. This has not been tested with any mesh.

`helm template` and `--dry-run` do not run hooks. `--no-hooks` skips the migration, and the new pods then start against the old schema.

**Out of band:** set `migration.enabled: false` to render no Job, no migrate ServiceAccount, no migrate NetworkPolicy and no owner-Secret reference. You must then run the migrate image once per release, with `OPENMETTLE_MIGRATE_DATABASE_URL` set to the owner URL, and let it complete successfully before upgrading API and worker. Database roles and the database itself are provisioned outside the chart (core ADR 0003 and README).

## Validation

```sh
bash tests/chart/render.sh                    # helm lint, render matrix, kubeconform
python3 -m unittest discover -s tests/chart -v  # policy, negative-case and contract tests
```

Tested on: Helm 4.3.0 and kubeconform 0.8.0, with Kubernetes 1.37.0 schemas (the kind node version pinned by core). These are test pins, not a compatibility claim; `render.sh` fails on any other Helm version. The chart sets no `kubeVersion` floor.

### Kind smoke test (I2/I3)

[`tests/kind/smoke.py`](../../tests/kind/README.md) installs the chart on an ephemeral kind cluster (Kubernetes 1.37.0, kind v0.33.0; core's pins). It uses core images built from the pinned core commit `5cd8a9d`, referenced by digest, and a synthetic PostgreSQL fixture. It checks these acceptance items against live state:

| Item | Smoke-tested |
| --- | --- |
| api, worker and migrate images install by digest | Yes (digest read back from the node's containerd) |
| Migration hook completes before the Deployments roll out | Yes (under namespace default-deny) |
| API and worker Ready; `/readyz` 200 | Yes |
| Worker scales to 2 while the API stays at 1 | Yes, through `worker.replicas` |
| No optional package present | Yes |
| Same-digest `helm upgrade` reruns migrate as a no-op and stays Ready | Yes |
| `helm uninstall` leaves no release objects | Yes (including release NetworkPolicies) |
| App namespace enforces Pod Security `restricted` | Yes |
| NetworkPolicy enforced under namespace default-deny | Yes (implemented in I3; hosted kind run pending CI) |
| I4 artifact volume, database CA, Ingress, PDB | No. Off in the smoke run; render tests and kubeconform only |
| Registry pulls, TLS to PostgreSQL, ingress controller, multi-node | No (owner's qualification) |

The workflow ([`kind-smoke.yml`](../../.github/workflows/kind-smoke.yml)) runs on pull requests and pushes to `main` that touch the chart or the harness, and on manual dispatch. The I2 checks passed on [pull-request run 44505148955](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44505148955) (5 min 15 s), which tested the merge of `b8f2d79` into `main`; the workflow has not yet run on `main`, and the I3 NetworkPolicy checks have not yet run on a hosted kind cluster until pushed to CI (see [`tests/kind`](../../tests/kind/README.md)). The tests check chart defaults against a byte-verified copy of core's `runtime/process-contract.json` (`tests/fixtures/core-5cd8a9d/`). The chart's default ServiceAccount names (`<fullname>-api`) differ from the contract's example names (`openmettle-api`); set `serviceAccount.name` to use those.

## Pending

- **I2/I3:** hosted `kind-smoke` verification of I3 NetworkPolicy enforcement (including whether kind v0.33 kindnet enforces policies live) on pull-request CI and `main`, and owner acceptance.
- **I4 (render contract delivered):** live verification of the artifact volume (StorageClass binding, `fsGroup`), the database CA against TLS-enabled PostgreSQL, the API PDB during a drain, and the Ingress behind Traefik, including the access-log [acceptance check](#ingress-and-tls). None has run on a cluster.
- **I5 / V1-04:** OIDC and auth settings, login key mounts, a `--check-auth-config` hook and identity-provider egress. No auth values are accepted yet.
- **V1-20** (managed inference, accelerated tools) and **V1-06** (external providers or gateway): separate charts and releases, never subcharts of core.
- Qualification on the owner's cluster is an owner action.
