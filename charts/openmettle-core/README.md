# openmettle-core chart

CPU-only packaging for the OpenMettle core API, worker and schema migration. Increment I1 of V1-32 is the **render contract**: templates, the values schema, security defaults and render-time tests. I2 adds a **kind install smoke test** ([`tests/kind`](../../tests/kind/README.md)). I3 adds **NetworkPolicies** (chart-scoped deny-all plus per-component allows) and live enforcement probes in the kind smoke test; the hosted kind run for I3 is pending pull-request CI execution. I4 adds optional, off-by-default **artifact storage, a database CA mount, an Ingress with TLS and an API PodDisruptionBudget**, plus a [synthetic example overlay](../../examples/values-synthetic.yaml). I5 adds optional, off-by-default **browser sign-in / OIDC mounts and API-only OIDC provider egress** (core ADR 0025). The I4 and I5 options are render-tested and kubeconform-validated only; none has been installed on a cluster. Neither a render nor a smoke run is application acceptance or qualification.

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
| NetworkPolicy | `<fullname>-api`, `<fullname>-worker` | DNS and database egress; API-only ingress on TCP 8080 from `networkPolicy.api.ingressFrom` and, when `auth.enabled` is true, API-only OIDC egress from `networkPolicy.api.oidc` |
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
- `database.issuance.existingSecret` while `auth.enabled` is true: the session issuance URL (see [Database roles and Secrets](#database-roles-and-secrets)). It must stay empty while `auth.enabled` is false.
- `networkPolicy.database.to`: at least one Kubernetes `NetworkPolicyPeer` for PostgreSQL while `networkPolicy.enabled` is true. An empty list is rejected at render time because Kubernetes treats an empty `to` list as allowing every destination.

| Key | Default | Meaning |
| --- | --- | --- |
| `images.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `images.pullSecrets` | `[]` | Names of existing pull Secrets |
| `images.<component>.{registry,repository,digest}` | `""` | See above |
| `database.<component>.{existingSecret,key}` | `""`, `url` | See above |
| `database.issuance.{existingSecret,key}` | `""`, `url` | Required while `auth.enabled` is true and refused while it is false: an `openmettle_issuance` login URL, rendered as `OPENMETTLE_API_ISSUANCE_DATABASE_URL` on the API container only. Rendering fails if it names the same Secret and key as `database.api`, `database.worker` or `database.migrate` |
| `database.connectionBudget` | `null` | Optional; see [Connection budget](#connection-budget) |
| `api.replicas`, `worker.replicas` | `1` | Independent |
| `api.resources`, `worker.resources` | requests `100m` CPU, `64Mi` | Core's contract examples, not qualified sizing. Only `cpu`, `memory` and `ephemeral-storage` are accepted. |
| `<component>.serviceAccount.{create,name,annotations}` | `true`, `""`, `{}` | `name` is required when `create` is false. Rendering fails if two components (including the migration, when enabled) resolve to the same name, or if any name is `default` |
| `<component>.settings.dbMaxConnections` | `4` | `OPENMETTLE_<ROLE>_DB_MAX_CONNECTIONS`, 1–64 |
| `<component>.settings.dbTimeoutMs` | `2000` | `OPENMETTLE_<ROLE>_DB_TIMEOUT_MS`, 1–30000 |
| `<component>.settings.shutdownTimeoutMs` | `5000` | `OPENMETTLE_<ROLE>_SHUTDOWN_TIMEOUT_MS`, 1–60000 |
| `api.settings.issuanceDbMaxConnections` | `2` | `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS`, 1–64; rendered only while `auth.enabled` is true. The worker has no such setting |
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
| `networkPolicy.api.oidc.to` | `[]` | Required while `auth.enabled` and `networkPolicy.enabled` are both true (must be empty while `auth.enabled` is false): API-only OIDC provider egress peers |
| `networkPolicy.api.oidc.port` | `443` | TCP port for API OIDC provider egress, 1–65535 (for example `8443` for self-hosted Keycloak) |
| `networkPolicy.dns.to` | `kube-system` / `k8s-app: kube-dns` | `NetworkPolicyPeer` list for UDP and TCP 53 egress. Must be non-empty while enabled |
| `networkPolicy.database.to` | `[]` | Required while enabled: `NetworkPolicyPeer` list for PostgreSQL egress on `networkPolicy.database.port` |
| `networkPolicy.database.port` | `5432` | TCP port for database egress, 1–65535 |
| `networkPolicy.telemetry.otlp.to` | `[]` | Required while `telemetry.otlp.enabled` and `networkPolicy.enabled` are both true (must be empty while `telemetry.otlp.enabled` is false): OTLP collector egress peers for `api` and `worker` only (never `migrate`) |
| `networkPolicy.telemetry.otlp.port` | `4318` | TCP port for OTLP collector egress, 1–65535 |
| `database.caBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Mount one key of an existing ConfigMap at `/etc/openmettle/db-ca/ca.crt`; see [Database CA](#database-ca) |
| `storage.artifacts.enabled` | `false` | Mount an artifact volume in api and worker and set their `ARTIFACTS_DIR`; see [Artifact storage](#artifact-storage) |
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
| `auth.enabled` | `false` | Enable browser and optional native sign-in / OIDC plus authenticated `/v1/*` routes for the API only; see [Browser sign-in / OIDC](#browser-sign-in--oidc) |
| `auth.configMapName` | `""` | Required while enabled: existing ConfigMap holding a version-2 auth settings document |
| `auth.configKey` | `auth.json` | ConfigMap key projected read-only at `/etc/openmettle/auth/auth.json` |
| `auth.loginKeysSecretName` | `""` | Required while enabled: existing Secret holding raw 32-byte login key files, mounted read-only at `/etc/openmettle/auth-keys` |
| `auth.providerCaBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Optional existing ConfigMap key mounted read-only at `/etc/openmettle/auth-ca/ca.crt` in the API pod only |
| `telemetry.logging.{format,level}` | `null`, `null` | Optional `OPENMETTLE_<ROLE>_LOG_FORMAT` (`json` or `text`) and `OPENMETTLE_<ROLE>_LOG_LEVEL` (`error`, `warn`, `info` or `debug`; `trace` refused) across `api`, `worker` and `migrate`; `null` emits no `LOG_*` env vars |
| `telemetry.otlp.enabled` | `false` | Enable OTLP/HTTP protobuf trace and/or metrics export for `api` and `worker` only (never `migrate`); see [OTLP trace and metrics export](#otlp-trace-and-metrics-export-telemetryotlp-api-and-worker-only) |
| `telemetry.otlp.tracesEndpoint` | `""` | Optional canonical `https://` URL with a lowercase DNS host (`OPENMETTLE_{API,WORKER}_OTLP_TRACES_ENDPOINT`); at least one of `tracesEndpoint` or `metricsEndpoint` is required while enabled, and both must be `""` while false |
| `telemetry.otlp.metricsEndpoint` | `""` | Optional canonical `https://` URL with a lowercase DNS host (`OPENMETTLE_{API,WORKER}_OTLP_METRICS_ENDPOINT`, core ADR 0028); at least one of `tracesEndpoint` or `metricsEndpoint` is required while enabled, and both must be `""` while false |
| `telemetry.otlp.privateRanges` | `[]` | Up to 32 unique private CIDRs (RFC 1918, CGNAT or ULA) joined with commas into `OPENMETTLE_{API,WORKER}_OTLP_PRIVATE_RANGES` when non-empty; must be empty while disabled |
| `telemetry.otlp.caBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Optional existing ConfigMap key mounted read-only at `/etc/openmettle/otlp-ca/ca.crt` in `api` and `worker` pods only (`OPENMETTLE_{API,WORKER}_OTLP_CA_FILE`); must be disabled while `telemetry.otlp.enabled` is false |

`<component>` is `api` or `worker`; `<ROLE>` is `API` or `WORKER` (plus `MIGRATE` for `telemetry.logging`).

Every process gets an explicit environment: `BIND` (`0.0.0.0:8080` or `0.0.0.0:8081`; core otherwise binds loopback), `DATABASE_URL` from its own Secret through `secretKeyRef`, the settings above, optional `LOG_FORMAT`/`LOG_LEVEL` across all three roles when non-null, optional `OTLP_TRACES_ENDPOINT`/`OTLP_METRICS_ENDPOINT`/`OTLP_CA_FILE`/`OTLP_PRIVATE_RANGES` on `api` and `worker` when `telemetry.otlp.enabled` is true, `ARTIFACTS_DIR=/var/lib/openmettle/artifacts` on `api` and `worker` when `storage.artifacts.enabled` is true, and—when `auth.enabled` is true on the API only—`OPENMETTLE_API_AUTH_CONFIG=/etc/openmettle/auth/auth.json`, `OPENMETTLE_API_ISSUANCE_DATABASE_URL` from `database.issuance` through `secretKeyRef` and `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS`. Neither issuance variable is ever rendered without `auth.enabled`, or on the worker or the migrate Job: core exits 78 in each of those cases. The chart never uses `envFrom`. Each variable carries its own component prefix, as core ADR 0002 requires. Set `sslmode` explicitly in every URL, because SQLx defaults to `prefer`, which permits plaintext fallback. Readiness `timeoutSeconds` is `ceil(dbTimeoutMs / 1000) + 1`, because `/readyz` waits up to the database timeout.

Keep site values in a private overlay outside this repository and pass it with `-f`; see [Private overlays](#private-overlays). The synthetic files under `tests/chart/values/` use reserved `example.test` names and all-zero digests; they render but cannot be installed.

### Connection budget

Core ADR 0003 bounds PostgreSQL connections at the server. When `database.connectionBudget` is set, rendering fails unless

`(api.replicas + api.maxSurge) × (api.dbMaxConnections + api.issuanceDbMaxConnections) + (worker.replicas + worker.maxSurge) × worker.dbMaxConnections + 1 (migrator) ≤ connectionBudget`,

where `api.issuanceDbMaxConnections` counts only while `auth.enabled` is true, because each API pod then opens a second, lazy issuance pool (core ADR 0030). For example, with sign-in enabled, 2 API and 2 worker replicas and the default pool sizes, core's README budgets 2 × (4 + 2) + 2 × 4 + 1 + 3 headroom = 24 connections; the chart's check additionally counts each component's `maxSurge` replicas.

Set it to the connections available to this release, after subtracting reserved and administrative or backup headroom. The check covers configured pools only. It also excludes Terminating pods: during a rollout, a replaced pod keeps its pool open while it drains, for up to `terminationGracePeriodSeconds`, so the actual peak can briefly exceed the computed one. Leave headroom for that. Enforce each role's share in PostgreSQL with `CONNECTION LIMIT`; the chart does not manage roles.

### Database roles and Secrets

Provision the PostgreSQL roles and the database outside the chart before the first migration, as core's README ("Schema migrations") describes. Core migration 18 refuses to run, and rolls back, while `openmettle_issuance` is missing, so existing installations must create it before upgrading to a core release that includes it (core ADR 0030):

| Login role | Secret value | Mounted into |
| --- | --- | --- |
| `openmettle_owner` | `database.migrate` | migrate Job only |
| `openmettle_api` | `database.api` | `api` |
| `openmettle_issuance` | `database.issuance` | `api` only, and only while `auth.enabled` is true |
| `openmettle_worker` | `database.worker` | `worker` |

Each Secret must carry a different login: core's boundary audit refuses a login role that reaches more than one of `openmettle_api`, `openmettle_issuance` and `openmettle_worker`, and the API refuses an issuance URL whose user equals its primary URL's user. The chart can only compare Secret names and keys, so it rejects the obvious reuse and leaves the login check to core. Where `openmettle_api` SQL may have been exposed before the upgrade, revoke pre-upgrade sessions after migration 18 as core ADR 0030 ("Upgrade") describes; the chart does not do this.

## Security defaults

These are fixed and are not values:

- Pod: `runAsNonRoot`, `runAsUser`/`runAsGroup` 65532 (the core image user), seccomp `RuntimeDefault`. `fsGroup: 65532` is added to api and worker pods when mounting the artifact volume (with `fsGroupChangePolicy: OnRootMismatch`) and to the api pod when `auth.enabled` is true (so mode `0440` login key Secret files are readable by GID `65532` without world-read permission).
- Container: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, `privileged: false`. By default no volumes are mounted. The only optional volumes are the artifact claim (read-write, api and worker), the database CA ConfigMap (read-only, every component), browser sign-in config, login keys and optional provider CA (read-only, api only), and the optional OTLP collector CA ConfigMap (read-only, api and worker only). The root filesystem stays read-only either way.
- `automountServiceAccountToken: false` on every ServiceAccount and every pod, plus `enableServiceLinks: false`. The processes never call the Kubernetes API, so the chart creates no RBAC.
- Credentials come only from existing Secrets. The owner credential reaches only the migration Job, and the session issuance credential only the API container while `auth.enabled` is true. The chart never uses `lookup`.
- `/healthz` and `/readyz` are unauthenticated. The Service is ClusterIP only, `networkPolicy.api.ingressFrom` defaults to empty, and the Ingress is off by default.

## NetworkPolicy

`networkPolicy.enabled` defaults to `true`. When enabled, the chart renders a chart-scoped deny-all plus per-component allow policies:

- **`<fullname>-deny-all`** selects every pod of this release (`app.kubernetes.io/name` and `app.kubernetes.io/instance`) with `policyTypes: [Ingress, Egress]` and no rules.
- **`<fullname>-api`**, **`<fullname>-worker`** and **`<fullname>-migrate`** each select only their own component and declare `policyTypes: [Ingress, Egress]`:
  - **Egress** is restricted to `networkPolicy.dns.to` on UDP and TCP 53 and `networkPolicy.database.to` on TCP `networkPolicy.database.port` (default `5432`), plus—on `<fullname>-api` only when `auth.enabled` is true—`networkPolicy.api.oidc.to` on TCP `networkPolicy.api.oidc.port` (default `443`), and—on `<fullname>-api` and `<fullname>-worker` only (never `<fullname>-migrate`) when `telemetry.otlp.enabled` is true—`networkPolicy.telemetry.otlp.to` on TCP `networkPolicy.telemetry.otlp.port` (default `4318`). Rendering fails if `dns.to` or `database.to` is empty while `networkPolicy.enabled` is true, if `networkPolicy.api.oidc.to` is empty while both `auth.enabled` and `networkPolicy.enabled` are true, if `networkPolicy.api.oidc.to` is non-empty while `auth.enabled` is false, if `networkPolicy.telemetry.otlp.to` is empty while both `telemetry.otlp.enabled` and `networkPolicy.enabled` are true, or if `networkPolicy.telemetry.otlp.to` is non-empty while `telemetry.otlp.enabled` is false. Worker and migrate policies never render OIDC egress, and migrate never renders OTLP egress.
  - The default `networkPolicy.dns.to` selects pods labelled `k8s-app: kube-dns` in the `kube-system` namespace, matching kubeadm (including kind) and K3s CoreDNS. Override it where cluster DNS uses different labels, namespace or IP blocks.
  - **Ingress** is allowed only on the API pod's container port (TCP `8080`) from `networkPolicy.api.ingressFrom`. It defaults to `[]` (no ingress rule rendered, so all pod-to-pod ingress is denied). Kubelet liveness/readiness probes and `kubectl port-forward` originate from the node or inside the pod's network namespace rather than from another pod peer, so they are unaffected. Worker and migrate pods never render an ingress rule.
- **Migrate hook policy.** `<fullname>-migrate` carries `helm.sh/hook: pre-install,pre-upgrade`, `helm.sh/hook-weight: "-10"` and `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded`, matching the migrate ServiceAccount. Hooks run before ordinary release resources, so on first install in a namespace that denies by default—and on upgrades while `<fullname>-deny-all` is in place—the hook policy gives the migrate Job DNS and database egress and is deleted once the hook succeeds. When `migration.enabled` is false, no migrate NetworkPolicy is rendered.
- **Cluster CNI requirement.** `NetworkPolicy` resources have no effect unless the target cluster's network plugin enforces them. K3s's embedded network policy controller (kube-router) enforces `NetworkPolicy` by default unless disabled (`--disable-network-policy`). Verify enforcement on the target cluster as part of qualification; setting `networkPolicy.enabled: false` disables all policy objects and waives the `networkPolicy.database.to` requirement.

## Private overlays

The chart ships no site values. Compose an install from the chart defaults plus one or more private overlays kept outside this public repository: an ignored `config/<site>.local.yaml` here, or a private configuration repository. Helm merges `-f` files left to right, so later files win. Lists such as `ingress.hosts` or `networkPolicy.database.to` are replaced, not merged.

Two clearly marked synthetic overlays live under `examples/` (both use reserved `.example`/`.example.test` domains, all-zero digests, RFC 5737 TEST-NET egress peers, an illustrative RFC 1918 `telemetry.otlp.privateRanges` CIDR and placeholder Secret, ConfigMap and claim names; both render and pass `kubeconform`, and neither can be installed as-is):

- [`examples/values-synthetic.yaml`](../../examples/values-synthetic.yaml) — multi-replica overlay enabling every I4, I5 and I6 option (2 API replicas, API PDB, PVC, db CA, Ingress/TLS, OIDC and OTLP).
- [`examples/values-workstation-profile.yaml`](../../examples/values-workstation-profile.yaml) — single-node private workstation profile (1 API replica, 1 worker replica, explicit per-component CPU/memory bounds, API PDB disabled so single-node drains are not blocked, `ReadWriteOnce` artifact PVC and explicit Ingress/PostgreSQL/OIDC/OTLP NetworkPolicy boundaries).

Copy either example to a private location (or layer your gitignored `config/<site>.local.yaml` on top of the workstation profile so machine-specific digests, hosts, CIDRs, Secrets and StorageClass names stay out of source control) and review the render before any apply:

```sh
helm template openmettle charts/openmettle-core --namespace openmettle \
  -f examples/values-workstation-profile.yaml -f config/site.local.yaml > /tmp/openmettle.yaml
# review /tmp/openmettle.yaml, then (owner action) install with a timeout covering the migration:
helm upgrade --install openmettle charts/openmettle-core --namespace openmettle \
  -f examples/values-workstation-profile.yaml -f config/site.local.yaml --timeout 15m
```

The overlay references objects the chart never creates: the three database URL Secrets (four, with the issuance Secret, when `auth.enabled` is true), the database CA ConfigMap, an existing artifact PVC (if used), the TLS Secret, the IngressClass, any Traefik Middleware, and (when `auth.enabled` is true) the auth settings ConfigMap, login-keys Secret and optional provider CA ConfigMap. Create them in the release namespace first. Configure browser sign-in under `auth:` and `networkPolicy.api.oidc:`; the schema still rejects an unknown top-level `oidc:` key.

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

- **Core uses the path (core ADR 0031, minimum `openmettle-core` commit `94d21f8`).** While enabled, the chart sets `OPENMETTLE_API_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` to `/var/lib/openmettle/artifacts`; the migration Job receives neither. At startup, before telemetry or the listener, each process requires the mount to be an existing directory (not a symbolic link), creates `staging/` and `revisions/` (mode `0700`) if absent, checks both are readable directories and `fsync`s the root. Otherwise it exits `78` with `configuration error: invalid ARTIFACTS_DIR`, so an unwritable volume shows as a crash-looping pod, never a Ready one. While disabled, neither variable is set and core opens no directory. Core `94d21f8` contains the storage engine only; the `/v1` upload and download routes arrive in V1-15 PR2, so nothing writes payloads through the API yet.
- **Exactly one source while enabled.** Set `existingClaim` to mount a PVC you manage, or `size` for a chart-owned PVC `<fullname>-artifacts`. Rendering fails if both or neither are set. `accessModes`, `storageClassName` and `annotations` describe the chart-owned PVC only. With `existingClaim`, a non-null `storageClassName` or non-empty `annotations` is rejected rather than ignored.
- **Access modes and storage concurrency limits.** Both api and worker mount the claim, so only `ReadWriteOnce` and `ReadWriteMany` are accepted:
  - **`ReadWriteOnce` (single-node / workstation profile):** attaches at node level and permits multiple pods (`api` + `worker`) only on **one node**, which ADR 0031 requires: every api and worker pod must run on the node that mounts the volume, because exclusive creation, `rename` and `fsync` are local-filesystem guarantees. On a multi-node cluster, pods scheduled to another node stay `Pending` unless co-located via `nodeSelector`/`affinity`. Even at `replicas: 1`, the default rolling update (`maxSurge: 1`, `maxUnavailable: 0`) briefly starts a second pod during rollout; to avoid surge pods (and keep the database connection-budget peak flat) on a constrained workstation, set `api.strategy: {maxSurge: 0, maxUnavailable: 1}` and `worker.strategy: {maxSurge: 0, maxUnavailable: 1}` in your private overlay.
  - **`ReadWriteMany` (multi-node scaling):** required when `api` and `worker` pods span multiple nodes. ADR 0031 also requires every writer to see one directory with POSIX `rename`, `O_EXCL` creation and `fsync` semantics, which many network filesystems weaken. Neither the chart nor core qualifies any `ReadWriteMany` storage class; qualify yours before relying on it. Application-level artifact coordination and quota accounting still live in PostgreSQL (core ADR 0005), not filesystem locks; see [Connection budget](#connection-budget) when raising `api.replicas` or `worker.replicas`.
- **Ownership.** `fsGroup: 65532` with `fsGroupChangePolicy: OnRootMismatch` is added to the api and worker pods so that the non-root user can write a freshly provisioned volume. Whether a volume honours `fsGroup` depends on its CSI driver. `readOnlyRootFilesystem` and `runAsUser` stay unchanged.
- **Kept on uninstall.** The chart-owned PVC carries `helm.sh/resource-policy: keep`, which takes precedence over a user annotation with the same key. `helm uninstall` leaves it and its data in place. A later install with the same release name and `size` fails, because the PVC exists outside the release. Set `existingClaim: <fullname>-artifacts` to reuse it. Deleting the claim (and data) is a separate, deliberate owner action.
- **Encryption and backup.** OpenMettle does not encrypt payloads at rest; use volume encryption. Backups must capture PostgreSQL and the volume consistently (ADR 0031); the chart provides neither (V1-30/V1-31). Only kind's single-node `local-path` StorageClass is exercised, by the kind smoke test.

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

- **Body limit.** Core refuses browser initiation bodies over 256 bytes, native token/logout form bodies over their fixed bounds, and `/v1/*` JSON request bodies over 64 KiB (`65536` bytes; core ADRs 0018, 0027 and 0029). The ingress limit is defence in depth and must allow the routes you expose. A Traefik `Middleware` in the release namespace, created by the operator:

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

## Browser sign-in / OIDC

`auth` exposes core ADRs 0025, 0027 and 0029's opt-in sign-in and authenticated `/v1/*` runtime mounting for `openmettle-api`. It is **off by default** (`auth.enabled: false`): when disabled, `OPENMETTLE_API_AUTH_CONFIG` is unset, no auth volumes or OIDC egress rules are rendered, and the API serves `/healthz` and `/readyz` only (`404` on every sign-in and `/v1/*` path).

### Mount paths and permissions (API only)

The chart never creates ConfigMaps or Secrets. Every file comes from a pre-existing object in the release namespace and is mounted read-only into the `api` container only, without `subPath` (preserving atomic kubelet directory projection):

| Source value | Volume | In-pod path | Mode / notes |
| --- | --- | --- | --- |
| `auth.configMapName` + `auth.configKey` (default `auth.json`) | `auth-config` | `/etc/openmettle/auth/auth.json` (dir `/etc/openmettle/auth`) | Projected via `items` as `auth.json`; sets `OPENMETTLE_API_AUTH_CONFIG=/etc/openmettle/auth/auth.json` |
| `auth.loginKeysSecretName` | `auth-login-keys` | `/etc/openmettle/auth-keys/<file>` (dir `/etc/openmettle/auth-keys`) | `defaultMode: 288` (`0440` octal) with API pod `fsGroup: 65532`: readable by UID/GID `65532`, never world-readable |
| `auth.providerCaBundle.{configMapName,key}` (optional, default `ca.crt`) | `auth-provider-ca` | `/etc/openmettle/auth-ca/ca.crt` (dir `/etc/openmettle/auth-ca`) | Projected via `items` as `ca.crt`; reference in `providers[].trust` as `{"roots": "bundle", "bundle_path": "/etc/openmettle/auth-ca/ca.crt"}` |

- **Non-overlapping sibling directories.** The three mounts sit side by side under `/etc/openmettle/` (`/etc/openmettle/auth`, `/etc/openmettle/auth-keys`, `/etc/openmettle/auth-ca`, alongside `/etc/openmettle/db-ca`). Kubernetes mounts ConfigMap volumes read-only, so nesting another volume inside `/etc/openmettle/auth` (such as `/etc/openmettle/auth/keys`) would fail container startup with `EROFS` when the runtime attempts to create the nested mountpoint. The `/etc/openmettle/auth-keys/<file>` path also matches core ADR 0015's document example.
- **Why `worker` and `migrate` never mount auth or receive OIDC egress.** Core ADRs 0025, 0027 and 0029 restrict `OPENMETTLE_API_AUTH_CONFIG` to `openmettle-api`. Neither `openmettle-worker` nor `openmettle-migrate` serves sign-in or `/v1/*` routes, reads login keys or contacts an identity provider. Keeping the ConfigMap, login-keys Secret, provider CA and `networkPolicy.api.oidc` egress rule strictly on the API pod preserves least privilege so a worker or migration job never has access to login-key material or provider reachability.
- **Session issuance credential (core ADR 0030).** Sign-in completion issues sessions on a second database pool as `openmettle_issuance`, so `auth.enabled: true` also requires `database.issuance.existingSecret` and renders `OPENMETTLE_API_ISSUANCE_DATABASE_URL` and `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS` on the API container. Both pools reach the same PostgreSQL peers, so `networkPolicy.database` needs no change. Core images before `2c62e8a` (migration 18) do not read either variable, so use matching images. See [Database roles and Secrets](#database-roles-and-secrets).
- **Strict guards.** When `auth.enabled` is true, `auth.configMapName`, `auth.loginKeysSecretName` and `database.issuance.existingSecret` are required, and while `networkPolicy.enabled` is true `networkPolicy.api.oidc.to` must list at least one OIDC provider peer (on TCP `networkPolicy.api.oidc.port`, default `443`, configurable `1`–`65535` for self-hosted providers such as Keycloak on `8443`). When `auth.enabled` is false, `auth.providerCaBundle.enabled: true`, non-empty `networkPolicy.api.oidc.to` and a non-empty `database.issuance.existingSecret` are all rejected so unused CA mounts, egress rules or credentials are never silently left behind.

### Offline validation, rollout and prerequisites

- **Check the mounted files before rollout.** Run core's offline validator inside the exact API image (with the same mounts and environment) before rolling out (core ADRs 0015 and 0020):

  ```sh
  openmettle-api --check-auth-config /etc/openmettle/auth/auth.json
  ```

  Note that `--check-auth-config` accepts **both** version-1 and version-2 documents (because it validates files offline), whereas serving through `OPENMETTLE_API_AUTH_CONFIG` **requires a version-2 document** containing the `browser` profile and exits `78` on a version-1 document (core ADR 0025). The chart does not add a pre-upgrade `--check-auth-config` hook in I5; an invalid mounted document fails API startup with exit `78` before the listener binds.
- **No live reload.** Core reads the auth document, login keys and CA bundle once at startup (core ADR 0025). After updating the ConfigMap, Secret or provider CA bundle, restart the API Deployment (`kubectl rollout restart deployment/<fullname>-api`). For login-key rotation, follow core ADR 0015's staged procedure: add the new 32-byte key to `decrypt_only` and roll out; promote it to `active` and roll out; remove the retired key after the maximum login lifetime plus rollout overlap.
- **Database prerequisites.** Passing `--check-auth-config` validates local files only and makes no database or provider request. Before sign-in requests can succeed, provision the durable provider authority and active revision (core ADR 0012), configure the login admission limit (core ADR 0014; an unset limit refuses every initiation), and create home invitations where required (core ADR 0022).
- **Mandatory exposure gates.** Enabling `auth.enabled: true` mounts sign-in routes on the API container port, but does not by itself satisfy core ADR 0025's exposure gates. Before routing external traffic to sign-in, complete the TLS, path-preservation, body-limit and verified Ingress/Traefik access-log redaction steps in [Ingress and TLS](#ingress-and-tls).
- **Optional native sign-in and `/v1/*` application routes.** When `OPENMETTLE_API_AUTH_CONFIG` is set to a version-2 document (minimum `openmettle-core` commit `adef30a`), `openmettle-api` mounts browser sign-in (core ADR 0025), the 15 authenticated `/v1/*` application operations over browser cookies with `Origin` CSRF binding (core ADR 0027), and—when the optional `"native"` profile is present in the document—the five `/auth/native/{authorize,callback,token,session,logout}` routes plus native bearer-token authentication on `/v1/*` (core ADR 0029). Sign-in routes, provider/native callbacks and same-origin app links cannot use `/healthz`, `/readyz`, `/v1` or `/v1/*`.

## Telemetry / OTLP trace and metrics export

`telemetry` exposes core ADR 0024's structured stderr logging settings across all three roles (minimum `openmettle-core` commit `13c5227`) and core ADRs 0026 and 0028's opt-in OTLP/HTTP protobuf trace and metrics export for `openmettle-api` and `openmettle-worker` (minimum `openmettle-core` commits `ac047ec` for traces and `67f4fc2` for metrics); all are satisfied by the chart's pinned core commit `94d21f8`. Both leave default renders completely unchanged (`telemetry.logging.{format,level}: null` and `telemetry.otlp.enabled: false`).

### Structured logging (`telemetry.logging`, all roles)

- When `telemetry.logging.format` is set (`"json"` or `"text"`), the chart emits `OPENMETTLE_API_LOG_FORMAT`, `OPENMETTLE_WORKER_LOG_FORMAT` and `OPENMETTLE_MIGRATE_LOG_FORMAT`. When `null`, no `LOG_FORMAT` variable is emitted and core defaults to `json`.
- When `telemetry.logging.level` is set (`"error"`, `"warn"`, `"info"` or `"debug"`), the chart emits `OPENMETTLE_API_LOG_LEVEL`, `OPENMETTLE_WORKER_LOG_LEVEL` and `OPENMETTLE_MIGRATE_LOG_LEVEL`. `"trace"` is intentionally refused (core ADR 0024). When `null`, no `LOG_LEVEL` variable is emitted and core defaults to `info`.
- Structured logs are written to stderr for node-level collection and are never exported over OTLP.

### OTLP trace and metrics export (`telemetry.otlp`, `api` and `worker` only)

- **Off by default.** While `telemetry.otlp.enabled` is `false`, no `OTLP_*` variables, CA bundle mounts or collector egress rules are rendered. Leftover `tracesEndpoint`, `metricsEndpoint`, non-empty `privateRanges`, `caBundle.enabled: true` and non-empty `networkPolicy.telemetry.otlp.to` are all refused while `telemetry.otlp.enabled` is `false`, matching core ADRs 0026 and 0028 that a set key is never silently ignored.
- **Traces, metrics or both over HTTPS.** While `telemetry.otlp.enabled` is `true`, set `tracesEndpoint`, `metricsEndpoint` or both (rendering fails if both are empty; only non-empty endpoints emit `OPENMETTLE_{API,WORKER}_OTLP_{TRACES,METRICS}_ENDPOINT`). Each non-empty endpoint must be a canonical `https://` URL with a lowercase DNS host (at least two labels; final label neither all-digits nor `0x`/`0X`-hex per WHATWG URL rules, no `http://`, no IP literal, no credentials, no query, fragment, percent-encoding, dot-segments or explicit `:443`). Core sends OTLP/HTTP protobuf (`application/x-protobuf`) over its bounded HTTP/1.1 transport with no proxy, redirect, retry or collector authentication header, sharing one random per-process UUIDv4 `service.instance.id` across trace and metric exports (core ADR 0028).
- **In-cluster collectors and `privateRanges`.** Core refuses private IP answers by default (core ADR 0010). Helm and the values schema check CIDR syntax, uniqueness and count (`<= 32`), while `openmettle-core` enforces canonical host-bit masking and RFC 1918 / CGNAT / ULA private-range membership fail-closed at startup (exit `78`). For an in-cluster collector such as Grafana Alloy on TCP `4318`, `telemetry.otlp.privateRanges` (emitted comma-joined as `OPENMETTLE_{API,WORKER}_OTLP_PRIVATE_RANGES`) must cover the address DNS resolves to (typically the Service ClusterIP CIDR), while `networkPolicy.telemetry.otlp.to` and `networkPolicy.telemetry.otlp.port` (default `4318`) are evaluated post-DNAT against the collector pods and their target port. `networkPolicy.telemetry.otlp.{to,port}` is shared across traces and metrics: when `networkPolicy.enabled` is `true` and both `tracesEndpoint` and `metricsEndpoint` are set, both endpoints must be reachable through that single `to`/`port` rule (pointing one signal at a different collector or port will be blocked by default-deny egress and logged at runtime as `telemetry.dropped`).
- **Optional CA bundle at sibling path `/etc/openmettle/otlp-ca/ca.crt`.** When `telemetry.otlp.caBundle.enabled` is `true`, the chart mounts one key of a pre-existing ConfigMap read-only at `/etc/openmettle/otlp-ca` (volume `otlp-ca`, projected via `items` as `ca.crt`, no `subPath`) in `api` and `worker` pods only, and sets `OPENMETTLE_{API,WORKER}_OTLP_CA_FILE=/etc/openmettle/otlp-ca/ca.crt`. Sitting at `/etc/openmettle/otlp-ca` keeps it a non-overlapping sibling of `/etc/openmettle/db-ca`, `/etc/openmettle/auth`, `/etc/openmettle/auth-keys` and `/etc/openmettle/auth-ca`. The chart never creates ConfigMaps or Secrets.
- **Why `migrate` is excluded.** `openmettle-migrate` is a one-shot stderr-only process (core ADR 0026) and never reads `OTLP_*` variables. It never receives `OPENMETTLE_MIGRATE_OTLP_*` env vars, never mounts `otlp-ca`, and `<fullname>-migrate` never receives OTLP egress.
- **No probe spans, no ambient `OTEL_*`, no live reload, no bundled collector.** Core never exports spans for `/healthz` or `/readyz`, ignores inbound `traceparent`/`tracestate`, and neutralizes ambient `OTEL_*` environment variables (core ADR 0026). The chart sets no `OTEL_*` variables and deploys no collector; Grafana Alloy or another OTLP/HTTP collector is provisioned separately. Core reads `OTLP_CA_FILE` once at startup—after rotating the collector CA ConfigMap, restart `api` and `worker` (`kubectl rollout restart deployment/<fullname>-api deployment/<fullname>-worker`).

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

### Kind smoke test (I2/I3/I7/I10)

[`tests/kind/smoke.py`](../../tests/kind/README.md) installs the chart on an ephemeral kind cluster (Kubernetes 1.37.0, kind v0.33.0; core's pins). It uses core images built from the pinned core commit `2c62e8a` (`CORE_COMMIT`), referenced by digest, and a synthetic PostgreSQL fixture with the four login roles of [Database roles and Secrets](#database-roles-and-secrets). It checks these acceptance items against live state:

| Item | Smoke-tested |
| --- | --- |
| api, worker and migrate images install by digest | Yes (digest read back from the node's containerd) |
| Migration hook completes before the Deployments roll out | Yes (under namespace default-deny; the history must reach migration 18, `openmettle_issuance`) |
| API and worker Ready; `/readyz` 200 | Yes |
| Worker scales to 2 while the API stays at 1 | Yes, through `worker.replicas` |
| No optional package present (default install; `/auth/*` and `/v1/*` answer `404`; no `*ISSUANCE*` variable on `api`, `worker` or the migrate hook Job) | Yes |
| Same-digest `helm upgrade` reruns migrate as a no-op and stays Ready | Yes |
| Enabled-profile upgrade (`api.replicas: 2`, API PDB, `storage.artifacts` RWO PVC, `telemetry.logging` `json`/`debug`, `auth.enabled: true` with `browser` + `native` v2 profile) | Yes (checks rollout, `/healthz` + `/readyz` 200, PDB `maxUnavailable: 1` & `disruptionsAllowed >= 1`, PVC `Bound` + `/var/lib/openmettle/artifacts` mount + `OPENMETTLE_{API,WORKER}_ARTIFACTS_DIR` + `staging/` and `revisions/` created `0700` by core at startup, API-only `auth` mounts + `0440`/`fsGroup: 65532` `openmettle-api --check-auth-config`, `OPENMETTLE_API_ISSUANCE_DATABASE_URL` (required `secretKeyRef` to the issuance Secret) and `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS=2` on `api` only, with no issuance variable or Secret reference on `worker` or the migrate hook Job, live `/auth/session` `403`, `/auth/native/session` `403` & `/v1/capabilities` `401` problem JSON body (`code: "unauthenticated"`), and ADR 0024 JSON/debug stderr logs on `api` and `worker`) |
| `helm uninstall` leaves no non-kept release objects | Yes (release Deployments, Services, NetworkPolicies and PDB removed; chart-owned artifact PVC kept via `helm.sh/resource-policy: keep`) |
| App namespace enforces Pod Security `restricted` | Yes |
| NetworkPolicy enforced under namespace default-deny | Yes |
| I4 database CA against TLS PostgreSQL, Ingress behind Traefik, multi-node/drain eviction | No (render tests and kubeconform only; owner's qualification) |
| I5/I10 live OIDC provider exchange (`networkPolicy.api.oidc` to an external/in-cluster IdP) | Mounts, `0440`/`fsGroup: 65532` key readability and `/auth/*` + `/v1/*` route mounting are smoke-tested in I10; live OIDC provider exchange is qualified in core `oidc-qualification.yml` and pending owner cluster qualification |
| I6/I9 OTLP trace & metrics export (`api`/`worker` CA mount & collector egress) | No. Off in the chart smoke run (qualified in core `telemetry-qualification.yml`); chart render tests and kubeconform only |
| Registry pulls, TLS to PostgreSQL, ingress controller, multi-node | No (owner's qualification) |

The workflow ([`kind-smoke.yml`](../../.github/workflows/kind-smoke.yml)) runs on pull requests and pushes to `main` that touch `CORE_COMMIT`, the chart or the harness, and on manual dispatch. All 10 checks—including I2 install/upgrade/uninstall, I3 NetworkPolicy enforcement, I7 enabled-profile upgrade, I9 core `b5ee68d` (`main`, PR #15) and I10 core `adef30a` (adding default-off `404` checks plus enabled-profile `auth.enabled: true` mounts, `--check-auth-config` and `/auth/*` + `/v1/*` route checks; [pull-request run 44761077005](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44761077005)) and V1-15 core `94d21f8` (adding `ARTIFACTS_DIR` in every api and worker pod spec and a live `stat` of the store's `staging/` and `revisions/` directories, UID `65532` mode `0700`, on the `local-path` PVC; [pull-request run 44778163598](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44778163598) on `19e770c`)—passed on hosted `kind-smoke` CI (see [`tests/kind`](../../tests/kind/README.md)). AUTHSEC-01 moves the pin to core `2c62e8a` (migration 18) and adds the `openmettle_issuance` role, its Secret and the issuance isolation checks above; their hosted `kind-smoke` result is recorded on the pull request that introduced them and on core issue #73. The tests check chart defaults against a byte-verified copy of core's `runtime/process-contract.json` (`tests/fixtures/core/`). The chart's default ServiceAccount names (`<fullname>-api`) differ from the contract's example names (`openmettle-api`); set `serviceAccount.name` to use those.

## Pending

- **I2/I3/I7/I8/I9/I10:** owner acceptance (hosted `kind-smoke` verification on core `adef30a`, including `auth` + `/v1/*` smoke checks, passed in [run 44761077005](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44761077005); on core `94d21f8`, including the `ARTIFACTS_DIR` store checks, it passed in [run 44778163598](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44778163598)).
- **I4 (render contract delivered; API PDB and single-node RWO artifact PVC added to I7 kind smoke; `ARTIFACTS_DIR` wired for core V1-15 PR1):** artifact upload and download through `/v1` (V1-15 PR2) against the mounted volume, live verification of the database CA against TLS-enabled PostgreSQL, the API PDB during a real node drain, `ReadWriteMany` multi-node artifact storage, and the Ingress behind Traefik, including the access-log [acceptance check](#ingress-and-tls).
- **I5/I10 (render contract delivered; API-only `auth` mounts, Secret `0440`/`fsGroup: 65532` `--check-auth-config` readability and `/auth/*` + `/v1/*` route mounting added to I10 kind smoke):** live cluster qualification of `networkPolicy.api.oidc` egress and `auth.providerCaBundle` against a real OIDC provider (core's `oidc-qualification.yml` already qualifies browser and native sign-in against Keycloak 26.8.2; owner cluster qualification remains separate), plus an optional pre-upgrade `--check-auth-config` hook if needed.
- **AUTHSEC-01 (core #73):** `database.issuance` and `api.settings.issuanceDbMaxConnections` are delivered with render tests and kind smoke checks; owner acceptance of core ADR 0030 and live qualification of sign-in through both pools on the owner's cluster remain open. Core ADR 0030 ("Evidence required for acceptance") lists core's own two-pool tests.
- **I6/I9 (render contract for `tracesEndpoint` + `metricsEndpoint` delivered; `telemetry.logging` `json`/`debug` added to I7 kind smoke):** chart-installed live cluster qualification of `telemetry.otlp` export, `/etc/openmettle/otlp-ca/ca.crt` trust verification and `networkPolicy.telemetry.otlp` egress against an OTLP/HTTP collector (core's own `telemetry-qualification.yml` already qualifies live Alloy + Prometheus ingestion on kind; owner cluster qualification remains separate).
- **V1-20** (managed inference, accelerated tools) and **V1-06** (external providers or gateway): separate charts and releases, never subcharts of core.
- Qualification on the owner's cluster is an owner action.
