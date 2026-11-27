# openmettle-core chart

CPU-only packaging for the OpenMettle core API, worker (maintenance and opt-in turn execution), schema migration, opt-in per-model `openmettle-gateway` proxy, and opt-in coordinated maintenance-window backup `CronJob` workloads (pinned to `openmettle-core` [`CORE_COMMIT`](../../CORE_COMMIT), schema through migration `45`). Optional capabilities—artifact storage, database CA mounts, HTTPS Ingress, API PodDisruptionBudget, browser/native OIDC sign-in, OTLP telemetry export, `worker.inference`, `worker.mcp`, `gateways`, `vault`, and `backup`—are all off by default. The [kind smoke coverage](#kind-smoke-test) lists the live profiles exercised on a disposable cluster.

## What it renders

| Resource | Name | Notes |
| --- | --- | --- |
| Deployment | `<fullname>-api` | Port 8080 (`http`); liveness `/healthz`, readiness `/readyz`; opt-in `vault` RAM-staged `0400` keys |
| Deployment | `<fullname>-worker` | Port 8081 (`http`); same probes; no Service; opt-in `worker.inference`, `worker.mcp` and `vault` |
| Deployment | `<fullname>-gateway-<name>` | Optional (`gateways.<name>`); port 8082 (`http`); liveness `/healthz`, readiness `/readyz`; one Deployment per served model |
| CronJob | `<fullname>-backup` (or `<prefix>-<hash>-backup` when `> 52` chars) | Optional (`backup.enabled`); `concurrencyPolicy: Forbid`, `backoffLimit: 0`; runs `openmettle-admin backup capture` with `images.admin` + `images.postgresClient`; see [Coordinated maintenance-window backup (`backup`)](#coordinated-maintenance-window-backup-backup) |
| Service | `<fullname>-api` | ClusterIP; `api.service.port` → named port `http` |
| Service | `<fullname>-gateway-<name>` | Optional (`gateways.<name>`); ClusterIP; `gateways.<name>.service.port` (default `8082`) → named port `http` |
| ServiceAccount | `<fullname>-api`, `<fullname>-worker` | One per component; no token mounted |
| ServiceAccount | `<fullname>-gateway-<name>` | Optional (`gateways.<name>`, when `serviceAccount.create` is true); one per gateway; no token mounted |
| ServiceAccount | `<fullname>-backup` | Optional (`backup.enabled` and `backup.serviceAccount.create`); no token mounted |
| ServiceAccount | `<fullname>-migrate` | Hook, weight `-10` |
| Job | `<fullname>-migrate` | Hook, weight `0`; see [Schema migration](#schema-migration) |
| NetworkPolicy | `<fullname>-deny-all` | Release-wide Ingress/Egress deny-all (`networkPolicy.enabled`, default `true`) |
| NetworkPolicy | `<fullname>-api`, `<fullname>-worker` | DNS and database egress; API-only ingress on TCP 8080 from `networkPolicy.api.ingressFrom` and OIDC egress when `auth.enabled` is true; worker-only inference egress (`worker.inference.enabled`) and external MCP/OAuth egress (`worker.mcp.enabled`); OTLP egress on both when `telemetry.otlp.enabled` is true |
| NetworkPolicy | `<fullname>-gateway-<name>` | Optional (`gateways.<name>`); ingress on TCP 8082 from this release's worker pods by default (or `gateways.<name>.networkPolicy.ingressFrom` when set), and egress to DNS, PostgreSQL, `gateways.<name>.networkPolicy.upstream`, and (when enabled) OTLP |
| NetworkPolicy | `<fullname>-backup` | Optional (`backup.enabled`); zero ingress, egress restricted strictly to DNS and PostgreSQL |
| NetworkPolicy | `<fullname>-migrate` | Hook, weight `-10`; DNS and database egress for the migrate pod |
| PersistentVolumeClaim | `<fullname>-artifacts` | Optional (`storage.artifacts` with `size`); kept on uninstall. See [Artifact storage](#artifact-storage) |
| Ingress | `<fullname>-api` | Optional (`ingress.enabled`); HTTPS to the API Service. See [Ingress and TLS](#ingress-and-tls) |
| PodDisruptionBudget | `<fullname>-api` | Optional (`api.podDisruptionBudget.enabled`). See [API PodDisruptionBudget](#api-poddisruptionbudget) |

`<fullname>` is the release name if it already contains `openmettle-core`, otherwise `<release>-openmettle-core`, truncated to 52 characters (each `<fullname>-gateway-<name>` resource name is additionally validated to stay within Kubernetes' 63-character limit). The chart creates no Namespace, Secret, ConfigMap, RBAC object, CRD, IngressClass, Traefik Middleware, device request or `resource.k8s.io` object. All resources are namespaced; set the namespace with `--namespace`.

## Values contract

[`values.schema.json`](values.schema.json) (JSON Schema draft 2020-12) rejects unknown keys at every level, so an unsupported key such as `oidc:` fails the render instead of being ignored. `affinity` is the only pass-through: its top-level keys are checked and Kubernetes validates the nested structure. Integer bounds copy core's (`src/lib.rs`, `src/migrate.rs`, `src/gateway_proxy.rs`). The schema also rejects the `global` key that Helm passes to subcharts, so this chart cannot be used as a subchart. This is by design: core is installed as its own release.

The chart refuses to render until you supply:

- `images.{api,worker,migrate}.repository` and `.digest`. Images render as `[registry/]repository@sha256:<digest>`. Tags are not accepted in either field. `registry` is optional. The migrate image is not needed when `migration.enabled` is false. When `gateways` is non-empty, `images.gateway.{repository,digest}` is required (and all three `images.gateway` fields must stay empty when `gateways` is `{}`). When `backup.enabled` is true, `images.admin.{repository,digest}` and `images.postgresClient.{repository,digest}` are required (and all three fields of each must stay empty while `backup.enabled` is false).
- `database.{api,worker,migrate}.existingSecret`: names of existing Secrets. Each holds a full `postgres://` URL under `key` (default `url`). The migrate Secret is not needed when `migration.enabled` is false.
- `database.issuance.existingSecret` while `auth.enabled` is true: the session issuance URL (see [Database roles and Secrets](#database-roles-and-secrets)). It must stay empty while `auth.enabled` is false.
- `database.gateway.existingSecret` while `gateways` is non-empty: the `openmettle_gateway` login URL (see [Database roles and Secrets](#database-roles-and-secrets)). It must stay empty while `gateways` is `{}`.
- `database.backup.existingSecret` while `backup.enabled` is true: an `openmettle_owner` login URL (may reuse `database.migrate`'s Secret; never `api`, `worker`, `issuance` or `gateway`). Must stay empty while `backup.enabled` is false.
- `networkPolicy.database.to`: at least one Kubernetes `NetworkPolicyPeer` for PostgreSQL while `networkPolicy.enabled` is true. An empty list is rejected at render time because Kubernetes treats an empty `to` list as allowing every destination.
- `worker.inference.configMapName` (and `networkPolicy.worker.inference.to` while `networkPolicy.enabled` is true) when `worker.inference.enabled` is true.
- `worker.inference.enabled: true` and (while `networkPolicy.enabled` is true) `networkPolicy.worker.mcp.to` when `worker.mcp.enabled` is true.
- `vault.existingSecret` when `vault.enabled` is true (distinct from `auth.loginKeysSecretName` and `backup.existingKeysSecret`).
- `backup.existingKeysSecret`, `backup.destination.existingClaim`, `backup.destination.domain`, and `backup.operatorId` (canonical lowercase UUID) when `backup.enabled` is true.
- `gateways.<name>.model`, `gateways.<name>.upstreamUrl`, and (while `networkPolicy.enabled` is true) `gateways.<name>.networkPolicy.upstream.to` for each configured gateway instance.

| Key | Default | Meaning |
| --- | --- | --- |
| `images.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `images.pullSecrets` | `[]` | Names of existing pull Secrets |
| `images.<component>.{registry,repository,digest}` | `""` | Digest-pinned image for `api`, `worker`, `migrate`, `gateway` (required iff `gateways` is non-empty), `admin` and `postgresClient` (both required iff `backup.enabled` is true) |
| `database.<component>.{existingSecret,key}` | `""`, `url` | Existing Secret holding a full `postgres://` URL (`api`, `worker`, `migrate`) |
| `database.issuance.{existingSecret,key}` | `""`, `url` | Required while `auth.enabled` is true and refused while it is false: an `openmettle_issuance` login URL, rendered as `OPENMETTLE_API_ISSUANCE_DATABASE_URL` on the API container only. Rendering fails if it names the same Secret and key as `database.api`, `database.worker`, `database.migrate`, `database.gateway` or `database.backup` |
| `database.gateway.{existingSecret,key}` | `""`, `url` | Required while `gateways` is non-empty and refused while `gateways` is `{}`: an `openmettle_gateway` login URL, rendered as `OPENMETTLE_GATEWAY_DATABASE_URL` on gateway containers only. Must not reuse the `(existingSecret, key)` of `api`, `worker`, `migrate`, `issuance` or `backup` |
| `database.backup.{existingSecret,key}` | `""`, `url` | Required while `backup.enabled` is true and refused while it is false: an `openmettle_owner` login URL rendered as `OPENMETTLE_ADMIN_DATABASE_URL` on the backup `CronJob` container only (may reuse `database.migrate`'s owner Secret; must never reuse `api`, `worker`, `issuance` or `gateway`) |
| `database.connectionBudget` | `null` | Optional; see [Connection budget](#connection-budget) |
| `api.replicas`, `worker.replicas` | `1` | Independent |
| `worker.sweepMs` | `null` | Worker maintenance sweep interval in milliseconds, 1000–3600000 inclusive. Setting it emits `OPENMETTLE_WORKER_SWEEP_MS` on the worker only. With null or omission the worker uses its built-in interval. |
| `worker.pollMs` | `null` | Worker run-claim poll interval in milliseconds, 100–60000 inclusive. Setting it emits `OPENMETTLE_WORKER_POLL_MS` on the worker only. With null or omission the worker uses its built-in interval. |
| `worker.inference.enabled` | `false` | Opt-in worker turn execution (`OPENMETTLE_WORKER_INFERENCE_CONFIG` and run-claim settings); see [Worker turn execution (`worker.inference`)](#worker-turn-execution-workerinference) |
| `worker.inference.{configMapName,configKey,catalogKey}` | `""`, `inference.json`, `catalog.json` | Existing ConfigMap holding both `inference.json` and `catalog.json` projected read-only at `/etc/openmettle/inference`; `configMapName` required iff enabled, and `catalogKey` must differ from `configKey` |
| `worker.inference.settings.{runSlots,leaseMs,executionTimeoutMs,executingPerActor,executingPerScope}` | `4`, `60000`, `300000`, `2`, `4` | Rendered on `worker` only while `worker.inference.enabled` is true (`OPENMETTLE_WORKER_{RUN_SLOTS,LEASE_MS,EXECUTION_TIMEOUT_MS,EXECUTING_PER_ACTOR,EXECUTING_PER_SCOPE}`). Guards enforce `leaseMs >= 6 * worker.settings.dbTimeoutMs` and `executionTimeoutMs >= 2 * leaseMs` |
| `worker.inference.caBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Optional existing ConfigMap CA bundle mounted read-only at `/etc/openmettle/inference-ca/ca.crt` on `worker` only (for verifying private-CA TLS terminators in front of `openmettle-gateway`); refused while `worker.inference.enabled` is false |
| `worker.mcp.enabled` | `false` | Opt-in worker external MCP and OAuth refresh egress/CA (`V1-14`, core ADR 0045); requires `worker.inference.enabled: true` |
| `worker.mcp.caBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Optional existing ConfigMap CA bundle mounted read-only at `/etc/openmettle/mcp-ca/ca.crt` on `worker` only; refused while `worker.mcp.enabled` is false |
| `api.resources`, `worker.resources` | requests `100m` CPU, `64Mi` | Core's contract examples, not qualified sizing. Only `cpu`, `memory` and `ephemeral-storage` are accepted. |
| `<component>.serviceAccount.{create,name,annotations}` | `true`, `""`, `{}` | `name` is required when `create` is false. Rendering fails if two components (including migration and any gateway) resolve to the same name, or if any name is `default` |
| `<component>.settings.dbMaxConnections` | `4` | `OPENMETTLE_<ROLE>_DB_MAX_CONNECTIONS`, 1–64 |
| `<component>.settings.dbTimeoutMs` | `2000` | `OPENMETTLE_<ROLE>_DB_TIMEOUT_MS`, 1–30000 |
| `<component>.settings.shutdownTimeoutMs` | `5000` | `OPENMETTLE_<ROLE>_SHUTDOWN_TIMEOUT_MS`, 1–60000 |
| `api.settings.issuanceDbMaxConnections` | `2` | `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS`, 1–64; rendered only while `auth.enabled` is true. The worker has no such setting |
| `<component>.terminationGracePeriodSeconds` | `15` | Must exceed `shutdownTimeoutMs`; rendering fails otherwise |
| `<component>.strategy.{maxSurge,maxUnavailable}` | `1`, `0` | Integers; both 0 is rejected |
| `api.service.port` | `8080` | Service port; container ports are fixed |
| `<component>.{podAnnotations,nodeSelector,tolerations,affinity}` | empty | Scheduling for api and worker |
| `gateways` | `{}` | Map of `0..N` per-model `openmettle-gateway` instances keyed by `<name>` (`^[a-z0-9]([-a-z0-9]{0,30}[a-z0-9])?$`); see [Inference proxy (`gateways`) and external TLS termination](#inference-proxy-gateways-and-external-tls-termination) |
| `gateways.<name>.{model,upstreamUrl}` | required per entry | Unique catalog model ID (`1..=128` UTF-8 bytes; literal `$` is escaped as `$$` in `OPENMETTLE_GATEWAY_MODEL` so Kubernetes `EnvVar` expansion never mutates the model ID) and canonical `http://host[:port][/]` upstream origin (DNS/IPv4 with optional single trailing `.`, rejecting empty DNS labels, or RFC 4291 bracketed IPv6; no `https://`, userinfo, path, query or fragment) |
| `gateways.<name>.settings.{cacheMode,upstreamConnectTimeoutMs,upstreamIdleTimeoutMs,dbMaxConnections,dbTimeoutMs,shutdownTimeoutMs}` | `scoped`, `5000`, `120000`, `4`, `2000`, `5000` | Per-gateway `OPENMETTLE_GATEWAY_*` settings (`cacheMode`: `scoped` or `per_request`) |
| `gateways.<name>.{replicas,resources,serviceAccount,terminationGracePeriodSeconds,strategy,service,podAnnotations,nodeSelector,tolerations,affinity}` | `1`, `100m`/`64Mi`, created, `15`, `1`/`0`, port `8082`, empty | Per-gateway Deployment, ServiceAccount and ClusterIP Service settings |
| `gateways.<name>.networkPolicy.{ingressFrom,upstream}` | `null`, `{to: [], port: 30000}` | `ingressFrom: null` allows TCP 8082 only from this release's `worker` pods; an explicit peer list overrides it (e.g. an external TLS terminator, or `[]` for deny-all). `upstream.to` is required non-empty while `networkPolicy.enabled` is true |
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
| `networkPolicy.worker.inference.{to,port}` | `[]`, `8082` | Required non-empty while `worker.inference.enabled` and `networkPolicy.enabled` are both true (must stay `[]` while `worker.inference.enabled` is false): worker-only TCP egress peers to in-cluster `openmettle-gateway` (`8082`) or an external TLS terminator (e.g. `8443`/`443`) |
| `networkPolicy.worker.mcp.{to,ports}` | `[]`, `[443]` | Required non-empty `to` while `worker.mcp.enabled` and `networkPolicy.enabled` are both true (must stay `[]` while `worker.mcp.enabled` is false): worker-only TCP egress peers to external MCP servers and OAuth token refresh endpoints across `1..16` unique TCP ports (`1–65535`) |
| `networkPolicy.dns.to` | `kube-system` / `k8s-app: kube-dns` | `NetworkPolicyPeer` list for UDP and TCP 53 egress. Must be non-empty while enabled |
| `networkPolicy.database.to` | `[]` | Required while enabled: `NetworkPolicyPeer` list for PostgreSQL egress on `networkPolicy.database.port` |
| `networkPolicy.database.port` | `5432` | TCP port for database egress, 1–65535 |
| `networkPolicy.telemetry.otlp.to` | `[]` | Required while `telemetry.otlp.enabled` and `networkPolicy.enabled` are both true (must be empty while `telemetry.otlp.enabled` is false): OTLP collector egress peers for `api`, `worker` and any configured `gateway` (never `migrate`) |
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
| `auth.catalogKey` | `""` | Optional key of the same ConfigMap holding the model catalog, projected read-only beside it at `/etc/openmettle/auth/catalog.json`; name that path as `catalog_file` in `auth.json`. Must differ from `configKey` and stay empty while `auth.enabled` is false. Optional in the schema, so `helm upgrade --reuse-values` from a release without it still renders. The examples leave it empty, because an existing auth ConfigMap may lack the key. See [Model catalog](#model-catalog) |
| `auth.loginKeysSecretName` | `""` | Required while enabled: existing Secret holding raw 32-byte login and optional cursor key files, mounted read-only at `/etc/openmettle/auth-keys` |
| `auth.providerCaBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Optional existing ConfigMap key mounted read-only at `/etc/openmettle/auth-ca/ca.crt` in the API pod only |
| `telemetry.logging.{format,level}` | `null`, `null` | Optional `OPENMETTLE_<ROLE>_LOG_FORMAT` (`json` or `text`) and `OPENMETTLE_<ROLE>_LOG_LEVEL` (`error`, `warn`, `info` or `debug`; `trace` refused) across `api`, `worker`, `migrate` and any configured `gateway`; `null` emits no `LOG_*` env vars |
| `telemetry.otlp.enabled` | `false` | Enable OTLP/HTTP protobuf trace and/or metrics export for `api`, `worker` and any configured `gateway` (never `migrate`); see [OTLP trace and metrics export](#otlp-trace-and-metrics-export-telemetryotlp-api-worker-and-gateways) |
| `telemetry.otlp.tracesEndpoint` | `""` | Optional canonical `https://` URL with a lowercase DNS host (`OPENMETTLE_{API,WORKER,GATEWAY}_OTLP_TRACES_ENDPOINT`); at least one of `tracesEndpoint` or `metricsEndpoint` is required while enabled, and both must be `""` while false |
| `telemetry.otlp.metricsEndpoint` | `""` | Optional canonical `https://` URL with a lowercase DNS host (`OPENMETTLE_{API,WORKER,GATEWAY}_OTLP_METRICS_ENDPOINT`, core ADR 0028); at least one of `tracesEndpoint` or `metricsEndpoint` is required while enabled, and both must be `""` while false |
| `telemetry.otlp.privateRanges` | `[]` | Up to 32 unique private CIDRs (RFC 1918, CGNAT or ULA) joined with commas into `OPENMETTLE_{API,WORKER,GATEWAY}_OTLP_PRIVATE_RANGES` when non-empty; must be empty while disabled |
| `telemetry.otlp.caBundle.{enabled,configMapName,key}` | `false`, `""`, `ca.crt` | Optional existing ConfigMap key mounted read-only at `/etc/openmettle/otlp-ca/ca.crt` in `api`, `worker` and `gateway` pods only (`OPENMETTLE_{API,WORKER,GATEWAY}_OTLP_CA_FILE`); must be disabled while `telemetry.otlp.enabled` is false |
| `vault.{enabled,existingSecret,configKey}` | `false`, `""`, `keyring.json` | Opt-in ADR 0045 credential vault keyring; `stage-vault-keys` initContainer stages `0400` regular files into RAM `emptyDir` (`subPath: keys`) at `/etc/openmettle/vault-keys` and emits `OPENMETTLE_{API,WORKER}_VAULT_KEYS_CONFIG` on `api` and `worker` only; see [Credential vault (`vault`) and worker MCP egress (`worker.mcp`)](#credential-vault-vault-and-worker-mcp-egress-workermcp) |
| `backup.{enabled,schedule,timeZone,suspend,startingDeadlineSeconds,activeDeadlineSeconds,successfulJobsHistoryLimit,failedJobsHistoryLimit}` | `false`, `0 3 * * *`, `null`, `false`, `300`, `3600`, `3`, `3` | Opt-in ADR 0046 coordinated maintenance-window backup `CronJob` (`concurrencyPolicy: Forbid`, `backoffLimit: 0`); see [Coordinated maintenance-window backup (`backup`)](#coordinated-maintenance-window-backup-backup) |
| `backup.{existingKeysSecret,keysConfigKey,destination,operatorId,reason,drainTimeoutSecs,releaseOnSuccess,retention,graphiti,chroma,configBundle,resources,serviceAccount,podAnnotations,nodeSelector,tolerations,affinity}` | disabled / safe defaults | Separate backup keyring Secret (`0400` RAM-staged), off-host destination PVC + domain + `requireSeparateDevice: true`, operator UUID + audit reason, drain timeout (`300 s`, `< activeDeadlineSeconds`), GFS retention (`7`/`4`/`12`, `prune: true`), optional Graphiti/Chroma/non-secret config bundle, and isolated scheduling/ServiceAccount |

`<component>` is `api` or `worker` (and `gateways.<name>` for per-gateway overrides); `<ROLE>` is `API`, `WORKER`, `GATEWAY` or `MIGRATE`.

Every process gets an explicit environment: `BIND` (`0.0.0.0:8080`, `0.0.0.0:8081` or `0.0.0.0:8082`; core otherwise binds loopback), `DATABASE_URL` from its own Secret through `secretKeyRef`, the settings above, optional `LOG_FORMAT`/`LOG_LEVEL` across all roles when non-null, optional `OTLP_TRACES_ENDPOINT`/`OTLP_METRICS_ENDPOINT`/`OTLP_CA_FILE`/`OTLP_PRIVATE_RANGES` on `api`, `worker` and `gateway` when `telemetry.otlp.enabled` is true, `ARTIFACTS_DIR=/var/lib/openmettle/artifacts` on `api` and `worker` when `storage.artifacts.enabled` is true, `OPENMETTLE_WORKER_INFERENCE_CONFIG=/etc/openmettle/inference/inference.json` plus run-claim settings on `worker` only when `worker.inference.enabled` is true, `OPENMETTLE_GATEWAY_{MODEL,UPSTREAM_URL,CACHE_MODE,UPSTREAM_CONNECT_TIMEOUT_MS,UPSTREAM_IDLE_TIMEOUT_MS}` on each `gateway` container only, and—when `auth.enabled` is true on the API only—`OPENMETTLE_API_AUTH_CONFIG=/etc/openmettle/auth/auth.json`, `OPENMETTLE_API_ISSUANCE_DATABASE_URL` from `database.issuance` through `secretKeyRef` and `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS`. Issuance, worker inference, artifact and gateway variables never cross component boundaries: core exits 78 on unexpected cross-role settings. The chart never uses `envFrom`. Each variable carries its own component prefix, as core ADR 0002 requires. Set `sslmode` explicitly in every URL, because SQLx defaults to `prefer`, which permits plaintext fallback. Readiness `timeoutSeconds` is `ceil(dbTimeoutMs / 1000) + 1`, because `/readyz` waits up to the database timeout.

Keep site values in a private overlay outside this repository and pass it with `-f`; see [Private overlays](#private-overlays). The synthetic files under `tests/chart/values/` use reserved `example.test` names and all-zero digests; they render but cannot be installed.

### Connection budget

Core ADR 0003 bounds PostgreSQL connections at the server. When `database.connectionBudget` is set, rendering fails unless

`(api.replicas + api.maxSurge) × (api.dbMaxConnections + api.issuanceDbMaxConnections) + (worker.replicas + worker.maxSurge) × worker.dbMaxConnections + Σ_gateways (g.replicas + g.maxSurge) × g.dbMaxConnections + 1 (migrator) + 3 (backup CronJob) ≤ connectionBudget`,

where `api.issuanceDbMaxConnections` counts only while `auth.enabled` is true (core ADR 0030), the gateway sum counts every configured `gateways.<name>` instance, and `+ 3` counts only while `backup.enabled` is true (`openmettle-admin backup capture` holds a 2-connection `openmettle_owner` SQLx pool plus 1 concurrent `pg_dump` connection, core ADR 0046). For example, with sign-in enabled, 2 API and 2 worker replicas, no gateways, no backup CronJob and the default pool sizes, core's README budgets 2 × (4 + 2) + 2 × 4 + 1 + 3 headroom = 24 connections; the chart's check additionally counts each component's `maxSurge` replicas (and each gateway's `(replicas + maxSurge) × dbMaxConnections`, plus `3` when `backup.enabled` is true).

Set it to the connections available to this release, after subtracting reserved and administrative headroom. The check covers configured pools only. It also excludes Terminating pods: during a rollout, a replaced pod keeps its pool open while it drains, for up to `terminationGracePeriodSeconds`, so the actual peak can briefly exceed the computed one. Leave headroom for that. Enforce each role's share in PostgreSQL with `CONNECTION LIMIT`; the chart does not manage roles.

### Database roles and Secrets

Provision the PostgreSQL roles and the database outside the chart before the first migration, as core's README ("Schema migrations") describes. Core migration 18 refuses to run, and rolls back, while `openmettle_issuance` is missing, and migration 23 refuses unless a restricted `openmettle_gateway` role exists (without superuser, `CREATEDB`, `CREATEROLE`, `REPLICATION` or `BYPASSRLS`):

| Role | Secret value | Mounted into |
| --- | --- | --- |
| `openmettle_owner` | `database.migrate` (and `database.backup` while `backup.enabled` is true) | migrate hook Job (`OPENMETTLE_MIGRATE_DATABASE_URL`) and, while `backup.enabled` is true, backup `CronJob` (`OPENMETTLE_ADMIN_DATABASE_URL`) only; `database.backup` may reuse `database.migrate`'s owner Secret |
| `openmettle_api` | `database.api` | `api` |
| `openmettle_issuance` | `database.issuance` | `api` only, and only while `auth.enabled` is true |
| `openmettle_worker` | `database.worker` | `worker` |
| `openmettle_gateway` | `database.gateway` | every `gateways.<name>` pod only, and only while `gateways` is non-empty |

Each runtime Secret must carry a different login: core's boundary audit refuses a login role that reaches more than one of `openmettle_api`, `openmettle_issuance`, `openmettle_worker` and `openmettle_gateway`, and the API refuses an issuance URL whose user equals its primary URL's user. The chart can only compare Secret names and keys, so it rejects obvious reuse across `api`, `worker`, `migrate`, `issuance` and `gateway`, and rejects `database.backup` reusing any non-owner role Secret (`api`, `worker`, `issuance`, `gateway`) while permitting `database.backup` to reference the same `openmettle_owner` Secret as `database.migrate`. Where `openmettle_api` SQL may have been exposed before upgrading across migration 18, revoke pre-upgrade sessions as core ADR 0030 ("Upgrade") describes; the chart does not do this.

When `gateways` is `{}` (the default), no chart pod logs in as `openmettle_gateway`, so creating it `NOLOGIN` (for example `CREATE ROLE openmettle_gateway NOLOGIN;`) satisfies migrations 23–45 until you enable a gateway. Before enabling any entry under `gateways`, grant `LOGIN` with a dedicated password and `CONNECTION LIMIT` to `openmettle_gateway` and create the `database.gateway` URL Secret. From core migration 37 (ADR 0044), `openmettle_gateway` holds `EXECUTE` only on `openmettle.gateway_dispatch`, `openmettle.gateway_dispatch_scoped` and `openmettle.gateway_settle_report`, with zero table privileges on `openmettle.*`. From migration 45 (ADR 0046), `backup_maintenance_gate`, `backup_runs` and `backup_rpo_telemetry_state` grant zero direct table or column privileges to any runtime role; runtime reads/fences run exclusively through `SECURITY DEFINER` helpers (`backup_maintenance_is_active()`, `backup_maintenance_lock_open()` for `api`/`worker`, and `backup_observe_telemetry()` for `worker` only).

#### Quotas from migrations 24–27

The migrate hook applies migrations 24–27 on either path. What the operator must do next depends on whether the database was empty:

- **New database.** Core enables quota metering and override enforcement at once, and the first API replica with `storage.artifacts` enabled pins the empty artifact volume (core ADR 0040). Before admitting runs, set a personal `usage_tokens` limit in `openmettle.quota_defaults`. Without it, admission is refused as unconfigured. Uploads still need the `openmettle.storage_instance` limits. Neither step has a core operator script; [First install](../../docs/first-install.md#104-storage-and-run-quotas) gives the statements the kind smoke test runs.
- **Existing database at migration 23 or earlier.** Follow core's [`docs/operator/storage-adoption-and-quota-upgrade.md`](https://github.com/OpenMettle/openmettle-core/blob/87a395e25e26f2e83c7ba34cc40561a0acf92b09/docs/operator/storage-adoption-and-quota-upgrade.md) in a maintenance window. The chart's pre-upgrade migrate hook runs while the old worker is still running. Set `worker.replicas: 0` first, or disable `storage.artifacts` for the old worker, so that no legacy artifact cleaner runs during the migration. After the upgrade, run core's `openmettle-admin` image for `storage adopt`, `quota drain-orphans` and `quota activate`. [Running `openmettle-admin`](../../docs/first-install.md#running-openmettle-admin) gives a one-off Job manifest for ad-hoc admin tasks.

## Security defaults

These are fixed and are not values:

- Pod: `runAsNonRoot`, `runAsUser`/`runAsGroup` 65532 (the core image user), seccomp `RuntimeDefault`. `fsGroup: 65532` is added to api and worker pods when mounting the artifact volume (with `fsGroupChangePolicy: OnRootMismatch`), to the api pod when `auth.enabled` is true (so mode `0440` login key Secret files are readable by GID `65532`), to api and worker pods when `vault.enabled` is true (for `stage-vault-keys`), and to the backup `CronJob` pod (for `prepare-backup-runtime` and the backup destination PVC). Gateway pods never mount artifacts, login keys or vault keys and never set `fsGroup`.
- Container: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, `privileged: false`. By default no volumes are mounted. Optional volumes are strictly role-scoped: the artifact claim (read-write on `api`/`worker`, read-only on `backup`), database CA ConfigMap (read-only on every component; staged to a regular file in a memory `emptyDir` on `backup` for `O_NOFOLLOW`), browser sign-in config/login keys/provider CA (`api` only), worker inference config/catalog/CA and external MCP CA (`worker` only), OTLP CA (`api`, `worker` and `gateway` only), RAM-staged `0400` vault keys (`api` and `worker` only), and backup runtime/keys/destination/optional dump volumes (`backup` only). The root filesystem stays read-only either way.
- `automountServiceAccountToken: false` on every ServiceAccount and every pod, plus `enableServiceLinks: false`. The processes never call the Kubernetes API, so the chart creates no RBAC.
- Credentials come only from existing Secrets. The owner credential reaches only the migration Job and (when `backup.enabled` is true) the backup `CronJob`, the session issuance credential only the API container while `auth.enabled` is true, the gateway credential only `gateways.<name>` containers, vault keys only `api`/`worker` (via RAM `0400` staging), and backup keys only `backup` (via RAM `0400` staging). The chart never uses `lookup`.
- `/healthz` and `/readyz` are unauthenticated. Services are ClusterIP only, `networkPolicy.api.ingressFrom` defaults to empty, gateway ingress defaults to this release's worker pods only, backup pods accept zero ingress, and the Ingress is off by default.

## NetworkPolicy

`networkPolicy.enabled` defaults to `true`. When enabled, the chart renders a chart-scoped deny-all plus per-component allow policies:

- **`<fullname>-deny-all`** selects every pod of this release (`app.kubernetes.io/name` and `app.kubernetes.io/instance`) with `policyTypes: [Ingress, Egress]` and no rules.
- **`<fullname>-api`**, **`<fullname>-worker`**, **`<fullname>-migrate`**, **`<fullname>-backup`** (when `backup.enabled` is true), and each **`<fullname>-gateway-<name>`** select only their own component and declare `policyTypes: [Ingress, Egress]`:
  - **Egress** is restricted to `networkPolicy.dns.to` on UDP and TCP 53 and `networkPolicy.database.to` on TCP `networkPolicy.database.port` (default `5432`), plus:
    - on `<fullname>-api` only when `auth.enabled` is true: `networkPolicy.api.oidc.to` on TCP `networkPolicy.api.oidc.port` (default `443`);
    - on `<fullname>-worker` only when `worker.inference.enabled` is true: `networkPolicy.worker.inference.to` on TCP `networkPolicy.worker.inference.port` (default `8082`);
    - on `<fullname>-worker` only when `worker.mcp.enabled` is true: `networkPolicy.worker.mcp.to` on TCP `networkPolicy.worker.mcp.ports` (default `[443]`, `1..16` unique ports);
    - on each `<fullname>-gateway-<name>`: `gateways.<name>.networkPolicy.upstream.to` on TCP `gateways.<name>.networkPolicy.upstream.port` (default `30000`);
    - on `<fullname>-api`, `<fullname>-worker` and each `<fullname>-gateway-<name>` (never `<fullname>-migrate` or `<fullname>-backup`) when `telemetry.otlp.enabled` is true: `networkPolicy.telemetry.otlp.to` on TCP `networkPolicy.telemetry.otlp.port` (default `4318`).
    Rendering fails if any required peer list is empty while enabled, or if a disabled feature (`auth`, `worker.inference`, `worker.mcp`, `telemetry.otlp`) carries leftover egress peers.
  - The default `networkPolicy.dns.to` selects pods labelled `k8s-app: kube-dns` in the `kube-system` namespace, matching kubeadm (including kind) and K3s CoreDNS. Override it where cluster DNS uses different labels, namespace or IP blocks.
  - **Ingress** is allowed on `<fullname>-api` (TCP `8080`) only from `networkPolicy.api.ingressFrom` (default `[]`, denying all pod ingress), and on each `<fullname>-gateway-<name>` (TCP `8082`) from this release's `worker` pods by default (`ingressFrom: null`), or from explicit peers in `gateways.<name>.networkPolicy.ingressFrom` (e.g. an external TLS terminator), or denied (`[]`). Kubelet liveness/readiness probes and `kubectl port-forward` originate from the node or inside the pod's network namespace rather than from another pod peer, so they are unaffected. Worker, migrate and backup pods never render an ingress rule.
- **Migrate hook policy.** `<fullname>-migrate` carries `helm.sh/hook: pre-install,pre-upgrade`, `helm.sh/hook-weight: "-10"` and `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded`, matching the migrate ServiceAccount. Hooks run before ordinary release resources, so on first install in a namespace that denies by default—and on upgrades while `<fullname>-deny-all` is in place—the hook policy gives the migrate Job DNS and database egress and is deleted once the hook succeeds. When `migration.enabled` is false, no migrate NetworkPolicy is rendered.
- **Cluster CNI requirement.** `NetworkPolicy` resources have no effect unless the target cluster's network plugin enforces them. K3s's embedded network policy controller (kube-router) enforces `NetworkPolicy` by default unless disabled (`--disable-network-policy`). Verify enforcement on the target cluster as part of qualification; setting `networkPolicy.enabled: false` disables all policy objects and waives the egress peer requirements.

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

The overlay references objects the chart never creates: the three database URL Secrets (four, with the issuance Secret, when `auth.enabled` is true), the database CA ConfigMap, an existing artifact PVC (if used), the TLS Secret, the IngressClass, any Traefik Middleware, and (when `auth.enabled` is true) the auth settings ConfigMap (with the model catalog key, if `auth.catalogKey` is set), login-keys Secret and optional provider CA ConfigMap. Create them in the release namespace first. [First install](../../docs/first-install.md) walks through each one for a fresh install with sign-in. Configure browser sign-in under `auth:` and `networkPolicy.api.oidc:`; the schema still rejects an unknown top-level `oidc:` key.

## Database CA

`database.caBundle` mounts one key of an existing ConfigMap holding a PEM CA bundle. The chart never creates it:

```sh
kubectl --namespace openmettle create configmap openmettle-db-ca --from-file=ca.crt=<path to PEM bundle>
```

- **Mount.** When enabled, the api, worker and migrate pods each mount the key read-only at the fixed path `/etc/openmettle/db-ca/ca.crt` (volume `db-ca`, directory `/etc/openmettle/db-ca`). The key is projected under the fixed file name `ca.crt`, so it never becomes a path. The schema and a render guard also reject keys containing `/`, the key `.` and keys starting with `..`, which Kubernetes refuses. The same rule applies to every ConfigMap key value.
- **No environment variable.** The chart sets no `PGSSLROOTCERT` or other `PG*` variable. Core ADR 0002 requires each process's environment to carry only its own `OPENMETTLE_<ROLE>_` prefix and forbids shared database defaults. SQLx reads TLS options from each URL instead. Reference the file in **every** URL Secret (api, worker and owner):

  `postgres://<role>:<password>@<host>:5432/openmettle?sslmode=verify-full&sslrootcert=/etc/openmettle/db-ca/ca.crt`

  `verify-full` checks the certificate chain and the host name. Without an explicit `sslmode`, SQLx uses `prefer`, which permits plaintext.
- **Missing ConfigMap.** The volume is not optional. If the ConfigMap or key is missing, pods stay in `ContainerCreating`, and the migration hook waits until the Helm timeout.
- **Rotation.** The kubelet refreshes ConfigMap volumes (not `subPath` mounts, which the chart does not use) after a delay. Whether SQLx reloads the file for new connections has not been verified. Restart the Deployments after changing the bundle.
- Not tested against a TLS-enabled PostgreSQL. The kind smoke fixture uses `sslmode=disable`.

## Artifact storage

`storage.artifacts` mounts one PersistentVolumeClaim read-write at `/var/lib/openmettle/artifacts` in the api and worker pods. The migration Job never mounts it. PostgreSQL stores artifact metadata and accounting (core ADR 0005); the volume is for payload bytes.

- **Core uses the path (core ADR 0031, minimum `openmettle-core` commit `94d21f8`).** While enabled, the chart sets `OPENMETTLE_API_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` to `/var/lib/openmettle/artifacts`; the migration Job receives neither. At startup, before telemetry or the listener, each process requires the mount to be an existing directory (not a symbolic link), creates `staging/` and `revisions/` (mode `0700`) if absent, checks both are readable directories and `fsync`s the root. Otherwise it exits `78` with `configuration error: invalid ARTIFACTS_DIR`, so an unwritable volume shows as a crash-looping pod, never a Ready one. While disabled, neither variable is set and core opens no directory. Core `94d21f8` contains the storage engine only. From core `3613a51` (V1-15 PR2) the API serves `/v1/artifacts` multipart uploads, revisions and byte-range downloads from this store when `auth.enabled: true` is also set; uploads additionally need the operator-set storage limits in `openmettle.storage_instance`, or they answer `503 provisioning` (core ADR 0031).
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

- **Body limit.** Core refuses browser initiation bodies over 256 bytes, native token/logout form bodies over their fixed bounds, `POST /v1/runs` and `POST …/effective-configuration` bodies over 128 KiB (`131072` bytes), other `/v1/*` JSON request bodies over 64 KiB (`65536` bytes), and artifact uploads over their `max_bytes` (at most 64 MiB) (core ADRs 0018, 0027, 0029, 0031 and 0032; core README, "Authenticated application routes"). The ingress limit is defence in depth and must allow the routes you expose: `65536` refuses large run proposals. A Traefik `Middleware` in the release namespace, created by the operator:

  ```yaml
  apiVersion: traefik.io/v1alpha1
  kind: Middleware
  metadata: {name: openmettle-request-limits, namespace: openmettle}
  spec:
    buffering:
      maxRequestBodyBytes: 131072   # synthetic: POST /v1/runs bodies reach 128 KiB; raise it for uploads
  ```

  Attach it with the annotation `traefik.ingress.kubernetes.io/router.middlewares: <namespace>-openmettle-request-limits@kubernetescrd`. Never attach `StripPrefix`, `ReplacePath` or `ReplacePathRegex`: the callback path must arrive exactly as the browser sent it (ADRs 0017 and 0018).
- **Timeouts and header limits** are entry-point settings, for example `entryPoints.websecure.transport.respondingTimeouts.readTimeout`. Core's router limits a request head after it is parsed. Slow or oversized heads and idle connections are the controller's job (ADR 0018).
- **TLS** terminates at Traefik. Annotate `traefik.ingress.kubernetes.io/router.entrypoints: websecure` and `traefik.ingress.kubernetes.io/router.tls: "true"`, and redirect the plain-HTTP entry point to HTTPS controller-wide.

**SSE through Traefik.** The kind fixture uses one HTTPS entry point on port 8443. Its request read timeout and keep-alive idle timeout are 60 s, its response write timeout is 0 s (unlimited), and its upstream response-header timeout is 30 s. Core flushes a comment when the stream opens and every 15 s while quiet. Keep response buffering off for the events route. Traefik streams `text/event-stream` without a buffering middleware and forwards `X-Accel-Buffering: no`. If your request-limit middleware buffers responses, scope it to other routes. Access logs and tracing are disabled in the fixture. The individual controller flags and replay checks are in the [kind runbook](../../tests/kind/README.md#queued-run-replay-through-https-ingress).

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
| `auth.configMapName` + `auth.catalogKey` (optional) | `auth-config` | `/etc/openmettle/auth/catalog.json` | A second `items` entry of the same volume, projected as `catalog.json`; no extra volume, mount or environment variable |
| `auth.loginKeysSecretName` | `auth-login-keys` | `/etc/openmettle/auth-keys/<file>` (dir `/etc/openmettle/auth-keys`) | `defaultMode: 288` (`0440` octal) with API pod `fsGroup: 65532`: readable by UID/GID `65532`, never world-readable |
| `auth.providerCaBundle.{configMapName,key}` (optional, default `ca.crt`) | `auth-provider-ca` | `/etc/openmettle/auth-ca/ca.crt` (dir `/etc/openmettle/auth-ca`) | Projected via `items` as `ca.crt`; reference in `providers[].trust` as `{"roots": "bundle", "bundle_path": "/etc/openmettle/auth-ca/ca.crt"}` |

- **Non-overlapping sibling directories.** The three mounts sit side by side under `/etc/openmettle/` (`/etc/openmettle/auth`, `/etc/openmettle/auth-keys`, `/etc/openmettle/auth-ca`, alongside `/etc/openmettle/db-ca`). Kubernetes mounts ConfigMap volumes read-only, so nesting another volume inside `/etc/openmettle/auth` (such as `/etc/openmettle/auth/keys`) would fail container startup with `EROFS` when the runtime attempts to create the nested mountpoint. The `/etc/openmettle/auth-keys/<file>` path also matches core ADR 0015's document example.
- **Why `worker` and `migrate` never mount auth or receive OIDC egress.** Core ADRs 0025, 0027 and 0029 restrict `OPENMETTLE_API_AUTH_CONFIG` to `openmettle-api`. Neither `openmettle-worker` nor `openmettle-migrate` serves sign-in or `/v1/*` routes, reads login keys or contacts an identity provider. Keeping the ConfigMap, login-keys Secret, provider CA and `networkPolicy.api.oidc` egress rule strictly on the API pod preserves least privilege so a worker or migration job never has access to login-key material or provider reachability.
- **Session issuance credential (core ADR 0030).** Sign-in completion issues sessions on a second database pool as `openmettle_issuance`, so `auth.enabled: true` also requires `database.issuance.existingSecret` and renders `OPENMETTLE_API_ISSUANCE_DATABASE_URL` and `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS` on the API container. Both pools reach the same PostgreSQL peers, so `networkPolicy.database` needs no change. Core images before `2c62e8a` (migration 18) do not read either variable, so use matching images. See [Database roles and Secrets](#database-roles-and-secrets).
- **Strict guards.** When `auth.enabled` is true, `auth.configMapName`, `auth.loginKeysSecretName` and `database.issuance.existingSecret` are required, and while `networkPolicy.enabled` is true `networkPolicy.api.oidc.to` must list at least one OIDC provider peer (on TCP `networkPolicy.api.oidc.port`, default `443`, configurable `1`–`65535` for self-hosted providers such as Keycloak on `8443`). When `auth.enabled` is false, `auth.providerCaBundle.enabled: true`, non-empty `networkPolicy.api.oidc.to` and a non-empty `database.issuance.existingSecret` are all rejected so unused CA mounts, egress rules or credentials are never silently left behind.

### Model catalog

Fresh `POST /v1/runs` admission needs three top-level members of the version-2 `auth.json`: `catalog_file`, `admission_limits` and `cursor_keys`. Without any of them it answers `503 provisioning`. `POST …/effective-configuration` needs `catalog_file`, and without it `GET /v1/models` and `GET /v1/presets` list nothing (core README, "Model catalog and run admission limits"; core ADRs 0032 and 0036). `catalog_file` must be an absolute path to a regular file that the API reads once at startup. Put the catalog in the auth ConfigMap under its own key, and set `auth.catalogKey` to that key. The chart then projects it read-only in the `auth-config` volume as `/etc/openmettle/auth/catalog.json`, so set `"catalog_file": "/etc/openmettle/auth/catalog.json"`. An invalid or missing catalog makes `--check-auth-config` and API startup exit `78`. `auth.catalogKey` is empty by default, which leaves the render unchanged. Core has no operator reference for the catalog format; [First install](../../docs/first-install.md#model-catalog) derives a synthetic catalog from core's test fixture, as the kind smoke test does.

For `getRun` and `streamRunEvents`, configure the top-level `cursor_keys` member of the version-2 `auth.json`. Point its `active` key and any `verify_only` keys at separate raw 32-byte files under `/etc/openmettle/auth-keys`. Use distinct IDs and material for every cursor and login key (`login.keys`). All API replicas need the same signing and verification keys. The API mounts `auth.loginKeysSecretName` read-only. Worker and migration pods receive no auth key volume. See core ADRs 0015 and 0034 for rotation.

### Offline validation, rollout and prerequisites

- **Check the mounted files before rollout.** Run core's offline validator inside the exact API image (with the same mounts and environment) before rolling out (core ADRs 0015 and 0020):

  ```sh
  openmettle-api --check-auth-config /etc/openmettle/auth/auth.json
  ```

  Note that `--check-auth-config` accepts **both** version-1 and version-2 documents (because it validates files offline), whereas serving through `OPENMETTLE_API_AUTH_CONFIG` **requires a version-2 document** containing the `browser` profile and exits `78` on a version-1 document (core ADR 0025). The chart does not add a pre-upgrade `--check-auth-config` hook in I5; an invalid mounted document fails API startup with exit `78` before the listener binds.
- **No live reload.** Core reads the auth document, login keys and CA bundle once at startup (core ADR 0025). After updating the ConfigMap, Secret or provider CA bundle, restart the API Deployment (`kubectl rollout restart deployment/<fullname>-api`). For login-key rotation, follow core ADR 0015's staged procedure: add the new 32-byte key to `decrypt_only` and roll out; promote it to `active` and roll out; remove the retired key after the maximum login lifetime plus rollout overlap.
- **Database prerequisites.** Passing `--check-auth-config` validates local files only and makes no database or provider request. Before sign-in requests can succeed, provision the durable provider authority and active revision (core ADR 0012), configure the login admission limit (core ADR 0014; an unset limit refuses every initiation), and create home invitations where required (core ADR 0022). [First install](../../docs/first-install.md#10-operator-steps-on-the-fresh-database) orders these steps.
- **Mandatory exposure gates.** Enabling `auth.enabled: true` mounts sign-in routes on the API container port, but does not by itself satisfy core ADR 0025's exposure gates. Before routing external traffic to sign-in, complete the TLS, path-preservation, body-limit and verified Ingress/Traefik access-log redaction steps in [Ingress and TLS](#ingress-and-tls).
- **Optional native sign-in and `/v1/*` application routes.** When `OPENMETTLE_API_AUTH_CONFIG` is set to a version-2 document (minimum `openmettle-core` commit `adef30a`), `openmettle-api` mounts browser sign-in (core ADR 0025), the 15 authenticated `/v1/*` application operations over browser cookies with `Origin` CSRF binding (core ADR 0027), and—when the optional `"native"` profile is present in the document—the five `/auth/native/{authorize,callback,token,session,logout}` routes plus native bearer-token authentication on `/v1/*` (core ADR 0029). Sign-in routes, provider/native callbacks and same-origin app links cannot use `/healthz`, `/readyz`, `/v1` or `/v1/*`.

## Worker turn execution (`worker.inference`)

`worker.inference` exposes core ADRs 0033, 0043 and 0044's opt-in turn execution for `openmettle-worker`. It is **off by default** (`worker.inference.enabled: false`): while disabled, `openmettle-worker` runs maintenance sweeps only, no inference volumes or env vars are rendered, and leftover `configMapName`, `caBundle.enabled: true` or non-empty `networkPolicy.worker.inference.to` are refused.

- **ConfigMap projection (worker only).** `worker.inference.configMapName` names an existing ConfigMap holding both the ADR 0043 inference document (`configKey`, default `inference.json`) and the model catalog (`catalogKey`, default `catalog.json`, which must differ from `configKey`). Both keys are projected read-only via `items` (no `subPath`) into volume `inference-config` at `/etc/openmettle/inference`, setting `OPENMETTLE_WORKER_INFERENCE_CONFIG=/etc/openmettle/inference/inference.json` on `worker` only. Set `"catalog_file": "/etc/openmettle/inference/catalog.json"` inside `inference.json`.
- **Optional CA bundle at sibling path `/etc/openmettle/inference-ca/ca.crt`.** When `worker.inference.caBundle.enabled` is true, one key of an existing ConfigMap is projected read-only as `ca.crt` into volume `inference-ca` at `/etc/openmettle/inference-ca` on `worker` only (non-overlapping sibling of `/etc/openmettle/inference`, `/etc/openmettle/db-ca` and `/etc/openmettle/otlp-ca`). Reference it inside `inference.json` as `"trust": {"roots": "bundle", "bundle_path": "/etc/openmettle/inference-ca/ca.crt"}`. No extra env var is emitted.
- **Run-claim settings and poll interval.** When `worker.inference.enabled` is true, `worker.inference.settings` emits `OPENMETTLE_WORKER_RUN_SLOTS`, `OPENMETTLE_WORKER_LEASE_MS`, `OPENMETTLE_WORKER_EXECUTION_TIMEOUT_MS`, `OPENMETTLE_WORKER_EXECUTING_PER_ACTOR` and `OPENMETTLE_WORKER_EXECUTING_PER_SCOPE` on `worker` only (never `api`, `gateway` or `migrate`). Render guards enforce core's bounds: `leaseMs >= 6 * worker.settings.dbTimeoutMs` and `executionTimeoutMs >= 2 * leaseMs`. Independently, `worker.pollMs` (`100`–`60000`, default `null`) emits `OPENMETTLE_WORKER_POLL_MS` on `worker` only when non-null.
- **Worker-only egress.** While `worker.inference.enabled` and `networkPolicy.enabled` are both true, `networkPolicy.worker.inference.to` must list the in-cluster `openmettle-gateway` pods or external TLS terminator on TCP `networkPolicy.worker.inference.port` (default `8082`, or e.g. `8443`/`443` for a TLS terminator). Neither `api` nor `migrate` receives this egress rule. Core reads the inference config, catalog and CA bundle once at startup; restart the worker Deployment after updating the ConfigMaps.

## Inference proxy (`gateways`) and external TLS termination

`gateways` packages `0..N` per-model `openmettle-gateway` workloads (core ADR 0044, [`docs/operator/gateway-proxy.md`](https://github.com/OpenMettle/openmettle-core/blob/87a395e25e26f2e83c7ba34cc40561a0acf92b09/docs/operator/gateway-proxy.md)). It is **empty by default** (`gateways: {}`): while empty, no gateway Deployments, Services, ServiceAccounts or NetworkPolicies render, and `images.gateway` and `database.gateway.existingSecret` must stay empty.

- **One gateway Deployment per served model.** Each map entry `gateways.<name>` (`^[a-z0-9]([-a-z0-9]{0,30}[a-z0-9])?$`, rendered in deterministic `sortAlpha` order as `<fullname>-gateway-<name>`) declares a unique `model` (`1..=128` UTF-8 bytes; the chart escapes any literal `$` as `$$` when emitting `OPENMETTLE_GATEWAY_MODEL` so Kubernetes `EnvVar` `$(VAR)` expansion delivers the exact `model` string to `openmettle-gateway`) and a canonical plain-HTTP `upstreamUrl` (`http://host[:port][/]`, accepting DNS/IPv4 hostnames including a single trailing `.` or RFC 4291 bracketed IPv6 literals, while additionally rejecting empty DNS labels such as leading `.` or `..`—no `https://`, userinfo, path, query or fragment). Each instance gets its own Deployment, ClusterIP Service (`service.port` → `8082`), ServiceAccount, and NetworkPolicy.
- **Strict environment and mount isolation.** Each gateway container receives only `OPENMETTLE_GATEWAY_*` environment variables (`BIND`, `DATABASE_URL` from `database.gateway`, `DB_MAX_CONNECTIONS`, `DB_TIMEOUT_MS`, `SHUTDOWN_TIMEOUT_MS`, `MODEL`, `UPSTREAM_URL`, `CACHE_MODE`, `UPSTREAM_CONNECT_TIMEOUT_MS`, `UPSTREAM_IDLE_TIMEOUT_MS`, plus optional `LOG_*` and `OTLP_*`), and mounts only optional `db-ca` and `otlp-ca` ConfigMaps—never `artifacts`, `auth-*` or `inference-*`.
- **Cache isolation mode.** `settings.cacheMode` defaults to `scoped` (deriving a 64-char hex `cache_salt` per authorized scope/owner/model); set `per_request` to generate a fresh `cache_salt` per request.

`openmettle-gateway` serves plain HTTP on port `8082`. Choose one of the two transport topologies described in core `docs/operator/gateway-proxy.md`:

1. **In-cluster plain HTTP under enforced CNI `NetworkPolicy` (default `ingressFrom: null`).** Leave `gateways.<name>.networkPolicy.ingressFrom` unset (`null`) so `<fullname>-gateway-<name>` accepts TCP `8082` **only** from this release's `worker` pods. Point `networkPolicy.worker.inference` at the gateway pod selector on port `8082`, and point `inference.json` at `http://<fullname>-gateway-<name>.<namespace>.svc.cluster.local:8082/v1/chat/completions` with `private_cidrs` covering the cluster Service/pod CIDRs (and omitting `trust`, which core refuses on `http://` routes). Verify CNI enforcement (and CNI WireGuard/IPsec encryption if multi-node traffic crosses hosts).
2. **External TLS terminator (for example Traefik) fronting `openmettle-gateway`.** Create a TLS `Ingress` (or equivalent terminator route) for the gateway Service outside the chart, set `gateways.<name>.networkPolicy.ingressFrom` to select **only** the TLS terminator's pods (blocking direct `worker` → `gateway:8082` connections so traffic cannot bypass TLS), point `networkPolicy.worker.inference` at the terminator on its HTTPS port (e.g. `8443` or `443`), mount the terminator's CA via `worker.inference.caBundle` (`/etc/openmettle/inference-ca/ca.crt`), and configure `inference.json` with `https://<terminator-host>:<port>/v1/chat/completions`, `private_cidrs`, and `"trust": {"roots": "bundle", "bundle_path": "/etc/openmettle/inference-ca/ca.crt"}`.
   - **Mandatory TLS-terminator controls (outside the chart).** The terminator receives per-round `Authorization: Bearer` tokens and inference request/response bodies. Configure the terminator to **drop `Authorization` and request/response bodies from access logs and traces** (matching the Traefik flags in [Ingress and TLS](#ingress-and-tls)), **forward `Authorization` and `x-request-id` unchanged** over HTTP/1.1 to `<fullname>-gateway-<name>:8082`, **keep response buffering off** for SSE streams, and set response/idle timeouts at least as high as `gateways.<name>.settings.upstreamIdleTimeoutMs`.

## Credential vault (`vault`) and worker MCP egress (`worker.mcp`)

`vault` packages core ADR 0045 (`V1-28`, [`docs/operator/credential-vault-and-key-recovery.md`](https://github.com/OpenMettle/openmettle-core/blob/87a395e25e26f2e83c7ba34cc40561a0acf92b09/docs/operator/credential-vault-and-key-recovery.md)) and `worker.mcp` packages worker-only external MCP and OAuth token-refresh egress (`V1-14`). Both are **off by default**.

- **Why `stage-vault-keys` stages keys into a RAM `emptyDir` (`0400`).** Core's `VaultKeyRing::load_from_config` (`src/vault.rs`) enforces strict owner-only permissions (`(mode & 0o077) == 0`, e.g. `0400`) on every 32-byte key file. Under Kubernetes `PodSecurity: restricted` (`runAsUser: 65532`), kubelet mounts Secret volumes owned by `root:65532` with `defaultMode: 0440` (group-readable, which core refuses) and atomic `..data` symlinks. When `vault.enabled` is true, `api` and `worker` pods run an unprivileged `stage-vault-keys` initContainer (reusing the component's own digest-pinned image) that copies non-dotfile entries from the read-only `0440` Secret mount into a `keys/` subdirectory inside a `1Mi` RAM-backed `emptyDir` (`medium: Memory`) via `cp -L` and `chmod 0400`, owned by UID `65532` (`chmod 0700` on `keys/` avoids `EPERM` on kubelet's root-owned `emptyDir` mountpoint). The main `api` and `worker` containers mount only that staged `keys/` directory read-only (`subPath: keys`) at `/etc/openmettle/vault-keys` and never mount the raw `vault-keys-secret` volume, setting `OPENMETTLE_API_VAULT_KEYS_CONFIG` and `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` to `/etc/openmettle/vault-keys/<vault.configKey>` (default `keyring.json`).
- **Role and key-custody isolation.** `vault` mounts and env vars reach `api` and `worker` only—never `gateway`, `migrate` or `backup`. Render guards refuse `vault.existingSecret`, `auth.loginKeysSecretName` or `backup.existingKeysSecret` matching one another or any configured `database.<role>.existingSecret`, so database URL Secrets can never be mounted or staged wholesale into keyring directories.
- **Rotation trade-off (no kubelet hot-reload).** Because keys are copied once at pod start into RAM `emptyDir` (verifying that no dot-prefixed Secret entries exist and every 32-byte key file referenced by the keyring manifest is present) and core reads the keyring once at startup, rotating `vault.existingSecret` requires a rolling restart (`kubectl rollout restart deployment/<fullname>-api deployment/<fullname>-worker`). Follow core ADR 0045's staged rotation order (add new key -> roll out -> promote `active_key_id` -> roll out -> re-encrypt with `openmettle-admin vault rotate` -> remove retired key).
- **Worker-only external MCP/OAuth egress and CA bundle (`worker.mcp`).** External MCP server definitions and OAuth `refresh_routes` live inside `inference.json`, so `worker.mcp.enabled: true` requires `worker.inference.enabled: true`. While enabled, `networkPolicy.worker.mcp.to` (required non-empty while `networkPolicy.enabled` is true) allows worker-only TCP egress across `networkPolicy.worker.mcp.ports` (default `[443]`, `1..16` unique ports). Optionally set `worker.mcp.caBundle.enabled: true` to project a private CA bundle read-only at `/etc/openmettle/mcp-ca/ca.crt` on `worker` only (non-overlapping sibling of `/etc/openmettle/inference-ca`). Neither `api`, `gateway`, `migrate` nor `backup` receives MCP egress or the MCP CA bundle.

## Coordinated maintenance-window backup (`backup`)

`backup` packages core ADR 0046 (`V1-30`, [`docs/operator/maintenance-backup-and-recovery.md`](https://github.com/OpenMettle/openmettle-core/blob/87a395e25e26f2e83c7ba34cc40561a0acf92b09/docs/operator/maintenance-backup-and-recovery.md)) as an opt-in `batch/v1` `CronJob` (`<fullname>-backup` when `<= 52` characters, or a deterministic `<36-char-prefix>-<8-hex-sha256>-backup` name within Kubernetes' 52-character `CronJob` limit for longer release names), off by default.

- **Two-image runtime (`images.admin` + `images.postgresClient`) under `PodSecurity: restricted`.** `openmettle-admin backup capture` requires a PostgreSQL 18 `pg_dump` binary on `PATH` and `openmettle_owner` access via `OPENMETTLE_ADMIN_DATABASE_URL`. Because core's `admin` image (`debian:bookworm-slim`) carries only `openmettle-admin` (no `pg_dump`), the CronJob runs an unprivileged `prepare-backup-runtime` initContainer (`images.admin`, digest-pinned) that copies `/usr/local/bin/openmettle-admin` into a shared `128Mi` `emptyDir`, stages and validates `backup.existingKeysSecret` into `0400` regular files inside a `1Mi` RAM `emptyDir` (`subPath: keys`, exiting `78` on dot-prefixed entries or missing/non-32-byte key files), and dereferences `database.caBundle` (and any `backup.configBundle` ConfigMap files) via `cp -L` into regular files inside memory `emptyDir`s so core's strict `O_NOFOLLOW` file opens succeed (ConfigMap mounts use Kubernetes `..data` symlinks). The main `backup` container then runs `/opt/openmettle-bin/openmettle-admin backup capture ...` inside the digest-pinned `images.postgresClient` container (such as `docker.io/library/postgres:18.1-bookworm@sha256:...` or a minimal Debian Bookworm `postgresql-client-18` image matching core's Bookworm glibc ABI).
- **Concurrency, retries, timeouts and Job-stable request keys.** `concurrencyPolicy: Forbid`, `backoffLimit: 0`, and `podFailurePolicy` failing immediately if `prepare-backup-runtime` exits `78` guarantee that overlapping schedules never race and failed captures never blindly retry. Each Job derives a Job-stable idempotency key from its `batch.kubernetes.io/controller-uid` label (`OPENMETTLE_BACKUP_JOB_UID` -> `--request-key cronjob-$(OPENMETTLE_BACKUP_JOB_UID)`), so if Kubernetes ever starts a replacement Pod for the same Job after PostgreSQL staged `publishing`, the replacement Pod replays the exact same request key and finishes publication cleanly. To finish an interrupted `publishing` run manually from a new Job, core requires replaying **all four** original capture identity fields (`--request-key`, `--operator-id`, `--destination-domain`, and `--reason`—not only `--request-key`, because `openmettle-admin backup status` omits `request_key` and a subsequent `helm upgrade` may have changed `backup.{operatorId,destination.domain,reason}`). Recover those four values either from the retained failed Kubernetes `Job` (`kubectl -n <ns> get job <failed-job> -o json`, reading `cronjob-` + `metadata.labels["batch.kubernetes.io/controller-uid"]` and `spec.template.spec.containers[0].args`) or, as `openmettle_owner`, from PostgreSQL (`SELECT id, request_key, operator_id, destination_domain, manifest_summary->>'reason' AS reason FROM openmettle.backup_runs WHERE state = 'publishing';`). Then render a one-off Job (`kubectl -n <ns> create job backup-finish --from=cronjob/<cronjob-name> --dry-run=client -o json`), set `--request-key`, `--operator-id`, `--destination-domain`, and `--reason` (escaping any literal `$` as `$$` for Kubernetes `args` expansion) to those exact recorded values, and apply it. `backup.activeDeadlineSeconds` (default `3600`) must exceed `backup.drainTimeoutSecs` (default `300`). `backup.reason` and `backup.chroma.qualificationRef` escape literal `$` as `$$` so Kubernetes `EnvVar` expansion never alters audit text.
- **Credentials, storage and network isolation.**
  - `OPENMETTLE_ADMIN_DATABASE_URL` comes from `database.backup` (an `openmettle_owner` login Secret; may reuse `database.migrate`, never `api`/`worker`/`issuance`/`gateway`). Core holds up to `3` connections (`2` SQLx + `1` `pg_dump`), counted in `database.connectionBudget`.
  - `backup.existingKeysSecret` is staged to `0400` in RAM at `/etc/openmettle/backup-keys/<backup.keysConfigKey>` (default `keyring.json`) and must differ from `vault.existingSecret`, `auth.loginKeysSecretName`, and every `database.<role>.existingSecret` (separate key custody).
  - `/tmp` is backed by a `64Mi` RAM `emptyDir` (`medium: Memory`) so ephemeral `PGPASSFILE` and strict-TLS Unix-socket directories never touch node disk.
  - When `storage.artifacts.enabled` is true, the artifact PVC is mounted **read-only** at `/var/lib/openmettle/artifacts` and passed via `--artifact-root`.
  - `backup.destination.existingClaim` must be a pre-existing isolated PVC distinct from `storage.artifacts` (and any Graphiti/Chroma claims). `backup.destination.requireSeparateDevice` defaults to `true` (passing `--require-separate-device` so core verifies distinct filesystem devices); set it to `false` only on single-node dev/smoke clusters where PVCs share one backing host filesystem.
  - `<fullname>-backup` receives its own `ServiceAccount` (`automountServiceAccountToken: false`) and a `NetworkPolicy` allowing **DNS and PostgreSQL egress only** (zero ingress; no OIDC, inference, MCP or OTLP egress).
- **Maintenance-window failure safety.** When `backup.releaseOnSuccess` is `true` (default), `openmettle-admin` passes `--release-on-success` and releases the maintenance window only after verified publication succeeds. Note that preflight validation failures exit *before* core mutates the maintenance gate (preserving the prior `maintenance_active` state, which may already be `true` from an earlier window), whereas failures after admission closes (drain timeout, accounting drift, destination I/O failure, or an interrupted lease) intentionally leave `openmettle.backup_maintenance_gate.maintenance_active = true`. Always inspect the failed Job (`kubectl logs job/<name>`) and check `openmettle-admin backup status` first before retrying a `publishing` run or running `openmettle-admin backup release-maintenance` per core's `docs/operator/maintenance-backup-and-recovery.md`. Use `backup.suspend: true` to deploy the CronJob without automatic triggers and run on-demand captures with `kubectl create job <job-name> --from=cronjob/<cronjob-name>`.

## Telemetry / OTLP trace and metrics export

`telemetry` exposes core ADR 0024's structured stderr logging settings across all roles and core ADRs 0026 and 0028's opt-in OTLP/HTTP protobuf trace and metrics export for `openmettle-api`, `openmettle-worker` and every configured `openmettle-gateway` (never `openmettle-migrate`). Both leave default renders completely unchanged (`telemetry.logging.{format,level}: null` and `telemetry.otlp.enabled: false`).

### Structured logging (`telemetry.logging`, all roles)

- When `telemetry.logging.format` is set (`"json"` or `"text"`), the chart emits `OPENMETTLE_API_LOG_FORMAT`, `OPENMETTLE_WORKER_LOG_FORMAT`, `OPENMETTLE_MIGRATE_LOG_FORMAT` and (when `gateways` is non-empty) `OPENMETTLE_GATEWAY_LOG_FORMAT`. When `null`, no `LOG_FORMAT` variable is emitted and core defaults to `json`.
- When `telemetry.logging.level` is set (`"error"`, `"warn"`, `"info"` or `"debug"`), the chart emits `OPENMETTLE_API_LOG_LEVEL`, `OPENMETTLE_WORKER_LOG_LEVEL`, `OPENMETTLE_MIGRATE_LOG_LEVEL` and (when `gateways` is non-empty) `OPENMETTLE_GATEWAY_LOG_LEVEL`. `"trace"` is intentionally refused (core ADR 0024). When `null`, no `LOG_LEVEL` variable is emitted and core defaults to `info`.
- Structured logs are written to stderr for node-level collection and are never exported over OTLP.

### OTLP trace and metrics export (`telemetry.otlp`, `api`, `worker` and `gateways`)

- **Off by default.** While `telemetry.otlp.enabled` is `false`, no `OTLP_*` variables, CA bundle mounts or collector egress rules are rendered. Leftover `tracesEndpoint`, `metricsEndpoint`, non-empty `privateRanges`, `caBundle.enabled: true` and non-empty `networkPolicy.telemetry.otlp.to` are all refused while `telemetry.otlp.enabled` is `false`, matching core ADRs 0026 and 0028 that a set key is never silently ignored.
- **Traces, metrics or both over HTTPS.** While `telemetry.otlp.enabled` is `true`, set `tracesEndpoint`, `metricsEndpoint` or both (rendering fails if both are empty; only non-empty endpoints emit `OPENMETTLE_{API,WORKER,GATEWAY}_OTLP_{TRACES,METRICS}_ENDPOINT`). Each non-empty endpoint must be a canonical `https://` URL with a lowercase DNS host (at least two labels; final label neither all-digits nor `0x`/`0X`-hex per WHATWG URL rules, no `http://`, no IP literal, no credentials, no query, fragment, percent-encoding, dot-segments or explicit `:443`). Core sends OTLP/HTTP protobuf (`application/x-protobuf`) over its bounded HTTP/1.1 transport with no proxy, redirect, retry or collector authentication header, sharing one random per-process UUIDv4 `service.instance.id` across trace and metric exports (core ADR 0028).
- **In-cluster collectors and `privateRanges`.** Core refuses private IP answers by default (core ADR 0010). Helm and the values schema check CIDR syntax, uniqueness and count (`<= 32`), while `openmettle-core` enforces canonical host-bit masking and RFC 1918 / CGNAT / ULA private-range membership fail-closed at startup (exit `78`). For an in-cluster collector such as Grafana Alloy on TCP `4318`, `telemetry.otlp.privateRanges` (emitted comma-joined as `OPENMETTLE_{API,WORKER,GATEWAY}_OTLP_PRIVATE_RANGES`) must cover the address DNS resolves to (typically the Service ClusterIP CIDR), while `networkPolicy.telemetry.otlp.to` and `networkPolicy.telemetry.otlp.port` (default `4318`) are evaluated post-DNAT against the collector pods and their target port. `networkPolicy.telemetry.otlp.{to,port}` is shared across traces and metrics: when `networkPolicy.enabled` is `true` and both `tracesEndpoint` and `metricsEndpoint` are set, both endpoints must be reachable through that single `to`/`port` rule (pointing one signal at a different collector or port will be blocked by default-deny egress and logged at runtime as `telemetry.dropped`).
- **Optional CA bundle at sibling path `/etc/openmettle/otlp-ca/ca.crt`.** When `telemetry.otlp.caBundle.enabled` is `true`, the chart mounts one key of a pre-existing ConfigMap read-only at `/etc/openmettle/otlp-ca` (volume `otlp-ca`, projected via `items` as `ca.crt`, no `subPath`) in `api`, `worker` and `gateway` pods only, and sets `OPENMETTLE_{API,WORKER,GATEWAY}_OTLP_CA_FILE=/etc/openmettle/otlp-ca/ca.crt`. Sitting at `/etc/openmettle/otlp-ca` keeps it a non-overlapping sibling of `/etc/openmettle/db-ca`, `/etc/openmettle/auth`, `/etc/openmettle/auth-keys`, `/etc/openmettle/auth-ca`, `/etc/openmettle/inference` and `/etc/openmettle/inference-ca`. The chart never creates ConfigMaps or Secrets.
- **Why `migrate` is excluded.** `openmettle-migrate` is a one-shot stderr-only process (core ADR 0026) and never reads `OTLP_*` variables. It never receives `OPENMETTLE_MIGRATE_OTLP_*` env vars, never mounts `otlp-ca`, and `<fullname>-migrate` never receives OTLP egress.
- **No probe spans, no ambient `OTEL_*`, no live reload, no bundled collector.** Core never exports spans for `/healthz` or `/readyz`, ignores inbound `traceparent`/`tracestate`, and neutralizes ambient `OTEL_*` environment variables (core ADR 0026). The chart sets no `OTEL_*` variables and deploys no collector; Grafana Alloy or another OTLP/HTTP collector is provisioned separately. Core reads `OTLP_CA_FILE` once at startup—after rotating the collector CA ConfigMap, restart `api`, `worker` and any `gateway` Deployments.

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

### Kind smoke test

[`tests/kind/smoke.py`](../../tests/kind/README.md) installs the chart on an ephemeral kind cluster (Kubernetes 1.37.0, kind v0.33.0; core's pins). It uses core images (`api`, `worker`, `migrate`, `gateway` and `admin`) built from the pinned core commit `87a395e` (`CORE_COMMIT`), referenced by digest, plus core's pinned `postgres:18.1-bookworm` image as `images.postgresClient`, and a synthetic PostgreSQL fixture with all five login roles of [Database roles and Secrets](#database-roles-and-secrets). It checks these acceptance items against live state:

| Item | Smoke-tested |
| --- | --- |
| `api`, `worker`, `migrate`, `gateway` and `admin` images install by digest | Yes (digests read back from the node's containerd and verified via CRI) |
| Migration hook completes before the Deployments roll out | Yes (under namespace default-deny; verifies history through migration `45`, migrations `19/20/37` and `38–45` role boundaries—including `runtime_feature_gates`, `restore_reconciliation_gate`, `deletion_journal`, column-scoped `external_connections`, and `SECURITY DEFINER`-only `backup_*` access—and fresh-install quota/artifact-volume markers) |
| API and worker Ready; `/readyz` 200 | Yes |
| Worker scales to 2 while the API stays at 1 | Yes, through `worker.replicas` |
| No optional package present on default install | Yes (no Ingress, PVC, PDB, CronJob, gateway Deployment/Service/ServiceAccount/NetworkPolicy; `/auth/*` and `/v1/*` including quota routes answer `404`; no `*ISSUANCE*`, `*INFERENCE*`, `*VAULT*` or `*GATEWAY*` env vars) |
| Same-digest `helm upgrade` reruns migrate as a no-op and stays Ready | Yes |
| Enabled-profile upgrade (`api.replicas: 2`, API PDB, `storage.artifacts` RWO PVC, `telemetry.logging` `json`/`debug`, `auth.enabled: true` with `browser` + `native` v2 profile, `auth.catalogKey` and `database.issuance`) | Yes (rollout, `/healthz` + `/readyz` 200, PDB, Bound PVC + `staging/`/`revisions/` `0700` owned by 65532, API-only `auth` + `issuance` isolation, `--check-auth-config`, live `/auth/*` + `/v1/*` + quota 401 posture, `/v1/artifacts` upload/retry/revision/byte-range round trip across both API pods, catalog-backed `POST /v1/runs` admit/replay/cancel, and ADR 0024 JSON/debug logs) |
| Queued-run SSE through Traefik with TLS, two API replicas and worker expiry | Yes (periodic heartbeats, resume across API replacement, worker queue expiry, terminal replay and past-terminal `204`) |
| `gateways` + `worker.inference` end-to-end turn execution (both plain-HTTP in-cluster and external Traefik TLS terminator with `worker.inference.caBundle` and `ingressFrom` enforcement) | Yes (synthetic SGLang stand-in; verifies worker/gateway mounts and isolation, ADR 0024 JSON gateway logs, live `NetworkPolicy` blocking non-worker pods in plain mode and direct worker-to-gateway connections in TLS mode, succeeded run + assistant output, stripped `Authorization` + 64-hex `cache_salt` upstream, and settled `gateway_requests`, `gateway_usage_reports` and `quota_reservations` rows in PostgreSQL) |
| Opt-in `vault` RAM-staged `0400` keys + `backup` `CronJob` manual capture and offline `openmettle-admin backup verify` | Yes (distinct vault/backup Secrets and backup destination PVC; verifies `stage-vault-keys` `0400` regular files owned by `65532` on `api`/`worker` and gateway isolation, `CronJob` + DNS/DB-only `NetworkPolicy`, manual `kubectl create job --from=cronjob/...` capture completing with `backup.capture_succeeded`, `openmettle.backup_runs` `succeeded` + `maintenance_active = false`, and an offline `PodSecurity: restricted` `openmettle-admin backup verify` Job verifying all 5 encrypted components and 2 artifact revisions) |
| `helm uninstall` leaves no non-kept release objects | Yes (release Deployments, CronJob, Services, EndpointSlices, NetworkPolicies and PDB removed; chart-owned artifact PVC kept via `helm.sh/resource-policy: keep`; test-owned Secrets, ConfigMaps, backup destination PVC and `default-deny` untouched) |
| App namespace enforces Pod Security `restricted` | Yes |
| NetworkPolicy enforced under namespace default-deny | Yes |
| Database CA against TLS PostgreSQL, multi-node/drain eviction, `ReadWriteMany` storage | No (render tests and kubeconform only; owner's qualification) |
| Live OIDC provider exchange (`networkPolicy.api.oidc`), external MCP servers (`worker.mcp`) and OTLP collector export (`telemetry.otlp`) | Render tests and kubeconform here; core's `oidc-qualification.yml` and `telemetry-qualification.yml` separately qualify Keycloak and Alloy/Prometheus; owner cluster qualification remains separate |
| Core registry pulls, site ingress, live GPU/SGLang backend, separate-device off-host backup PVC, isolated restore drill (`V1-31`) and multi-node scheduling | No (owner's qualification / `V1-31` follow-up) |

The workflow ([`kind-smoke.yml`](../../.github/workflows/kind-smoke.yml)) runs on pull requests and pushes to `main` that touch `CORE_COMMIT`, the chart or the harness, and on manual dispatch; see [`tests/kind`](../../tests/kind/README.md). The chart policy tests also check chart defaults against a byte-verified copy of core's `runtime/process-contract.json` (`tests/fixtures/core/`) for `api`, `worker` and `gateway`. The chart's default ServiceAccount names (`<fullname>-api`, `<fullname>-worker`, `<fullname>-gateway-<name>`) differ from the contract's example names (`openmettle-api`, `openmettle-worker`, `openmettle-gateway`); set `serviceAccount.name` to use those.

## Pending

- **V1-31 isolated restore drill & recovery runbook (`openmettle-deploy#3`):** full isolated restore drill automation and Kubernetes operator recovery runbook building on this `backup` `CronJob` packaging.
- **Owner cluster qualification:** live verification of the database CA against TLS-enabled PostgreSQL (including `backup` `CronJob` `O_NOFOLLOW` `sslrootcert` staging), the API PDB during a real node drain, `ReadWriteMany` multi-node artifact storage, separate-device off-host backup storage (`requireSeparateDevice: true`), site Ingress and gateway TLS-terminator access-log redaction ([acceptance check](#ingress-and-tls)), live OIDC provider exchange (`networkPolicy.api.oidc`, `auth.providerCaBundle`), external MCP/OAuth egress (`worker.mcp`), and chart-installed OTLP export (`telemetry.otlp`) against the owner's cluster.
- **V1-06 live model-server qualification:** `openmettle-gateway` and `worker.inference` are packaged as opt-in workloads in `charts/openmettle-core` and smoke-tested against a synthetic SGLang stand-in; qualification against a live SGLang / GPU model server remains separate.
- **V1-20 (managed inference model servers, accelerated tools):** separate charts and releases, never subcharts of core.
- Releases, live rollouts and qualification on the owner's cluster remain owner actions.
