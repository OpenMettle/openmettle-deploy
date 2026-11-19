# openmettle-core chart

CPU-only packaging for the OpenMettle core API, worker and schema migration. This is V1-32 increment I1, the **render contract**: templates, the values schema, security defaults and render-time tests. The chart has not been installed on any cluster yet. A successful render is not application acceptance or qualification.

## What it renders

| Resource | Name | Notes |
| --- | --- | --- |
| Deployment | `<fullname>-api` | Port 8080 (`http`); liveness `/healthz`, readiness `/readyz` |
| Deployment | `<fullname>-worker` | Port 8081 (`http`); same probes; no Service |
| Service | `<fullname>-api` | ClusterIP; `api.service.port` → named port `http` |
| ServiceAccount | `<fullname>-api`, `<fullname>-worker` | One per component; no token mounted |
| ServiceAccount | `<fullname>-migrate` | Hook, weight `-10` |
| Job | `<fullname>-migrate` | Hook, weight `0`; see [Schema migration](#schema-migration) |

`<fullname>` is the release name if it already contains `openmettle-core`, otherwise `<release>-openmettle-core`, truncated to 52 characters. The chart creates no Namespace, Secret, RBAC object, CRD, device request or `resource.k8s.io` object. All resources are namespaced; set the namespace with `--namespace`.

## Values contract

[`values.schema.json`](values.schema.json) (JSON Schema draft 2020-12) rejects unknown keys at every level, so an unsupported key such as `oidc:` fails the render instead of being ignored. `affinity` is the only pass-through: its top-level keys are checked and Kubernetes validates the nested structure. Integer bounds copy core's (`src/lib.rs`, `src/migrate.rs`).

The chart refuses to render until you supply:

- `images.{api,worker,migrate}.repository` and `.digest`. Images render as `[registry/]repository@sha256:<digest>`. Tags are not accepted in either field. `registry` is optional. The migrate image is not needed when `migration.enabled` is false.
- `database.{api,worker,migrate}.existingSecret`: names of existing Secrets. Each holds a full `postgres://` URL under `key` (default `url`). The migrate Secret is not needed when `migration.enabled` is false.

| Key | Default | Meaning |
| --- | --- | --- |
| `images.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `images.pullSecrets` | `[]` | Names of existing pull Secrets |
| `images.<component>.{registry,repository,digest}` | `""` | See above |
| `database.<component>.{existingSecret,key}` | `""`, `url` | See above |
| `database.connectionBudget` | `null` | Optional; see [Connection budget](#connection-budget) |
| `api.replicas`, `worker.replicas` | `1` | Independent |
| `api.resources`, `worker.resources` | requests `100m` CPU, `64Mi` | Core's contract examples, not qualified sizing. Only `cpu`, `memory` and `ephemeral-storage` are accepted. |
| `<component>.serviceAccount.{create,name,annotations}` | `true`, `""`, `{}` | `name` is required when `create` is false; components never share a ServiceAccount |
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
| `migration.activeDeadlineSeconds` | `900` | Job deadline |
| `migration.resources`, `migration.serviceAccount` | `{}`, created | As above |

`<component>` is `api` or `worker`; `<ROLE>` is `API` or `WORKER`.

Every process gets an explicit environment: `BIND` (`0.0.0.0:8080` or `0.0.0.0:8081`; core otherwise binds loopback), `DATABASE_URL` from its own Secret through `secretKeyRef`, and the settings above. The chart never uses `envFrom`. Each variable carries its own component prefix, as core ADR 0002 requires. Set `sslmode` explicitly in every URL, because SQLx defaults to `prefer`, which permits plaintext fallback. Readiness `timeoutSeconds` is `ceil(dbTimeoutMs / 1000) + 1`, because `/readyz` waits up to the database timeout.

Keep site values in a private overlay outside this repository and pass it with `-f`. The synthetic files under `tests/chart/values/` use reserved `example.test` names and all-zero digests; they render but cannot be installed.

### Connection budget

Core ADR 0003 bounds PostgreSQL connections at the server. When `database.connectionBudget` is set, rendering fails unless

`(api.replicas + api.maxSurge) × api.dbMaxConnections + (worker.replicas + worker.maxSurge) × worker.dbMaxConnections + 1 (migrator) ≤ connectionBudget`.

Set it to the connections available to this release, after subtracting reserved and administrative or backup headroom. The check covers configured pools only. Enforce each role's share in PostgreSQL with `CONNECTION LIMIT`; the chart does not manage roles.

## Security defaults

These are fixed and are not values:

- Pod: `runAsNonRoot`, `runAsUser`/`runAsGroup` 65532 (the core image user), seccomp `RuntimeDefault`. No `fsGroup`, because the chart mounts no storage yet.
- Container: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, `privileged: false`. No volumes are mounted.
- `automountServiceAccountToken: false` on every ServiceAccount and every pod, plus `enableServiceLinks: false`. The processes never call the Kubernetes API, so the chart creates no RBAC.
- Credentials come only from existing Secrets. The owner credential reaches only the migration Job. The chart never uses `lookup`.
- `/healthz` and `/readyz` are unauthenticated. The Service is ClusterIP only, and the chart has no Ingress yet.

## Schema migration

Core runs migrations once per release, before new API and worker pods start (core ADR 0003). The chart does this with a Helm hook Job:

- `helm.sh/hook: pre-install,pre-upgrade`. Helm creates or updates the Deployments only after the Job succeeds. Hooks run before ordinary resources, so the migrate ServiceAccount is a hook too, at a lower weight.
- `before-hook-creation,hook-succeeded` delete policy. A successful run leaves nothing behind. A failed Job and its ServiceAccount stay for diagnosis, and the next install or upgrade replaces them.
- `restartPolicy: Never`, `backoffLimit: 2`, `activeDeadlineSeconds` from values. A `podFailurePolicy` fails the Job immediately on exit 78 (invalid configuration). Exit 1, for example a lock timeout, may retry.
- **No rollback hook.** Migrations are forward-only, and an older binary refuses a newer schema. Recovery from a bad release is a corrective forward release or a restore (V1-30/V1-31), not `helm rollback` across a schema change.

`helm template` and `--dry-run` do not run hooks. `--no-hooks` skips the migration, and the new pods then start against the old schema.

**Out of band:** set `migration.enabled: false` to render no Job, no migrate ServiceAccount and no owner-Secret reference. You must then run the migrate image once per release, with `OPENMETTLE_MIGRATE_DATABASE_URL` set to the owner URL, and let it complete successfully before upgrading API and worker. Database roles and the database itself are provisioned outside the chart (core ADR 0003 and README).

## Validation

```sh
bash tests/chart/render.sh                    # helm lint, render matrix, kubeconform
python3 -m unittest discover -s tests/chart -v  # policy, negative-case and contract tests
```

Tested on: Helm 4.3.0 and kubeconform 0.8.0, with Kubernetes 1.37.0 schemas (the kind node version pinned by core). These are test pins, not a compatibility claim. The chart sets no `kubeVersion` floor. The tests check chart defaults against a byte-verified copy of core's `runtime/process-contract.json` (`tests/fixtures/core-5cd8a9d/`). The chart's default ServiceAccount names (`<fullname>-api`) differ from the contract's example names (`openmettle-api`); set `serviceAccount.name` to use those.

## Pending

- **I2:** kind smoke test: install with migrations, readiness, worker scaling, idempotent upgrade and clean uninstall. Also confirms hook ordering under Helm 4.3 `--wait`.
- **I3:** NetworkPolicies (chart-scoped deny-all, per-component allows).
- **I4:** artifact PVC, database CA mount, Ingress and TLS, PodDisruptionBudget, a synthetic example profile and overlay documentation. All will be off by default.
- **I5 / V1-04:** OIDC and auth settings, login key mounts, a `--check-auth-config` hook and identity-provider egress. No auth values are accepted yet.
- **V1-20** (managed inference, accelerated tools) and **V1-06** (external providers or gateway): separate charts and releases, never subcharts of core.
- Qualification on the owner's cluster is an owner action.
