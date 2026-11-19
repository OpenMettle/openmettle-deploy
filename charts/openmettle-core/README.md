# openmettle-core chart

CPU-only packaging for the OpenMettle core API, worker and schema migration. Increment I1 of V1-32 is the **render contract**: templates, the values schema, security defaults and render-time tests. I2 adds a **kind install smoke test** ([`tests/kind`](../../tests/kind/README.md)). No smoke run has passed yet; see [Validation](#validation). Neither a render nor a smoke run is application acceptance or qualification.

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

[`values.schema.json`](values.schema.json) (JSON Schema draft 2020-12) rejects unknown keys at every level, so an unsupported key such as `oidc:` fails the render instead of being ignored. `affinity` is the only pass-through: its top-level keys are checked and Kubernetes validates the nested structure. Integer bounds copy core's (`src/lib.rs`, `src/migrate.rs`). The schema also rejects the `global` key that Helm passes to subcharts, so this chart cannot be used as a subchart. This is by design: core is installed as its own release.

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

`<component>` is `api` or `worker`; `<ROLE>` is `API` or `WORKER`.

Every process gets an explicit environment: `BIND` (`0.0.0.0:8080` or `0.0.0.0:8081`; core otherwise binds loopback), `DATABASE_URL` from its own Secret through `secretKeyRef`, and the settings above. The chart never uses `envFrom`. Each variable carries its own component prefix, as core ADR 0002 requires. Set `sslmode` explicitly in every URL, because SQLx defaults to `prefer`, which permits plaintext fallback. Readiness `timeoutSeconds` is `ceil(dbTimeoutMs / 1000) + 1`, because `/readyz` waits up to the database timeout.

Keep site values in a private overlay outside this repository and pass it with `-f`. The synthetic files under `tests/chart/values/` use reserved `example.test` names and all-zero digests; they render but cannot be installed.

### Connection budget

Core ADR 0003 bounds PostgreSQL connections at the server. When `database.connectionBudget` is set, rendering fails unless

`(api.replicas + api.maxSurge) × api.dbMaxConnections + (worker.replicas + worker.maxSurge) × worker.dbMaxConnections + 1 (migrator) ≤ connectionBudget`.

Set it to the connections available to this release, after subtracting reserved and administrative or backup headroom. The check covers configured pools only. It also excludes Terminating pods: during a rollout, a replaced pod keeps its pool open while it drains, for up to `terminationGracePeriodSeconds`, so the actual peak can briefly exceed the computed one. Leave headroom for that. Enforce each role's share in PostgreSQL with `CONNECTION LIMIT`; the chart does not manage roles.

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
- `before-hook-creation,hook-succeeded` delete policy on both hooks. A successful run leaves nothing behind. When the Job fails, Helm 4.3 still deletes the hooks that completed before it and carry `hook-succeeded` (`pkg/action/hooks.go`). The migrate ServiceAccount is therefore removed, and only the failed Job and its pods stay for diagnosis. The next install or upgrade recreates the ServiceAccount and replaces the Job.
- `restartPolicy: Never`, `backoffLimit: 2`, `activeDeadlineSeconds` from values. A `podFailurePolicy` fails the Job immediately on exit 78 (invalid configuration). Exit 1, for example a lock timeout, may retry.
- `activeDeadlineSeconds` must exceed `connectTimeoutMs + lockTimeoutMs + statementTimeoutMs`, or rendering fails. One attempt connects, waits for locks and then runs statements, so a smaller deadline would end a long statement before its configured timeout. This is a lower bound only: migrations with several long statements, and retries, need more.
- `migration.{nodeSelector,tolerations,affinity,podAnnotations}` schedule the hook pod independently of api and worker.
- **No rollback hook.** Migrations are forward-only, and `helm rollback` runs no migration. Only the migrator refuses a database at a newer schema version. The API and worker do not check the schema version; core ADR 0003 lists a schema-compatibility readiness gate as not yet covered. A rollback to the previous release therefore relies on ADR 0003's rule that each migration stays compatible with the previous release's API and worker. Nothing guarantees compatibility further back. Recovery from a bad release is a corrective forward release or a restore (V1-30/V1-31).

**Helm timeout.** Helm waits for each hook only for `--timeout`, which defaults to 300 s, while the Job deadline defaults to 900 s. Give `helm install` and `helm upgrade` a `--timeout` of at least `migration.activeDeadlineSeconds` (for the defaults, `--timeout 15m`). If Helm's timeout expires first, Helm marks the release failed and deletes the migrate ServiceAccount as described above, while the Job keeps running. The running pod may still finish, but the Job cannot create a retry pod without its ServiceAccount. Re-running the install or upgrade deletes and replaces the Job, which stops any pod still running. This is recoverable: each migration runs in one transaction, so an interrupted run leaves no partial migration, and the next run continues from the last committed version.

**Sidecar injection.** If a service mesh or another admission webhook injects a long-running sidecar into the hook pod, the pod does not finish when the migrate container exits. The Job then never completes and Helm waits until its timeout. Exclude the hook pod from injection, for example with `migration.podAnnotations` if your mesh supports an opt-out annotation. This has not been tested with any mesh.

`helm template` and `--dry-run` do not run hooks. `--no-hooks` skips the migration, and the new pods then start against the old schema.

**Out of band:** set `migration.enabled: false` to render no Job, no migrate ServiceAccount and no owner-Secret reference. You must then run the migrate image once per release, with `OPENMETTLE_MIGRATE_DATABASE_URL` set to the owner URL, and let it complete successfully before upgrading API and worker. Database roles and the database itself are provisioned outside the chart (core ADR 0003 and README).

## Validation

```sh
bash tests/chart/render.sh                    # helm lint, render matrix, kubeconform
python3 -m unittest discover -s tests/chart -v  # policy, negative-case and contract tests
```

Tested on: Helm 4.3.0 and kubeconform 0.8.0, with Kubernetes 1.37.0 schemas (the kind node version pinned by core). These are test pins, not a compatibility claim; `render.sh` fails on any other Helm version. The chart sets no `kubeVersion` floor.

### Kind smoke test (I2)

[`tests/kind/smoke.py`](../../tests/kind/README.md) installs the chart on an ephemeral kind cluster (Kubernetes 1.37.0, kind v0.33.0; core's pins). It uses core images built from the pinned core commit `5cd8a9d`, referenced by digest, and a synthetic PostgreSQL fixture. It checks these acceptance items against live state:

| Item | Smoke-tested |
| --- | --- |
| api, worker and migrate images install by digest | Yes (digest read back from the node's containerd) |
| Migration hook completes before the Deployments roll out | Yes |
| API and worker Ready; `/readyz` 200 | Yes |
| Worker scales to 2 while the API stays at 1 | Yes, through `worker.replicas` |
| No optional package present | Yes |
| Same-digest `helm upgrade` reruns migrate as a no-op and stays Ready | Yes |
| `helm uninstall` leaves no release objects | Yes |
| App namespace enforces Pod Security `restricted` | Yes |
| NetworkPolicy, storage, ingress, registry pulls, multi-node | No (I3, I4 or the owner's qualification) |

The workflow ([`kind-smoke.yml`](../../.github/workflows/kind-smoke.yml)) runs on manual dispatch and on merges to `main` that touch the chart or the harness. **No run has passed yet**, so these items are designed but unverified until one does. Pull requests run only the harness's cluster-free tests. The tests check chart defaults against a byte-verified copy of core's `runtime/process-contract.json` (`tests/fixtures/core-5cd8a9d/`). The chart's default ServiceAccount names (`<fullname>-api`) differ from the contract's example names (`openmettle-api`); set `serviceAccount.name` to use those.

## Pending

- **I2:** a passing dispatched kind smoke run. The harness and workflow exist, but the run is unverified (see [Kind smoke test](#kind-smoke-test-i2)). A passing run also confirms hook ordering under Helm 4.3 `--wait=watcher`.
- **I3:** NetworkPolicies (chart-scoped deny-all, per-component allows).
- **I4:** artifact PVC, database CA mount, Ingress and TLS, PodDisruptionBudget, a synthetic example profile and overlay documentation. All will be off by default.
- **I5 / V1-04:** OIDC and auth settings, login key mounts, a `--check-auth-config` hook and identity-provider egress. No auth values are accepted yet.
- **V1-20** (managed inference, accelerated tools) and **V1-06** (external providers or gateway): separate charts and releases, never subcharts of core.
- Qualification on the owner's cluster is an owner action.
