# Kind install smoke test (V1-32 I2/I3)

`smoke.py` installs `charts/openmettle-core` on a temporary [kind](https://kind.sigs.k8s.io/) cluster classified `dev`. The images are core's `api`, `worker` and `migrate` targets, built from a pinned core commit and referenced by digest. It is a test harness, not an installer. Nothing is pushed, published or applied to any other cluster.

**Status:** all 10 checks (I2 install/upgrade/uninstall, I3 namespace default-deny and live NetworkPolicy enforcement, I7 enabled-profile upgrade, I9 core `b5ee68d` on PR #15 / `main`, and I10 core `adef30a` adding default-off `404` checks plus enabled-profile `auth.enabled: true` API-only mounts, `--check-auth-config` and `/auth/*` + `/v1/*` route checks on [pull-request run 44761077005](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44761077005), and V1-15 core `94d21f8` (ADR 0031) adding check 10's `ARTIFACTS_DIR` store checks on [pull-request run 44778163598](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44778163598) of `19e770c`) passed on hosted `kind-smoke.yml` CI. AUTHSEC-01 moves the pin to core `2c62e8a` (core ADR 0030, migration 18) and extends checks 2, 5, 7 and 10 with the `openmettle_issuance` login, its URL Secret and the API-only issuance credential; the hosted `kind-smoke` result for that pin is recorded on the pull request that introduced it and on core issue #73. V1-15 PR2 / V1-10 PR2 move the pin to core `3613a51` (core ADRs 0031 and 0032, migration 19) and extend check 2 with migration 19's live role boundaries and check 10 with a `/v1/artifacts` upload, idempotent retry, revision and byte-range download round trip on the artifact PVC; their hosted `kind-smoke` result is recorded on the pull request that introduced them. Core `24808cb` (migrations 21–27) adds the `NOLOGIN` `openmettle_gateway` fixture role and the fresh-install quota markers to check 2, and the `/v1` quota route posture to checks 5 and 10. It also seeds the personal `usage_tokens` limit that check 11's admission now needs. The first-install path adds `auth.catalogKey` to the enabled profile: check 10 mounts core's catalog fixture beside `auth.json` and admits, replays and cancels one run through `POST /v1/runs` ([below](#check-10-run-admission-through-post-v1runs)). The cluster-free tests in `test_smoke.py` cover the harness's own logic, including its orchestration against a recording fake cluster; they are not evidence that the chart installs or that kindnet enforces NetworkPolicy.

## What a passing run shows

Every assertion reads live cluster, Helm, containerd or PostgreSQL state. A rendered manifest never counts.

| # | Check | Observed through |
| --- | --- | --- |
| 1 | api, worker and migrate install by digest from core `24808cb` (`CORE_COMMIT`) | Each digest is read back from the node's containerd and resolved through CRI. Kubelet reports each digest reference as already present (`Pulled` events that report a real pull do not count). For api and worker, the pod spec `image` is `<registry>/openmettle/<role>@sha256:…` with `imagePullPolicy: Never`, and CRI (`crictl ps`) reports the running container's image id as the image the digest reference resolved to. The kubelet's `imageID` may name the `import-<date>@sha256:…` alias that `kind load` created, so it is reported but not compared. The migrate hook pod is deleted on success, so migrate is evidenced only by the kubelet's `Pulled` event naming its digest reference as already present; its pod spec and running image id are not read. |
| 2 | Migration hook completes before the Deployments exist | A `Completed` event for the migrate Job precedes both Deployments' `creationTimestamp`. `openmettle._sqlx_migrations` holds only successful rows and reaches version 27 (`0027_fenced_capacity_grants.sql`, core ADR 0042). Because the database was empty, migrations 24 and 26 started with quota metering and override enforcement active, each with its timestamp. `openmettle.storage_volume_control` is still unpinned and allows the API to pin it (core ADR 0040). The worker can update `lease_expires_at`, `execution_expires_at` and `cancel_reason`. The API can update only `cancel_reason` among those three columns. Read as the fixture superuser, migration 19's role boundaries hold: `openmettle.run_dispatch_lock` has exactly its singleton row (`id = true`, `lock_guard = false`); `openmettle_worker` has `SELECT` on it and `UPDATE` on `lock_guard` only (no table-level `UPDATE`), `UPDATE (claim_token, claimed_at)` on `openmettle.runs` and no `INSERT` on the admission columns; `openmettle_api` has `INSERT (actor_approval_id, round_limit, queue_expires_at)` on `openmettle.runs`, no `UPDATE` on `claim_token`, and no `SELECT` or `UPDATE` on any column of `run_dispatch_lock`. The Job is deleted afterwards (`hook-succeeded`). |
| 3 | API and worker Ready; `/readyz` 200 | Helm `--wait=watcher`, `readyReplicas`, the pod `Ready` condition, zero restarts, and HTTP through `kubectl port-forward` to the API Service (kubelet serves port-forward inside the pod's network namespace, so pod-to-pod NetworkPolicies do not apply to it; pod-to-pod API ingress is tested separately in check 9) |
| 4 | Worker scales to 2 while the API stays at 1 | `helm upgrade` with `worker.replicas: 2`. The API pod is unchanged. |
| 5 | No optional package | The release manifest (`helm get manifest`, each object read back live) is exactly the API and worker Deployments, the API Service, their two ServiceAccounts, and the three non-hook NetworkPolicies (`deny-all`, `api`, `worker`). So are the Deployments, Services, ServiceAccounts, Jobs, ConfigMaps, Secrets and NetworkPolicies that carry the release label. Hooks are not in the manifest; the migrate Job and its hook egress policy are covered by checks 2 and 9. There are no Ingress, PVC, PodDisruptionBudget, ResourceClaim or HPA objects, and no pod resources other than `cpu`, `memory` and `ephemeral-storage`. With `auth.enabled: false`, `GET /auth/session`, `GET /auth/native/session`, `GET /v1/capabilities` and the four `/v1` quota operations (below) all return `404`, and neither the live `api` and `worker` pod specs nor the release's hook manifest (`helm get hooks`, which holds the migrate Job) contain an `*ISSUANCE*` variable or the issuance Secret name (core exits 78 on either issuance setting without `AUTH_CONFIG`). Only this Helm release exists. |
| 6 | A same-digest upgrade reruns migrate as a no-op and stays Ready | A new migrate Job completes on each upgrade. Migration history (versions, checksums, install times) is unchanged. A repeated identical upgrade changes no Deployment generation and replaces no pod. |
| 7 | `helm uninstall` leaves no non-kept release objects | No Ingress, Deployment, ReplicaSet, pod, Service, EndpointSlice, ServiceAccount, Job, ConfigMap, Secret, NetworkPolicy or PodDisruptionBudget carries the release label, and no Helm release Secret remains. The chart-owned artifact PVC (`openmettle-core-artifacts`, created during check 10 with `helm.sh/resource-policy: keep`) survives uninstall, and the four test-owned URL Secrets (including `openmettle-issuance-database`), synthetic auth ConfigMap/login-keys Secret and `default-deny` NetworkPolicy are left alone. |
| 8 | The app namespace enforces Pod Security `restricted` | The namespace label, a server-side dry run of a non-compliant pod that admission rejects, and the chart's pods running in that namespace |
| 9 | NetworkPolicy enforced under namespace default-deny | The app namespace carries a test-owned `default-deny` NetworkPolicy (`podSelector: {}`, Ingress + Egress), plus the release's `deny-all`, `api` and `worker` policies, and install/migrate succeed under it. Live `kubectl exec` probes prove allowed paths connect (api and worker to `postgres.openmettle-smoke-db` on 5432 by DNS name; configured peer `netpol-peer` to API `/readyz` returning HTTP 200) and denied paths time out or are rejected (api and worker to decoy `netpol-peer` on 5432 and to CoreDNS on metrics port 9153; unconfigured `postgres` pod to API `/readyz`). Every denial has a passing control probe from the unrestricted database namespace so an unreachable target never passes as a denial; an inconclusive exec error fails the run, and any denied probe that connects fails loudly with a diagnostic explaining that kindnet's fail-open policy controller is not enforcing. |
| 10 | Enabled-profile upgrade (`api.replicas: 2`, API PDB, RWO artifact PVC, `telemetry.logging` `json`/`debug`, `auth.enabled: true` with `database.issuance`) | After the default-profile checks complete, a `helm upgrade` enables `api.replicas: 2`, `api.podDisruptionBudget` (`maxUnavailable: 1`), `storage.artifacts` (`64Mi`, `ReadWriteOnce` on the single-node kind cluster's default `local-path-provisioner` StorageClass), `telemetry.logging` (`format: json`, `level: debug`) and `auth.enabled: true` (mounting a synthetic version-2 `browser` + `native` ConfigMap at `/etc/openmettle/auth/auth.json`, its model catalog key at `/etc/openmettle/auth/catalog.json` through `auth.catalogKey`, and a random 32-byte `0440` login-key Secret at `/etc/openmettle/auth-keys/active.key` on `api` only, with a synthetic RFC 5737 `networkPolicy.api.oidc` peer, and `database.issuance.existingSecret: openmettle-issuance-database`). The harness waits for rollout (`kubectl rollout status`), checks `/healthz` and `/readyz` 200, verifies the PDB (`maxUnavailable: 1`, `unhealthyPodEvictionPolicy: AlwaysAllow`, `disruptionsAllowed >= 1`), verifies the PVC (`Bound`, `helm.sh/resource-policy: keep`, mounted at `/var/lib/openmettle/artifacts` with `fsGroup: 65532`, and `OPENMETTLE_{API,WORKER}_ARTIFACTS_DIR` set to that path in every `api` and `worker` pod spec), runs `stat` inside every `api` and `worker` container to show that core's `artifact_fs::Store::open` created `staging/` and `revisions/` on the bound volume as directories owned by UID 65532 with permission bits `0700` (core ADR 0031; a set-group-ID bit from `fsGroup` handling is ignored; a pod whose store failed to open exits `78` before listening and never becomes Ready), verifies `auth` volumes/env are mounted on `api` only and absent from `worker`, verifies that every `api` container has `OPENMETTLE_API_ISSUANCE_DATABASE_URL` as a required `secretKeyRef` to `openmettle-issuance-database` key `url` and `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS=2` while the `worker` pod specs and the migrate hook Job carry no `*ISSUANCE*` variable or issuance Secret reference (core ADR 0030; the worker and migrator exit 78 if they receive the URL), executes `/usr/local/bin/openmettle-api --check-auth-config /etc/openmettle/auth/auth.json` inside every `api` pod (proving live `0440` + `fsGroup: 65532` key readability under Pod Security `restricted`), verifies live mounted responses (`GET /auth/session` `403`, `GET /auth/native/session` `403`, and `GET /v1/capabilities` `401` problem JSON body with `code: "unauthenticated"`), checks the `/v1` quota routes (below), runs a `/v1/artifacts` round trip on the PVC (below), admits one run through `POST /v1/runs` with the mounted catalog (below), and verifies every stderr log line from `api` and `worker` parses as ADR 0024 JSON (no `message` field, only allowlisted fields, `process.started` on every pod, and `DEBUG`-level `http.request.completed` on `api`). |
| 11 | Queued-run SSE through the deployed HTTPS Ingress | Two periodic heartbeats, resume after API replacement, one run reservation, worker expiry, terminal replay and a final `204`. |

Core's process-contract assertions (environment isolation, ServiceAccount tokens, QoS, database-loss readiness, SIGTERM exit codes) are not repeated. Core `tests/kubernetes` owns them.

### Check 10: `/v1/artifacts` on the PVC (core ADR 0031)

There is no OIDC provider in the cluster, so the harness seeds one synthetic browser session in the fixture database as core's issuance stores it (core `src/sessions.rs`; the same rows as core's `tests/schema/authz_runs.rs` `seeded_session`): a login provider and revision, a user with a personal scope, an identity, an active approval, a consumed login transaction and a `local_sessions` row holding only the SHA-256 of the length-framed session id and secret. It also sets `storage_instance` limits (1 MiB), without which uploads answer `503 provisioning`. It also sets a personal `usage_tokens` default in `quota_defaults`. A fresh install enforces metering, and without that default check 11's admission is refused as unconfigured (core ADR 0040). The cookie value exists only in the harness and is redacted like the passwords. Session validation then runs unmodified in the API over its own `openmettle_api` pool. Sign-in and session issuance themselves are not exercised here (core `oidc-qualification.yml` covers live Keycloak sign-in).

Every request sends `Cookie: __Host-openmettle-session=…` and `Origin: https://app.example.test` (the synthetic document's browser origin, which core requires on the cookie channel) through `kubectl port-forward` to one of the two API pods, and every response must carry `OpenMettle-API-Version: 1.0` and `Cache-Control: no-store`. Writes alternate between the pods; each read goes to the pod that did not write that revision, so stored bytes cross pods through the shared volume.

1. `POST /v1/artifacts?max_bytes=1024` (pod A) with an `Idempotency-Key` and a `multipart/form-data` body: a `metadata` part `{}` then a `file` part `smoke.txt`, `text/plain`, `openmettle-pvc-artifact-v1\n`. `201` with `state: active`, `revision: "1"`, `size_bytes` the payload length, the payload's lowercase SHA-256, `display_name: smoke.txt`, `media_type: text/plain`, a personal scope and canonical UUIDs.
2. The same request on pod B with the same key, another boundary and the `file` part first: `201` with an identical revision document (same `artifact_id` and `revision_id`).
3. `POST /v1/artifacts/{artifact_id}/revisions?max_bytes=1024` (pod A), a new key and new bytes: `201`, same artifact, new `revision_id`, `revision: "2"`.
4. `GET /v1/artifacts/{artifact_id}/revisions/{revision_id}` (pod B): `200` with the revision 2 document as uploaded.
5. `GET …/content` (pod B): `200` with exactly the revision 2 bytes, `Content-Type: text/plain`, `Content-Length`, `Accept-Ranges: bytes`, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment; filename*=UTF-8''smoke.txt` and no `Content-Range`; with `Range: bytes=0-9`, `206` with the first 10 bytes, `Content-Range: bytes 0-9/<total>` and `Content-Length: 10`; with `Range: bytes=999999-`, `416` `application/problem+json` with `code: range_not_satisfiable` and `Content-Range: bytes */<total>`.

The run reports only the outcome (pods, revisions, statuses and sizes), not the identifiers or the session.

### Check 10: run admission through `POST /v1/runs`

The auth document carries `catalog_file: /etc/openmettle/auth/catalog.json`, `admission_limits` (4 live per actor, 8 per scope, 32 queued, 300 s queue timeout, round cap 10) and `cursor_keys`; without any of them fresh admission answers `503 provisioning`. The catalog is core's `tests/fixtures/conversation-catalog-v1.json`, read from the pinned checkout, with the `prompt_bound` that core's own HTTP tests add to model `a` (preset `study`). It is a second key of the auth ConfigMap, projected through `auth.catalogKey`, and `--check-auth-config` and API startup load it in every API pod.

After the artifact round trip, on one API pod through `kubectl port-forward`, with the seeded session cookie and `Origin`:

1. `GET /v1/models`: `200`, listing catalog model `a`.
2. `POST /v1/conversations` with `{}` and an `Idempotency-Key`: `201` with a conversation and root branch.
3. `POST /v1/runs` appending one text turn with `selection: {preset: study}`: `201` with `state: queued`. The fresh database enforces metering, so this needs the personal `usage_tokens` default seeded above.
4. The same request and key: `200` with the same `run_id`, still `queued`.
5. `POST /v1/runs/{run_id}/cancel` with its own key: `200` with `state: cancelled`, so check 11's admission finds no live run for the actor.

The bodies follow core's contract examples `CreatePersonalConversation` and `AppendProposal`. The run is never executed: the packaged worker runs maintenance only.

### `/v1` quota routes (core ADR 0040)

Checks 5 and 10 send each quota operation once through a port-forward to the API Service. The requests carry no cookie, `Origin`, `Authorization` or `Idempotency-Key`, and use a synthetic scope ID:

- `GET /v1/quotas/personal`
- `GET /v1/projects/{id}/quotas`
- `PUT /v1/admin/scopes/{id}/quotas/usage_tokens`
- `POST /v1/admin/scopes/{id}/quotas/usage_tokens/revoke`

With `auth.enabled: false`, each returns `404`. With `auth.enabled: true`, core decides the session channel before path, key or body validation. Each therefore returns `401` with `OpenMettle-API-Version: 1.0`, `Cache-Control: no-store` and an `application/problem+json` body with `status: 401` and `code: "unauthenticated"`. Authenticated quota reads and override writes are not exercised here; core's schema and HTTP tests cover them.

### Queued-run replay through HTTPS ingress

Check 11 uses the chart's Ingress for `app.example.test`. The client port-forwards to Traefik's HTTPS listener, verifies a per-run certificate and hostname, and sends the browser cookie, Origin, Host and TLS SNI for that host. Traefik discovers both API endpoints from the chart's Service. The enabled profile allows only the controller pod selector from the fixture namespace to reach the API. Both API pods mount the same `cursor_keys.active` file and a separate login key. Each file contains 32 fresh raw bytes.

The [controller manifest](ingress.yaml) pins Traefik v3.7.19. It watches the application namespace for class `smoke-traefik`. The fixture uses the following settings.

| Setting | Fixture value |
| --- | --- |
| Entry point and TLS | `websecure.address=:8443`, `websecure.http.tls=true` |
| Client request read / response write / idle keep-alive timeout | `websecure.transport.respondingtimeouts.readtimeout=60s`, `writetimeout=0s`, `idletimeout=60s` |
| Upstream connection timeout | `serverstransport.forwardingtimeouts.dialtimeout=3s` bounds a connection attempt while kindnet updates NetworkPolicy rules for a replacement pod IP. |
| Upstream response-header timeout | `serverstransport.forwardingtimeouts.responseheadertimeout=30s` |
| SSE response buffering | No buffering middleware. The client requires `text/event-stream`, `X-Accel-Buffering: no` and a flushed opening comment. |
| Controller telemetry | Access logs off, application log level `ERROR`, tracing off |
| Chart configuration | `api.replicas=2`, rolling update with `maxUnavailable=0`, `worker.sweepMs=1000`, `RUN_SLOTS` unset |

1. The harness admits this run through a fixture caller of core's store, not `POST /v1/runs` (check 10 covers the HTTP route). The fixture's limits reserve the one admission slot, which the replay scenario relies on. The harness builds [the fixture caller](admit.rs) against the pinned core's cached Docker build stage and lockfile, then runs the executable in the disposable PostgreSQL pod with only the API database login supplied on stdin. It admits a real personal-scope run with a 120 s queue timeout and retries the same request in a fresh transaction. Core must return the same queued run. Its row reserves the one admission slot (ADR 0032). The maintenance-only worker leaves it queued.
2. Through HTTPS, read `run.created` at sequence 1 and disconnect. Check the queued snapshot and reconnect with the creation cursor in `Last-Event-ID`. Require two separately flushed `: heartbeat` comments after the opening comment, with 8–25 s between arrivals and at least 16 s of quiet in total. The run row version, queue deadline and empty lease fields must stay unchanged.
3. Disconnect, restart the API Deployment and sample `/readyz` through the same ingress during rollout. Each sample must return `200` within a five-second retry window while Traefik and kindnet pick up endpoint changes. Once both original pod UIDs are gone and the two replacements are Ready, require another `200` through ingress before resuming the stream.
4. Resume from the creation cursor and keep the stream open. The worker's `expire_queued` sweep must emit exactly one `run.failed` at sequence 2 with `reason=queue_expired`, then EOF. Require one keyed run, its original deadline, empty claim and lease fields and one durable expiry event. Compare the terminal snapshot and cursor with the event, replay both items in sequence from the beginning and require an empty `204` when resuming past the terminal cursor.

The job summary records the observed quiet interval and outcomes. This scenario exercises a reserved run that expires before dispatch. Model and tool execution require a worker executor.

## Image digests without a registry

The chart accepts only `repository@sha256:<digest>`. `kind load docker-image` imports an image under its tag. The harness then gives it a digest name on the node, without a registry:

1. `kind load docker-image` runs `ctr --namespace=k8s.io images import --all-platforms --digests` on the node. That creates the name `<repo>:<tag>` and, for some archives, `import-<date>@sha256:<digest>`. It never creates `<repo>@sha256:<digest>`. Sources: kind v0.33.0 `pkg/cluster/nodeutils/util.go` (`LoadImageArchive`), and containerd v2.3.4 (kind v0.33.0's node image, `images/base/Dockerfile`) `core/transfer/image/imagestore.go`.
2. containerd's CRI resolves a pod image by exact normalized name (`LocalResolve` → `imageStore.Resolve` in `internal/cri/server/images/service.go` and `internal/cri/store/image/image.go`). A digest reference therefore resolves only if containerd holds an image with exactly that name.
3. The harness reads the tag's target digest from `ctr images ls` and adds the name `<repo>@<that digest>` with `ctr --namespace=k8s.io images tag`. kind does the same when it re-tags (`ReTagImage`). The CRI image store picks the name up from containerd's image-create event (`UpdateImage`).
4. It then requires the new name to point at the same digest, and `crictl inspecti` of the digest reference to return the same image ID as the tag. The summary records whether the reference already resolved before the name was added (`resolved_before_alias`).

The registry host is `openmettle-smoke.invalid`, which never resolves (RFC 6761), and the pull policy is `Never`. If resolution fails, the run stops at step 4, or kubelet refuses the pod with `ErrImageNeverPull` and the Helm wait fails. The digest is containerd's view of the imported image. It is not a registry digest, and nothing is published.

## Fixtures and secrets

- PostgreSQL runs in its own namespace (`openmettle-smoke-db`, with pods labelled `app.kubernetes.io/name: postgres`) with core's pinned image (`POSTGRES_IMAGE`), `emptyDir` storage and TLS disabled (`sslmode=disable`). This is acceptable only for this fixture.
- The fixture also creates a namespace-level `default-deny` NetworkPolicy in `openmettle-smoke` (mirroring the owner's default-deny app namespaces) and a second, empty PostgreSQL Deployment `netpol-peer` in `openmettle-smoke-db` reusing `POSTGRES_IMAGE` and the fixture admin Secret. `netpol-peer` is not a configured database peer (so api/worker egress to it on 5432 must be denied) and is the sole default-profile `networkPolicy.api.ingressFrom` peer (so its `GET /readyz` must return 200 while `postgres`'s must be denied).
- The fixture provisions four disjoint login roles, `openmettle_owner`, `openmettle_api`, `openmettle_issuance` and `openmettle_worker`, each with its own random password, plus a database `openmettle` owned by the owner, before migration 1, as in core's README "Schema migrations" and `runtime/verify-migrate-image.sh`. Core migration 18 refuses to run without `openmettle_issuance` (core ADR 0030). Core migration 23 refuses to run without a restricted `openmettle_gateway` role (core ADR 0037). No chart process logs in as it, so the fixture creates it `NOLOGIN`, with no password or Secret.
- The test, not the chart, creates the four URL Secrets (`openmettle-owner-database` for migrate only, `openmettle-api-database`, `openmettle-worker-database`, and `openmettle-issuance-database`, which only the check 10 profile references) plus the synthetic version-2 auth ConfigMap (`openmettle-smoke-auth-config`, holding `auth.json` and `catalog.json`) and Secret holding separate per-run random 32-byte login and cursor keys (`openmettle-smoke-auth-login-keys`) consumed by check 10.
- Check 10 seeds one synthetic user, approval and browser session directly in the fixture database as the fixture superuser (see [Check 10](#check-10-v1artifacts-on-the-pvc-core-adr-0031)). Only the session's hash reaches the database; the cookie is random for each run and treated like a password below.
- Passwords are random for each run. They are never printed: failure messages and diagnostics are redacted before they are truncated, and the summary is refused if it contains one. core's `Runner` keeps only the last 2000 characters of a failed command's stderr, which can split a password so that whole-value redaction misses its remainder. The harness therefore asks core's `Runner` for the result without its exit-status check, checks the status itself, and redacts the whole stderr before keeping the last 2000 characters. All other values are synthetic.
- The migration settings are shorter than the chart defaults (deadline 120 s, statement timeout 60 s) to bound a hung hook. Helm's `--timeout` is 300 s.

## Reused from core

The harness imports these names from core `tests/kubernetes/qualify.py` at the pinned commit. It first checks that the checkout is exactly `CORE_COMMIT` with no local changes, including ignored files that would enter the Docker build context, and refuses if `git` fails. It writes no bytecode into the checkout:

- **Pins:** `KIND_VERSION`, `KUBECTL_VERSION`, `NODE_IMAGE` and `POSTGRES_IMAGE`.
- **Guards:** `check_opt_in`, `check_tools`, `check_docker_context`, `check_cluster_absent`, `check_cluster_identity` and `child_environment`.
- **Helpers:** `Runner`, `http_get`, `Refusal` and `QualificationFailure`.

CI installs kind and kubectl with core's `tests/kubernetes/install-tools.sh` from the same checkout, and Helm with this repository's `tests/chart/install-tools.sh`. The harness adds these deploy-specific guards:

- a core-commit check (and, in `kind-smoke.yml`, a check that `CORE_COMMIT` is on core's `main`);
- the Helm version pin;
- removal of inherited `HELM_*` settings, with Helm's cache, config and data kept in the run directory;
- a per-run namespace label.

The guards from core keep core's meaning:

- an explicit opt-in;
- a local `unix://` Docker context only;
- a fresh cluster named `openmettle-dev-qual-<8 hex>`;
- a temporary kubeconfig;
- an identity check immediately before each `kubectl apply` and each Helm install, upgrade and uninstall: one created context, a loopback API server, and one node with kind's cluster label. `kind load` and `ctr images tag` act on the node container named for this run, and cleanup deletes the cluster by this run's name; they have no separate identity check.

Cleanup deletes only the cluster this run created and the image tags it built successfully. SIGTERM and SIGHUP (for example a cancelled job) interrupt the run and still clean up. Exit codes: 0 passed, 1 failed (including cleanup or an interruption), 3 refused.

## Running it

CI runs it on GitHub-hosted `ubuntu-24.04`, on pull requests and pushes to `main` that change the chart, `tests/kind`, the Helm installer or the workflow, and on manual dispatch. The repository is public, so hosted minutes are free; the path filter only skips runs that cannot affect the result. Every pull request also runs the cluster-free tests in `checks.yml`. The job summary shows the non-secret JSON report. The one passing run took 5 min 15 s.

```sh
python3 -m unittest discover -s tests/kind -v   # harness logic, no cluster
# Also exercises core's guards: OPENMETTLE_CORE_DIR=<dir containing tests/kubernetes/qualify.py at CORE_COMMIT>
```

A local cluster run needs the same conditions as core's harness: a disposable Linux amd64 Docker daemon reached through a `unix://` context, and an openmettle-core checkout at `CORE_COMMIT`.

```sh
# From the openmettle-deploy checkout on a disposable Linux amd64 Docker host with OpenSSL.
run_dir=$(mktemp -d)
git clone --quiet --no-checkout https://github.com/OpenMettle/openmettle-core.git "$run_dir/core"
git -C "$run_dir/core" checkout --quiet --detach "$(cat CORE_COMMIT)"
bash "$run_dir/core/tests/kubernetes/install-tools.sh" "$run_dir/k8s"
bash tests/chart/install-tools.sh "$run_dir/chart"
OPENMETTLE_K8S_QUALIFICATION=isolated-dev OPENMETTLE_K8S_DOCKER_CONTEXT=default \
  python3 tests/kind/smoke.py --core-dir "$run_dir/core" --tools-dir "$run_dir/k8s" \
    --helm-dir "$run_dir/chart" --report "$run_dir/kind-smoke.json"
```

## Limitations

- The harness uses one amd64 kind node running Kubernetes 1.37.0. Check 5 verifies that the default install creates no PVC, Ingress or PodDisruptionBudget and returns `404` on `/auth/*` and `/v1/*`. Check 10 verifies the API PDB, the single-node `ReadWriteOnce` artifact store, and upload, retry, revision and byte-range reads for one small text file across both API pods. It also checks JSON debug logs, API-only auth mounts, `0440`/`fsGroup: 65532` key access with `--check-auth-config`, and the mounted auth and API routes. Core's `tests/schema/authz_http.rs` covers large, interrupted or concurrent uploads, quota refusals, project scopes, sharing and the native bearer channel.
- Check 11 exercises queued-run SSE through the deployed Traefik HTTPS Ingress, including heartbeats, resume after both API pods are replaced, and replay of worker-driven queue expiry. Site ingress configuration, PostgreSQL TLS and database CA, multi-node scheduling and `ReadWriteMany` storage, node-drain eviction, live OIDC provider exchange and OTLP export still require separate qualification.
- NetworkPolicy enforcement depends on kind v0.33's built-in `kindnet` (which runs `kube-network-policies` fail-open). If `kindnet` does not enforce NetworkPolicy on the hosted runner, check 9 fails loudly rather than passing vacuously; installing a third-party CNI (such as Calico or Cilium) in the smoke cluster would require owner sign-off and a pinned upstream entry.
- Core images are built locally. The fixture pulls its pinned Traefik image. Core registry pulls, pull secrets and published digests are not exercised.
- Not a qualification of the owner's cluster. That remains an owner action.
