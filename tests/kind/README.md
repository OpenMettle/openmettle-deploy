# Kind install smoke test (V1-32 I2)

`smoke.py` installs `charts/openmettle-core` on a temporary [kind](https://kind.sigs.k8s.io/) cluster classified `dev`. The images are core's `api`, `worker` and `migrate` targets, built from a pinned core commit and referenced by digest. It is a test harness, not an installer. Nothing is pushed, published or applied to any other cluster.

**Status:** the cluster run passed once, on [pull-request run 44505148955](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44505148955) of [`kind-smoke.yml`](../../.github/workflows/kind-smoke.yml) (5 min 15 s). That run tested the merge of `b8f2d79` into `main` `1d8c930`; the workflow has not yet run on `main`. Harness changes made after `b8f2d79` (the release-manifest comparison, redaction before truncation, the core-checkout and signal guards) are verified only by the pull request's next run. The cluster-free tests in `test_smoke.py` cover the harness's own logic, including its orchestration against a recording fake cluster; they are not evidence that the chart installs.

## What a passing run shows

Every assertion reads live cluster, Helm, containerd or PostgreSQL state. A rendered manifest never counts.

| # | Check | Observed through |
| --- | --- | --- |
| 1 | api, worker and migrate install by digest from core `5cd8a9d` | Each digest is read back from the node's containerd and resolved through CRI. Kubelet reports each digest reference as already present (`Pulled` events that report a real pull do not count). For api and worker, the pod spec `image` is `<registry>/openmettle/<role>@sha256:…` with `imagePullPolicy: Never`, and CRI (`crictl ps`) reports the running container's image id as the image the digest reference resolved to. The kubelet's `imageID` may name the `import-<date>@sha256:…` alias that `kind load` created, so it is reported but not compared. The migrate hook pod is deleted on success, so migrate is evidenced only by the kubelet's `Pulled` event naming its digest reference as already present; its pod spec and running image id are not read. |
| 2 | Migration hook completes before the Deployments exist | A `Completed` event for the migrate Job precedes both Deployments' `creationTimestamp`. `openmettle._sqlx_migrations` holds only successful rows. The Job is deleted afterwards (`hook-succeeded`). |
| 3 | API and worker Ready; `/readyz` 200 | Helm `--wait=watcher`, `readyReplicas`, the pod `Ready` condition, zero restarts, and HTTP through `kubectl port-forward` to the API Service |
| 4 | Worker scales to 2 while the API stays at 1 | `helm upgrade` with `worker.replicas: 2`. The API pod is unchanged. |
| 5 | No optional package | The release manifest (`helm get manifest`, each object read back live) is exactly the API and worker Deployments, the API Service and their two ServiceAccounts. So are the Deployments, Services, ServiceAccounts, Jobs, ConfigMaps and Secrets that carry the release label. Hooks are not in the manifest; the migrate Job is covered by check 2. There are no NetworkPolicy, Ingress, PVC, PodDisruptionBudget, ResourceClaim or HPA objects, and no pod resources other than `cpu`, `memory` and `ephemeral-storage`. Only this Helm release exists. |
| 6 | A same-digest upgrade reruns migrate as a no-op and stays Ready | A new migrate Job completes on each upgrade. Migration history (versions, checksums, install times) is unchanged. A repeated identical upgrade changes no Deployment generation and replaces no pod. |
| 7 | `helm uninstall` leaves no release objects | No Deployment, ReplicaSet, pod, Service, EndpointSlice, ServiceAccount, Job, ConfigMap or Secret carries the release label, and no Helm release Secret remains. The three test-owned URL Secrets are left alone. |
| 8 | The app namespace enforces Pod Security `restricted` | The namespace label, a server-side dry run of a non-compliant pod that admission rejects, and the chart's pods running in that namespace |

Core's process-contract assertions (environment isolation, ServiceAccount tokens, QoS, database-loss readiness, SIGTERM exit codes) are not repeated. Core `tests/kubernetes` owns them.

## Image digests without a registry

The chart accepts only `repository@sha256:<digest>`. `kind load docker-image` imports an image under its tag. The harness then gives it a digest name on the node, without a registry:

1. `kind load docker-image` runs `ctr --namespace=k8s.io images import --all-platforms --digests` on the node. That creates the name `<repo>:<tag>` and, for some archives, `import-<date>@sha256:<digest>`. It never creates `<repo>@sha256:<digest>`. Sources: kind v0.33.0 `pkg/cluster/nodeutils/util.go` (`LoadImageArchive`), and containerd v2.3.4 (kind v0.33.0's node image, `images/base/Dockerfile`) `core/transfer/image/imagestore.go`.
2. containerd's CRI resolves a pod image by exact normalized name (`LocalResolve` → `imageStore.Resolve` in `internal/cri/server/images/service.go` and `internal/cri/store/image/image.go`). A digest reference therefore resolves only if containerd holds an image with exactly that name.
3. The harness reads the tag's target digest from `ctr images ls` and adds the name `<repo>@<that digest>` with `ctr --namespace=k8s.io images tag`. kind does the same when it re-tags (`ReTagImage`). The CRI image store picks the name up from containerd's image-create event (`UpdateImage`).
4. It then requires the new name to point at the same digest, and `crictl inspecti` of the digest reference to return the same image ID as the tag. The summary records whether the reference already resolved before the name was added (`resolved_before_alias`).

The registry host is `openmettle-smoke.invalid`, which never resolves (RFC 6761), and the pull policy is `Never`. If resolution fails, the run stops at step 4, or kubelet refuses the pod with `ErrImageNeverPull` and the Helm wait fails. The digest is containerd's view of the imported image. It is not a registry digest, and nothing is published.

## Fixtures and secrets

- PostgreSQL runs in its own namespace with core's pinned image (`POSTGRES_IMAGE`), `emptyDir` storage and TLS disabled (`sslmode=disable`). This is acceptable only for this fixture.
- The fixture provisions `openmettle_owner`, `openmettle_api` and `openmettle_worker`, plus a database `openmettle` owned by the owner, as in core's README "Schema migrations" and `runtime/verify-migrate-image.sh`.
- The test, not the chart, creates the three URL Secrets: `openmettle-owner-database` (migrate only), `openmettle-api-database` and `openmettle-worker-database`.
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
bash <core>/tests/kubernetes/install-tools.sh "$(mktemp -d)/k8s"
bash tests/chart/install-tools.sh "$(mktemp -d)/chart"
OPENMETTLE_K8S_QUALIFICATION=isolated-dev OPENMETTLE_K8S_DOCKER_CONTEXT=default \
  python3 tests/kind/smoke.py --core-dir <core> --tools-dir <k8s dir> --helm-dir <chart dir> --report /tmp/kind-smoke.json
```

## Limitations

- One single-node kind cluster on amd64, Kubernetes 1.37.0. No NetworkPolicy (I3), storage, ingress, TLS or multi-node scheduling.
- Images are built locally. Registry pulls, pull secrets and published digests are not exercised.
- Not a qualification of the owner's cluster. That remains an owner action.
