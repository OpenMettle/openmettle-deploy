# Kind install smoke test (V1-32 I2)

`smoke.py` installs `charts/openmettle-core` on a temporary [kind](https://kind.sigs.k8s.io/) cluster classified `dev`. The images are core's `api`, `worker` and `migrate` targets, built from a pinned core commit and referenced by digest. It is a test harness, not an installer. Nothing is pushed, published or applied to any other cluster.

**Status:** the cluster run has not passed yet. It needs a dispatched run of [`kind-smoke.yml`](../../.github/workflows/kind-smoke.yml). Until then the checks below are designed but unverified. The cluster-free tests in `test_smoke.py` cover only the harness's own logic.

## What a passing run shows

Every assertion reads live cluster, Helm, containerd or PostgreSQL state. A rendered manifest never counts.

| # | Check | Observed through |
| --- | --- | --- |
| 1 | api, worker and migrate install by digest from core `5cd8a9d` | Pod spec `image` is `<registry>/openmettle/<role>@sha256:…` with `imagePullPolicy: Never`. The digest is read back from the node's containerd and resolved through CRI. Kubelet reports each reference as already present, and the running container's reported `imageID` resolves through CRI to the same image. It may name the `import-<date>@sha256:…` alias that `kind load` created. |
| 2 | Migration hook completes before the Deployments exist | A `Completed` event for the migrate Job precedes both Deployments' `creationTimestamp`. `openmettle._sqlx_migrations` holds only successful rows. The Job is deleted afterwards (`hook-succeeded`). |
| 3 | API and worker Ready; `/readyz` 200 | Helm `--wait=watcher`, `readyReplicas`, the pod `Ready` condition, zero restarts, and HTTP through `kubectl port-forward` to the API Service |
| 4 | Worker scales to 2 while the API stays at 1 | `helm upgrade` with `worker.replicas: 2`. The API pod is unchanged. |
| 5 | No optional package | Release objects are exactly the API and worker Deployments, the API Service and their two ServiceAccounts. There are no NetworkPolicy, Ingress, PVC, PodDisruptionBudget, ResourceClaim or HPA objects, and no pod resources other than `cpu`, `memory` and `ephemeral-storage`. Only this Helm release exists. |
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
- Passwords are random for each run. They are never printed: diagnostics are redacted, and the summary is refused if it contains one. All other values are synthetic.
- The migration settings are shorter than the chart defaults (deadline 120 s, statement timeout 60 s) to bound a hung hook. Helm's `--timeout` is 300 s.

## Reused from core

The harness imports these names from core `tests/kubernetes/qualify.py` at the pinned commit. It first checks that the checkout is exactly `CORE_COMMIT` with no local changes, and it writes no bytecode into the checkout:

- **Pins:** `KIND_VERSION`, `KUBECTL_VERSION`, `NODE_IMAGE` and `POSTGRES_IMAGE`.
- **Guards:** `check_opt_in`, `check_tools`, `check_docker_context`, `check_cluster_absent`, `check_cluster_identity` and `child_environment`.
- **Helpers:** `Runner`, `http_get`, `Refusal` and `QualificationFailure`.

CI installs kind and kubectl with core's `tests/kubernetes/install-tools.sh` from the same checkout, and Helm with this repository's `tests/chart/install-tools.sh`. The harness adds these deploy-specific guards:

- a core-commit check;
- the Helm version pin;
- removal of inherited `HELM_*` settings, with Helm's cache, config and data kept in the run directory;
- a per-run namespace label.

The guards from core keep core's meaning:

- an explicit opt-in;
- a local `unix://` Docker context only;
- a fresh cluster named `openmettle-dev-qual-<8 hex>`;
- a temporary kubeconfig;
- an identity check before each change: one created context, a loopback API server, and one node with kind's cluster label.

Cleanup deletes only the cluster this run created and the image tags it built. Exit codes: 0 passed, 1 failed (including cleanup), 3 refused.

## Running it

CI runs it on GitHub-hosted `ubuntu-24.04`:

- on manual dispatch;
- on pushes to `main` that change the chart, `tests/kind`, the Helm installer or the workflow.

It does not run on pull requests, because hosted minutes are billed while this repository is private. Pull requests run the cluster-free tests in `checks.yml`. The job summary shows the non-secret JSON report. The run's duration has not been measured. Core's comparable job takes 3–5.5 minutes, and this one builds the same images, plus three Helm operations.

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
