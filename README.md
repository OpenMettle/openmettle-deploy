# OpenMettle deploy

Generic Kubernetes/Helm packaging for the [accepted architecture](https://github.com/OpenMettle/openmettle-core/blob/main/ARCHITECTURE-v1.md). V1-32 owns the core Helm chart, V1-06 packages `openmettle-gateway` and worker inference routing inside it, and V1-20 owns the separate optional GPU/model-server profile.

**Status:** `charts/openmettle-core` is pinned to `openmettle-core` commit `11f86638cdfbea938f3ea3230b38c0bf1bfa79a7` ([`CORE_COMMIT`](CORE_COMMIT), schema through migration `37`).

- **Default install (CPU-only, off-by-default optionals):** renders digest-pinned `api` and `worker` Deployments, the `api` ClusterIP Service, per-component ServiceAccounts, a `pre-install`/`pre-upgrade` schema migration Job hook (`openmettle-migrate`), and release-scoped deny-all plus per-component `NetworkPolicy` objects, validated by a strict JSON Schema (`values.schema.json`) and render guards.
- **Opt-in core capabilities:** database CA bundle (`database.caBundle`), `ReadWriteOnce`/`ReadWriteMany` artifact storage (`storage.artifacts` → `ARTIFACTS_DIR`), HTTPS `Ingress` (`ingress`), API `PodDisruptionBudget`, browser/native OIDC sign-in + `/v1/*` API mounts + model catalog + `openmettle_issuance` credential (`auth`, `database.issuance`), structured stderr logging (`telemetry.logging`), and HTTPS OTLP/HTTP trace and metrics export (`telemetry.otlp`).
- **Opt-in turn execution and inference proxy (V1-06 / core ADRs 0043 and 0044):** `worker.pollMs`, `worker.inference` (ConfigMap-projected `inference.json` and `catalog.json`, optional private CA bundle, run-claim settings and worker inference egress), and `0..N` per-model `gateways` (`openmettle-gateway` Deployments, ClusterIP Services, ServiceAccounts and NetworkPolicies with default worker-only ingress or an explicit external TLS-terminator `ingressFrom`, plus `images.gateway` and `database.gateway`). Leaving `worker.inference.enabled: false`, `worker.pollMs: null` and `gateways: {}` keeps default renders unchanged.
- **Verification and remaining owner gates:** `checks.yml` runs repository checks, SHA-256-verified Helm `v4.3.0` + `kubeconform v0.8.0 -strict` across the render matrix, chart policy tests (including `runtime/process-contract.json` parity for `api`, `worker` and `gateway`) and cluster-free harness tests. `kind-smoke.yml` runs 13 live checks on an ephemeral kind cluster, including default-profile install/upgrade/uninstall, `NetworkPolicy` and Pod Security `restricted` enforcement, enabled-profile PVC/auth/artifact/admission checks, HTTPS SSE replay across API replacement and worker expiry, and end-to-end turn execution through both plain-HTTP and Traefik TLS-terminated `openmettle-gateway` against a synthetic SGLang stand-in. Live qualification against TLS PostgreSQL, real OIDC/OTLP endpoints, live SGLang/GPU backends, mandatory ingress/terminator access-log redaction, and the owner's cluster remain open owner gates (see the [chart README](charts/openmettle-core/README.md#pending)).

## First install

[`docs/first-install.md`](docs/first-install.md) is the ordered path from an empty single-node cluster and an empty PostgreSQL 18 database to a signed-in user, authenticated `/v1` calls and an admitted run, at the pinned core commit (leaving `gateways` and `worker.inference` off until paired with a model server). It covers prerequisites, image builds, the auth document and model catalog (`auth.catalogKey`), install, core's operator scripts on a fresh database, a one-off `openmettle-admin` Job, and what remains outside the baseline install. It has not yet been run on a real cluster.

## Package boundaries

- `charts/openmettle-core`: CPU-only API, worker (maintenance and opt-in inference execution), schema migration, and opt-in per-model `openmettle-gateway` proxy workloads with their PostgreSQL and storage integrations. It must render without a GPU, DRA API or vendor operator.
- Separate optional packages (V1-20): managed inference model servers (such as SGLang), accelerated tools and supporting services. Enable them independently as separate charts/releases and qualify their dependencies explicitly.
- Deployment profiles supply storage classes/PVC access, ingress, identity endpoints, resource budgets and image pins. Real profiles remain private.

## Development

```sh
python3 scripts/check_repository.py
bash tests/chart/render.sh                      # helm lint, render matrix, kubeconform
python3 -m unittest discover -s tests/chart -v  # chart policy tests; needs PyYAML
python3 -m unittest discover -s tests/kind -v   # kind smoke harness logic; no cluster
```

CI checks repository hygiene and runs the chart `render` job: SHA-256-verified Helm and kubeconform (`tests/chart/install-tools.sh`, linux/amd64), the commands above, and a byte comparison of the core contract fixture with the pinned core commit. The `kind-smoke` workflow installs the chart on an ephemeral kind cluster. It runs on pull requests and pushes to `main` that touch the chart or harness, and on manual dispatch; see [`tests/kind`](tests/kind/README.md). Locally, the scripts use `helm` and `kubeconform` from `PATH` (or `HELM` and `KUBECONFORM`). kubeconform downloads schemas from the pinned source at run time. Beyond the ephemeral kind smoke, no cluster deployment, backup or restore is implied. Keep local values in ignored `config/*.local.yaml` or an external private configuration repository. [`examples/values-synthetic.yaml`](examples/values-synthetic.yaml) (multi-replica full feature matrix) and [`examples/values-workstation-profile.yaml`](examples/values-workstation-profile.yaml) (single-node private workstation profile) are synthetic, non-installable starting points for such an overlay; see [Private overlays](charts/openmettle-core/README.md#private-overlays).

## Operations

Use render/diff checks before any apply. API and worker replica/resource settings are independent. Credentials are external inputs, never committed defaults. PVCs store artifacts; PostgreSQL stores application metadata/coordination. DRA allocates devices; the application resource controller owns capacity reservations and confirmed release. Maintenance-window backup and isolated restore remain V1-30/V1-31 implementation gates.

See [repository boundaries](REPOSITORIES.md), [provenance](UPSTREAM.md) and the [delivery tracker](https://github.com/orgs/OpenMettle/projects/1/views/1?filterQuery=%5BV1-00%5D&pane=issue&itemId=307308630). Releases and live rollouts remain owner actions.
