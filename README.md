# OpenMettle deploy

Generic Kubernetes/Helm packaging for the [accepted architecture](https://github.com/OpenMettle/openmettle-core/blob/main/ARCHITECTURE-v1.md). V1-32 owns the core Helm implementation and V1-20 owns the qualified optional GPU profile.

**Status:** `charts/openmettle-core` has its render contract (V1-32 I1), kind install smoke test (I2, [`tests/kind`](tests/kind/README.md)), and NetworkPolicies (I3): API and worker Deployments, the API Service, per-component ServiceAccounts, a migration hook Job and egress NetworkPolicy hook, chart-scoped deny-all and per-component NetworkPolicies, a strict values schema and render-time tests. The I2 kind smoke test passed on [a pull-request run](https://github.com/OpenMettle/openmettle-deploy/actions/runs/44505148955) of the merge of `b8f2d79` into `main`; hosted kind execution for I3 NetworkPolicy enforcement is pending pull-request CI. I4 adds optional, off-by-default artifact storage, a database CA mount, an Ingress with TLS and an API PodDisruptionBudget, and I5 adds optional, off-by-default browser sign-in / OIDC mounts and API-only provider egress (core ADR 0025). I4 and I5 are render-tested only. Ingress access-log redaction is a mandatory controller setting that the chart documents but cannot enforce; native sign-in runtime mounting and live cluster qualification remain pending (see the [chart README](charts/openmettle-core/README.md#pending)).

## Package boundaries

- `charts/openmettle-core`: CPU-only API/worker core and its configured PostgreSQL/storage integrations. It must render without a GPU, DRA API or vendor operator.
- Future optional packages: managed inference, accelerated tools and supporting services. Enable them independently and qualify their dependencies explicitly.
- Deployment profiles supply storage classes/PVC access, ingress, identity endpoints, resource budgets and image pins. Real profiles remain private.

## Development

```sh
python3 scripts/check_repository.py
bash tests/chart/render.sh                      # helm lint, render matrix, kubeconform
python3 -m unittest discover -s tests/chart -v  # chart policy tests; needs PyYAML
python3 -m unittest discover -s tests/kind -v   # kind smoke harness logic; no cluster
```

CI checks repository hygiene and runs the chart `render` job: SHA-256-verified Helm and kubeconform (`tests/chart/install-tools.sh`, linux/amd64), the commands above, and a byte comparison of the core contract fixture with the pinned core commit. The `kind-smoke` workflow installs the chart on an ephemeral kind cluster. It runs on pull requests and pushes to `main` that touch the chart or harness, and on manual dispatch; see [`tests/kind`](tests/kind/README.md). Locally, the scripts use `helm` and `kubeconform` from `PATH` (or `HELM` and `KUBECONFORM`). kubeconform downloads schemas from the pinned source at run time. Beyond the ephemeral kind smoke, no cluster deployment, backup or restore is implied. Keep local values in ignored `config/*.local.yaml` or an external private configuration repository. [`examples/values-synthetic.yaml`](examples/values-synthetic.yaml) is a synthetic, non-installable starting point for such an overlay; see [Private overlays](charts/openmettle-core/README.md#private-overlays).

## Operations

Use render/diff checks before any apply. API and worker replica/resource settings are independent. Credentials are external inputs, never committed defaults. PVCs store artifacts; PostgreSQL stores application metadata/coordination. DRA allocates devices; the application resource controller owns capacity reservations and confirmed release. Maintenance-window backup and isolated restore remain V1-30/V1-31 implementation gates.

See [repository boundaries](REPOSITORIES.md), [provenance](UPSTREAM.md) and the [delivery tracker](https://github.com/orgs/OpenMettle/projects/1/views/1?filterQuery=%5BV1-00%5D&pane=issue&itemId=307308630). Releases and live rollouts remain owner actions.
