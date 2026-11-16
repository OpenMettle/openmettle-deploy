# OpenMettle deploy

Generic Kubernetes/Helm packaging for the [accepted architecture](https://github.com/OpenMettle/openmettle-core/blob/main/ARCHITECTURE-v1.md). **Bootstrap only:** chart metadata and package boundaries are present; there are no workload templates or installable services yet. V1-32 owns the core Helm implementation and V1-20 owns the qualified optional GPU profile.

## Package boundaries

- `charts/openmettle-core`: CPU-only API/worker core and its configured PostgreSQL/storage integrations. It must render without a GPU, DRA API or vendor operator.
- Future optional packages: managed inference, accelerated tools and supporting services. Enable them independently and qualify their dependencies explicitly.
- Deployment profiles supply storage classes/PVC access, ingress, identity endpoints, resource budgets and image pins. Real profiles remain private.

## Development

```sh
python3 scripts/check_repository.py
```

The bootstrap CI checks repository hygiene. Add a pinned Helm toolchain, lint/render/schema checks and the CPU-only/optional-package render matrix when workload templates arrive. No successful cluster deployment, backup or restore is implied by this scaffold. Keep local values in ignored `config/*.local.yaml` or an external private configuration repository.

## Operations

Use render/diff checks before any apply. API and worker replica/resource settings are independent. Credentials are external inputs, never committed defaults. PVCs store artifacts; PostgreSQL stores application metadata/coordination. DRA allocates devices; the application resource controller owns capacity reservations and confirmed release. Maintenance-window backup and isolated restore remain V1-30/V1-31 implementation gates.

See [repository boundaries](REPOSITORIES.md), [provenance](UPSTREAM.md) and the [delivery tracker](https://github.com/orgs/OpenMettle/projects/1/views/1?filterQuery=%5BV1-00%5D&pane=issue&itemId=307308630). Releases and live rollouts remain owner actions.
