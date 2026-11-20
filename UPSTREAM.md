# Provenance

Repository hygiene, editor/attribute defaults and the MIT licence originate from OpenMettle/repository-template at commit `eb327e329929a054fde30c75c2cfd7e862057040` (MIT). The bootstrap adapts its guidance and CI.

The new Rust/Flutter scaffolding and repository documentation were authored for OpenMettle. No Open WebUI implementation, model weights, curated fork sources or runtime images are imported here. MIT covers original repository material and the retained starter; linked third-party materials keep their own terms.

Before adding dependencies or distributing images, complete the version-specific provenance and notices inventory in V1-42. A repository licence does not clear all later runtime dependencies.

## Test and CI tooling

None of these is part of the chart or any image, and none is redistributed. Checksums were resolved on 19 November 2026 from each project's published checksum file or the PyPI JSON API and checked against the downloaded artifact.

| Component | Version | Origin | Licence | Use and verification |
| --- | --- | --- | --- | --- |
| Helm | 4.3.0 | https://github.com/helm/helm (`https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz`) | Apache-2.0 | CI lint and render. linux/amd64 archive SHA-256 `86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb` in `tests/chart/install-tools.sh`, from `helm-v4.3.0-linux-amd64.tar.gz.sha256sum` |
| kubeconform | 0.8.0 | https://github.com/yannh/kubeconform (release `v0.8.0`) | Apache-2.0 | CI manifest validation. linux/amd64 archive SHA-256 `9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883` in `tests/chart/install-tools.sh`, from the release `CHECKSUMS` |
| Kubernetes JSON schemas | 1.37.0 at commit `11639286f15b208b6c7f1f93bc2c1a70f42cfbcb` | https://github.com/yannh/kubernetes-json-schema | Apache-2.0 | Fetched by kubeconform at run time; pinned in `tests/chart/render.sh` |
| PyYAML | 6.0.3 | https://pypi.org/project/PyYAML/6.0.3/ (https://github.com/yaml/pyyaml) | MIT | Test-only YAML parsing in `tests/chart`. Hash-pinned CPython 3.12 manylinux x86_64 wheel in `tests/chart/requirements.txt`, installed into a CI virtual environment. Local runs here used PyYAML 6.0 |
| OpenMettle core process contract | commit `a93a2773948ec602fec29c387b463e71efa49343` | https://github.com/OpenMettle/openmettle-core `runtime/process-contract.json` | MIT | Unmodified test fixture in `tests/fixtures/core/`; CI compares it byte for byte with the pinned commit |
| OpenMettle core kind harness and images | commit `a93a2773948ec602fec29c387b463e71efa49343` | https://github.com/OpenMettle/openmettle-core (`tests/kubernetes/qualify.py`, `tests/kubernetes/install-tools.sh`, `Dockerfile`) | MIT (core); image contents keep their own licences (core ADR 0002) | `tests/kind/smoke.py` imports core's kind, kubectl, node-image and PostgreSQL pins, its guards and two helpers from `qualify.py` at run time; nothing is copied. The `kind-smoke` workflow checks core out at the commit, installs kind and kubectl with core's SHA-256-verified installer and builds the api, worker and migrate images locally. They are never pushed or distributed |
| actions/checkout | `d23441a48e516b6c34aea4fa41551a30e30af803` (v6) | https://github.com/actions/checkout | MIT | Checks out this repository in every workflow. `kind-smoke` also uses it to check out the public core repository at the pinned commit. Always with `persist-credentials: false` |

The kind smoke test therefore uses core's pins without restating them: kind v0.33.0, kubectl v1.37.0, `kindest/node:v1.37.0@sha256:a1ed56cf…0ae5` and `postgres:18.1-bookworm@sha256:cc9f4143…221a`. Core records their origins, digests and licences in its `tests/kubernetes/README.md` and `provenance/register.json`. Core's base images (`rust:1.100.0-slim-bookworm`, `debian:bookworm-slim`) are digest-pinned in core's `Dockerfile`. CI builds the images but does not distribute them.

CI also uses `shellcheck`, `python3` and `pip` (to create the PyYAML virtual environment) as preinstalled on the GitHub-hosted `ubuntu-24.04` runner image. Their versions are not pinned and change when GitHub updates the image.

The chart's Helm template helpers follow common Helm chart conventions (`helm create` naming and labels) and were written for OpenMettle; no third-party chart source is copied.
