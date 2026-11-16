# Working in this repository

Read the README and relevant documentation before changing code. This repository is a bootstrap for the accepted OpenMettle v1 architecture; do not assume that product features or an installer exist.

- Keep changes focused on the requested behavior and explain material trade-offs.
- Keep site-specific values, credentials and private data outside tracked files.
- Preserve upstream licenses, copyright notices and provenance.
- Clearly distinguish implemented behavior from plans and unverified assumptions.
- Prefer validation and dry-run behavior for infrastructure changes. Do not apply to a live cluster, erase storage or publish a release without task authorization.
- Run `python3 scripts/check_repository.py` and the component-specific checks relevant to the change. Report checks not run and why.
- Add meaningful tests for changed behavior; do not describe repository hygiene checks as application coverage.
- Update user-facing documentation when configuration, operation or recovery changes.
- Never invent benchmark results, supported hardware, working commands or compatibility guarantees.

## OpenMettle delivery

- Read the accepted baseline linked from README and the ticket acceptance/dependencies before implementing.
- Keep backend API delivery ahead of Flutter. Preserve private user/project scopes and server-authoritative permissions.
- Work in a branch and open a focused PR. The owner performs merges, releases, IDE installs and live rollouts.
- Bootstrap scaffolding does not satisfy V1-01, V1-32 or V1-33 acceptance. Keep implementation and qualification claims separate.
- Record dependency versions, origin and licence before reuse. Do not copy or translate restricted Open WebUI implementation into these repositories.
- Keep real site details and personal identifiers out of tracked examples. Use synthetic test data.
