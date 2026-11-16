# Repository boundaries

| Repository | Ownership |
| --- | --- |
| [openmettle-core](https://github.com/OpenMettle/openmettle-core) | Accepted architecture, decision records, application API/event/capacity contracts, Rust API and worker binaries, domain logic, persistence and service adapters |
| [openmettle-app](https://github.com/OpenMettle/openmettle-app) | Flutter web/mobile presentation, API client, accessibility and client recovery |
| [openmettle-deploy](https://github.com/OpenMettle/openmettle-deploy) | Generic Helm packaging, optional service packages, profile schemas and installation/recovery documentation |
| [openmettle-acp](https://github.com/OpenMettle/openmettle-acp) | Existing local coding agent and its future OpenMettle backend adapter |

Curated forks retain their own upstream histories and licences. The existing Open WebUI fork is source evidence and current-stack work, not the source tree for the replacement. One Rust workspace supplies independently deployable API and worker binaries; a service boundary does not require another repository. Add repositories only when ownership or release boundaries justify them.

Site domains, credentials, LAN addresses, storage locations and hardware-specific values stay in private deployment configuration. Nothing in this bootstrap deploys to a cluster or publishes packages.

## Contract ownership

Core owns versioned HTTP/OpenAPI, SSE event and capacity contracts. App and ACP consume released or commit-pinned contracts; they do not define a separate permission or execution model. Deploy pins compatible component images and contract versions. Add generated clients only after the contracts exist and have conformance checks.

## Changes and delivery

The Git repository is the maintained source for the baseline after this export. Keep the accepted v1 record immutable except for corrections explicitly recorded in a decision entry. Propose substantive changes as new numbered decisions with their reason, affected contracts and ticket links. The planning Page remains the discussion/source archive; the project tracker remains the live work index.
