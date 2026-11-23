# First install with sign-in

This guide takes an empty single-node Kubernetes cluster and an empty PostgreSQL 18 database to this end state: a person can sign in, call authenticated `/v1` routes, and a run can be admitted. It uses `charts/openmettle-core` at core commit `24808cbf78dd552d751c85c9e37a16d1d66c7ca4` ([`CORE_COMMIT`](../CORE_COMMIT)).

**Status.** This path has not yet been run end to end on a real cluster. The kind smoke test ([`tests/kind`](../tests/kind/README.md)) runs most of it on an ephemeral cluster; [How this guide differs from the kind smoke test](#how-this-guide-differs-from-the-kind-smoke-test) lists where they differ. A step marked *unverified* is not exercised by the kind smoke test or by core CI.

Every name, hostname, address, digest and value below is synthetic. Keep real values in a private overlay ([Private overlays](../charts/openmettle-core/README.md#private-overlays)) and out of this repository.

Synthetic names used throughout:

| Item | Synthetic value |
| --- | --- |
| Namespace and Helm release | `openmettle` (resources are named `openmettle-openmettle-core-*`) |
| Application hostname | `openmettle.example.test` |
| OIDC issuer (Keycloak realm) | `https://idp.example.test/realms/openmettle` |
| Private overlay | `config/site.local.yaml` (ignored by Git) |
| Core checkout at the pin | `$CORE` |

## Steps

1. [Prerequisites](#1-prerequisites)
2. [Namespace and Pod Security](#2-namespace-and-pod-security)
3. [PostgreSQL roles, database and URL Secrets](#3-postgresql-roles-database-and-url-secrets)
4. [OIDC provider registration](#4-oidc-provider-registration)
5. [Images](#5-images)
6. [Auth document, model catalog and keys](#6-auth-document-model-catalog-and-keys)
7. [Ingress, TLS and request limits](#7-ingress-tls-and-request-limits)
8. [Values overlay](#8-values-overlay)
9. [Install and migrate](#9-install-and-migrate)
10. [Operator steps on the fresh database](#10-operator-steps-on-the-fresh-database)
11. [First sign-in](#11-first-sign-in)
12. [Quotas and run admission](#12-quotas-and-run-admission)

Then: [Running `openmettle-admin`](#running-openmettle-admin), [Upgrade-only steps a fresh install must skip](#upgrade-only-steps-a-fresh-install-must-skip), [Not yet possible at this pin](#not-yet-possible-at-this-pin).

## 1. Prerequisites

The chart creates no Namespace, Secret, ConfigMap, IngressClass, Traefik Middleware or database object. Provide these first:

- A single-node cluster whose network plugin enforces NetworkPolicy. K3s does by default ([NetworkPolicy](../charts/openmettle-core/README.md#networkpolicy)).
- Helm 4.3.0, which is the version the chart is tested with ([Validation](../charts/openmettle-core/README.md#validation)).
- PostgreSQL 18 reachable from the cluster. Core qualifies only major version 18.
- An OIDC provider. Core qualifies browser sign-in against Keycloak 26.8.2.
- An ingress controller. The chart documentation and kind smoke test use Traefik v3.
- A default StorageClass, or a named one, for the artifact PersistentVolumeClaim.
- A container registry that the node can pull from, and Docker with Buildx to build the core images.
- `psql` 18 on an operator workstation that can reach the PostgreSQL primary, plus a checkout of core at the pinned commit:

  ```sh
  git clone https://github.com/OpenMettle/openmettle-core.git "$CORE"
  git -C "$CORE" checkout --detach "$(cat CORE_COMMIT)"
  ```

Run core's operator scripts from that workstation, from the root of `$CORE`. You can connect directly or through `kubectl port-forward` to the database Service. Do not run the scripts in a pod: the kubelet keeps container output in node logs, and `home-invitation-create.psql` prints a one-time secret.

## 2. Namespace and Pod Security

```sh
kubectl create namespace openmettle
kubectl label namespace openmettle pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

Every chart pod satisfies `restricted` (kind smoke check 8). A namespace-wide default-deny NetworkPolicy is optional, and the chart works under one (kind smoke check 9). If you add one, also give the [`openmettle-admin` Job](#running-openmettle-admin) its own egress policy.

**Check:** `kubectl get namespace openmettle --show-labels` shows `pod-security.kubernetes.io/enforce=restricted`.

## 3. PostgreSQL roles, database and URL Secrets

As a PostgreSQL superuser, create one dedicated database and five roles before the first migration. Core's README ("Schema migrations") defines the four login roles. Its rules apply: no role is a superuser or has `CREATEROLE`, `CREATEDB`, `REPLICATION` or `BYPASSRLS`, no role belongs to another role, and you grant nothing yourself. Migration 23 refuses to run without a restricted `openmettle_gateway` role (core ADR 0037). No chart process logs in as that role, so create it without a login (this is what the kind smoke fixture does):

```sql
CREATE ROLE openmettle_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE openmettle_api LOGIN PASSWORD :'api_password' CONNECTION LIMIT 8;
CREATE ROLE openmettle_issuance LOGIN PASSWORD :'issuance_password' CONNECTION LIMIT 4;
CREATE ROLE openmettle_worker LOGIN PASSWORD :'worker_password' CONNECTION LIMIT 8;
CREATE ROLE openmettle_gateway NOLOGIN;
CREATE DATABASE openmettle OWNER openmettle_owner;
```

Size the connection limits with the [connection budget](../charts/openmettle-core/README.md#connection-budget). The figures above are core's illustrative ones.

Create one URL Secret per login role, each with the key `url`. The chart compares only Secret names and keys, so use a separate Secret for each role. Write each URL to a file with a restrictive umask so the password does not reach shell history:

```sh
# url file content (synthetic):
# postgres://openmettle_api:<password>@db.example.test:5432/openmettle?sslmode=verify-full&sslrootcert=/etc/openmettle/db-ca/ca.crt
kubectl -n openmettle create secret generic openmettle-owner-database    --from-file=url=./owner.url
kubectl -n openmettle create secret generic openmettle-api-database      --from-file=url=./api.url
kubectl -n openmettle create secret generic openmettle-issuance-database --from-file=url=./issuance.url
kubectl -n openmettle create secret generic openmettle-worker-database   --from-file=url=./worker.url
kubectl -n openmettle create configmap openmettle-db-ca --from-file=ca.crt=./db-ca.pem
```

| Secret | Chart value | Mounted into |
| --- | --- | --- |
| `openmettle-owner-database` | `database.migrate.existingSecret` | migrate hook Job only |
| `openmettle-api-database` | `database.api.existingSecret` | `api` |
| `openmettle-issuance-database` | `database.issuance.existingSecret` | `api` only, with `auth.enabled` |
| `openmettle-worker-database` | `database.worker.existingSecret` | `worker` |

Set `sslmode` explicitly in every URL. Without it SQLx uses `prefer`, which permits plaintext. When the URLs name `sslrootcert=/etc/openmettle/db-ca/ca.crt`, set `database.caBundle` to the ConfigMap above ([Database CA](../charts/openmettle-core/README.md#database-ca)). Keep the owner URL Secret: the migrate hook and [`openmettle-admin`](#running-openmettle-admin) use it, and you also need the owner login for the `psql` steps.

**Check:** `psql` as `openmettle_owner` connects to `openmettle`, and `SELECT rolname FROM pg_roles WHERE rolname LIKE 'openmettle_%' ORDER BY 1;` lists the five roles.

## 4. OIDC provider registration

Register one client for the application. Core's Keycloak qualification (`$CORE/tests/keycloak/fixture.py`, `realm()`) imports a client with these properties:

| Keycloak client setting | Value |
| --- | --- |
| Protocol | `openid-connect` |
| Client authentication | Off (`publicClient: true`); the auth document has no client secret |
| Standard flow | On. Implicit flow, direct access grants and service accounts are off |
| Valid redirect URIs | Exactly the `providers[].callback` URL from step 6, for example `https://openmettle.example.test/auth/callback`, without wildcards |
| Web origins | None |
| `pkce.code.challenge.method` | `S256` |
| `exclude.issuer.from.auth.response` | `false`. The callback refuses a response without RFC 9207 `iss` |

Record the issuer and the client ID. Copy the `authorization_endpoint`, `token_endpoint` and `jwks_uri` from the realm's discovery document at `<issuer>/.well-known/openid-configuration`. For each person who will sign in, record the stable `sub` claim from the provider's administration records. The first sign-in uses it in [step 10](#10-operator-steps-on-the-fresh-database).

The API alone calls the provider, directly and without a proxy (core ADR 0010). Allow that egress with `networkPolicy.api.oidc.to` and `networkPolicy.api.oidc.port` (for example `8443` for a self-hosted Keycloak). If the issuer hostname resolves to a private address, list a CIDR that covers that address in `providers[].private_cidrs`. If the provider uses a private CA, mount it with `auth.providerCaBundle` and set `providers[].trust` to `{"roots": "bundle", "bundle_path": "/etc/openmettle/auth-ca/ca.crt"}`.

## 5. Images

Core publishes no images. Build `api`, `worker`, `migrate` and `admin` from core's `Dockerfile` at the pinned commit, push them to your registry and reference each one by digest. The chart refuses tags.

```sh
cd "$CORE"
for target in api worker migrate admin; do
  docker buildx build --platform "linux/$NODE_ARCH" --target "$target" \
    --tag "$REGISTRY/openmettle/$target:$(git rev-parse --short=12 HEAD)" \
    --metadata-file "/tmp/openmettle-$target.json" --push .
  jq -r '."containerimage.digest"' "/tmp/openmettle-$target.json"   # sha256:...
done
```

`NODE_ARCH` is your node's architecture (`amd64` or `arm64`), and `REGISTRY` is your registry host and path. The `Dockerfile` pins its base images by digest. This guide does not verify that those digests cover your architecture. Check with `docker buildx imagetools inspect` on each pinned `FROM` reference before you build. The kind smoke test builds amd64 only. If the registry is private, create a pull Secret and list it in `images.pullSecrets`. Image distribution remains subject to core's V1-42 provenance inventory, so keep the images in a private registry.

Write `images.{api,worker,migrate}.{registry,repository,digest}` into the private overlay. The chart does not reference the `admin` image; record its digest for [`openmettle-admin`](#running-openmettle-admin).

**Check:** `docker buildx imagetools inspect "$REGISTRY/openmettle/api@<digest>"` resolves from a host that uses the same registry credentials as the node.

## 6. Auth document, model catalog and keys

### Keys

Generate one 32-byte login key and one separate 32-byte cursor key. Then store both in one Secret (core README, "Run cursor keys"):

```sh
(umask 077; set -C; openssl rand 32 > login-active.key; openssl rand 32 > cursor-active.key)
kubectl -n openmettle create secret generic openmettle-auth-keys \
  --from-file=login-active.key=./login-active.key --from-file=cursor-active.key=./cursor-active.key
```

The chart mounts the Secret read-only at `/etc/openmettle/auth-keys` with mode `0440` in the API pod only (`auth.loginKeysSecretName`).

### `auth.json` (version 2)

Fresh `POST /v1/runs` admission needs `catalog_file`, `admission_limits` and `cursor_keys`. Without any one of them, it answers `503 provisioning`. The rest of the document is required for sign-in. The shape below is the kind smoke document without its native profile. The values are illustrative, not recommendations; core ADR 0015 lists each field's bounds.

```json
{
  "version": 2,
  "login": {
    "lifetime_seconds": 300,
    "keys": {"active": {"id": "login-a", "path": "/etc/openmettle/auth-keys/login-active.key"}, "decrypt_only": []}
  },
  "cursor_keys": {"active": {"id": "cursor-a", "path": "/etc/openmettle/auth-keys/cursor-active.key"}, "verify_only": []},
  "catalog_file": "/etc/openmettle/auth/catalog.json",
  "admission_limits": {"live_per_actor": 4, "live_per_scope": 8, "queued_in_instance": 32,
                       "queue_timeout_seconds": 300, "round_cap": 10},
  "id_token": {"max_issued_at_age_seconds": 300, "future_skew_seconds": 60},
  "provider_refresh": {"freshness_seconds": 3600, "cooldown_seconds": 60, "deadline_milliseconds": 5000,
                       "max_providers": 2, "max_callers": 32, "max_document_gets": 3},
  "session": {"lifetime_seconds": 28800, "retained_per_user": 16, "deadline_milliseconds": 5000},
  "providers": [{
    "id": "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
    "issuer": "https://idp.example.test/realms/openmettle",
    "client_id": "openmettle",
    "revision": "r1",
    "authorization_endpoint": "https://idp.example.test/realms/openmettle/protocol/openid-connect/auth",
    "token_endpoint": "https://idp.example.test/realms/openmettle/protocol/openid-connect/token",
    "discovery_url": "https://idp.example.test/realms/openmettle/.well-known/openid-configuration",
    "jwks_url": "https://idp.example.test/realms/openmettle/protocol/openid-connect/certs",
    "callback": "https://openmettle.example.test/auth/callback",
    "destination": "web",
    "private_cidrs": [],
    "trust": {"roots": "native"}
  }],
  "browser": {
    "provider_id": "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
    "origin": "https://openmettle.example.test",
    "landing_path": "/home",
    "paths": {"initiation": "/auth/login", "session_check": "/auth/session", "logout": "/auth/logout"},
    "rates": {"initiation": {"burst": 20, "interval_milliseconds": 500},
              "callback": {"burst": 20, "interval_milliseconds": 500},
              "session_check": {"burst": 120, "interval_milliseconds": 100},
              "logout": {"burst": 20, "interval_milliseconds": 500}},
    "max_in_flight": 64
  }
}
```

- Generate a new provider UUID; do not reuse the example's. Record `providers[].id`, `issuer`, `client_id` and `revision`. [Step 10](#10-operator-steps-on-the-fresh-database) writes the same four values to the database.
- `browser.origin` is `https://` plus the Ingress hostname. The `callback` path, the three `paths` and `landing_path` must be distinct and must not be `/healthz`, `/readyz`, `/v1` or under `/v1`.
- Omit the optional `native` object unless you register a native app (core README, "Native sign-in profile").

### Model catalog

`catalog_file` names a JSON model catalog (core ADRs 0032 and 0036). Core has no operator reference for the catalog format. The only example at this pin is the test fixture `$CORE/tests/fixtures/conversation-catalog-v1.json`. Admission estimates the prompt from the selected model's `prompt_bound`, which that fixture omits. Core's HTTP tests and the kind smoke test add this bound to model `a`, the model that preset `study` selects:

```sh
jq '.models.a.prompt_bound = {"fixed_tokens": 4, "tokens_per_turn": 4, "tokens_per_part": 2,
                              "tokens_per_byte": 1, "tokens_per_attachment": 10}' \
  "$CORE/tests/fixtures/conversation-catalog-v1.json" > catalog.json
```

The result is a synthetic catalog. It is enough for admission, because at this pin no model is called ([Not yet possible](#not-yet-possible-at-this-pin)). Leave out `cost_bound` and any `usage_cost_micros` quota until cost metering is qualified (core `docs/operator/storage-adoption-and-quota-upgrade.md`, section 2).

### ConfigMap

Store both files in one ConfigMap. `auth.configKey` projects `auth.json`, and `auth.catalogKey` projects the catalog beside it as `/etc/openmettle/auth/catalog.json`:

```sh
kubectl -n openmettle create configmap openmettle-auth \
  --from-file=auth.json=./auth.json --from-file=catalog.json=./catalog.json
```

**Check (offline, before install; *unverified* outside a pod).** Run core's validator in the API image with the files at their in-pod paths. Run the container as your own user, because the key files are mode `0600`:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/auth:/etc/openmettle/auth:ro" -v "$PWD/keys:/etc/openmettle/auth-keys:ro" \
  "$REGISTRY/openmettle/api@<api digest>" --check-auth-config /etc/openmettle/auth/auth.json
```

Here `./auth` holds `auth.json` and `catalog.json`, and `./keys` holds both key files. Expect `auth configuration valid (local files only)` and exit 0. [Step 9](#9-install-and-migrate) repeats the check inside the running pod, which is the form the kind smoke test exercises.

## 7. Ingress, TLS and request limits

Create these in the release namespace. The chart references them but does not create them:

- **TLS Secret** for the hostname, for example `kubectl -n openmettle create secret tls openmettle-tls --cert=tls.crt --key=tls.key`, or one issued by cert-manager.
- **Access-log redaction** in the controller's static configuration. This is mandatory before routing sign-in traffic: [Mandatory before routing login traffic](../charts/openmettle-core/README.md#mandatory-before-routing-login-traffic-no-request-targets-cookies-or-bodies-in-logs). On K3s, use the `traefik` `HelmChartConfig`.
- **Body-limit middleware.** `POST /v1/runs` bodies can be up to 128 KiB (`131072` bytes), so a limit of `65536` refuses large run proposals. Artifact uploads need more, up to their `max_bytes` (at most 64 MiB) plus multipart overhead:

  ```yaml
  apiVersion: traefik.io/v1alpha1
  kind: Middleware
  metadata: {name: openmettle-request-limits, namespace: openmettle}
  spec:
    buffering:
      maxRequestBodyBytes: 131072   # synthetic; raise it if you expose uploads
  ```

  Attach it with `traefik.ingress.kubernetes.io/router.middlewares: openmettle-openmettle-request-limits@kubernetescrd`. A buffering middleware can also buffer responses, which breaks the run-event SSE stream ("SSE through Traefik" in [Ingress and TLS](../charts/openmettle-core/README.md#ingress-and-tls)). This guide does not need that stream.

`networkPolicy.api.ingressFrom` must select only the controller's pods. For K3s's bundled Traefik, that is namespace `kube-system` and pod label `app.kubernetes.io/name: traefik`, as in the workstation example.

## 8. Values overlay

Start from [`examples/values-workstation-profile.yaml`](../examples/values-workstation-profile.yaml). Put your real values in `config/site.local.yaml`, which Git ignores:

```yaml
images:
  api:     {registry: <registry host>, repository: <path>/api,     digest: sha256:<api digest>}
  worker:  {registry: <registry host>, repository: <path>/worker,  digest: sha256:<worker digest>}
  migrate: {registry: <registry host>, repository: <path>/migrate, digest: sha256:<migrate digest>}
database:
  api:      {existingSecret: openmettle-api-database}
  worker:   {existingSecret: openmettle-worker-database}
  migrate:  {existingSecret: openmettle-owner-database}
  issuance: {existingSecret: openmettle-issuance-database}
  caBundle: {enabled: true, configMapName: openmettle-db-ca}
auth:
  enabled: true
  configMapName: openmettle-auth
  configKey: auth.json
  catalogKey: catalog.json
  loginKeysSecretName: openmettle-auth-keys
  providerCaBundle: {enabled: false}
ingress:
  hosts: [openmettle.example.test]
  tls: [{secretName: openmettle-tls, hosts: [openmettle.example.test]}]
networkPolicy:
  api:
    oidc: {to: [{ipBlock: {cidr: 192.0.2.20/32}}], port: 443}
  database: {to: [{ipBlock: {cidr: 192.0.2.10/32}}]}
  telemetry: {otlp: {to: []}}
telemetry:
  otlp: {enabled: false, tracesEndpoint: "", metricsEndpoint: "", privateRanges: [], caBundle: {enabled: false}}
  # The workstation example exports OTLP. Either disable it as above, or set your collector endpoints,
  # networkPolicy.telemetry.otlp.to and the CA ConfigMap (chart README, "Telemetry / OTLP").
```

Lists replace lists rather than merging, so each `to:` above replaces the example's peers. Storage uses the profile's chart-owned `ReadWriteOnce` claim (`storage.artifacts.size`). That works on one node. On several nodes, use a `ReadWriteMany` class qualified for POSIX `rename`, exclusive create and `fsync` ([Artifact storage](../charts/openmettle-core/README.md#artifact-storage)). On a constrained node, `api.strategy` and `worker.strategy` `{maxSurge: 0, maxUnavailable: 1}` avoid surge pods.

**Check:** render and review before installing:

```sh
helm template openmettle charts/openmettle-core --namespace openmettle \
  -f examples/values-workstation-profile.yaml -f config/site.local.yaml > /tmp/openmettle.yaml
```

The render fails with a message naming any missing or conflicting value.

## 9. Install and migrate

```sh
helm upgrade --install openmettle charts/openmettle-core --namespace openmettle \
  -f examples/values-workstation-profile.yaml -f config/site.local.yaml --timeout 15m
```

The migrate hook runs `openmettle-migrate` as the owner before Helm creates the Deployments (`pre-install,pre-upgrade`). Its deadline is `migration.activeDeadlineSeconds` (default 900 s), and `--timeout` must be at least that long. If Helm times out first, it deletes the hook's ServiceAccount and NetworkPolicy while the Job keeps running ([Schema migration](../charts/openmettle-core/README.md#schema-migration)). A failed Job remains for diagnosis. Read its log with `kubectl -n openmettle logs job/openmettle-openmettle-core-migrate`. Exit 78 means invalid configuration. A role or provisioning error names each violation.

**Checks after install:**

| Check | Expected |
| --- | --- |
| `kubectl -n openmettle get deploy` | `openmettle-openmettle-core-api` and `-worker` Ready |
| As owner: `SELECT max(version) FROM openmettle._sqlx_migrations WHERE success;` | `27` |
| As owner: core's marker query in `docs/operator/storage-adoption-and-quota-upgrade.md`, section 2 | `metering_enforced` and `overrides_enforced` true, with both timestamps set. A fresh database starts enforced. `adoption_run_id` is null |
| `kubectl -n openmettle exec deploy/openmettle-openmettle-core-api -- /usr/local/bin/openmettle-api --check-auth-config /etc/openmettle/auth/auth.json` | `auth configuration valid (local files only)` |
| `curl -i https://openmettle.example.test/healthz` | `200`, body `ok` |
| `curl -i https://openmettle.example.test/readyz` | `200`, body `ready` (`503` while PostgreSQL is unreachable) |
| `curl -i https://openmettle.example.test/v1/capabilities` (no session) | `401`, `application/problem+json` with `"code": "unauthenticated"`, headers `OpenMettle-API-Version: 1.0` and `Cache-Control: no-store` |
| `curl -i https://openmettle.example.test/auth/session` (no session) | `403` |

Without the Ingress, use `kubectl -n openmettle port-forward service/openmettle-openmettle-core-api 8080:8080` and `http://127.0.0.1:8080`. Also run the controller access-log acceptance check before you sign in: [Acceptance check](../charts/openmettle-core/README.md#mandatory-before-routing-login-traffic-no-request-targets-cookies-or-bodies-in-logs).

## 10. Operator steps on the fresh database

Run these in order, as `openmettle_owner` on the primary, from `$CORE`. Each core script prints one fixed line on success and changes nothing on refusal. Use canonical lowercase UUIDs for the provider, invitation, operator and request IDs, and record them in your change record.

### 10.1 Record the login provider authority

Sign-in fails closed until the database records each provider from `auth.json` (core ADR 0012). Core ADR 0013 requires a new provider and its first revision to be inserted in one owner transaction, with an explicit actor and reason. **Core has no operator script for this.** The kind smoke test (`session_seed_sql` in [`tests/kind/smoke.py`](../tests/kind/smoke.py)) records its provider with these two statements in one transaction. Run the same statements with the `id`, `issuer`, `client_id` and `revision` values from `auth.json`:

```sh
psql -X -v ON_ERROR_STOP=1 \
  -v provider="$provider" -v issuer="$issuer" -v client="$client_id" -v revision="$revision" \
  -v actor="$actor" -v reason="$reason" <<'SQL'
BEGIN;
INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason)
    VALUES (:'provider', :'issuer', :'client', :'actor', :'reason');
INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES (:'provider', :'revision');
COMMIT;
SQL
```

The smoke test runs these statements as the fixture superuser. Running them as `openmettle_owner` is *unverified*. To change the revision later, use the ADR 0013 operator protocol. Do not insert again.

### 10.2 Set the login admission limit

Every sign-in initiation is refused until the outstanding-login limit is set (core ADR 0014). Core selects no value. Choose 1–65536:

```sh
psql -X -q -v expected_limit= -v limit=64 -v actor="$actor" -v reason="$reason" \
  -f docs/operator/login-admission-limit.psql
```

### 10.3 Invite the first person

Follow core's [home invitations procedure](https://github.com/OpenMettle/openmettle-core/blob/24808cbf78dd552d751c85c9e37a16d1d66c7ca4/docs/operator/home-invitations.md). Inspect the provider to get `expected_generation`, which is `0` for a new provider. Then run `docs/operator/home-invitation-create.psql` with the person's exact issuer and `sub`. `redeem_before_ms` may be at most seven days ahead. Run it in an unrecorded terminal. Its second output line is the one-time code: deliver it privately, and keep it out of tickets and logs.

### 10.4 Storage and run quotas

These are owner-set inputs, and core has no operator script for either. The kind smoke test (`session_seed_sql`) runs the following statements, and the values here are synthetic:

```sql
-- Uploads: without these, /v1/artifacts uploads answer 503 provisioning (core ADR 0005).
UPDATE openmettle.storage_instance SET instance_budget_bytes = 1048576, personal_limit_bytes = 1048576;
-- Runs: a fresh database enforces metering, so POST /v1/runs answers 503 provisioning
-- (quota resource_kind usage_tokens, scope personal) until this default exists (core ADR 0040).
INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
    VALUES ('personal', 'usage_tokens', 1000000);
```

Project uploads also need `project_limit_bytes`. Size the storage values for your volume, leaving operational headroom (core README, "Schema migrations").

## 11. First sign-in

**Unverified at this pin.** The API serves the sign-in routes, but no sign-in page. Initiation accepts only a form `POST` whose `Origin` is exactly `browser.origin` (core README, "Browser login handoff"). Core expects the app (openmettle-app) to serve that form, and the chart deploys no app. Until an app is deployed, submit the form from a document already on the application origin:

1. In a desktop browser, open `https://openmettle.example.test/readyz`.
2. Open the developer console on that tab and run:

   ```js
   const form = Object.assign(document.createElement('form'), {method: 'POST', action: '/auth/login'});
   const code = prompt('Invitation code (leave empty after the first sign-in)');
   if (code) form.append(Object.assign(document.createElement('input'), {type: 'hidden', name: 'invitation_code', value: code}));
   document.body.append(form);
   form.submit();
   ```

3. Sign in at the provider. The callback sets `__Host-openmettle-session` and redirects to `landing_path` (`/home`). The API answers `404` there, because no app is installed.

The code travels only in the form body, which the ingress must not log. If `/readyz` ever answers with `Referrer-Policy: no-referrer`, the browser sends `Origin: null` and initiation is refused. A malformed code is refused at once with `login request refused`. A wrong code is refused only after the provider step, with the same message as any other refused sign-in (core `home-invitations.md`).

Redemption creates the user, identity, personal scope and approval. To make this person the first account administrator (optional), follow core's [account administrator procedure](https://github.com/OpenMettle/openmettle-core/blob/24808cbf78dd552d751c85c9e37a16d1d66c7ca4/docs/operator/account-admin-recovery.md) with `docs/operator/grant-account-admin.psql`. That procedure needs the internal user UUID. Core names no query for it, so this read-only lookup by the invited issuer and subject is not defined by core:

```sql
SELECT user_id FROM openmettle.user_identities WHERE issuer = :'issuer' AND subject = :'subject';
```

`account_admin` grants no access to anyone's content (core ADR 0027).

**Checks, in the same browser.** Run console commands from a tab on `https://openmettle.example.test/readyz`, for the `Origin` reason above:

| Request | Expected |
| --- | --- |
| Console: `(await fetch('/auth/session')).status` | `204` |
| Open `https://openmettle.example.test/v1/capabilities` | `200`, JSON with an empty capability list |
| Open `https://openmettle.example.test/v1/quotas/personal` | `200` |
| Open `https://openmettle.example.test/v1/models` | `200`, `items` listing the catalog's models (`a` and `b`) |

## 12. Quotas and run admission

With the personal `usage_tokens` default from step 10.4, create a conversation and admit a run in the browser console of a tab on `/readyz`. Writes need an `Idempotency-Key`. The browser adds `Origin` and the session cookie for same-origin `fetch`. The bodies follow core's contract examples `CreatePersonalConversation` and `AppendProposal` (`contracts/openapi/openmettle-v1.json`):

```js
const post = (path, key, body) => fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json',
  'Idempotency-Key': key}, body: JSON.stringify(body)}).then(async r => [r.status, await r.json()]);
const [s1, root] = await post('/v1/conversations', 'first-conversation', {});        // 201
const run = {conversation_id: root.conversation_id, branch_id: root.branch_id, proposal: {
  expected_head_message_id: null,
  turn: {mode: 'append', input_message_id: crypto.randomUUID(), parts: [{text: 'hello'}]},
  selection: {preset: 'study'}}};
const [s2, created] = await post('/v1/runs', 'first-run', run);                      // 201, created.state === 'queued'
```

Sending the same key and body again returns `200` with the same `run_id`. Then `GET /v1/runs/{run_id}` returns the snapshot. These are the endpoint of this guide: a person signed in, called authenticated `/v1` routes and admitted a run. Kind smoke check 10 runs the same conversation, admission, replay and cancel through the API with a seeded session.

| Response | Cause |
| --- | --- |
| `503 provisioning` with `quota` `{"resource_kind": "usage_tokens", "scope_kind": "personal"}` | Step 10.4's default is missing |
| `503 provisioning` without `quota` | `catalog_file`, `admission_limits` or `cursor_keys` is missing from `auth.json`, or `auth.catalogKey` is unset |
| `429` | An `admission_limits` bound or a quota is exhausted |
| `401` | No session, or the write's `Origin` is not `browser.origin` |

The run stays queued until `queue_timeout_seconds`. The worker then expires it as `run.failed` with `reason=queue_expired` (kind smoke check 11). To end it sooner, send `POST /v1/runs/{run_id}/cancel` with an `Idempotency-Key`.

## Running `openmettle-admin`

`openmettle-admin` is core's owner-operated maintenance binary (`$CORE/src/bin/admin.rs`). It reads `OPENMETTLE_ADMIN_DATABASE_URL`, which is the `openmettle_owner` URL, and supports `storage adopt ROOT`, `quota drain-orphans`, `quota activate` and `quota verify [ROOT]`. A fresh install needs none of them. `quota verify` is an optional consistency check, and the others belong to the [upgrade runbook](https://github.com/OpenMettle/openmettle-core/blob/24808cbf78dd552d751c85c9e37a16d1d66c7ca4/docs/operator/storage-adoption-and-quota-upgrade.md). The chart has no admin workload. Run the image as a one-off Job in the release namespace with the owner Secret and no other privileges:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: openmettle-admin-quota-verify
  namespace: openmettle
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      # Not the chart's labels, so the release's NetworkPolicies do not select this pod.
      labels: {app.kubernetes.io/name: openmettle-admin}
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      enableServiceLinks: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: admin
          image: <registry host>/<path>/admin@sha256:<admin digest>
          args: [quota, verify]                       # database-only form
          env:
            - name: OPENMETTLE_ADMIN_DATABASE_URL
              valueFrom: {secretKeyRef: {name: openmettle-owner-database, key: url}}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: db-ca, mountPath: /etc/openmettle/db-ca, readOnly: true}
      volumes:
        - name: db-ca
          configMap: {name: openmettle-db-ca, items: [{key: ca.crt, path: ca.crt}]}
```

- **Commands that read the volume.** `quota verify /var/lib/openmettle/artifacts` and `storage adopt` also mount the artifact claim at that path. `storage adopt` mounts it read-write. The chart-owned claim is `openmettle-openmettle-core-artifacts`. With `ReadWriteOnce`, the Job must run on the node that mounts the claim.
- **Namespace default-deny.** Add a NetworkPolicy that selects `app.kubernetes.io/name: openmettle-admin` and allows egress only to DNS and the database peers.
- **Result.** Read it with `kubectl -n openmettle logs job/openmettle-admin-quota-verify`. The output holds counts, not credentials. `quota verify` exits non-zero on drift.
- **After the run.** Delete the Job.

This manifest passes `kubeconform` against the pinned Kubernetes 1.37.0 schemas. It has not been run on a cluster.

## Upgrade-only steps a fresh install must skip

A fresh install must not run these steps. They apply only to an existing database or a restore:

- `openmettle-admin storage adopt`, `quota drain-orphans` and `quota activate`. A fresh database starts with metering and overrides enforced, and the API pins the empty artifact volume itself (core ADR 0040).
- Setting `worker.replicas: 0` before migrating, which stops legacy artifact cleaners. That step is for upgrades from migration 23 or earlier.
- Withdrawing pending invitations before migration 13, and revoking pre-upgrade sessions after migration 18 (core ADR 0030, "Upgrade").
- `restore-login-provider.psql`, which applies only to a retired provider, and core's database backup restore checklist.

## Not yet possible at this pin

- **An admitted run is never executed.** The packaged `openmettle-worker` runs maintenance sweeps only and exits 78 if run slots are configured. The production executor is V1-07. A queued run waits until it is cancelled or expires.
- **No model call can happen.** The chart deploys no gateway reconciliation workload (`openmettle_gateway` exists only as a `NOLOGIN` role) and no gateway adapter or model server. The catalog above is synthetic.
- **No sign-in page.** The interim same-origin form in [step 11](#11-first-sign-in) is a manual stopgap until openmettle-app is deployed.

## How this guide differs from the kind smoke test

The kind smoke test ([`tests/kind/smoke.py`](../tests/kind/smoke.py)) is the only executable form of this sequence. It differs from this guide as follows:

| Step | Kind smoke test | This guide | Why |
| --- | --- | --- | --- |
| Images | Built for amd64, imported into the node's containerd, given a digest name and run with `pullPolicy: Never` | Pushed to a registry and pulled by digest | The test has no registry |
| PostgreSQL | In-cluster PostgreSQL 18.1 on `emptyDir`, `sslmode=disable`, with roles created by an init script | External PostgreSQL 18, `verify-full`, database CA ConfigMap | TLS to PostgreSQL is not exercised by the test |
| Install sequence | Installs the default profile, then upgrades to the enabled profile | Installs the enabled profile directly | The test also checks the default profile |
| Migration timeouts | 120 s deadline and `--timeout 300s` | Chart defaults: 900 s and `--timeout 15m` | Bounds a hung hook in CI |
| Namespace | Adds a namespace default-deny policy | Default-deny optional | Both work |
| OIDC | No provider; a synthetic issuer and an RFC 5737 egress peer | A real Keycloak registration | Core's `keycloak-qualification.yml` covers live sign-in |
| Provider authority, user, session | Inserted directly as the fixture superuser: provider and revision, user, scope, identity, approval, login and session | Provider and revision inserted as owner (10.1), then a home invitation and a real browser sign-in | No provider in the test |
| Login admission limit, invitation, account admin | Not run | Core scripts (10.2, 10.3, 11) | Not needed with a seeded session |
| Storage and quota seeds | Same SQL as 10.4, as superuser | As owner | — |
| Auth document | `browser` plus `native` profile, native trust roots, `catalog_file`, `admission_limits`, `cursor_keys` | `browser` only | Native is optional |
| Catalog | Core fixture plus `prompt_bound`, through `auth.catalogKey` | Same | — |
| Run admission | `POST /v1/runs` through a pod port-forward, then replay and cancel (check 10). Check 11 also admits through a fixture caller of core's store | `POST /v1/runs` from the browser through the Ingress | — |
| Ingress | Traefik v3.7.19 on port 8443, per-run certificate, no middleware, access logs off | K3s Traefik with redaction and the body-limit middleware | The test does not route sign-in |
| Logging and worker | `json`/`debug` logs, `worker.sweepMs: 1000` | Chart defaults | Speeds up expiry in CI |
| `openmettle-admin` | Not run | Optional Job | — |
