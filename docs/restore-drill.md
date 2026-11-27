# Isolated Restore Drill and Operator Recovery Runbook (V1-31)

This runbook defines the repeatable Kubernetes recovery and isolated-target restore drill procedure for `charts/openmettle-core` pinned to `CORE_COMMIT` (schema through migration `45`, core ADRs `0013`, `0031`, `0035`, `0039`, `0040`, `0041`, `0045` and `0046`).

[`tests/kind/restore_drill.py`](../tests/kind/restore_drill.py) (`.github/workflows/restore-drill.yml`) automates this procedure end-to-end on an ephemeral `kind` cluster classified `dev`. Passing the `dev` harness proves chart, CLI, SQL and `NetworkPolicy` mechanics; it does **not** substitute for an owner-executed drill on the target workstation and off-host NAS (`V1-01`, `V1-31`, `V1-33`).

## Scope and safety boundaries

1. **Isolated target only.** Always restore into a separate namespace or cluster, a fresh PostgreSQL database (`openmettle`) with freshly generated role passwords, and a fresh artifact `PersistentVolumeClaim`. Never run `pg_restore`, `storage rebind` or `restore replay` against a live primary database or mounted primary artifact volume.
2. **Default-deny network isolation before restore.** Apply `pod-security.kubernetes.io/enforce=restricted` and a namespace-wide `default-deny` `NetworkPolicy` to the target namespace before creating any recovery `Job` or workload, so target pods cannot reach primary PostgreSQL, primary `openmettle-gateway` Services, or unapproved external endpoints. Keep `backup.suspend: true` (or `backup.enabled: false`) on the drill target so it cannot write to or prune a shared backup destination.
3. **Separate backup and vault key custody.** `OPENMETTLE_ADMIN_BACKUP_KEYS_CONFIG` and `OPENMETTLE_API_VAULT_KEYS_CONFIG` / `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` must remain distinct Secrets and keyrings (`ADR 0045`, `ADR 0046`). `openmettle-admin` refuses identical paths or key material.
4. **RPO / RTO targets.** Single-node v1 targets **RPO <= 24 hours** (`86,400 s` between the restored backup's `quiesced_at` timestamp and incident/drill cutover, narrowed further when a post-backup `deletion-journal` export is replayed) and **RTO <= 4 hours** (`14,400 s` from recovery start to verified `/readyz` `200`, `quota verify` `0` drift, and authenticated `/v1` verification on the target).
5. **Explicit non-goals.** Legacy Open WebUI database or file import is excluded from v1 recovery (`ADR 0003`). Optional Graphiti (`neo4j.dump`) and Chroma (`chroma.tar` or `qualified-rebuild`) recovery steps apply only when `manifest.json` records a provisioned mode other than `not-provisioned`.

---

## Step 1 — Preflight verification and unpacking

Run an offline `PodSecurity: restricted` recovery `Job` using the digest-pinned `openmettle-admin` image, mounting the backup destination PVC `readOnly: true`, staging the backup keyring into a `Memory` `emptyDir` (`0400`, UID `65532`), and mounting an isolated scratch PVC (`0700`) at `/var/recovery`:

```sh
# 1. Verify backup-meta.json, encrypted manifest, and AEAD stream tags for all components.
openmettle-admin backup verify \
  --backup-dir /var/backups/openmettle/<backup-dir> \
  --backup-keys-config /etc/openmettle/backup-keys/keyring.json

# 2. Decrypt and unpack into a mode-0700 directory on the target scratch volume.
openmettle-admin backup unpack \
  --backup-dir /var/backups/openmettle/<backup-dir> \
  --output-dir /var/recovery/unpacked \
  --backup-keys-config /etc/openmettle/backup-keys/keyring.json
```

Before touching PostgreSQL or the target artifact PVC, inspect `/var/recovery/unpacked/manifest.json`:

- **Schema compatibility:** `schema_version` must be `<=` the migration version shipped by the target chart's `CORE_COMMIT` (`45` at `87a395e`). Never restore a newer schema dump onto an older `openmettle-core` binary.
- **Required vault key IDs:** check `vault_required_key_ids`. Every listed key ID must exist in the target `vault.existingSecret` keyring before starting `api`/`worker` or running `openmettle-admin vault rotate`; otherwise encrypted `external_connections` rows sealed under missing key versions cannot be decrypted or rotated.
- **Optional stores:** check `graphiti_neo4j.mode` (`not-provisioned` or `offline-dump`) and `chroma.mode` (`not-provisioned`, `archive` or `qualified-rebuild`). If `offline-dump` or `archive` is recorded, restore `neo4j.dump` / `chroma.tar` onto isolated target stores before enabling those adapters; if `qualified-rebuild` is recorded, rebuild Chroma embeddings offline against `chroma.qualification_ref` before opening retrieval traffic.
- **RPO anchor:** record `quiesced_at` and `deletion_journal.journal_seq`.

---

## Step 2 — Provision isolated target namespace and PostgreSQL roles

1. Create the target namespace with `pod-security.kubernetes.io/enforce=restricted` and apply a namespace-wide `default-deny` `NetworkPolicy` plus explicit egress rules allowing target recovery Jobs to reach only CoreDNS (`53/UDP`, `53/TCP`) and the **isolated target** PostgreSQL endpoint (`5432/TCP`).
2. On the isolated target PostgreSQL 18 instance, create the five disjoint login roles with fresh random passwords and an empty `openmettle` database owned by `openmettle_owner`:

```sql
CREATE ROLE openmettle_owner LOGIN PASSWORD '<fresh-owner-password>';
CREATE ROLE openmettle_api LOGIN PASSWORD '<fresh-api-password>';
CREATE ROLE openmettle_issuance LOGIN PASSWORD '<fresh-issuance-password>';
CREATE ROLE openmettle_worker LOGIN PASSWORD '<fresh-worker-password>';
CREATE ROLE openmettle_gateway LOGIN PASSWORD '<fresh-gateway-password>';
CREATE DATABASE openmettle OWNER openmettle_owner;
```

3. Create the target Kubernetes `Secret`s (`database.api`, `database.worker`, `database.migrate`, `database.issuance`, `database.gateway`, and optional `database.backup`), distinct `auth.loginKeysSecretName` (fresh 32-byte `active.key` and `cursor.key`), and `vault.existingSecret`.

---

## Step 3 — Restore PostgreSQL dump and run `openmettle-migrate`

1. Restore `/var/recovery/unpacked/pg.dump` as `openmettle_owner` using PostgreSQL 18 `pg_restore` from the publisher-pinned `postgresClient` image. Supply the password via a `0600` `PGPASSFILE` on a `Memory` `emptyDir` — never on the command line:

```sh
umask 077
export PGPASSFILE=/tmp/pgpass
# Escape any '\' or ':' in dynamic fields per libpq .pgpass rules if applicable.
printf '%s:%s:openmettle:openmettle_owner:%s\n' "$PGHOST" "$PGPORT" "$OWNER_PASSWORD" > "$PGPASSFILE"
chmod 0600 "$PGPASSFILE"

pg_restore \
  --format=custom \
  --no-owner \
  --exit-on-error \
  --host="$PGHOST" \
  --port="$PGPORT" \
  --username=openmettle_owner \
  --dbname=openmettle \
  /var/recovery/unpacked/pg.dump
rm -f "$PGPASSFILE"
```

2. Run `openmettle-migrate` (with `OPENMETTLE_MIGRATE_DATABASE_URL` pointing to the target `openmettle_owner` Secret) so any forward migrations between `manifest.json`'s `schema_version` and `CORE_COMMIT` apply cleanly and role privileges plus owner default-ACL revocations (`pg_default_acl` `defaclnamespace = 0`) are enforced.
3. Because `backup capture` runs inside an active maintenance window (`ADR 0046`), the restored `openmettle.backup_maintenance_gate` row starts with `maintenance_active = true` and `backup_run_id` set to the captured run (`publishing` state in `openmettle.backup_runs`). Keep maintenance active until Step 5d completes.

---

## Step 4 — Lock restore gate, rebind artifact volume, and replay deletion journal

### 4a. Choose `SELECTED_JOURNAL` and lock `restore_reconciliation_gate`

- **Preferred (complete post-backup journal export available):** use the newest verified off-host `openmettle-admin journal export` file whose `origin` matches the installation and whose `watermark` sequence is `>=` `manifest.deletion_journal.journal_seq`. Pass `--export-complete` to `restore lock`.
- **Fallback (only the backup's bundled journal is available):** use `/var/recovery/unpacked/deletion-journal.bin` **without** `--export-complete`, then record break-glass acceptance before replay:
  `openmettle-admin restore accept-coverage-gap --restore-run <RESTORE_RUN_UUID> --operator-id <OPERATOR_UUID> --request-key <KEY> --reason <REASON>`.

Read the header and footer lines of `SELECTED_JOURNAL`:

- `origin <ORIGIN_US>`
- optional `lifecycle_origin <LIFECYCLE_ORIGIN_US>` and `lifecycle_baseline <LIFECYCLE_BASELINE_HEX>` (always pass both together when present)
- optional `connection_origin <CONNECTION_ORIGIN_US>`
- `watermark <ORIGIN_US> <REQUIRED_SEQ> <REQUIRED_DIGEST_HEX> <EXPORTED_US>`

Close `openmettle.restore_reconciliation_gate` (`OPENMETTLE_ADMIN_DATABASE_URL` = target `openmettle_owner` URL):

```sh
openmettle-admin restore lock \
  --required-origin "$ORIGIN_US" \
  --required-lifecycle-origin "$LIFECYCLE_ORIGIN_US" \
  --required-lifecycle-baseline-digest "$LIFECYCLE_BASELINE_HEX" \
  --required-connection-origin "$CONNECTION_ORIGIN_US" \
  --required-seq "$REQUIRED_SEQ" \
  --required-digest "$REQUIRED_DIGEST_HEX" \
  --export-complete
```

### 4b. Copy unpacked artifacts and run `storage rebind`

Copy the unpacked artifact directory tree onto the empty target artifact PVC (`/var/lib/openmettle/artifacts`, owned by UID/GID `65532`) and rebind the volume identity (`ADR 0040`):

```sh
for entry in /var/recovery/unpacked/artifacts/* /var/recovery/unpacked/artifacts/.[!.]*; do
  [ -e "$entry" ] || continue
  cp -a -- "$entry" /var/lib/openmettle/artifacts/
done
openmettle-admin storage rebind /var/lib/openmettle/artifacts
```

- **If `storage rebind` exits `0` (`failed 0`):** proceed directly to Step 4d.
- **If `storage rebind` exits `1` (`storage rebind incomplete`):** stderr prints `--replace-adoption-run <BARRIER_UUID>` and stdout lists every `failed <reservation_id>: missing revision` (or size/digest mismatch). Follow Step 4c in exact order.

### 4c. Handling missing or unrecoverable artifact payloads (`storage declare-lost`)

Never declare a revision lost before replaying post-backup database journal records: a file missing from disk may already have been purged after the backup (`ADR 0041` / `docs/operator/restore-artifact-volume.md`):

```sh
# 1. Catch up the database deletion journal first while keeping the restore gate closed.
openmettle-admin restore replay --db-only "$SELECTED_JOURNAL"

# 2. For each revision still active/retained whose on-disk payload is genuinely unrecoverable,
#    record an audited loss declaration (transitions state -> 'lost' / HTTP 410 Gone, decrements
#    active_bytes, and appends artifact_revision.lost to deletion_journal).
openmettle-admin storage declare-lost /var/lib/openmettle/artifacts \
  --revision "$MISSING_REVISION_UUID" \
  --operator-id "$OPERATOR_UUID" \
  --request-key "restore-lost-$MISSING_REVISION_UUID" \
  --reason "payload missing from recovery media during isolated restore"

# 3. Complete volume rebind under the held adoption barrier.
openmettle-admin storage rebind /var/lib/openmettle/artifacts \
  --replace-adoption-run "$BARRIER_UUID"
```

### 4d. Full `restore replay` and `quota verify`

Run full volume + database replay to unlink any resurrected post-backup purged files from `/var/lib/openmettle/artifacts`, apply post-backup external-connection share revocations and disconnects, verify `original_purge_after` retention deadlines, verify zero accounting drift, and open `restore_reconciliation_gate`:

```sh
openmettle-admin restore replay "$SELECTED_JOURNAL" /var/lib/openmettle/artifacts
openmettle-admin quota verify /var/lib/openmettle/artifacts
```

Require `quota verify` to exit `0` and print:
`storage mismatches 0, budget mismatches 0, settlement mismatches 0, pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0`.

---

## Step 5 — Pre-worker security, session, vault, and run-reconciliation checklist

Complete every item below **before** starting `openmettle-worker` or exposing `openmettle-api` ingress traffic.

### 5a. Invalidate pre-restore sessions and pending OIDC transactions (`ADR 0013`)

Increment `access_generation` and append a new `login_provider_revisions` epoch for every active (non-retired) login provider so all pre-restore `local_sessions` cookies/bearers fail closed with `401 unauthenticated` and any in-flight `login_transactions` from the snapshot are fenced:

```sql
BEGIN;
LOCK TABLE openmettle.login_providers IN SHARE ROW EXCLUSIVE MODE;
WITH active_providers AS (
    SELECT p.id, r.revision
      FROM openmettle.login_providers p
      JOIN LATERAL (
          SELECT revision
            FROM openmettle.login_provider_revisions lpr
           WHERE lpr.provider_id = p.id
           ORDER BY lpr.epoch DESC
           LIMIT 1
      ) r ON r.revision IS NOT NULL
),
bumped AS (
    UPDATE openmettle.login_providers p
       SET access_generation = p.access_generation + 1,
           changed_by = 'operator:<operator-uuid>',
           change_reason = 'isolated restore session invalidation'
      FROM active_providers ap
     WHERE p.id = ap.id
 RETURNING p.id
)
INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
SELECT ap.id, ap.revision
  FROM active_providers ap
  JOIN bumped b ON b.id = ap.id;
COMMIT;
```

Deploy the target release with freshly generated 32-byte `active.key` and `cursor.key` values in `auth.loginKeysSecretName`.

### 5b. Verify and rotate credential vault keys (`ADR 0045`)

Check encrypted connection counts by state and key ID:

```sh
openmettle-admin vault status
```

Confirm every `key_id <id> <count>` with `<count> > 0` is staged in the target `vault.existingSecret`. To rotate recovered credentials onto a fresh target key (`active_key_id`), stage both the previous decrypt key(s) and the new active key in `keyring.json` and run:

```sh
openmettle-admin vault rotate \
  --vault-keys /etc/openmettle/vault-keys/keyring.json \
  --operator-id "$OPERATOR_UUID" \
  --request-key "restore-vault-rotate-1" \
  --reason "re-seal recovered external connections onto target vault key"
```

### 5c. Cancel parked `waiting` and `queued` runs (`ADR 0035`, `ADR 0039`)

Coordinated backup capture drains `executing` worker leases before `pg_dump`, but runs parked in `waiting` (such as pending human approvals in `openmettle.run_approvals` or revision-`0` two-phase external write `intent` rows in `openmettle.operations`) and `queued` runs remain non-terminal in the snapshot. Cancel them as `openmettle_owner` before starting `openmettle-worker` so:

- stale approval tokens/decisions are refused (`409 conflict`) rather than reviving pre-incident external actions;
- trigger `openmettle.resolve_terminal_write_intents()` transitions every revision-`0` write `intent` (`idempotent`, `lookup`, `non_repeatable`) to `outcome = 'outcome_unknown', revision = 1` and records `unresolved-write:<operation_id>` in `openmettle.run_events` without re-dispatching external effects; and
- `openmettle.quota_release_terminal_runs` releases any held run token/cost reservations cleanly.

```sql
BEGIN;
WITH target_runs AS (
    SELECT r.id, r.scope_id
      FROM openmettle.runs r
     WHERE r.state IN ('queued', 'running', 'waiting')
     ORDER BY r.id
       FOR UPDATE
),
cancelled AS (
    UPDATE openmettle.runs r
       SET state = 'cancelled',
           wait_reason = NULL,
           cancel_reason = coalesce(r.cancel_reason, 'revoked'),
           claim_token = NULL,
           claimed_at = NULL,
           lease_expires_at = NULL,
           execution_expires_at = NULL
      FROM target_runs t
     WHERE r.id = t.id
 RETURNING r.id, r.scope_id
),
framed_events AS (
    SELECT c.scope_id,
           c.id AS run_id,
           'run-terminal'::text AS append_key,
           'openmettle.run-cancelled'::text AS format,
           1::integer AS format_version,
           convert_to('{"reason":"revoked"}', 'UTF8') AS payload,
           decode('6f70656e6d6574746c652f6576656e742f3100', 'hex')
               || int8send(octet_length(c.scope_id::text)::bigint) || convert_to(c.scope_id::text, 'UTF8')
               || int8send(octet_length(c.id::text)::bigint) || convert_to(c.id::text, 'UTF8')
               || int8send(octet_length('run-terminal')::bigint) || convert_to('run-terminal', 'UTF8')
               || int8send(octet_length('openmettle.run-cancelled')::bigint) || convert_to('openmettle.run-cancelled', 'UTF8')
               || int8send(4::bigint) || int4send(1)
               || int8send(octet_length(convert_to('{"reason":"revoked"}', 'UTF8'))::bigint)
               || convert_to('{"reason":"revoked"}', 'UTF8') AS identity
      FROM cancelled c
),
inserted_events AS (
    INSERT INTO openmettle.run_events (
        scope_id, run_id, sequence, append_key, identity, digest, format, format_version, payload
    )
    SELECT f.scope_id,
           f.run_id,
           coalesce((SELECT max(e.sequence) FROM openmettle.run_events e WHERE e.run_id = f.run_id), 0) + 1,
           f.append_key,
           f.identity,
           sha256(f.identity),
           f.format,
           f.format_version,
           f.payload
      FROM framed_events f
        ON CONFLICT (run_id, append_key) DO NOTHING
 RETURNING run_id
)
SELECT CASE
           WHEN count(*) > 0 THEN openmettle.quota_release_terminal_runs(array_agg(id ORDER BY id))
           ELSE 0
       END
  FROM cancelled;
COMMIT;
```

### 5d. Release snapshot maintenance gate and scrub unpacked staging

```sh
openmettle-admin backup release-maintenance \
  --operator-id "$OPERATOR_UUID" \
  --request-key "restore-release-maintenance-1" \
  --reason "isolated restore pre-worker reconciliation complete" \
  --abort-active-run

openmettle-admin quota verify /var/lib/openmettle/artifacts
rm -rf /var/recovery/unpacked
```

---

## Step 6 — Start target workloads, verify invariants, and record RPO / RTO

1. Install or upgrade `charts/openmettle-core` in the isolated target namespace with `storage.artifacts.existingClaim` bound to the reconciled target PVC, `vault.enabled: true` pointing at the target vault Secret, and `backup.suspend: true` (or `backup.enabled: false`).
2. Wait for `Deployment/<release>-api`, `Deployment/<release>-worker`, and any configured `Deployment/<release>-gateway-*` to report Ready and `GET /readyz` -> `200`. Record `recovery_completed_at`.
3. Verify post-restore functional and security invariants before cutover or drill sign-off:
   - Pre-restore session cookies/tokens return `401 unauthenticated`.
   - Newly authenticated sessions see surviving personal and project conversations, artifacts, and authorized connections with intact ownership and role boundaries (`404 not_found` across personal scopes and non-members; `403 policy` on `Viewer` writes).
   - Revisions declared lost in Step 4c return `200` metadata (`state: "lost"`, non-null `lost_at`) and `410 Gone` (`code: "payload_lost"`) on `/content` for authorized readers, while remaining `404` for unauthorized callers.
   - Post-backup purged revisions and revoked connection shares replayed in Step 4d remain purged/revoked (`0` resurrected files on disk; `disconnected` connections retain no ciphertext).
   - Retained revisions keep their exact pre-backup `original_purge_after` deadline (not reset from wall-clock restore time).
   - Parked `waiting` runs from the snapshot report `state: "cancelled"`, `POST /v1/runs/{run_id}/approvals/{approval_id}/decision` returns `409 conflict`, and revision-`0` write intents report `outcome = 'outcome_unknown'` (`revision = 1`) with zero unsolicited external/gateway calls on worker startup.
   - `openmettle-admin quota verify /var/lib/openmettle/artifacts` exits `0` with all seven mismatch counters equal to `0`, and `openmettle-admin journal export` succeeds on the restored database.
4. Compute and archive the drill metrics:
   - `restored_data_age_seconds = drill_cutover_at - manifest.quiesced_at` (must be `<= 86,400 s` for the 24h RPO target).
   - `recovery_duration_seconds = recovery_completed_at - recovery_started_at` (must be `<= 14,400 s` for the 4h RTO target).

## Drill cadence

- **Automated CI (`dev` classification):** `.github/workflows/restore-drill.yml` runs `tests/kind/restore_drill.py` on pull requests and `main` pushes touching `CORE_COMMIT`, `charts/openmettle-core/**`, `tests/kind/**`, `tests/chart/install-tools.sh`, `docs/restore-drill.md`, or `.github/workflows/restore-drill.yml`, and via `workflow_dispatch`.
- **Operator qualification (`V1-31` / `V1-33`):** execute and record a live isolated-target drill on the workstation + off-host NAS before production cutover, on a recurring quarterly schedule, and after any material change to backup format/encryption (`ADR 0046`), artifact storage/journal reconciliation (`ADR 0040` / `ADR 0041`), vault key custody (`ADR 0045`), or PostgreSQL major/schema lifecycle migrations.
