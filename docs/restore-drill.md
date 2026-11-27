# Isolated Restore Drill and Operator Recovery Runbook (V1-31)

This runbook defines the repeatable Kubernetes recovery and isolated-target restore drill procedure for `charts/openmettle-core` pinned to `CORE_COMMIT` (schema through migration `45`, core ADRs `0013`, `0027`, `0031`, `0035`, `0039`, `0040`, `0041`, `0045` and `0046`).

[`tests/kind/restore_drill.py`](../tests/kind/restore_drill.py) (`.github/workflows/restore-drill.yml`) automates this procedure end-to-end on an ephemeral `kind` cluster classified `dev`. Passing the `dev` harness proves chart, CLI, SQL and `NetworkPolicy` mechanics; it does **not** substitute for an owner-executed drill on the target workstation and off-host NAS (`V1-01`, `V1-31`, `V1-33`).

## Scope and safety boundaries

1. **Isolated target only.** Always restore into a separate namespace or cluster, a fresh PostgreSQL database (`openmettle`) with freshly generated role passwords, and a fresh artifact `PersistentVolumeClaim`. Never run `pg_restore`, `storage rebind` or `restore replay` against a live primary database or mounted primary artifact volume.
2. **Default-deny network and Pod Security isolation before workloads.** Apply `pod-security.kubernetes.io/enforce=restricted` and namespace-wide `default-deny` `NetworkPolicy` manifests across both the target application namespace and any in-cluster target database namespace **before** submitting database fixtures, recovery `Job`s, or runtime workloads, so target pods cannot reach primary PostgreSQL, primary `openmettle-gateway` Services, or unapproved external endpoints at any point in their lifecycle. Keep `backup.suspend: true` (or `backup.enabled: false`) on the drill target so it cannot write to or prune a shared backup destination.
3. **Separate backup and vault key custody.** `OPENMETTLE_ADMIN_BACKUP_KEYS_CONFIG` and `OPENMETTLE_API_VAULT_KEYS_CONFIG` / `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` must remain distinct Secrets, files, and 32-byte key material (`ADR 0045`, `ADR 0046`). `openmettle-admin` refuses overlapping paths, inodes, or duplicate key bytes whenever `OPENMETTLE_API_VAULT_KEYS_CONFIG` is set in the preflight environment.
4. **RPO / RTO targets.** Single-node v1 targets **RPO <= 24 hours** (`86,400 s` between the restored backup's `quiesced_at` timestamp and incident/drill cutover) and **RTO <= 4 hours** (`14,400 s` from recovery initiation — before target provisioning and media staging — through final post-restore HTTP/SQL acceptance and `quota verify` completion).
5. **Explicit non-goals.** Legacy Open WebUI database or file import is excluded from v1 recovery (`ADR 0003`). Optional Graphiti (`neo4j.dump`) and Chroma (`chroma.archive` or `qualified_rebuild`) recovery steps apply only when `manifest.json` records a provisioned state other than `not_provisioned`.

---

## Step 1 — Preflight verification and unpacking

Stage **both** the backup keyring (`/etc/openmettle/backup-keys`) and the target vault keyring (`/etc/openmettle/vault-keys`) via `Memory` `emptyDir` `initContainer`s writing `0400` files owned by UID `65532` and mounted `readOnly: true` with `subPath: keys`, mount the backup destination PVC `readOnly: true`, mount an isolated scratch PVC at `/var/recovery`, and export `OPENMETTLE_API_VAULT_KEYS_CONFIG` so `BackupKeyRing::load_from_config` enforces backup/vault key separation during preflight:

```sh
set -eu
export OPENMETTLE_API_VAULT_KEYS_CONFIG=/etc/openmettle/vault-keys/keyring.json

# 1. Verify backup-meta.json, backup/vault key separation, encrypted manifest, and AEAD stream tags.
openmettle-admin backup verify \
  --backup-dir /var/backups/openmettle/<backup-dir> \
  --backup-keys-config /etc/openmettle/backup-keys/keyring.json

# 2. Decrypt and unpack into a mode-0700 directory on the target scratch volume.
openmettle-admin backup unpack \
  --backup-dir /var/backups/openmettle/<backup-dir> \
  --output-dir /var/recovery/unpacked \
  --backup-keys-config /etc/openmettle/backup-keys/keyring.json
```

`backup unpack` writes `pg.dump`, `gateway-entitlements.json`, `deletion-journal.bin`, `artifacts/` (with `revisions/`, `staging/`, and `.openmettle-volume-id` sentinels when pinned), `config/` (including `vault-key-inventory.json`), optional `neo4j.dump`, optional `chroma.archive`, and plaintext `manifest.json`. Inspect `/var/recovery/unpacked/manifest.json` before touching PostgreSQL or PVCs:

- **Schema compatibility:** `schema_version` must be `<=` the migration version shipped by the target chart's `CORE_COMMIT` (`45` at `87a395e`). Never restore a newer schema dump onto an older `openmettle-core` binary.
- **Required vault key IDs:** check `vault_required_key_ids` (and `/var/recovery/unpacked/config/vault-key-inventory.json`). Every listed key ID must exist in `/etc/openmettle/vault-keys/keyring.json` before starting `api`/`worker` or running `openmettle-admin vault rotate`.
- **Artifact volume mode:** check `artifact_volume.volume_id` (non-null UUID when artifact storage is pinned; `null` on storage-disabled deployments).
- **Optional stores:** check `graphiti_neo4j.status` (`"not_provisioned"` or `"offline_dump"`) and `chroma.mode` (`"not_provisioned"`, `"archive"` or `"qualified_rebuild"`). If `neo4j.dump` is unpacked, restore Neo4j offline (`neo4j-admin database load`) before enabling Graphiti; if `chroma.archive` is unpacked, restore Chroma's persistent directory from `chroma.archive`; if `chroma.mode` is `"qualified_rebuild"`, rebuild `chroma_vector_embeddings` offline against `chroma.qualification_ref` before opening retrieval traffic.
- **RPO anchor:** record `quiesced_at` and `deletion_journal.journal_seq`.

---

## Step 2 — Provision isolated target namespace and PostgreSQL roles

1. Create the target namespace(s) with `pod-security.kubernetes.io/enforce=restricted` and apply namespace-wide `default-deny` `NetworkPolicy` manifests plus explicit egress/ingress rules allowing target recovery Jobs to reach only CoreDNS (`53/UDP`, `53/TCP`) and the **isolated target** PostgreSQL endpoint (`5432/TCP`) **before** creating any Pods, Jobs, or Deployments.
2. On the isolated target PostgreSQL 18 instance, create the five disjoint login roles with fresh random passwords, create the `openmettle` database owned by `openmettle_owner`, and apply the required `PUBLIC` revocations and runtime `CONNECT` grants (`pg_dump --schema=openmettle` omits database and `public`-schema ACLs, which `openmettle-migrate` verifies when schema `>= 1` is already recorded):

```sql
CREATE ROLE openmettle_owner LOGIN PASSWORD '<fresh-owner-password>';
CREATE ROLE openmettle_api LOGIN PASSWORD '<fresh-api-password>';
CREATE ROLE openmettle_issuance LOGIN PASSWORD '<fresh-issuance-password>';
CREATE ROLE openmettle_worker LOGIN PASSWORD '<fresh-worker-password>';
CREATE ROLE openmettle_gateway LOGIN PASSWORD '<fresh-gateway-password>';
CREATE DATABASE openmettle OWNER openmettle_owner;
REVOKE ALL ON DATABASE openmettle FROM PUBLIC;
GRANT CONNECT ON DATABASE openmettle TO openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway;
\connect openmettle
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

3. Create the target Kubernetes `Secret`s (`database.api`, `database.worker`, `database.migrate`, `database.issuance`, `database.gateway`, and optional `database.backup`), distinct `auth.loginKeysSecretName` (fresh 32-byte `active.key` and `cursor.key`), and `vault.existingSecret`.

---

## Step 3 — Restore PostgreSQL dump and run `openmettle-migrate`

1. Restore `/var/recovery/unpacked/pg.dump` as `openmettle_owner` using PostgreSQL 18 `pg_restore` from the publisher-pinned `postgresClient` image. Stage the isolated target PostgreSQL CA bundle (`database.caBundle.configMapName` / `database.caBundle.key`) via an `initContainer` (`cp -L /run/openmettle-db-ca-src/ca.crt /run/openmettle-db-ca-stage/ca.crt && chmod 0444 /run/openmettle-db-ca-stage/ca.crt` into a `Memory` `emptyDir`, matching `templates/backup-cronjob.yaml`) mounted `readOnly: true` at the exact `sslrootcert` path referenced by the target owner URL (`/etc/openmettle/db-ca/ca.crt` when rendered by `database.caBundle`; `openmettle-admin backup status` and `backup release-maintenance` open `sslrootcert` with `O_NOFOLLOW` and refuse `ConfigMap` symlinks). Enforce server identity verification (`PGSSLMODE=verify-full`, `PGSSLROOTCERT=/etc/openmettle/db-ca/ca.crt` matching that `sslrootcert` path, `PGGSSENCMODE=disable`; `PGSSLMODE=disable` is confined strictly to the synthetic `dev`-classified `kind` fixture), supply credentials exclusively through a `0600` `PGPASSFILE` on a `Memory` `emptyDir` with libpq `\` and `:` escaping — never on the command line — and clean up `PGPASSFILE` via an `EXIT` trap under `set -eu` so a `pg_restore` failure is never masked:

```sh
set -eu
umask 077
export PGPASSFILE=/tmp/pgpass
export PGSSLMODE=verify-full
export PGSSLROOTCERT="${PGSSLROOTCERT:-/etc/openmettle/db-ca/ca.crt}"
export PGGSSENCMODE=disable
trap 'rm -f "$PGPASSFILE"' EXIT
esc() { printf '%s' "$1" | sed 's/[\\:]/\\&/g'; }
printf '%s:%s:openmettle:openmettle_owner:%s\n' \
  "$(esc "$PGHOST")" "$(esc "${PGPORT:-5432}")" "$(esc "$OWNER_PASSWORD")" > "$PGPASSFILE"
chmod 0600 "$PGPASSFILE"

pg_restore \
  --format=custom \
  --no-owner \
  --exit-on-error \
  --host="$PGHOST" \
  --port="${PGPORT:-5432}" \
  --username=openmettle_owner \
  --dbname=openmettle \
  /var/recovery/unpacked/pg.dump
```

2. Run `openmettle-migrate` (`OPENMETTLE_MIGRATE_DATABASE_URL` = target `openmettle_owner` URL) so any forward migrations between `manifest.json`'s `schema_version` and `CORE_COMMIT` apply cleanly, role boundaries (`src/boundaries.sql`) are verified, and global/schema owner default-ACL revocations (`pg_default_acl` `defaclnamespace = 0`) are re-established.
3. Because `backup capture` exports its `pg_dump` snapshot inside an active maintenance window while the `openmettle.backup_runs` row is in `'draining'` state (prior to post-dump publication, `ADR 0046`), `openmettle.backup_maintenance_gate.maintenance_active = true` is the recovery invariant after `pg_restore` + `openmettle-migrate`. Keep maintenance active until Step 5e completes.

---

## Step 4 — Lock restore gate, rebind artifact volume, and replay deletion journal

### 4a. Bind `OPENMETTLE_ADMIN_DATABASE_URL`, choose `SELECTED_JOURNAL`, and lock `restore_reconciliation_gate`

`openmettle-admin` database subcommands read `OPENMETTLE_ADMIN_DATABASE_URL` (separate from `OPENMETTLE_MIGRATE_DATABASE_URL`). Bind `OPENMETTLE_ADMIN_DATABASE_URL` in the recovery Job via `secretKeyRef` from **both** `database.migrate.existingSecret` and `database.migrate.key` (default `url`; or `database.backup.existingSecret` / `database.backup.key`), stage `database.caBundle` as a regular `0444` file at the owner URL's `sslrootcert` path (`/etc/openmettle/db-ca/ca.crt` when `database.caBundle.enabled` is `true`, required for `O_NOFOLLOW` TLS verification in `backup status` and `backup release-maintenance`), for Steps 4a–4d, 5c, 5e, and 6, and carry a single verified journal export file (`SELECTED_JOURNAL` — either a newer off-host `openmettle-admin journal export` file from the same installation `origin`, or `/var/recovery/unpacked/deletion-journal.bin`) through both `restore lock` and `restore replay`:

- **When to pass `--export-complete`:** Pass `--export-complete` on `restore lock` **only** when `SELECTED_JOURNAL`'s `(seq, digest)` matches an independently recorded final `(journal_seq, chain_digest)` watermark captured *after* all primary writes, purges, and external-connection revocations stopped (for example, a clean maintenance-window backup with zero post-backup primary writes before loss, or a fresh `openmettle-admin journal export` taken from an intact stopped/fenced primary). Never pass `--export-complete` merely because an external export has a higher `seq` than the backup.
- **When post-export primary activity cannot be ruled out:** Whenever writes, purges, or connection revocations could have occurred on primary *after* `SELECTED_JOURNAL` was exported and *before* primary loss, **omit `--export-complete`** on `restore lock`, record the printed `restore_run <RESTORE_RUN_UUID>`, and run audited break-glass acceptance before opening the gate (per `ADR 0045`, `restore accept-coverage-gap` also conservatively transitions `authorized` external connections to `reauth_required`, clears encrypted tokens, and deactivates active connection shares):

```sh
# OPENMETTLE_ADMIN_DATABASE_URL bound via secretKeyRef {name: database.migrate.existingSecret, key: database.migrate.key}
openmettle-admin restore accept-coverage-gap \
  --restore-run "$RESTORE_RUN_UUID" \
  --operator-id "$OPERATOR_UUID" \
  --request-key "restore-gap-$RESTORE_RUN_UUID" \
  --reason "post-export primary activity before loss cannot be ruled out"
```

Read the header and footer lines of `SELECTED_JOURNAL` (`origin <ORIGIN_US>`, optional paired `lifecycle_origin <LC_US>` + `lifecycle_baseline <LB_HEX>`, optional `connection_origin <CO_US>`, and `watermark <ORIGIN_US> <REQUIRED_SEQ> <REQUIRED_DIGEST_HEX> <EXPORTED_US>`), lock the gate, and record the printed `restore_run <RESTORE_RUN_UUID>` (also used in Step 5e):

```sh
# OPENMETTLE_ADMIN_DATABASE_URL bound via secretKeyRef {name: database.migrate.existingSecret, key: database.migrate.key}.
# Include --export-complete ONLY when (REQUIRED_SEQ, REQUIRED_DIGEST_HEX) is certified complete after primary quiescence.
openmettle-admin restore lock \
  --required-origin "$ORIGIN_US" \
  --required-lifecycle-origin "$LC_US" \
  --required-lifecycle-baseline-digest "$LB_HEX" \
  --required-connection-origin "$CO_US" \
  --required-seq "$REQUIRED_SEQ" \
  --required-digest "$REQUIRED_DIGEST_HEX"
```

### 4b. Branch on `manifest.artifact_volume.volume_id` and run `storage rebind`

- **Storage-disabled deployment (`manifest.artifact_volume.volume_id` is `null`):** skip Steps 4b and 4c (`storage rebind` refuses unpinned volumes) and proceed directly to Step 4d omitting the artifact root path.
- **Pinned artifact volume (`manifest.artifact_volume.volume_id` is non-null):** copy the entries inside `/var/recovery/unpacked/artifacts/` onto the empty target artifact PVC (`/var/lib/openmettle/artifacts`, owned by UID/GID `65532`) and run `storage rebind` (`ADR 0040`):

```sh
set -eu
for entry in /var/recovery/unpacked/artifacts/* /var/recovery/unpacked/artifacts/.[!.]*; do
  [ -e "$entry" ] || continue
  cp -a -- "$entry" /var/lib/openmettle/artifacts/
done
openmettle-admin storage rebind /var/lib/openmettle/artifacts
```

- **If `storage rebind` exits `0` (`failed 0`):** proceed directly to Step 4d.
- **If `storage rebind` exits `1` (`storage rebind incomplete`):** stderr prints `--replace-adoption-run <BARRIER_UUID>` and stdout lists every `failed <reservation_id>: <reason>` (`missing revision`, `size_or_digest_mismatch`, etc.). Follow Step 4c in exact order — **do not run `storage declare-lost` before checking whether the revision was purged after the backup or can be restored intact from staging or another backup**.

### 4c. Resolving incomplete `storage rebind` barriers and declaring truly unrecoverable payloads lost

`storage declare-lost` is permanent and destructive: it unlinks leftover bytes, transitions the revision to `lost` (`410 Gone`), and appends an irreversible `artifact_revision.lost` entry to `openmettle.deletion_journal` (`ADR 0040`, `ADR 0041`, `docs/operator/restore-artifact-volume.md`). Execute the checks below in order under the held `BARRIER_UUID`:

1. **Catch up post-backup database deletions first** while keeping `restore_reconciliation_gate` closed:

   ```sh
   openmettle-admin restore replay --db-only "$SELECTED_JOURNAL"
   ```

   Inspect each failing `reservation_id` against `openmettle.artifact_revisions` and `openmettle.deletion_journal`:

   ```sql
   SELECT r.id AS revision_id,
          r.state,
          r.size_bytes,
          encode(r.content_digest, 'hex') AS sha256,
          EXISTS (
              SELECT 1
                FROM openmettle.deletion_journal dj
               WHERE dj.entity_id = r.id
                 AND dj.event_kind = 'artifact_revision.purged'
          ) AS already_purged
     FROM openmettle.artifact_revisions r
    WHERE r.reservation_id = '<RESERVATION_UUID>'::uuid;
   ```

   If `already_purged = true`, **do not** run `storage declare-lost` — step 4 below (`storage rebind --replace-adoption-run "$BARRIER_UUID"`) completes that already-journaled purge cleanly.

2. **Check verified recovery staging and other backups from the recovery point before declaring loss.** A partial or interrupted copy onto `/var/lib/openmettle/artifacts` can leave `/var/recovery/unpacked/artifacts/revisions/<RESERVATION_UUID>` (or another backup archive from the same recovery point) completely intact. Verify any candidate payload's byte length and SHA-256 against `(size_bytes, sha256)` from step 1; if intact, restore it into `/var/lib/openmettle/artifacts/revisions/<RESERVATION_UUID>` (`chmod 0600`, UID/GID `65532`) and skip step 3 for that revision:

   ```sh
   cand="/var/recovery/unpacked/artifacts/revisions/$RESERVATION_UUID"
   if [ -f "$cand" ] && [ "$(sha256sum "$cand" | awk '{print $1}')" = "$EXPECTED_SHA256" ]; then
     cp -a -- "$cand" "/var/lib/openmettle/artifacts/revisions/$RESERVATION_UUID"
     chmod 0600 "/var/lib/openmettle/artifacts/revisions/$RESERVATION_UUID"
   fi
   ```

3. **Reserve `storage declare-lost` strictly for `active` or `retained` revisions confirmed unrecoverable** across `/var/recovery/unpacked/artifacts` and all backups from the recovery point:

   ```sh
   openmettle-admin storage declare-lost /var/lib/openmettle/artifacts \
     --revision "$UNRECOVERABLE_REVISION_UUID" \
     --operator-id "$OPERATOR_UUID" \
     --request-key "restore-lost-$UNRECOVERABLE_REVISION_UUID" \
     --reason "payload verified absent or corrupt across all recovery copies"
   ```

4. **Resume and complete `storage rebind` under the held adoption barrier:**

   ```sh
   openmettle-admin storage rebind /var/lib/openmettle/artifacts \
     --replace-adoption-run "$BARRIER_UUID"
   ```

### 4d. Full `restore replay` and `quota verify`

- **Pinned artifact volume (`manifest.artifact_volume.volume_id` is non-null):**

```sh
set -eu
openmettle-admin restore replay "$SELECTED_JOURNAL" /var/lib/openmettle/artifacts
openmettle-admin quota verify /var/lib/openmettle/artifacts
```

- **Storage-disabled deployment (`manifest.artifact_volume.volume_id` is `null`):**

```sh
set -eu
openmettle-admin restore replay "$SELECTED_JOURNAL"
openmettle-admin quota verify
```

Require `quota verify` to exit `0` and print:
`storage mismatches 0, budget mismatches 0, settlement mismatches 0, pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0`.

---

## Step 5 — Pre-worker security, identity, vault, and run-reconciliation checklist

Complete every item below **before** releasing maintenance, starting `openmettle-worker`, or reopening authentication (`auth.enabled` / ingress).

### 5a. Invalidate all restored sessions and pending OIDC logins (`ADR 0013`)

Enumerate **every** provider in `openmettle.login_providers` (not only those in the current `auth.json`). Preserve retired providers (`latest revision IS NULL`), reapply any post-backup provider retirements via `ADR 0013`'s `retire` protocol (`access_generation + 1` and a `NULL` revision tombstone epoch), and for every remaining active provider append a fresh non-retirement epoch and advance `access_generation` in one `openmettle_owner` transaction (`psql -X -w -v ON_ERROR_STOP=1` with `PGPASSFILE` under an `EXIT` trap, `PGSSLMODE=verify-full`, `PGSSLROOTCERT=/etc/openmettle/db-ca/ca.crt` matching the owner URL's `sslrootcert`, and `PGGSSENCMODE=disable`):

```sql
BEGIN;
LOCK TABLE openmettle.login_providers IN SHARE ROW EXCLUSIVE MODE;
INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
SELECT p.id, r.revision
  FROM openmettle.login_providers p
  JOIN LATERAL (
      SELECT revision
        FROM openmettle.login_provider_revisions lpr
       WHERE lpr.provider_id = p.id
       ORDER BY lpr.epoch DESC
       LIMIT 1
  ) r ON r.revision IS NOT NULL;

UPDATE openmettle.login_providers p
   SET access_generation = p.access_generation + 1,
       changed_at = clock_timestamp(),
       changed_by = 'operator:<operator-uuid>',
       change_reason = 'isolated restore session invalidation'
  FROM (
      SELECT p2.id
        FROM openmettle.login_providers p2
        JOIN LATERAL (
            SELECT revision
              FROM openmettle.login_provider_revisions lpr
             WHERE lpr.provider_id = p2.id
             ORDER BY lpr.epoch DESC
             LIMIT 1
        ) r ON r.revision IS NOT NULL
  ) active
 WHERE p.id = active.id;
COMMIT;
```

Deploy the target release with freshly generated 32-byte `active.key` and `cursor.key` values in `auth.loginKeysSecretName`.

### 5b. Reconcile post-backup identity, account, and authorization revocations (`ADR 0013`, `ADR 0027`)

Bumping provider generation fences pre-restore cookies/bearers and pending logins, **not** fresh sign-ins by accounts whose authority was reduced after the backup. Before reopening authentication (`auth.enabled: true` / ingress):

- Reconcile post-backup user disablements (`openmettle.users.disabled_at`, `session_generation = session_generation + 1`), identity approval withdrawals (`openmettle.local_identity_approvals.active = false`, `access_generation = access_generation + 1`), administrator demotions (`openmettle.account_admins.active = false`), local group disablements/removals (`openmettle.local_groups.disabled_at`, `openmettle.local_group_memberships.active`), project archives/deletions (`openmettle.project_settings.archived_at`, `deleted_at`), capability grant revocations/denies (`openmettle.user_capability_grants`, `user_capability_denies`, `platform_capability_denies`), pending home-invitation withdrawals, and project membership/resource-share revocations (`openmettle.grant_assignments`, `openmettle.grant_changes`) against post-backup `authorization_audit` exports or operator change records.
- **Fail-closed rule:** if post-backup identity or authorization revocation evidence is unavailable, **keep authentication closed** (`auth.enabled: false` or ingress blocked) until an operator audits and re-approves principals and grants, so a disabled or removed user cannot sign in afresh with snapshot authority.

### 5c. Verify and rotate credential vault keys (`ADR 0045`)

With the target vault keyring staged read-only at `/etc/openmettle/vault-keys` and `OPENMETTLE_ADMIN_DATABASE_URL` set to the target `openmettle_owner` URL:

```sh
openmettle-admin vault status

# Optional key rotation once every key_id reported above is present in /etc/openmettle/vault-keys:
openmettle-admin vault rotate \
  --vault-keys /etc/openmettle/vault-keys/keyring.json \
  --operator-id "$OPERATOR_UUID" \
  --request-key "restore-vault-rotate-$RESTORE_RUN_UUID" \
  --reason "re-seal recovered external connections onto target vault key"
```

### 5d. Cancel parked `waiting` and `queued` runs and release eligible run quotas (`ADR 0035`, `ADR 0039`, `ADR 0040`)

Coordinated backup capture drains `executing` worker leases before `pg_dump`, while runs parked in `waiting` (such as pending human approvals in `openmettle.run_approvals` or revision-`0` two-phase external write `intent` rows in `openmettle.operations`) and `queued` runs remain non-terminal in the snapshot.

1. **As `openmettle_owner`** (`psql -X -w -v ON_ERROR_STOP=1` with `PGPASSFILE` under an `EXIT` trap, `PGSSLMODE=verify-full`, `PGSSLROOTCERT=/etc/openmettle/db-ca/ca.crt` matching the owner URL's `sslrootcert`, and `PGGSSENCMODE=disable`), cancel non-terminal runs first (which fires `AFTER UPDATE OF state` trigger `openmettle.resolve_terminal_write_intents()`, transitioning every revision-`0` write `intent` to `outcome = 'outcome_unknown', revision = 1` and allocating `unresolved-write:<operation_id>` via `runs.last_event_sequence`), and then in a second statement allocate contiguous `run-terminal` events through `runs.last_event_sequence` (using a tagged `$restore$` delimiter so Kubernetes container `command`/`args` `$$` expansion cannot corrupt the block):

```sql
BEGIN;
UPDATE openmettle.runs r
   SET state = 'cancelled',
       wait_reason = NULL,
       cancel_reason = coalesce(r.cancel_reason, 'revoked'),
       claim_token = NULL,
       claimed_at = NULL,
       lease_expires_at = NULL,
       execution_expires_at = NULL
  FROM (
      SELECT id
        FROM openmettle.runs
       WHERE state IN ('queued', 'running', 'waiting')
       ORDER BY id
         FOR UPDATE
  ) target
 WHERE r.id = target.id;

DO $restore$
DECLARE
    rec RECORD;
    seq bigint;
    payload constant bytea := convert_to('{"reason":"revoked"}', 'UTF8');
    ident bytea;
    field bytea;
BEGIN
    FOR rec IN
        SELECT r.id, r.scope_id
          FROM openmettle.runs r
         WHERE r.state = 'cancelled'
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.run_events e
                WHERE e.run_id = r.id
                  AND e.append_key = 'run-terminal'
           )
         ORDER BY r.id
           FOR UPDATE OF r
    LOOP
        ident := convert_to('openmettle/event/1', 'UTF8') || decode('00', 'hex');
        FOREACH field IN ARRAY ARRAY[
            convert_to(rec.scope_id::text, 'UTF8'),
            convert_to(rec.id::text, 'UTF8'),
            convert_to('run-terminal', 'UTF8'),
            convert_to('openmettle.run-cancelled', 'UTF8'),
            int4send(1),
            payload
        ]
        LOOP
            ident := ident || int8send(octet_length(field)::bigint) || field;
        END LOOP;

        UPDATE openmettle.runs
           SET last_event_sequence = last_event_sequence + 1
         WHERE scope_id = rec.scope_id
           AND id = rec.id
     RETURNING last_event_sequence INTO STRICT seq;

        INSERT INTO openmettle.run_events (
            scope_id, run_id, sequence, append_key, format, format_version, payload, identity, digest
        ) VALUES (
            rec.scope_id, rec.id, seq, 'run-terminal', 'openmettle.run-cancelled', 1, payload, ident, sha256(ident)
        );
    END LOOP;
END
$restore$;
COMMIT;
```

2. **As `openmettle_worker`** (`psql -X -w -v ON_ERROR_STOP=1` with `PGPASSFILE` under an `EXIT` trap, `PGSSLMODE=verify-full`, `PGSSLROOTCERT=/etc/openmettle/db-ca/ca.crt` matching `database.worker`'s `sslrootcert`, and `PGGSSENCMODE=disable`; `openmettle.quota_release_terminal_runs(uuid[])` enforces `session_user` membership in `openmettle_api` or `openmettle_worker` and automatically retains holds on runs with `intent` / `outcome_unknown` operations), unwind held run-level quota reservations on eligible terminal runs:

```sql
SELECT openmettle.quota_release_terminal_runs(
    coalesce(
        (SELECT array_agg(r.id ORDER BY r.id)
           FROM openmettle.runs r
          WHERE r.state IN ('succeeded', 'failed', 'cancelled', 'interrupted')),
        ARRAY[]::uuid[]
    )
);
```

### 5e. Release snapshot maintenance gate, assert `maintenance_active == false` and zero drift, then scrub staging

Run `backup release-maintenance` **last** (after Steps 5a–5d complete, with `database.caBundle` staged as a regular file at the owner URL's `sslrootcert` path when TLS CA verification is enabled), binding `--request-key` to `RESTORE_RUN_UUID` so a repeated recovery against a backup carrying an earlier recovery's `authorization_audit` row never short-circuits as an idempotent replay. Do **not** scrub `/var/recovery/unpacked` or proceed to Step 6 workload startup unless `backup release-maintenance` exits `0`, `openmettle-admin backup status` literally reports `"maintenance_active": false`, and `openmettle-admin quota verify` (passing `/var/lib/openmettle/artifacts` when `manifest.artifact_volume.volume_id` is non-null, or omitting the root argument on storage-disabled deployments where `manifest.artifact_volume.volume_id` is `null`) exits `0` with all seven mismatch counters equal to `0`:

```sh
set -eu
openmettle-admin backup release-maintenance \
  --operator-id "$OPERATOR_UUID" \
  --request-key "restore-release-maintenance-$RESTORE_RUN_UUID" \
  --reason "isolated restore pre-worker reconciliation complete" \
  --abort-active-run

status_json="$(openmettle-admin backup status)"
printf '%s\n' "$status_json"
printf '%s\n' "$status_json" | grep -Eq '"maintenance_active"[[:space:]]*:[[:space:]]*false'

# ARTIFACT_VOLUME_ID from Step 1 (manifest.artifact_volume.volume_id; empty or "null" when storage is disabled):
if [ -n "${ARTIFACT_VOLUME_ID:-}" ] && [ "$ARTIFACT_VOLUME_ID" != "null" ]; then
  quota_out="$(openmettle-admin quota verify /var/lib/openmettle/artifacts)"
else
  quota_out="$(openmettle-admin quota verify)"
fi
printf '%s\n' "$quota_out"
printf '%s\n' "$quota_out" | grep -Fxq \
  'storage mismatches 0, budget mismatches 0, settlement mismatches 0, pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0'

rm -rf /var/recovery/unpacked
```

---

## Step 6 — Start target workloads, verify invariants, and record RPO / RTO

1. Install or upgrade `charts/openmettle-core` in the isolated target namespace with `storage.artifacts.existingClaim` bound to the reconciled target PVC (when storage is enabled), `vault.enabled: true` pointing at the target vault Secret, and `backup.suspend: true` (or `backup.enabled: false`).
2. Wait for `Deployment/<release>-api`, `Deployment/<release>-worker`, and any configured `Deployment/<release>-gateway-*` to report Ready and `GET /readyz` -> `200`.
3. Verify post-restore functional and security invariants before recording `recovery_completed_at` and signing off:
   - Pre-restore session cookies/tokens and post-backup disabled accounts return `401 unauthenticated`.
   - Newly authenticated sessions see surviving personal and shared project conversations, shared project artifacts, and authorized connections with intact ownership and role boundaries (`404 not_found` across personal scopes and authenticated non-members; `403 policy` on `Viewer` writes).
   - Revisions declared lost in Step 4c return `200` metadata (`state: "lost"`, non-null `lost_at`) and `410 Gone` (`code: "payload_lost"`) on `/content` for authorized readers, while remaining `404` for unauthorized callers.
   - Post-backup purged revisions (`409 conflict` on `/content`, `state = 'purged'`, `0` resurrected files on disk) and revoked/disconnected connections (`404` for former sharees; `NULL` ciphertext) remain purged/revoked.
   - Retained revisions keep their exact pre-backup `purge_after` deadline (not reset from wall-clock restore time).
   - Parked `waiting` runs from the snapshot report `state: "cancelled"` with contiguous `run_events` sequences, `POST /v1/runs/{run_id}/approvals/{approval_id}/decision` (`{"decision": "approve", ...}`) returns `409 conflict`, and revision-`0` write intents report `outcome = 'outcome_unknown'` (`revision = 1`) with held reservations preserved and zero unsolicited external/gateway calls on worker startup.
   - `openmettle-admin quota verify` exits `0` with all seven mismatch counters equal to `0`, and `openmettle-admin journal export` succeeds on the restored database.
4. Record `recovery_completed_at` after the final verification check above and archive the drill metrics:
   - `restored_data_age_seconds = drill_cutover_at - manifest.quiesced_at` (must be `<= 86,400 s` for the 24h RPO target).
   - `recovery_duration_seconds = recovery_completed_at - recovery_started_at` (must be `<= 14,400 s` for the 4h RTO target, spanning target provisioning through final verification).

## Drill cadence

- **Automated CI (`dev` classification):** `.github/workflows/restore-drill.yml` runs `tests/kind/restore_drill.py` on pull requests and `main` pushes touching `CORE_COMMIT`, `charts/openmettle-core/**`, `tests/kind/**`, `tests/chart/install-tools.sh`, `docs/restore-drill.md`, or `.github/workflows/restore-drill.yml`, and via `workflow_dispatch`.
- **Operator qualification (`V1-31` / `V1-33`):** execute and record a live isolated-target drill on the workstation + off-host NAS before production cutover, on a recurring quarterly schedule, and after any material change to backup format/encryption (`ADR 0046`), artifact storage/journal reconciliation (`ADR 0040` / `ADR 0041`), vault key custody (`ADR 0045`), or PostgreSQL major/schema lifecycle migrations.
