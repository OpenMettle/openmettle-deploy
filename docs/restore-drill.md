# Isolated Restore Drill and Operator Recovery Runbook (V1-31)

This runbook defines the repeatable Kubernetes recovery and isolated-target restore drill procedure for `charts/openmettle-core` pinned to `CORE_COMMIT` (schema through migration `45`, core ADRs `0013`, `0027`, `0031`, `0035`, `0039`, `0040`, `0041`, `0045` and `0046`).

[`tests/kind/restore_drill.py`](../tests/kind/restore_drill.py) (`.github/workflows/restore-drill.yml`) automates this procedure end-to-end on an ephemeral `kind` cluster classified `dev`. Passing the `dev` harness proves chart, CLI, SQL and `NetworkPolicy` mechanics; it does **not** substitute for an owner-executed drill on the target workstation and off-host NAS (`V1-01`, `V1-31`, `V1-33`).

## Scope and safety boundaries

1. **Isolated target only.** Always restore into a separate namespace or cluster, a fresh PostgreSQL database (`openmettle`) with freshly generated role passwords, and a fresh artifact `PersistentVolumeClaim`. Never run `pg_restore`, `storage rebind` or `restore replay` against a live primary database or mounted primary artifact volume.
2. **Default-deny network and Pod Security isolation before workloads.** Apply `pod-security.kubernetes.io/enforce=restricted` and namespace-wide `default-deny` `NetworkPolicy` manifests across both the target application namespace and any in-cluster target database namespace **before** submitting database fixtures, recovery `Job`s, or runtime workloads, so target pods cannot reach primary PostgreSQL, primary `openmettle-gateway` Services, or unapproved external endpoints at any point in their lifecycle. Keep `backup.suspend: true` (or `backup.enabled: false`) on the drill target so it cannot write to or prune a shared backup destination.
3. **Separate backup and vault key custody.** `OPENMETTLE_ADMIN_BACKUP_KEYS_CONFIG` and `OPENMETTLE_API_VAULT_KEYS_CONFIG` / `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` must remain distinct Secrets, files, and 32-byte key material (`ADR 0045`, `ADR 0046`). Whenever `OPENMETTLE_API_VAULT_KEYS_CONFIG` is set in the environment, `openmettle-admin` fails closed if that keyring or any key file it names is unreadable or overlaps the backup keyring; on vault-disabled installations (`vault.enabled: false`), leave `OPENMETTLE_API_VAULT_KEYS_CONFIG` unset during backup preflight and stop recovery immediately if the unpacked `manifest.json` lists non-empty `vault_required_key_ids`.
4. **RPO / RTO targets.** Single-node v1 targets **RPO <= 24 hours** (`86,400 s` between the restored backup's `quiesced_at` timestamp and incident/drill cutover) and **RTO <= 4 hours** (`14,400 s` from recovery initiation — before target provisioning and media staging — through final post-restore HTTP/SQL acceptance and `quota verify` completion).
5. **Explicit non-goals.** Legacy Open WebUI database or file import is excluded from v1 recovery (`ADR 0003`). Optional Graphiti (`neo4j.dump`) and Chroma (`chroma.archive` or `qualified_rebuild`) recovery steps apply only when `manifest.json` records a provisioned state other than `not_provisioned`.

---

## Step 1 — Preflight verification and unpacking

- **Vault-enabled deployments (`vault.enabled: true`):** stage **both** the backup keyring (`/etc/openmettle/backup-keys`) and the target vault keyring (`/etc/openmettle/vault-keys`) via `Memory` `emptyDir` `initContainer`s writing `0400` files owned by UID `65532` and mounted `readOnly: true` with `subPath: keys`, and export `OPENMETTLE_API_VAULT_KEYS_CONFIG=/etc/openmettle/vault-keys/keyring.json` so `BackupKeyRing::load_from_config` enforces backup/vault key separation during preflight.
- **Vault-disabled deployments (`vault.enabled: false`):** stage only the backup keyring (`/etc/openmettle/backup-keys`) and leave `OPENMETTLE_API_VAULT_KEYS_CONFIG` and `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` **unset** during `backup verify` and `backup unpack` (`openmettle-admin` fails closed if `OPENMETTLE_API_VAULT_KEYS_CONFIG` points to a missing file). Do not create or mount a dummy vault keyring just to pass preflight.

Mount the backup destination PVC `readOnly: true` and an isolated scratch PVC at `/var/recovery`:

```sh
set -eu
# Vault-enabled target only (`vault.enabled: true`); leave unset when `vault.enabled: false`:
export OPENMETTLE_API_VAULT_KEYS_CONFIG=/etc/openmettle/vault-keys/keyring.json

# 1. Verify backup-meta.json, backup/vault key separation (when vault is enabled), encrypted manifest, and AEAD stream tags.
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
- **Required vault key IDs:** check `vault_required_key_ids` (and `/var/recovery/unpacked/config/vault-key-inventory.json`). If `vault_required_key_ids` is non-empty, **every** listed key ID must be present in `/etc/openmettle/vault-keys/keyring.json` (and `vault.enabled` must be `true`) before continuing recovery — **stop recovery** if `manifest.json` names any key ID that is unavailable on the target (or when restoring onto a `vault.enabled: false` target where keys were not provisioned). If `vault_required_key_ids` is `[]`, target may preserve `vault.enabled: false`.
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

3. Create the target Kubernetes `Secret`s (`database.api`, `database.worker`, `database.migrate`, `database.issuance`, `database.gateway`, and optional `database.backup`), distinct `auth.loginKeysSecretName` (fresh 32-byte `active.key` and `cursor.key`), and (when `vault.enabled` is `true` or `manifest.vault_required_key_ids` is non-empty) `vault.existingSecret`.

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
- **When post-export primary activity cannot be ruled out (break-glass recovery):** Whenever writes, purges, or connection revocations could have occurred on primary *after* `SELECTED_JOURNAL` was exported and *before* primary loss, **omit `--export-complete`** on `restore lock` and record the printed `restore_run <RESTORE_RUN_UUID>`. `openmettle-admin restore accept-coverage-gap` transitions `authorized` external connections to `reauth_required`, clears encrypted tokens, and deactivates active connection shares (`ADR 0045`) so `restore replay` can open the gate, **but it cannot reconstruct uncaptured artifact purges, conversation deletions, or principal/grant revocations after `SELECTED_JOURNAL`** (purged payloads already present in the backup snapshot can remain on disk). Before running `restore accept-coverage-gap` and reopening service:
  1. **Reconcile against independent records:** cross-check surviving primary logs/audit sinks, off-host deletion or authorization audit exports, IdP/Keycloak revocation records, and operator change logs, and purge or revoke any post-export deletions/revocations identified there.
  2. **Record explicit owner/operator break-glass sign-off:** document the uncertified `[exported_at, primary_loss]` window, every independent record checked, and the explicit sign-off authorizing break-glass reopening before invoking:

     ```sh
     # OPENMETTLE_ADMIN_DATABASE_URL bound via secretKeyRef {name: database.migrate.existingSecret, key: database.migrate.key}
     openmettle-admin restore accept-coverage-gap \
       --restore-run "$RESTORE_RUN_UUID" \
       --operator-id "$OPERATOR_UUID" \
       --request-key "restore-gap-$RESTORE_RUN_UUID" \
       --reason "break-glass recovery after independent reconciliation; operator sign-off recorded"
     ```

  3. **Fail restore validation while any deletion gap remains unresolved:** per `ARCHITECTURE-v1.md`, records never captured cannot be reconstructed, so any unresolved deletion/revocation coverage gap **MUST be recorded as a failed restore validation (`unresolved_deletion_coverage_gap`)** rather than signing off clean `V1-31` / `V1-33` qualification.

Read the header and footer lines of `SELECTED_JOURNAL` (`origin <ORIGIN_US>`, optional paired `lifecycle_origin <LC_US>` + `lifecycle_baseline <LB_HEX>`, optional `connection_origin <CO_US>`, and `watermark <ORIGIN_US> <REQUIRED_SEQ> <REQUIRED_DIGEST_HEX> <EXPORTED_US>`), lock the gate, and record the printed `restore_run <RESTORE_RUN_UUID>` (used across Steps 5b, 5c, 5e, and 6):

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

2. **Check verified recovery staging and other backups from the recovery point before declaring loss.** A partial or interrupted copy onto `/var/lib/openmettle/artifacts` can leave `/var/recovery/unpacked/artifacts/revisions/<RESERVATION_UUID>` (or another backup archive from the same recovery point) completely intact. First verify `/var/recovery/unpacked/artifacts/revisions` itself is a readable, searchable, listable non-symlink directory (so missing directory permissions cannot make `-e "$cand"` return false on an intact file); similarly walk every component of `/var/backups/openmettle` from `/` so an inaccessible ancestor or directory stops reconciliation instead of letting `-e "$media_dir"` return false (`EACCES`) on an existing media directory. Then require `$cand` to be a readable regular non-symlink file and verify its byte length and SHA-256 against `(size_bytes, sha256)` from step 1 without masking exit status behind pipelines; any directory-inspection, read, stat, or digest failure **must stop reconciliation immediately** rather than falling through to `storage declare-lost`. If verified intact, restore it into `/var/lib/openmettle/artifacts/revisions/<RESERVATION_UUID>` (`chmod 0600`, UID/GID `65532`) and skip step 3 for that revision:

   ```sh
   set -eu
   check_no_media_archives() {
     media_target="$1"
     if [ ! -d "/" ] || [ ! -x "/" ]; then
       echo "ERROR: root directory / is inaccessible; refusing storage declare-lost" >&2
       exit 1
     fi
     cur=""
     rest="${media_target#/}"
     while [ -n "$rest" ]; do
       case "$rest" in
         */*)
           comp="${rest%%/*}"
           rest="${rest#*/}"
           ;;
         *)
           comp="$rest"
           rest=""
           ;;
       esac
       [ -n "$comp" ] || continue
       next_path="$cur/$comp"
       if [ -z "$rest" ]; then
         if [ ! -e "$next_path" ] && [ ! -L "$next_path" ]; then
           return 0
         fi
         if [ -L "$next_path" ] || [ ! -d "$next_path" ] || [ ! -r "$next_path" ] || [ ! -x "$next_path" ] || ! ls -A -- "$next_path" >/dev/null; then
           echo "ERROR: recovery media directory $next_path is inaccessible or not a directory; refusing storage declare-lost" >&2
           exit 1
         fi
         for archive_cand in "$next_path"/backup-*; do
           if [ -e "$archive_cand" ] || [ -L "$archive_cand" ]; then
             echo "ERROR: backup archive $archive_cand remains available; unpack and inspect before storage declare-lost" >&2
             exit 1
           fi
         done
         return 0
       else
         if [ ! -e "$next_path" ] && [ ! -L "$next_path" ]; then
           return 0
         fi
         if [ ! -d "$next_path" ] || [ ! -x "$next_path" ]; then
           echo "ERROR: recovery media ancestor $next_path is inaccessible or not a directory; refusing storage declare-lost" >&2
           exit 1
         fi
         cur="$next_path"
       fi
     done
   }

   rev_dir="/var/recovery/unpacked/artifacts/revisions"
   if [ -L "$rev_dir" ] || [ ! -d "$rev_dir" ] || [ ! -r "$rev_dir" ] || [ ! -x "$rev_dir" ] || ! ls -A -- "$rev_dir" >/dev/null; then
     echo "ERROR: staging revisions directory $rev_dir is missing or inaccessible; refusing storage declare-lost" >&2
     exit 1
   fi
   cand="$rev_dir/$RESERVATION_UUID"
   recovered=0
   if [ -e "$cand" ] || [ -L "$cand" ]; then
     if [ -L "$cand" ] || [ ! -f "$cand" ] || [ ! -r "$cand" ]; then
       echo "ERROR: staging candidate $cand is unreadable or not a regular file; refusing storage declare-lost" >&2
       exit 1
     fi
     raw_wc="$(wc -c < "$cand")"
     cand_bytes="$(printf '%s' "$raw_wc" | tr -d '[:space:]')"
     raw_sha="$(sha256sum "$cand")"
     cand_sha="${raw_sha%% *}"
     if [ "${#cand_sha}" -eq 64 ] && [ "$cand_bytes" -eq "$EXPECTED_SIZE_BYTES" ] && [ "$cand_sha" = "$EXPECTED_SHA256" ]; then
       cp -a -- "$cand" "/var/lib/openmettle/artifacts/revisions/$RESERVATION_UUID"
       chmod 0600 "/var/lib/openmettle/artifacts/revisions/$RESERVATION_UUID"
       recovered=1
     fi
   fi
   if [ "$recovered" -eq 0 ]; then
     check_no_media_archives "/var/backups/openmettle"
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

Enumerate **every** provider in `openmettle.login_providers` (not only those in the current `auth.json`). Preserve retired providers (`latest revision IS NULL`), reapply any post-backup provider retirements via `ADR 0013`'s `retire` protocol (`access_generation + 1` and a `NULL` revision tombstone epoch), and for every remaining active provider advance the `login_provider_revisions` identity sequence past all restored rows (`ADR 0012` — preventing a trailing sequence after `pg_restore` or owner overrides from allocating an epoch `<= prev_max_epoch`), append a fresh non-retirement epoch while verifying the inserted `epoch` strictly advances past the provider's previous maximum (rolling back the entire transaction if any epoch is not current), and advance `access_generation` in one `openmettle_owner` transaction (`psql -X -w -v ON_ERROR_STOP=1` with `PGPASSFILE` under an `EXIT` trap, `PGSSLMODE=verify-full`, `PGSSLROOTCERT=/etc/openmettle/db-ca/ca.crt` matching the owner URL's `sslrootcert`, and `PGGSSENCMODE=disable`; uses a tagged `$provider_epoch$` delimiter so Kubernetes `command`/`args` `$$` expansion cannot mutate it):

```sql
BEGIN;
LOCK TABLE openmettle.login_providers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE openmettle.login_provider_revisions IN EXCLUSIVE MODE;

-- ADR 0012: keep the identity sequence strictly ahead of any restored or owner-inserted rows.
SELECT setval(
    pg_get_serial_sequence('openmettle.login_provider_revisions', 'epoch'),
    coalesce((SELECT max(epoch) FROM openmettle.login_provider_revisions), 1),
    EXISTS (SELECT 1 FROM openmettle.login_provider_revisions)
);

DO $provider_epoch$
DECLARE
    rec RECORD;
    new_epoch bigint;
BEGIN
    FOR rec IN
        SELECT p.id AS provider_id,
               r.revision AS latest_revision,
               r.epoch AS prev_max_epoch
          FROM openmettle.login_providers p
          JOIN LATERAL (
              SELECT lpr.epoch, lpr.revision
                FROM openmettle.login_provider_revisions lpr
               WHERE lpr.provider_id = p.id
               ORDER BY lpr.epoch DESC
               LIMIT 1
          ) r ON true
         WHERE r.revision IS NOT NULL
         ORDER BY p.id
    LOOP
        INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
        VALUES (rec.provider_id, rec.latest_revision)
        RETURNING epoch INTO STRICT new_epoch;

        IF new_epoch <= rec.prev_max_epoch
           OR EXISTS (
               SELECT 1
                 FROM openmettle.login_provider_revisions lpr
                WHERE lpr.provider_id = rec.provider_id
                  AND lpr.epoch > new_epoch
           )
        THEN
            RAISE EXCEPTION 'login_provider_revisions epoch % did not advance past previous maximum % for provider %',
                new_epoch, rec.prev_max_epoch, rec.provider_id
                USING ERRCODE = '22023';
        END IF;

        UPDATE openmettle.login_providers
           SET access_generation = access_generation + 1,
               changed_at = clock_timestamp(),
               changed_by = 'operator:<operator-uuid>',
               change_reason = 'isolated restore session invalidation'
         WHERE id = rec.provider_id;
    END LOOP;
END
$provider_epoch$;
COMMIT;
```

Deploy the target release with freshly generated 32-byte `active.key` and `cursor.key` values in `auth.loginKeysSecretName`.

### 5b. Reconcile post-backup identity, account, and authorization revocations (`ADR 0013`, `ADR 0027`)

Bumping provider generation fences pre-restore cookies/bearers and pending logins, **not** fresh sign-ins by accounts whose authority was reduced after the backup. Before reopening authentication (`auth.enabled: true` / ingress):

- Reconcile post-backup user disablements (`openmettle.users.disabled_at`, `session_generation = session_generation + 1`), identity approval withdrawals (`openmettle.local_identity_approvals.active = false`, `access_generation = access_generation + 1`), administrator demotions (`openmettle.account_admins.active = false`), local group disablements/removals (`openmettle.local_groups.disabled_at`, `openmettle.local_group_memberships.active`), project archives/deletions (`openmettle.project_settings.archived_at`, `deleted_at`), capability grant revocations/denies (`openmettle.user_capability_grants`, `user_capability_denies`, `platform_capability_denies`), family-policy schedules and model rules (`openmettle.family_policies`, `openmettle.family_policy_models` `rule_kind IN ('disabled', 'study_allow')`, audited under `family_policy.*` in `openmettle.authorization_audit`, `ADR 0044`), login-admission ceiling and outstanding pending-login rows (`openmettle.login_admission`, `openmettle.login_transactions`, `ADR 0014`), pending home-invitation withdrawals, and project membership/resource-share revocations (`openmettle.grant_assignments`, `openmettle.grant_changes`) against post-backup `authorization_audit` exports or operator change records.
  - `openmettle.authorization_audit.id` is a random `uuid DEFAULT gen_random_uuid()` (never monotonic). Immediately after Step 3 (`pg_restore` + `openmettle-migrate`, before target operator commands append new target audit rows), capture the restored snapshot's existing audit UUID set (`psql ... -Atc 'SELECT id FROM openmettle.authorization_audit ORDER BY id;' > /var/recovery/restored-audit-ids.txt`) and identify post-backup `family_policy.*` rows in the surviving primary `openmettle.authorization_audit` export by **UUID set-difference** (`target_kind = 'family_policy'` whose `id` is absent from `/var/recovery/restored-audit-ids.txt`; never use numeric watermarks or compare/sort random `id` UUIDs).
  - Order each grantee's post-backup `family_policy.*` transitions solely from **independently verified event order** (such as strictly increasing `occurred_at` corroborated against structured primary/off-host audit logs, operator change records, or surviving primary `openmettle.family_policies` / `openmettle.family_policy_models` state). **Fail closed on ordering ambiguity:** if post-backup `family_policy.*` rows exist and their chronological order cannot be established unambiguously (for instance, tied or clock-stepped `occurred_at` timestamps without an ordered external audit log or surviving primary current state to disambiguate), **do not guess an order — keep authentication and inference closed (`auth.enabled: false` / ingress blocked)** until an operator audits and explicitly re-establishes the grantee's policy and model restrictions.
  - Replay each ordered post-backup row with `$AUDIT_ROW_UUID` (`id`) bound into the SHA-256 `--request-key` input (`restore-fp-$RESTORE_RUN_UUID-<hash>` / `restore-fm-$RESTORE_RUN_UUID-<hash>`, 112 bytes <= the CLI's 128-byte limit, keeping valid model names up to 256 UTF-8 bytes recoverable while preventing `UNCHANGED` errors on toggles back to backup state, preventing `NotFound` errors on `set-policy -> set-model -> clear-policy`, preserving existing restored schedules when only model rules changed post-backup, and keeping script retries idempotent):

  ```sh
  set -eu
  # Replay one independently ordered post-backup family_policy.* row (`$AUDIT_ROW_UUID`).
  # Map details->>'grantee_kind' / details->>'grantee_id' and validate event fields fail-closed:
  case "$GRANTEE_KIND" in
    user) GRANTEE_FLAG="--user" ;;
    local_group) GRANTEE_FLAG="--local-group" ;;
    oidc_group) GRANTEE_FLAG="--oidc-group" ;;
    *) echo "unknown grantee_kind: $GRANTEE_KIND" >&2; exit 1 ;;
  esac

  case "$ACTION" in
    family_policy.model_disable|family_policy.model_enable|family_policy.model_study_allow|family_policy.model_study_revoke)
      case "${RULE_KIND:-}" in
        disabled|study_allow) ;;
        *) echo "invalid details.rule_kind: ${RULE_KIND:-}" >&2; exit 1 ;;
      esac
      case "${RULE_ACTIVE:-}" in
        true)  STATE_BIT="1"; MODEL_FLAG="--enable" ;;
        false) STATE_BIT="0"; MODEL_FLAG="--disable" ;;
        *) echo "invalid details.active: ${RULE_ACTIVE:-}" >&2; exit 1 ;;
      esac
      fm_hash="$(printf '%s\0%s\0%s\0%s\0%s\0%s' "$RESTORE_RUN_UUID" "$AUDIT_ROW_UUID" "$GRANTEE_ID" "$RULE_KIND" "$MODEL_NAME" "$STATE_BIT" | sha256sum)"
      fm_key="restore-fm-$RESTORE_RUN_UUID-${fm_hash%% *}"
      openmettle-admin family set-model \
        "$GRANTEE_FLAG" "$GRANTEE_ID" \
        --kind "$RULE_KIND" \
        --model "$MODEL_NAME" \
        "$MODEL_FLAG" \
        --operator-id "$OPERATOR_UUID" \
        --request-key "$fm_key" \
        --reason "reconcile post-backup family model rule before reopening inference"
      ;;
    family_policy.set)
      case "${OVERRIDE_SCHEDULES:-false}" in
        true)  OVERRIDE_BIT="1" ;;
        false) OVERRIDE_BIT="0" ;;
        *) echo "invalid details.override_group_schedules: ${OVERRIDE_SCHEDULES:-}" >&2; exit 1 ;;
      esac
      fp_hash="$(printf '%s\0%s\0%s\0set\0%s\0%s\0%s\0%s' "$RESTORE_RUN_UUID" "$AUDIT_ROW_UUID" "$GRANTEE_ID" "$POLICY_TZ" "${QUIET_WINDOW:-}" "${STUDY_WINDOW:-}" "$OVERRIDE_BIT" | sha256sum)"
      fp_key="restore-fp-$RESTORE_RUN_UUID-${fp_hash%% *}"
      set -- openmettle-admin family set-policy "$GRANTEE_FLAG" "$GRANTEE_ID" --zone "$POLICY_TZ"
      if [ -n "${QUIET_WINDOW:-}" ]; then set -- "$@" --quiet "$QUIET_WINDOW"; fi
      if [ -n "${STUDY_WINDOW:-}" ]; then set -- "$@" --study "$STUDY_WINDOW"; fi
      if [ "$OVERRIDE_BIT" = "1" ]; then set -- "$@" --override-group-schedules; fi
      "$@" \
        --operator-id "$OPERATOR_UUID" \
        --request-key "$fp_key" \
        --reason "reconcile post-backup family policy before reopening inference"
      ;;
    family_policy.clear)
      fp_clear_hash="$(printf '%s\0%s\0%s\0clear' "$RESTORE_RUN_UUID" "$AUDIT_ROW_UUID" "$GRANTEE_ID" | sha256sum)"
      fp_clear_key="restore-fp-$RESTORE_RUN_UUID-${fp_clear_hash%% *}"
      openmettle-admin family clear-policy \
        "$GRANTEE_FLAG" "$GRANTEE_ID" \
        --operator-id "$OPERATOR_UUID" \
        --request-key "$fp_clear_key" \
        --reason "reconcile post-backup family policy clearance before reopening inference"
      ;;
    *)
      echo "unexpected family_policy action: $ACTION" >&2
      exit 1
      ;;
  esac
  ```

- **Reconcile and verify login admission (`openmettle.login_admission`, `ADR 0014`):** Migration `0009_login_admission.sql` installs `outstanding_limit = NULL`, which **refuses every new browser/native login initiation** (`Unconfigured`) even while existing restored or seeded sessions continue authenticating. Restored unexpired rows in `openmettle.login_transactions` with `NOT session_issued` continue counting toward `outstanding_limit` until they expire or are cleaned up. Before reopening authentication (`auth.enabled: true` / ingress), reconcile any post-backup ceiling change via `openmettle-core`'s `docs/operator/login-admission-limit.psql` (including clearing `outstanding_limit` back to `NULL` with an empty `limit` argument when sign-in was intentionally closed post-backup so new login initiations stay refused) and clean up expired unreferenced gates if needed via `docs/operator/login-gate-cleanup.psql` (`batch` `1..=1000`). Confirm `outstanding_limit` matches the intended policy: when sign-in is intended to be open, verify `outstanding_limit` is `1..=65536` with positive available capacity (`outstanding_unissued < outstanding_limit`); when sign-in is intended to be closed, verify `outstanding_limit IS NULL`:

  ```sql
  SELECT la.outstanding_limit,
         (SELECT count(*)
            FROM openmettle.login_transactions lt
           WHERE NOT lt.session_issued
             AND lt.expires_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
         ) AS outstanding_unissued
    FROM openmettle.login_admission la
   WHERE la.id;
  ```

- **Fail-closed rule:** if post-backup identity, capability, or family-policy model restriction evidence is unavailable, **keep authentication and inference closed** (`auth.enabled: false` / ingress blocked) until an operator audits and re-approves principals, grants, and model policies, so a disabled user or model cannot regain access after restore.

### 5c. Verify and rotate credential vault keys (`ADR 0045`)

- **Vault-disabled deployments (`vault.enabled: false` and `manifest.vault_required_key_ids` is `[]`):** skip staging `/etc/openmettle/vault-keys` and skip `vault rotate`; running `openmettle-admin vault status` with `OPENMETTLE_ADMIN_DATABASE_URL` set confirms `encrypted 0`. If `manifest.vault_required_key_ids` is non-empty, **stop** and switch to the vault-enabled path with every required key staged before proceeding.
- **Vault-enabled deployments (`vault.enabled: true` or non-empty `manifest.vault_required_key_ids`):** with the target vault keyring staged read-only at `/etc/openmettle/vault-keys` and `OPENMETTLE_ADMIN_DATABASE_URL` set to the target `openmettle_owner` URL:

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

1. Install or upgrade `charts/openmettle-core` in the isolated target namespace preserving the source deployment's storage and vault settings (`storage.artifacts.existingClaim` bound to the reconciled target PVC when storage is enabled; `vault.enabled: true` pointing at `vault.existingSecret` when vault is enabled or required by `manifest.vault_required_key_ids`, or `vault.enabled: false` when vault is disabled and `manifest.vault_required_key_ids` is `[]`), and keeping `backup.suspend: true` (or `backup.enabled: false`).
2. Wait for `Deployment/<release>-api`, `Deployment/<release>-worker`, and any configured `Deployment/<release>-gateway-*` to report Ready and `GET /readyz` -> `200`.
3. Verify post-restore functional and security invariants before recording `recovery_completed_at` and signing off.
   - **Checks completable immediately (both open sign-in and intentionally closed `NULL` sign-in):**
     - **Credential invalidation and login admission:** Pre-restore session cookies/tokens return `401 unauthenticated` (Step 5a bumped every active provider epoch and `access_generation`, invalidating all pre-restore sessions and pending OIDC logins), and `openmettle.login_admission.outstanding_limit` matches the reconciled policy from Step 5b: when sign-in is intended to be open, verify `outstanding_limit` is `1..=65536` with positive available capacity (`outstanding_unissued < outstanding_limit`) so new login initiations are admitted; when sign-in is intentionally closed (`outstanding_limit IS NULL` or `auth.enabled: false`), confirm `outstanding_limit IS NULL` and verify new login initiations remain refused (`Unconfigured`) or auth routes remain disabled (`auth.enabled: false`).
     - **Reconciled database, vault, disk, and gate invariants (read-only `openmettle_owner` SQL, disk, and `openmettle-admin`):** Verify post-backup disabled users and withdrawn approvals (`users.disabled_at IS NOT NULL`, `local_identity_approvals.active = false`), revoked capability/project grants and resource shares (`grant_assignments`), disconnected/revoked external connections (`state = 'disconnected'`, `NULL` ciphertexts, `external_connection_shares.active = false`), reconciled `openmettle.family_policies` schedules and `openmettle.family_policy_models` active rules (`rule_kind IN ('disabled', 'study_allow')`), `openmettle-admin vault status`, lost/purged/retained `artifact_revisions` states (`state = 'lost'` with non-null `lost_at`; `state = 'purged'` with `0` resurrected files on disk; `retained` preserving exact pre-backup `purge_after`), cancelled `waiting`/`queued` runs + contiguous `run_events` (`run-terminal`) + `outcome_unknown` (`revision = 1`) write intents + quota hold disposition + zero unsolicited upstream/MCP calls on worker startup, and clean deletion-journal coverage (`SELECT coverage_complete FROM openmettle.restore_reconciliation_gate;` is `true`, and `SELECT count(*) FROM openmettle.authorization_audit WHERE actor_kind = 'operator' AND action = 'restore.accept_coverage_gap' AND target_kind = 'restore_gate' AND target_id = 'instance' AND details->>'restore_run_id' = '<RESTORE_RUN_UUID>';` returns `0` — scoping to Step 4a's `RESTORE_RUN_UUID` so historical break-glass audit rows carried forward in `pg.dump` from an earlier recovery do not fail a later certified `--export-complete` restore). If break-glass `restore accept-coverage-gap` was used and any deletion/revocation window remains unresolved, record the validation result as **failed** (`unresolved_deletion_coverage_gap`) and retain explicit owner break-glass sign-off rather than signing off clean `V1-31` / `V1-33` qualification.
     - **Accounting drift and durable post-restore journal export:** `openmettle-admin quota verify /var/lib/openmettle/artifacts` on deployments with a pinned artifact volume (or `openmettle-admin quota verify` without a root argument on storage-disabled deployments where `manifest.artifact_volume.volume_id` is `null`) exits `0` with all seven mismatch counters equal to `0`, and `openmettle-admin journal export "/var/backups/openmettle/post-restore-$RESTORE_RUN_UUID.export"` persists a fresh deletion journal onto **independent, durable recovery media** (never `/tmp` or an ephemeral pod `emptyDir`). Read back and verify that persisted file from independent storage before recording `recovery_completed_at` or handing off: confirm its `openmettle.deletion_journal.export/1` header, `watermark` footer, trailing `sha256 <hex>` checksum over all preceding bytes, and (whenever `storage declare-lost` ran in Step 4c) that every declared `<UNRECOVERABLE_REVISION_UUID>` appears in an `artifact_revision.lost <UNRECOVERABLE_REVISION_UUID>` record so any later restore against an older backup reproduces those loss decisions (`docs/operator/restore-artifact-volume.md`).
   - **Checks requiring a newly authenticated `/v1` user session (run immediately when sign-in is open; requires authorized sign-in reopening when `outstanding_limit IS NULL` or `auth.enabled: false`):**
     - Newly authenticated sessions see surviving personal and shared project conversations, shared project artifacts, and authorized connections with intact ownership and role boundaries (`404 not_found` across personal scopes and authenticated non-members; `403 policy` on `Viewer` writes); post-backup disabled accounts return `401 unauthenticated`.
     - Revisions declared lost in Step 4c return `200` metadata (`state: "lost"`, non-null `lost_at`) and `410 Gone` (`code: "payload_lost"`) on `/content` for authorized readers, while remaining `404` for unauthorized callers.
     - Post-backup purged revisions return `409 conflict` on `/content` and revoked/disconnected connections return `404` for former sharees.
     - Models disabled post-backup under family policy (`openmettle.family_policy_models`) return `403` (`code: "policy"`) on `POST /v1/runs` for newly authenticated affected users.
     - Parked `waiting` runs from the snapshot report `state: "cancelled"`, `POST /v1/runs/{run_id}/approvals/{approval_id}/decision` (`{"decision": "approve", ...}`) returns `409 conflict` with empty pending `/approvals`, and one fresh post-restore inference turn succeeds and settles cleanly.
     - **Never** bypass an intentionally closed sign-in policy on an operator recovery target by manually inserting rows into `openmettle.local_sessions` (direct session seeding in SQL is reserved strictly for isolated synthetic qualification drills after configuring a non-null `outstanding_limit` ceiling). Running the newly-authenticated `/v1` checks after a closed-sign-in recovery requires an explicit authorized reopening (`auth.enabled: true` / ingress and setting `login_admission.outstanding_limit` to `1..=65536` via `openmettle-core`'s `docs/operator/login-admission-limit.psql`).
   - **Sign-off and pending evidence when sign-in stays intentionally closed:**
     - If sign-in remains closed (`outstanding_limit IS NULL` or `auth.enabled: false`) at recovery handoff, record the sign-off state as `closed_signin_pending_auth_verification`, archive the completed closed-sign-in HTTP `401`/`Unconfigured`, SQL, disk, and `openmettle-admin` evidence, list the deferred newly-authenticated `/v1` checks above together with the owner approval/change ticket required to reopen sign-in, and execute + append those authenticated `/v1` checks immediately once sign-in is authorized to reopen. Do **not** sign off clean `V1-31` / `V1-33` qualification while authenticated `/v1` checks remain pending (isolated qualification drills configure an authorized non-null `outstanding_limit` ceiling on the isolated target so the full authenticated `/v1` suite completes before `recovery_completed_at`).
4. Record `recovery_completed_at` after the final verification check above and archive the drill metrics:
   - `restored_data_age_seconds = drill_cutover_at - manifest.quiesced_at` (must be `<= 86,400 s` for the 24h RPO target).
   - `recovery_duration_seconds = recovery_completed_at - recovery_started_at` (must be `<= 14,400 s` for the 4h RTO target, spanning target provisioning through final verification).

## Drill cadence

- **Automated CI (`dev` classification):** `.github/workflows/restore-drill.yml` runs `tests/kind/restore_drill.py` on pull requests and `main` pushes touching `CORE_COMMIT`, `charts/openmettle-core/**`, `tests/kind/**`, `tests/chart/install-tools.sh`, `docs/restore-drill.md`, or `.github/workflows/restore-drill.yml`, and via `workflow_dispatch`.
- **Operator qualification (`V1-31` / `V1-33`):** execute and record a live isolated-target drill on the workstation + off-host NAS before production cutover, on a recurring quarterly schedule, and after any material change to backup format/encryption (`ADR 0046`), artifact storage/journal reconciliation (`ADR 0040` / `ADR 0041`), vault key custody (`ADR 0045`), or PostgreSQL major/schema lifecycle migrations.
