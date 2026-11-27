#!/usr/bin/env python3
"""Isolated-target restore drill on an ephemeral kind cluster (V1-31, openmettle-deploy#3).

Test harness only; not an installer or live-cluster qualification. Reuses pinned core checkout
verification, tool/image guards, digest-aliasing helpers and secret redaction from `smoke.py` to
exercise `docs/restore-drill.md` end-to-end across two NetworkPolicy-isolated and PodSecurity
`restricted` namespace pairs (`openmettle-primary` + `openmettle-primary-db` and
`openmettle-restore-target` + `openmettle-restore-target-db`) on a temporary `kind` cluster
classified `dev`.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke  # noqa: E402

ROOT = smoke.ROOT
CHART = smoke.CHART
CORE_COMMIT = smoke.CORE_COMMIT
ROLES = smoke.ROLES
DEFAULT_ROLES = smoke.DEFAULT_ROLES
WORKLOADS = smoke.WORKLOADS
RELEASE = smoke.RELEASE
FULLNAME = smoke.FULLNAME
REQUIRED_MIGRATION = smoke.REQUIRED_MIGRATION

PRIMARY_APP_NS = "openmettle-primary"
PRIMARY_DB_NS = "openmettle-primary-db"
TARGET_APP_NS = "openmettle-restore-target"
TARGET_DB_NS = "openmettle-restore-target-db"
DRILL_NAMESPACES = (PRIMARY_APP_NS, PRIMARY_DB_NS, TARGET_APP_NS, TARGET_DB_NS)
RUN_LABEL = "openmettle.dev/drill-run"
RECOVERY_DB_CLIENT_LABEL = "openmettle.dev/recovery-db-client"
RECOVERY_NETPOL = "openmettle-target-recovery-egress"
DB_PROBE = "db-probe"
DB_PROBE_LABELS = {"app.kubernetes.io/name": DB_PROBE}
GAP_DB_NAME = "openmettle_gap"
GAP_OWNER_SECRET = "openmettle-owner-gap-database"

TARGET_ARTIFACTS_CLAIM = "openmettle-target-artifacts"
TARGET_RECOVERY_MEDIA_CLAIM = "openmettle-target-recovery-media"
TARGET_RECOVERY_SCRATCH_CLAIM = "openmettle-target-recovery-scratch"
RECOVERY_MEDIA_DIR = "/var/backups/openmettle"
RECOVERY_SCRATCH_DIR = "/var/recovery"
UNPACKED_DIR = f"{RECOVERY_SCRATCH_DIR}/unpacked"
RETAINED_JOURNAL_PATH = f"{RECOVERY_SCRATCH_DIR}/post-backup-journal.export"

VAULT_KEY_ID_1 = "vault-k1"
VAULT_KEY_FILE_1 = "vault-k1.key"
VAULT_KEY_ID_2 = "vault-k2"
VAULT_KEY_FILE_2 = "vault-k2.key"
BACKUP_KEY_ID = smoke.BACKUP_KEY_ID
BACKUP_KEY_FILE = smoke.BACKUP_KEY_FILE
WRONG_BACKUP_SECRET = "openmettle-drill-wrong-backup-keys"
WRONG_BACKUP_KEYS_DIR = "/etc/openmettle/wrong-backup-keys"

DRILL_OPERATOR_ID = "00000000-0000-4000-8000-00000000d031"
USER_A_IDS = {
    "provider": "00000000-0000-4000-8000-00000000c101",
    "user": "00000000-0000-4000-8000-00000000c102",
    "identity": "00000000-0000-4000-8000-00000000c103",
    "approval": "00000000-0000-4000-8000-00000000c104",
}
USER_B_IDS = {
    "user": "00000000-0000-4000-8000-00000000c202",
    "identity": "00000000-0000-4000-8000-00000000c203",
    "approval": "00000000-0000-4000-8000-00000000c204",
}
USER_C_IDS = {
    "user": "00000000-0000-4000-8000-00000000c302",
    "identity": "00000000-0000-4000-8000-00000000c303",
    "approval": "00000000-0000-4000-8000-00000000c304",
}
USER_D_IDS = {
    "user": "00000000-0000-4000-8000-00000000c402",
    "identity": "00000000-0000-4000-8000-00000000c403",
    "approval": "00000000-0000-4000-8000-00000000c404",
}

RPO_TARGET_SECONDS = 86_400
RTO_TARGET_SECONDS = 14_400
STORAGE_BUDGET_BYTES = 16 * (1 << 20)
SCOPE_STORAGE_LIMIT_BYTES = 4 * (1 << 20)

DRILL_SUMMARY_KEYS = {
    "result",
    "classification",
    "core_commit",
    "cluster",
    "primary_namespace",
    "target_namespace",
    "tools",
    "images",
    "rpo_rto",
    "limitations",
    "checks",
    "error",
    "cleanup_errors",
}
DRILL_LIMITATIONS = [
    "Ephemeral single-node amd64 kind cluster classified dev using local-path PVCs (requireSeparateDevice=false).",
    "Synthetic PostgreSQL 18 pods without TLS/CA and synthetic SGLang stand-in without GPU hardware.",
    "Does not substitute for owner-executed live workstation and off-host NAS restore qualification (V1-01, V1-31, V1-33).",
]

POD_SEC_CONTEXT = {
    "runAsNonRoot": True,
    "runAsUser": 65532,
    "runAsGroup": 65532,
    "fsGroup": 65532,
    "fsGroupChangePolicy": "OnRootMismatch",
    "seccompProfile": {"type": "RuntimeDefault"},
}
PG_POD_SEC_CONTEXT = {
    "runAsNonRoot": True,
    "runAsUser": 999,
    "runAsGroup": 999,
    "fsGroup": 999,
    "fsGroupChangePolicy": "OnRootMismatch",
    "seccompProfile": {"type": "RuntimeDefault"},
}
CONTAINER_SEC_CONTEXT = {
    "privileged": False,
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
    "capabilities": {"drop": ["ALL"]},
}

RESTORE_LOCK_RUN_RE = re.compile(
    r"\brestore_run\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
)
REBIND_BARRIER_RE = re.compile(
    r"--replace-adoption-run\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
QUOTA_DRIFT_RE = re.compile(
    r"^storage mismatches (\d+), budget mismatches (\d+), settlement mismatches (\d+), "
    r"pending gateway (\d+), file mismatches (\d+), quarantined (\d+), unsettled payloads (\d+)$"
)


class DrillFailure(Exception):
    """Observed restore-drill behaviour did not match the runbook invariant."""


# --- Pure logic (unit-tested in test_restore_drill.py) -------------------------------------


def stopped_primary_watermark_sql() -> str:
    """SQL query reading the stopped primary's authoritative `(journal_seq, chain_digest)`."""
    return "SELECT journal_seq, encode(chain_digest, 'hex') FROM openmettle.deletion_journal_head WHERE id;"


def parse_journal_export_watermarks(text: str) -> dict:
    """Extract restore-lock watermarks from a `deletion_journal` export text."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 4 or lines[0] != "openmettle.deletion_journal.export/1":
        raise DrillFailure("invalid deletion journal export header")
    origin_us: int | None = None
    lifecycle_origin_us: int | None = None
    lifecycle_baseline_digest: str | None = None
    connection_origin_us: int | None = None
    watermark_seq: int | None = None
    watermark_digest: str | None = None
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        tag = parts[0]
        if tag == "origin" and len(parts) == 2:
            origin_us = int(parts[1])
        elif tag == "lifecycle_origin" and len(parts) == 2:
            lifecycle_origin_us = int(parts[1])
        elif tag == "lifecycle_baseline" and len(parts) == 2:
            if not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
                raise DrillFailure("invalid lifecycle_baseline digest in journal export")
            lifecycle_baseline_digest = parts[1]
        elif tag == "connection_origin" and len(parts) == 2:
            connection_origin_us = int(parts[1])
        elif tag == "watermark" and len(parts) == 5:
            wm_origin = int(parts[1])
            watermark_seq = int(parts[2])
            if not re.fullmatch(r"[0-9a-f]{64}", parts[3]):
                raise DrillFailure("invalid watermark chain digest in journal export")
            watermark_digest = parts[3]
            if origin_us is not None and wm_origin != origin_us:
                raise DrillFailure("journal watermark origin disagrees with header origin")
    if origin_us is None or watermark_seq is None or watermark_digest is None:
        raise DrillFailure("journal export missing origin or watermark footer")
    if (lifecycle_origin_us is None) != (lifecycle_baseline_digest is None):
        raise DrillFailure("journal export has unpaired lifecycle_origin / lifecycle_baseline")
    return {
        "origin_us": origin_us,
        "lifecycle_origin_us": lifecycle_origin_us,
        "lifecycle_baseline_digest": lifecycle_baseline_digest,
        "connection_origin_us": connection_origin_us,
        "required_seq": watermark_seq,
        "required_digest": watermark_digest,
    }


def should_pass_export_complete(
    watermarks: dict, stopped_primary_watermark: tuple[int, str] | None
) -> bool:
    """Return True only when `(required_seq, required_digest)` matches an independently recorded
    final watermark captured after primary writes, purges, and connection revocations stopped."""
    if stopped_primary_watermark is None:
        return False
    stopped_seq, stopped_digest = stopped_primary_watermark
    return (
        isinstance(stopped_seq, int)
        and isinstance(stopped_digest, str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", stopped_digest))
        and watermarks.get("required_seq") == stopped_seq
        and watermarks.get("required_digest") == stopped_digest
    )


def restore_lock_args(watermarks: dict, *, export_complete: bool) -> list[str]:
    """Build `openmettle-admin restore lock` argv from parsed journal watermarks."""
    args = ["restore", "lock", "--required-origin", str(watermarks["origin_us"])]
    if watermarks.get("lifecycle_origin_us") is not None:
        args += [
            "--required-lifecycle-origin",
            str(watermarks["lifecycle_origin_us"]),
            "--required-lifecycle-baseline-digest",
            str(watermarks["lifecycle_baseline_digest"]),
        ]
    if watermarks.get("connection_origin_us") is not None:
        args += ["--required-connection-origin", str(watermarks["connection_origin_us"])]
    args += [
        "--required-seq",
        str(watermarks["required_seq"]),
        "--required-digest",
        str(watermarks["required_digest"]),
    ]
    if export_complete:
        args.append("--export-complete")
    return args


def parse_restore_lock_run_id(output: str) -> str:
    """Extract `restore_run <UUID>` from `openmettle-admin restore lock` stdout."""
    match = RESTORE_LOCK_RUN_RE.search(output)
    if not match:
        raise DrillFailure(f"restore lock stdout did not report restore_run UUID: {output!r}")
    return match.group(1)


def parse_cancelled_runs_count(sql_out: str) -> int:
    """Extract the unique `cancelled_runs=<n>` line emitted by `pre_worker_owner_reconcile_sql`,
    ignoring unrelated bare numeric rows such as `SELECT setval(...)`."""
    matches = [
        m.group(1)
        for ln in sql_out.splitlines()
        if (m := re.fullmatch(r"cancelled_runs=(\d+)", ln.strip())) is not None
    ]
    if len(matches) != 1:
        raise DrillFailure(f"expected single cancelled_runs=<n> line, got {sql_out!r}")
    return int(matches[0])


def verify_trailing_epoch_probe_failure(
    returncode: int,
    stderr: str,
    *,
    expected_new_epoch: int = 41,
    expected_prev_max: int = 100,
) -> None:
    """Require the unrepaired ADR 0012 trailing-sequence probe to fail specifically with the
    PostgreSQL epoch-guard exception rather than an unrelated exec/transport error."""
    expected_diag = (
        f"login_provider_revisions epoch {expected_new_epoch} "
        f"did not advance past previous maximum {expected_prev_max}"
    )
    if returncode == 0 or expected_diag not in stderr:
        raise DrillFailure(
            "trailing login_provider_revisions sequence probe did not fail with expected "
            f"epoch guard diagnostic ({expected_diag!r}): rc={returncode}, stderr={stderr!r}"
        )


def accept_coverage_gap_args(
    restore_run_id: str, operator_id: str, request_key: str, reason: str
) -> list[str]:
    """Build `openmettle-admin restore accept-coverage-gap` argv for uncertified exports."""
    for label, val in (("restore_run_id", restore_run_id), ("operator_id", operator_id)):
        if not smoke.UUID.fullmatch(val):
            raise DrillFailure(f"invalid {label} UUID: {val!r}")
    return [
        "restore",
        "accept-coverage-gap",
        "--restore-run",
        restore_run_id,
        "--operator-id",
        operator_id,
        "--request-key",
        request_key,
        "--reason",
        reason,
    ]


def parse_failed_rebind(
    stdout: str, stderr: str, expected_reservation_ids: str | list[str] | tuple[str, ...]
) -> str:
    """Extract the held adoption barrier UUID from a failed `storage rebind` invocation."""
    ids = (
        [expected_reservation_ids]
        if isinstance(expected_reservation_ids, str)
        else list(expected_reservation_ids)
    )
    if not ids:
        raise DrillFailure("parse_failed_rebind requires at least one expected reservation UUID")
    lines = stdout.splitlines()
    for res_id in ids:
        if not smoke.UUID.fullmatch(res_id):
            raise DrillFailure(f"invalid expected reservation UUID: {res_id!r}")
        expected_line = f"failed {res_id}: missing revision"
        if expected_line not in lines:
            raise DrillFailure(f"storage rebind stdout did not report {expected_line!r}: {stdout!r}")
    match = REBIND_BARRIER_RE.search(stderr)
    if not match:
        raise DrillFailure(f"storage rebind stderr did not report --replace-adoption-run UUID: {stderr!r}")
    return match.group(1)


def parse_quota_verify_zero(output: str) -> dict:
    """Require `openmettle-admin quota verify` to report 0 across all 7 drift counters."""
    for line in output.splitlines():
        match = QUOTA_DRIFT_RE.fullmatch(line.strip())
        if match:
            counts = [int(g) for g in match.groups()]
            keys = (
                "storage_mismatches",
                "budget_mismatches",
                "settlement_mismatches",
                "pending_gateway",
                "file_mismatches",
                "quarantined",
                "unsettled_payloads",
            )
            summary = dict(zip(keys, counts))
            if any(counts):
                raise DrillFailure(f"accounting drift non-zero: {summary}")
            return summary
    raise DrillFailure(f"quota verify output lacked drift summary line: {output!r}")


def parse_vault_status(output: str) -> dict:
    """Parse `openmettle-admin vault status` stdout into structured counts."""
    total_connections = None
    total_encrypted = None
    by_state: dict[str, int] = {}
    by_key_id: dict[str, int] = {}
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = re.fullmatch(r"connections (\d+), encrypted (\d+)", line)
        if header:
            total_connections = int(header.group(1))
            total_encrypted = int(header.group(2))
            continue
        parts = line.split()
        if len(parts) == 3 and parts[0] == "state":
            by_state[parts[1]] = int(parts[2])
        elif len(parts) == 3 and parts[0] == "key_id":
            by_key_id[parts[1]] = int(parts[2])
    if total_connections is None or total_encrypted is None:
        raise DrillFailure(f"unexpected vault status output: {output!r}")
    return {
        "connections": total_connections,
        "encrypted": total_encrypted,
        "by_state": by_state,
        "by_key_id": by_key_id,
    }


def evaluate_manifest_preflight(
    manifest: dict,
    *,
    max_schema: int = REQUIRED_MIGRATION,
    available_vault_keys: set[str] | None = None,
) -> dict:
    """Validate unpacked `manifest.json` compatibility before touching PostgreSQL or PVCs."""
    if manifest.get("format") != "openmettle-backup-manifest/v1":
        raise DrillFailure(f"unexpected backup manifest format: {manifest.get('format')!r}")
    schema = manifest.get("schema_version")
    if not isinstance(schema, int) or schema < 1 or schema > max_schema:
        raise DrillFailure(f"incompatible backup schema_version {schema!r} (max supported {max_schema})")
    quiesced_at = manifest.get("quiesced_at")
    if not isinstance(quiesced_at, str) or not quiesced_at.endswith("Z"):
        raise DrillFailure(f"manifest missing canonical UTC quiesced_at: {quiesced_at!r}")
    smoke.parse_time(quiesced_at)
    journal = manifest.get("deletion_journal") or {}
    journal_seq = journal.get("journal_seq")
    if not isinstance(journal_seq, int) or journal_seq < 0:
        raise DrillFailure(f"manifest has invalid deletion_journal.journal_seq: {journal_seq!r}")
    required_vault = manifest.get("vault_required_key_ids")
    if not isinstance(required_vault, list) or not all(isinstance(k, str) and k for k in required_vault):
        raise DrillFailure(f"manifest has invalid vault_required_key_ids: {required_vault!r}")
    if available_vault_keys is not None:
        missing = sorted(set(required_vault) - set(available_vault_keys))
        if missing:
            raise DrillFailure(f"target vault keyring lacks required key IDs from manifest: {missing}")
    art_vol = manifest.get("artifact_volume") or {}
    volume_id = art_vol.get("volume_id")
    if volume_id is not None and (not isinstance(volume_id, str) or not smoke.UUID.fullmatch(volume_id)):
        raise DrillFailure(f"manifest has invalid artifact_volume.volume_id: {volume_id!r}")
    graphiti_status = (manifest.get("graphiti_neo4j") or {}).get("status", "not_provisioned")
    if graphiti_status not in ("not_provisioned", "offline_dump"):
        raise DrillFailure(f"manifest has unexpected graphiti_neo4j.status: {graphiti_status!r}")
    chroma_mode = (manifest.get("chroma") or {}).get("mode", "not_provisioned")
    if chroma_mode not in ("not_provisioned", "archive", "qualified_rebuild"):
        raise DrillFailure(f"manifest has unexpected chroma.mode: {chroma_mode!r}")
    return {
        "backup_run_id": manifest.get("backup_run_id"),
        "schema_version": schema,
        "quiesced_at": quiesced_at,
        "journal_seq": journal_seq,
        "vault_required_key_ids": list(required_vault),
        "artifact_volume_id": volume_id,
        "artifact_revisions": art_vol.get("revision_count"),
        "graphiti_status": graphiti_status,
        "chroma_mode": chroma_mode,
    }


def evaluate_rpo_rto(
    quiesced_at_iso: str,
    cutover_at: datetime,
    recovery_started_at: datetime,
    recovery_completed_at: datetime,
    *,
    report: dict | None = None,
) -> dict:
    """Compute, record, and enforce V1-31 RPO (<= 24h) and RTO (<= 4h) bounds."""
    quiesced_at = smoke.parse_time(quiesced_at_iso)
    data_age = (cutover_at - quiesced_at).total_seconds()
    recovery_secs = (recovery_completed_at - recovery_started_at).total_seconds()
    breaches: list[str] = []
    if data_age < 0:
        breaches.append(f"negative restored_data_age_seconds ({data_age:.3f}s)")
    elif data_age > RPO_TARGET_SECONDS:
        breaches.append(f"RPO breached: restored_data_age_seconds={data_age:.2f} > {RPO_TARGET_SECONDS}")
    if recovery_secs <= 0:
        breaches.append(f"non-positive recovery_duration_seconds ({recovery_secs:.3f}s)")
    elif recovery_secs > RTO_TARGET_SECONDS:
        breaches.append(f"RTO breached: recovery_duration_seconds={recovery_secs:.2f} > {RTO_TARGET_SECONDS}")
    metrics = {
        "quiesced_at": quiesced_at_iso,
        "recovery_started_at": recovery_started_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "recovery_completed_at": recovery_completed_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "restored_data_age_seconds": round(data_age, 3),
        "rpo_target_seconds": RPO_TARGET_SECONDS,
        "rpo_met": 0 <= data_age <= RPO_TARGET_SECONDS,
        "recovery_duration_seconds": round(recovery_secs, 3),
        "rto_target_seconds": RTO_TARGET_SECONDS,
        "rto_met": 0 < recovery_secs <= RTO_TARGET_SECONDS,
    }
    if report is not None:
        report["rpo_rto"] = metrics
    if breaches:
        raise DrillFailure("; ".join(breaches))
    return metrics


def provider_epoch_advance_block_sql(operator_id: str) -> str:
    """PL/pgSQL block enforcing ADR 0012 / 0013 login-provider epoch advance (> prev_max_epoch)
    with full transaction rollback if the identity sequence trails restored rows."""
    if not smoke.UUID.fullmatch(operator_id):
        raise DrillFailure(f"invalid operator UUID: {operator_id!r}")
    return f"""\
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
               changed_by = 'operator:{operator_id}',
               change_reason = 'isolated restore session invalidation'
         WHERE id = rec.provider_id;
    END LOOP;
END
$provider_epoch$;"""


def pre_worker_owner_reconcile_sql(
    operator_id: str,
    *,
    disabled_principals: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
) -> str:
    """Owner SQL for Runbook Steps 5a (ADR 0012 / 0013 sequence sync, monotonic epoch advance,
    and session/provider invalidation), 5b (post-backup principal/approval revocations), and
    5d.1 (two-statement run cancellation preserving `resolve_terminal_write_intents()` and
    contiguous `runs.last_event_sequence` allocation)."""
    if not smoke.UUID.fullmatch(operator_id):
        raise DrillFailure(f"invalid operator UUID: {operator_id!r}")
    revocations_sql = ""
    for user_id, approval_id in disabled_principals:
        if not (smoke.UUID.fullmatch(user_id) and smoke.UUID.fullmatch(approval_id)):
            raise DrillFailure(f"invalid disabled principal UUIDs: {(user_id, approval_id)!r}")
        revocations_sql += f"""\
UPDATE openmettle.users
   SET disabled_at = coalesce(disabled_at, clock_timestamp()),
       session_generation = session_generation + 1
 WHERE id = '{user_id}'::uuid;
UPDATE openmettle.local_identity_approvals
   SET active = false,
       access_generation = access_generation + 1,
       changed_by = 'operator:{operator_id}',
       change_reason = 'post-backup principal revocation reconciliation'
 WHERE id = '{approval_id}'::uuid;
"""
    return f"""\
LOCK TABLE openmettle.login_providers IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE openmettle.login_provider_revisions IN EXCLUSIVE MODE;

SELECT setval(
    pg_get_serial_sequence('openmettle.login_provider_revisions', 'epoch'),
    coalesce((SELECT max(epoch) FROM openmettle.login_provider_revisions), 1),
    EXISTS (SELECT 1 FROM openmettle.login_provider_revisions)
);

{provider_epoch_advance_block_sql(operator_id)}

{revocations_sql}UPDATE openmettle.runs r
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
    payload constant bytea := convert_to('{{"reason":"revoked"}}', 'UTF8');
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

SELECT 'cancelled_runs=' || count(*)
  FROM openmettle.runs
 WHERE state = 'cancelled'
   AND cancel_reason = 'revoked';
"""


def worker_quota_release_sql() -> str:
    """Worker-role SQL for Runbook Step 5d.2 (`openmettle.quota_release_terminal_runs` requires
    `openmettle_api` or `openmettle_worker` membership and retains holds on `outcome_unknown`)."""
    return """\
SELECT openmettle.quota_release_terminal_runs(
    coalesce(
        (SELECT array_agg(r.id ORDER BY r.id)
           FROM openmettle.runs r
          WHERE r.state IN ('succeeded', 'failed', 'cancelled', 'interrupted')),
        ARRAY[]::uuid[]
    )
);
"""


def _validate_posix_abs_path(label: str, path: str) -> str:
    """Reject empty, relative, or shell-metacharacter paths interpolated into `/bin/sh` scripts."""
    if (
        not path
        or not path.startswith("/")
        or path == "/"
        or any(c in path for c in ('"', "'", "$", "`", "\\", "\n", "\r", "*", "?", "[", "\0"))
    ):
        raise DrillFailure(f"invalid {label} path: {path!r}")
    return path


def _sh_quote(value: str) -> str:
    """Single-quote an arbitrary non-control string safely for POSIX `/bin/sh`."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _validate_model_name(model: str) -> str:
    """Validate `model` against `openmettle-core` `model_config::name` / `family::valid_model`:
    1..=256 UTF-8 bytes and free of Unicode control characters."""
    if (
        not isinstance(model, str)
        or not model
        or len(model.encode("utf-8")) > 256
        or any(ord(c) <= 0x1F or 0x7F <= ord(c) <= 0x9F for c in model)
    ):
        raise DrillFailure(f"invalid family policy model name: {model!r}")
    return model


def _validate_hhmm_window(label: str, raw: str) -> str:
    """Validate an `HH:MM-HH:MM` schedule window matching `openmettle-core` `Hours::parse_window`."""
    if not isinstance(raw, str):
        raise DrillFailure(f"invalid family policy {label} window: {raw!r}")
    match = re.fullmatch(r"([0-9]{2}):([0-9]{2})-([0-9]{2}):([0-9]{2})", raw)
    if not match:
        raise DrillFailure(f"invalid family policy {label} window: {raw!r}")
    h1, m1, h2, m2 = (int(x) for x in match.groups())
    if h1 > 23 or h2 > 23 or m1 > 59 or m2 > 59 or (h1, m1) == (h2, m2):
        raise DrillFailure(f"invalid family policy {label} window: {raw!r}")
    return raw


def _family_request_key(prefix: str, restore_run_id: str, *parts: str) -> str:
    """Build a deterministic `<= 128`-byte request key for `openmettle-admin family` retries."""
    digest = hashlib.sha256("\0".join((restore_run_id, *parts)).encode("utf-8")).hexdigest()[:32]
    key = f"{prefix}-{restore_run_id}-{digest}"
    if len(key) > 128:
        raise DrillFailure(f"generated request_key exceeds 128 chars: {len(key)}")
    return key


def build_family_policy_reconcile_lines(
    operator_id: str,
    restore_run_id: str,
    entries: list[dict] | tuple[dict, ...],
) -> str:
    """Build `openmettle-admin family` commands reconciling post-backup family policies and
    model rules (`ADR 0044`) before reopening inference.

    Each entry dict takes:
      - `user_id`: canonical grantee user UUID
      - `policy`: `None` when an existing restored `family_policies` row keeps its schedule
        (only model rules changed post-backup), `"clear"` to deactivate a cleared policy, or a
        dict `{"zone": str, "quiet": str | None, "study": str | None,
        "override_group_schedules": bool}` carrying the complete recorded schedule when
        `family_policy.set` occurred post-backup
      - `models`: sequence of `(kind, model, enable)` tuples (`kind` in `{"disabled",
        "study_allow"}`, `enable` bool). Uses SHA-256-bounded request keys (`<= 128` bytes for
        every valid 1..=256-byte model identifier).
    """
    for label, val in (("operator_id", operator_id), ("restore_run_id", restore_run_id)):
        if not smoke.UUID.fullmatch(val):
            raise DrillFailure(f"invalid {label} UUID: {val!r}")
    lines: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise DrillFailure(f"expected family policy reconcile entry dict, got {entry!r}")
        user_id = entry.get("user_id", "")
        if not smoke.UUID.fullmatch(user_id):
            raise DrillFailure(f"invalid restricted user UUID: {user_id!r}")
        policy = entry.get("policy")
        if policy == "clear":
            policy_key = _family_request_key("restore-fp", restore_run_id, user_id, "clear")
            lines.append(
                f'openmettle-admin family clear-policy --user "{user_id}" '
                f'--operator-id "{operator_id}" --request-key "{policy_key}" '
                '--reason "reconcile post-backup family policy clearance before reopening inference"'
            )
        elif isinstance(policy, dict):
            zone = policy.get("zone", "")
            if not isinstance(zone, str) or not re.fullmatch(r"[A-Za-z0-9/+_.-]{1,128}", zone):
                raise DrillFailure(f"invalid family policy timezone: {zone!r}")
            quiet = policy.get("quiet")
            study = policy.get("study")
            override = bool(policy.get("override_group_schedules", False))
            parts = [f'openmettle-admin family set-policy --user "{user_id}" --zone "{zone}"']
            if quiet is not None:
                parts.append(f'--quiet "{_validate_hhmm_window("quiet", quiet)}"')
            if study is not None:
                parts.append(f'--study "{_validate_hhmm_window("study", study)}"')
            if override:
                parts.append("--override-group-schedules")
            policy_key = _family_request_key("restore-fp", restore_run_id, user_id, "set")
            parts.append(
                f'--operator-id "{operator_id}" --request-key "{policy_key}" '
                '--reason "reconcile post-backup family policy before reopening inference"'
            )
            lines.append(" ".join(parts))
        elif policy is not None:
            raise DrillFailure(f"invalid family policy directive: {policy!r}")

        for kind, model, enable in entry.get("models", ()):
            if kind not in ("disabled", "study_allow"):
                raise DrillFailure(f"invalid family policy rule kind: {kind!r}")
            if not isinstance(enable, bool):
                raise DrillFailure(f"invalid family policy enable flag: {enable!r}")
            _validate_model_name(model)
            state_bit = "1" if enable else "0"
            model_key = _family_request_key("restore-fm", restore_run_id, user_id, kind, model, state_bit)
            flag = "--enable" if enable else "--disable"
            lines.append(
                f'openmettle-admin family set-model --user "{user_id}" --kind {kind} '
                f'--model {_sh_quote(model)} {flag} '
                f'--operator-id "{operator_id}" --request-key "{model_key}" '
                '--reason "reconcile post-backup family model rule before reopening inference"'
            )
    return ("\n".join(lines) + "\n") if lines else ""


def build_step4c_reconcile_lines(
    *,
    selected_journal: str,
    artifacts_mount: str,
    unpacked_dir: str,
    operator_id: str,
    barrier_uuid: str,
    failed_revisions: list[tuple[str, str, int, str]],
    recovery_media_dir: str = RECOVERY_MEDIA_DIR,
) -> str:
    """Build Step 4c + 4d commands for pinned artifact volumes:
    1) replay --db-only first,
    2) verify the staging revisions directory is readable, searchable, and listable before
       evaluating individual candidates, verify staging copies as regular readable non-symlink
       files by byte length + SHA-256 without masking read/stat/digest exit codes (aborting
       reconciliation rather than falling through to `storage declare-lost` on error), and
       restore any intact payload (`chmod 0600`),
    3) verify recovery_media_dir (when present) is inspectable and contains no remaining backup
       archive before reserving `storage declare-lost` strictly for revisions confirmed
       absent/corrupt in all recovery copies,
    4) resume `storage rebind --replace-adoption-run` -> `restore replay` -> `quota verify`."""
    _validate_posix_abs_path("selected_journal", selected_journal)
    _validate_posix_abs_path("artifacts_mount", artifacts_mount)
    _validate_posix_abs_path("unpacked_dir", unpacked_dir)
    _validate_posix_abs_path("recovery_media_dir", recovery_media_dir)
    if not (smoke.UUID.fullmatch(operator_id) and smoke.UUID.fullmatch(barrier_uuid)):
        raise DrillFailure("invalid operator_id or barrier_uuid in build_step4c_reconcile_lines")
    lines = [f'openmettle-admin restore replay --db-only "{selected_journal}"']
    if failed_revisions:
        lines.append(
            f'rev_dir="{unpacked_dir}/artifacts/revisions"\n'
            'if [ -L "$rev_dir" ] || [ ! -d "$rev_dir" ] || [ ! -r "$rev_dir" ] || [ ! -x "$rev_dir" ] || ! ls -A -- "$rev_dir" >/dev/null; then\n'
            '  echo "ERROR: staging revisions directory $rev_dir is missing or inaccessible; refusing storage declare-lost" >&2\n'
            "  exit 1\n"
            "fi"
        )
    for rev_id, res_id, size_bytes, expected_sha256 in failed_revisions:
        if not (
            smoke.UUID.fullmatch(rev_id)
            and smoke.UUID.fullmatch(res_id)
            and isinstance(size_bytes, int)
            and size_bytes >= 0
            and re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        ):
            raise DrillFailure(f"invalid Step 4c revision descriptor: {(rev_id, res_id, size_bytes)!r}")
        lines.append(
            f'cand="$rev_dir/{res_id}"\n'
            f'dst="{artifacts_mount}/revisions/{res_id}"\n'
            "recovered=0\n"
            'if [ -e "$cand" ] || [ -L "$cand" ]; then\n'
            '  if [ -L "$cand" ] || [ ! -f "$cand" ] || [ ! -r "$cand" ]; then\n'
            '    echo "ERROR: staging candidate $cand is unreadable or not a regular file; refusing storage declare-lost" >&2\n'
            "    exit 1\n"
            "  fi\n"
            '  raw_wc="$(wc -c < "$cand")"\n'
            '  cand_bytes="$(printf \'%s\' "$raw_wc" | tr -d \'[:space:]\')"\n'
            '  case "$cand_bytes" in \'\'|*[!0-9]*)\n'
            '    echo "ERROR: failed to read byte size of staging candidate $cand" >&2\n'
            "    exit 1\n"
            "    ;;\n"
            "  esac\n"
            '  raw_sha="$(sha256sum "$cand")"\n'
            '  cand_sha="${raw_sha%% *}"\n'
            '  if [ "${#cand_sha}" -ne 64 ]; then\n'
            '    echo "ERROR: failed to compute SHA-256 of staging candidate $cand" >&2\n'
            "    exit 1\n"
            "  fi\n"
            f'  if [ "$cand_bytes" -eq {size_bytes} ] && [ "$cand_sha" = "{expected_sha256}" ]; then\n'
            '    cp -a -- "$cand" "$dst"\n'
            '    chmod 0600 "$dst"\n'
            "    recovered=1\n"
            f'    printf "STAGE_RECOVERED {rev_id}\\n"\n'
            "  fi\n"
            "fi\n"
            'if [ "$recovered" -eq 0 ]; then\n'
            f'  if [ -e "{recovery_media_dir}" ] || [ -L "{recovery_media_dir}" ]; then\n'
            f'    if [ -L "{recovery_media_dir}" ] || [ ! -d "{recovery_media_dir}" ] || [ ! -r "{recovery_media_dir}" ] || [ ! -x "{recovery_media_dir}" ] || ! ls -A -- "{recovery_media_dir}" >/dev/null; then\n'
            f'      echo "ERROR: recovery media directory {recovery_media_dir} is inaccessible; refusing storage declare-lost" >&2\n'
            "      exit 1\n"
            "    fi\n"
            "  fi\n"
            f'  for archive_cand in "{recovery_media_dir}"/backup-*; do\n'
            '    if [ -e "$archive_cand" ] || [ -L "$archive_cand" ]; then\n'
            '      echo "ERROR: backup archive $archive_cand remains available; unpack and inspect before storage declare-lost" >&2\n'
            "      exit 1\n"
            "    fi\n"
            "  done\n"
            f'  openmettle-admin storage declare-lost "{artifacts_mount}" '
            f'--revision "{rev_id}" --operator-id "{operator_id}" '
            f'--request-key "drill-lost-{rev_id}" '
            '--reason "simulated unrecoverable disk payload during V1-31 isolated restore drill"\n'
            f'  printf "DECLARED_LOST {rev_id}\\n"\n'
            "fi"
        )
    lines.extend([
        f'openmettle-admin storage rebind "{artifacts_mount}" --replace-adoption-run "{barrier_uuid}"',
        f'openmettle-admin restore replay "{selected_journal}" "{artifacts_mount}"',
        f'printf "QUOTA_STAGE4_BEGIN\\n"; openmettle-admin quota verify "{artifacts_mount}"; printf "QUOTA_STAGE4_END\\n"',
    ])
    return "\n".join(lines) + "\n"


def build_step5e_script(
    operator_id: str,
    restore_run_id: str,
    *,
    has_artifacts: bool,
    artifacts_mount: str = smoke.ARTIFACTS_MOUNT_PATH,
    unpacked_dir: str = UNPACKED_DIR,
    retained_journal: str = RETAINED_JOURNAL_PATH,
) -> str:
    """Build the Step 5e shell script so `unpacked_dir` and `retained_journal` are scrubbed ONLY
    after `backup release-maintenance` succeeds, `backup status` reports `"maintenance_active": false`,
    and `quota verify` reports zero across all seven drift counters."""
    _validate_posix_abs_path("artifacts_mount", artifacts_mount)
    _validate_posix_abs_path("unpacked_dir", unpacked_dir)
    _validate_posix_abs_path("retained_journal", retained_journal)
    for label, val in (("operator_id", operator_id), ("restore_run_id", restore_run_id)):
        if not smoke.UUID.fullmatch(val):
            raise DrillFailure(f"invalid {label} UUID: {val!r}")
    qv_cmd = f'openmettle-admin quota verify "{artifacts_mount}"' if has_artifacts else "openmettle-admin quota verify"
    zero_line = (
        "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
        "pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0"
    )
    return (
        "set -eu\n"
        "openmettle-admin backup release-maintenance "
        f'--operator-id "{operator_id}" --request-key "drill-release-maint-{restore_run_id}" '
        '--reason "isolated restore pre-worker reconciliation complete" --abort-active-run\n'
        'status_json="$(openmettle-admin backup status)"\n'
        'printf "BACKUP_STATUS_BEGIN\\n%s\\nBACKUP_STATUS_END\\n" "$status_json"\n'
        'printf "%s\\n" "$status_json" | grep -Eq \'"maintenance_active"[[:space:]]*:[[:space:]]*false\'\n'
        f'quota_out="$({qv_cmd})"\n'
        'printf "QUOTA_VERIFY_BEGIN\\n%s\\nQUOTA_VERIFY_END\\n" "$quota_out"\n'
        f'printf "%s\\n" "$quota_out" | grep -Fxq \'{zero_line}\'\n'
        f'rm -rf "{unpacked_dir}" "{retained_journal}"\n'
    )


def seed_users_sql(
    sess_a: tuple[str, str, str],
    sess_b: tuple[str, str, str],
    sess_c: tuple[str, str, str],
    sess_d: tuple[str, str, str],
) -> str:
    """Seed `user_a`, `user_b`, `user_c` (post-backup disabled), and `user_d` (active non-member)
    with approvals, browser sessions, storage limits and personal/project `usage_tokens` defaults."""
    users = (
        ("a", "01", USER_A_IDS, sess_a),
        ("b", "02", USER_B_IDS, sess_b),
        ("c", "03", USER_C_IDS, sess_c),
        ("d", "04", USER_D_IDS, sess_d),
    )
    for _, _, _, (sid, lid, sh) in users:
        if not (smoke.B64_ID.fullmatch(sid) and smoke.B64_ID.fullmatch(lid) and re.fullmatch(r"[0-9a-f]{64}", sh)):
            raise DrillFailure("malformed synthetic session seed values")
    p_id = USER_A_IDS["provider"]
    exp = smoke.SESSION_EXPIRES_MS
    by = "'restore-drill', 'synthetic restore drill fixture'"
    sql = f"""\
INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason)
    VALUES ('{p_id}', '{smoke.SESSION_ISSUER}', '{smoke.SESSION_CLIENT}', {by});
INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
    VALUES ('{p_id}', 'r1');
"""
    for tag, hex_bind, ids, (sid, lid, sh) in users:
        sql += f"""\
INSERT INTO openmettle.users (id) VALUES ('{ids["user"]}');
INSERT INTO openmettle.scopes (kind, personal_user_id) VALUES ('personal', '{ids["user"]}');
INSERT INTO openmettle.user_identities (id, user_id, issuer, subject)
    VALUES ('{ids["identity"]}', '{ids["user"]}', '{smoke.SESSION_ISSUER}', 'drill-user-{tag}');
INSERT INTO openmettle.local_identity_approvals (id, provider_id, identity_id, active, expires_ms, changed_by, change_reason)
    VALUES ('{ids["approval"]}', '{p_id}', '{ids["identity"]}', true, {exp}, {by});
INSERT INTO openmettle.login_nonce_reservations (key_id, nonce)
    VALUES ('drill-{tag}', substring(sha256(convert_to('{lid}', 'UTF8')) FROM 1 FOR 12));
INSERT INTO openmettle.login_transactions (id, binding, expires_ms, state_hash, nonce_hash, caller_hash,
        key_id, nonce, ciphertext, consumed, session_issued)
    SELECT '{lid}', decode('{hex_bind}', 'hex'), {exp}, sha256(convert_to('{lid}:s', 'UTF8')),
           sha256(convert_to('{lid}:n', 'UTF8')), sha256(convert_to('{lid}:c', 'UTF8')),
           key_id, nonce, NULL, true, true
      FROM openmettle.login_nonce_reservations WHERE key_id = 'drill-{tag}';
INSERT INTO openmettle.local_sessions (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id,
        issued_client, issued_epoch, issued_revision, provider_generation, approval_generation,
        user_generation, created_ms, expires_ms)
    SELECT '{sid}', decode('{sh}', 'hex'), '{lid}', '{p_id}', '{ids["identity"]}',
           '{ids["approval"]}', '{ids["user"]}', '{smoke.SESSION_CLIENT}', max(epoch), 1, 0, 0, 0, 1, {exp}
      FROM openmettle.login_provider_revisions WHERE provider_id = '{p_id}';
"""
    sql += f"""\
UPDATE openmettle.storage_instance
    SET instance_budget_bytes = {STORAGE_BUDGET_BYTES},
        personal_limit_bytes = {SCOPE_STORAGE_LIMIT_BYTES},
        project_limit_bytes = {SCOPE_STORAGE_LIMIT_BYTES};
INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
    VALUES ('personal', 'usage_tokens', {smoke.PERSONAL_TOKEN_LIMIT}),
           ('project', 'usage_tokens', {smoke.PERSONAL_TOKEN_LIMIT});
"""
    return sql


def fresh_post_restore_session_sql(
    user_ids: dict,
    session_id: str,
    login_id: str,
    secret_hash: str,
    nonce_tag: str,
) -> str:
    """Mint a fresh post-restore session row reading current provider/approval `access_generation`,
    user `session_generation`, and `max(epoch)`."""
    if not (
        smoke.B64_ID.fullmatch(session_id)
        and smoke.B64_ID.fullmatch(login_id)
        and re.fullmatch(r"[0-9a-f]{64}", secret_hash)
        and re.fullmatch(r"[a-z0-9-]{1,32}", nonce_tag)
    ):
        raise DrillFailure("malformed post-restore session values")
    p_id = USER_A_IDS["provider"]
    exp = smoke.SESSION_EXPIRES_MS
    return f"""\
INSERT INTO openmettle.login_nonce_reservations (key_id, nonce)
    VALUES ('{nonce_tag}', substring(sha256(convert_to('{login_id}', 'UTF8')) FROM 1 FOR 12));
INSERT INTO openmettle.login_transactions (id, binding, expires_ms, state_hash, nonce_hash, caller_hash,
        key_id, nonce, ciphertext, consumed, session_issued)
    SELECT '{login_id}', decode('01', 'hex'), {exp}, sha256(convert_to('{login_id}:s', 'UTF8')),
           sha256(convert_to('{login_id}:n', 'UTF8')), sha256(convert_to('{login_id}:c', 'UTF8')),
           key_id, nonce, NULL, true, true
      FROM openmettle.login_nonce_reservations WHERE key_id = '{nonce_tag}';
INSERT INTO openmettle.local_sessions (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id,
        issued_client, issued_epoch, issued_revision, provider_generation, approval_generation,
        user_generation, created_ms, expires_ms)
    SELECT '{session_id}', decode('{secret_hash}', 'hex'), '{login_id}', '{p_id}', '{user_ids["identity"]}',
           '{user_ids["approval"]}', '{user_ids["user"]}', '{smoke.SESSION_CLIENT}',
           (SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id = '{p_id}'),
           1,
           (SELECT access_generation FROM openmettle.login_providers WHERE id = '{p_id}'),
           (SELECT access_generation FROM openmettle.local_identity_approvals WHERE id = '{user_ids["approval"]}'),
           (SELECT session_generation FROM openmettle.users WHERE id = '{user_ids["user"]}'),
           1, {exp};
"""


def ns_peer(namespace: str, labels: dict) -> dict:
    return {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
        "podSelector": {"matchLabels": dict(labels)},
    }


def db_url(db_namespace: str, role: str, password: str, *, dbname: str = "openmettle") -> str:
    host = f"postgres.{db_namespace}.svc.cluster.local"
    return f"postgres://{smoke.DB_ROLE[role]}:{password}@{host}:5432/{dbname}?sslmode=disable"


def target_mcp_url() -> str:
    """Synthetic in-cluster MCP write destination served by `sglang-standin` in `TARGET_DB_NS`."""
    return f"http://{smoke.STANDIN}.{TARGET_DB_NS}.svc.cluster.local:{smoke.STANDIN_PORT}/tools/send"


def mcp_post_probe_command(host: str, port: int, path: str, body_json: str) -> list[str]:
    """POST a JSON payload over `/dev/tcp` inside `bash` and print the HTTP response status line."""
    script = (
        'exec 3<>"/dev/tcp/$0/$1" && body=$3 && '
        'printf "POST %s HTTP/1.1\\r\\nHost: %s:%s\\r\\nContent-Type: application/json\\r\\n'
        'Content-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s" '
        '"$2" "$0" "$1" "${#body}" "$body" >&3 && head -n 1 <&3'
    )
    return ["timeout", str(smoke.PROBE_SECONDS), "bash", "-c", script, host, str(port), path, body_json]


def drill_inference_document(app_namespace: str, catalog: dict) -> dict:
    """Reuse `smoke.smoke_inference_document` (ADR 0043 `installation` + `routes` schema) for `app_namespace`."""
    doc = smoke.smoke_inference_document(catalog, tls=False)
    endpoint = f"http://{smoke.GATEWAY_WORKLOAD}.{app_namespace}.svc.cluster.local:8082/v1/chat/completions"
    for route in doc["routes"].values():
        route["endpoint"] = endpoint
    return doc


def drill_chart_values(
    digests: dict,
    postgres_client_image: dict,
    *,
    db_namespace: str,
    artifacts_existing_claim: str | None,
    enable_backup: bool,
) -> dict:
    """Helm values for primary (`artifacts_existing_claim=None`, `enable_backup=True`) and isolated
    restore target (`artifacts_existing_claim=TARGET_ARTIFACTS_CLAIM`, `enable_backup=False`)."""
    gateway_peer = {"podSelector": {"matchLabels": {
        "app.kubernetes.io/name": "openmettle-core",
        "app.kubernetes.io/instance": RELEASE,
        "app.kubernetes.io/component": smoke.GATEWAY_COMPONENT,
    }}}
    values: dict = {
        "images": {
            "pullPolicy": "Never",
            **{
                role: {"registry": smoke.REGISTRY, "repository": f"openmettle/{role}", "digest": digests[role]}
                for role in (*DEFAULT_ROLES, "gateway")
            },
        },
        "database": {
            **{role: {"existingSecret": smoke.SECRET[role]} for role in (*DEFAULT_ROLES, "issuance", "gateway")},
        },
        "api": {"replicas": 1},
        "worker": {
            "replicas": 1,
            "sweepMs": 1000,
            "pollMs": 100,
            "inference": {
                "enabled": True,
                "configMapName": smoke.INFERENCE_PLAIN_CONFIG_MAP,
                "configKey": "inference.json",
                "catalogKey": smoke.AUTH_CATALOG_KEY,
                "settings": {
                    "runSlots": 2,
                    "leaseMs": 30000,
                    "executionTimeoutMs": 60000,
                    "executingPerActor": 2,
                    "executingPerScope": 4,
                },
            },
            "mcp": {"enabled": True},
        },
        "migration": {
            "activeDeadlineSeconds": smoke.MIGRATION_DEADLINE_SECONDS,
            "settings": {"connectTimeoutMs": 5000, "lockTimeoutMs": 15000, "statementTimeoutMs": 60000},
        },
        "networkPolicy": {
            "api": {
                "ingressFrom": [ns_peer(db_namespace, smoke.POSTGRES_LABELS)],
                "oidc": {"to": [{"ipBlock": {"cidr": smoke.AUTH_OIDC_CIDR}}], "port": 443},
            },
            "worker": {
                "inference": {"to": [gateway_peer], "port": 8082},
                "mcp": {"to": [ns_peer(db_namespace, smoke.STANDIN_LABELS)], "ports": [smoke.STANDIN_PORT]},
            },
            "database": {"to": [ns_peer(db_namespace, smoke.POSTGRES_LABELS)]},
        },
        "storage": {
            "artifacts": (
                {"enabled": True, "existingClaim": artifacts_existing_claim, "size": ""}
                if artifacts_existing_claim
                else {"enabled": True, "size": "64Mi", "accessModes": ["ReadWriteOnce"]}
            ),
        },
        "auth": {
            "enabled": True,
            "configMapName": smoke.AUTH_CONFIG_MAP,
            "configKey": "auth.json",
            "catalogKey": smoke.AUTH_CATALOG_KEY,
            "loginKeysSecretName": smoke.AUTH_LOGIN_KEYS_SECRET,
        },
        "gateways": {
            smoke.GATEWAY_NAME: {
                "model": smoke.CATALOG_MODEL,
                "upstreamUrl": f"http://{smoke.STANDIN}.{db_namespace}.svc.cluster.local:{smoke.STANDIN_PORT}",
                "networkPolicy": {
                    "upstream": {"to": [ns_peer(db_namespace, smoke.STANDIN_LABELS)], "port": smoke.STANDIN_PORT},
                },
            },
        },
        "vault": {
            "enabled": True,
            "existingSecret": smoke.VAULT_KEYS_SECRET,
            "configKey": "keyring.json",
        },
    }
    if enable_backup:
        values["images"]["admin"] = {
            "registry": smoke.REGISTRY, "repository": "openmettle/admin", "digest": digests["admin"],
        }
        values["images"]["postgresClient"] = dict(postgres_client_image)
        values["database"]["backup"] = {"existingSecret": smoke.SECRET["migrate"]}
        values["backup"] = {
            "enabled": True,
            "suspend": True,
            "schedule": "0 3 * * *",
            "existingKeysSecret": smoke.BACKUP_KEYS_SECRET,
            "keysConfigKey": "keyring.json",
            "destination": {
                "existingClaim": smoke.BACKUP_DEST_CLAIM,
                "domain": "primary-drill.example.test",
                "requireSeparateDevice": False,
            },
            "operatorId": DRILL_OPERATOR_ID,
            "reason": "v1-31 restore drill primary backup capture",
        }
    return values


def target_db_acl_sql(dbname: str = "openmettle") -> str:
    """PUBLIC revocations and runtime CONNECT grants omitted by `pg_dump --schema=openmettle`."""
    return (
        f"REVOKE ALL ON DATABASE {dbname} FROM PUBLIC;\n"
        f"GRANT CONNECT ON DATABASE {dbname} TO "
        "openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway;\n"
        f"\\connect {dbname}\n"
        "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n"
    )


def isolation_and_config_manifests(
    *,
    app_ns: str,
    db_ns: str,
    passwords: dict,
    catalog: dict,
    vault_keys: list[tuple[str, str, str]],
    backup_key_b64: str | None,
    wrong_backup_key_b64: str | None,
    is_target: bool,
    run_id: str,
) -> dict:
    """Phase 1 manifests (`Namespace`, `NetworkPolicy`, `Secret`, `ConfigMap`, `PVC`) applied
    strictly BEFORE any database or stand-in `Deployment` is submitted."""
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    restricted_ns_labels = {
        **labels,
        "pod-security.kubernetes.io/enforce": "restricted",
        "pod-security.kubernetes.io/enforce-version": "latest",
    }
    sql = "".join(
        f"CREATE ROLE {smoke.DB_ROLE[role]} LOGIN PASSWORD '{passwords[role]}';\n"
        for role in smoke.DB_LOGINS
    )
    sql += "CREATE DATABASE openmettle OWNER openmettle_owner;\n"
    if is_target:
        sql += target_db_acl_sql("openmettle")

    vault_keyring = json.dumps({
        "version": 1,
        "active_key_id": vault_keys[-1][0],
        "keys": [{"id": kid, "file": f"{smoke.VAULT_KEYS_DIR}/{fname}"} for kid, fname, _ in vault_keys],
    }).encode("utf-8")
    vault_secret_data = {
        "keyring.json": base64.b64encode(vault_keyring).decode("ascii"),
        **{fname: kb64 for _, fname, kb64 in vault_keys},
    }

    dns_egress = {
        "to": [ns_peer("kube-system", {"k8s-app": "kube-dns"})],
        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
    }
    pg_ingress_peers = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": app_ns}}}]
    if not is_target:
        pg_ingress_peers.append({"podSelector": {"matchLabels": DB_PROBE_LABELS}})
    gateway_labels = {
        "app.kubernetes.io/name": "openmettle-core",
        "app.kubernetes.io/instance": RELEASE,
        "app.kubernetes.io/component": smoke.GATEWAY_COMPONENT,
    }
    worker_labels = {
        "app.kubernetes.io/name": "openmettle-core",
        "app.kubernetes.io/instance": RELEASE,
        "app.kubernetes.io/component": "worker",
    }

    items: list[dict] = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": app_ns, "labels": restricted_ns_labels}},
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": db_ns, "labels": restricted_ns_labels}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": smoke.NAMESPACE_DENY, "namespace": app_ns, "labels": labels},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": RECOVERY_NETPOL, "namespace": app_ns, "labels": labels},
         "spec": {
             "podSelector": {"matchLabels": {RECOVERY_DB_CLIENT_LABEL: "true"}},
             "policyTypes": ["Ingress", "Egress"],
             "egress": [
                 dns_egress,
                 {"to": [ns_peer(db_ns, smoke.POSTGRES_LABELS)],
                  "ports": [{"protocol": "TCP", "port": 5432}]},
             ],
         }},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": smoke.NAMESPACE_DENY, "namespace": db_ns, "labels": labels},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": "postgres-network", "namespace": db_ns, "labels": labels},
         "spec": {
             "podSelector": {"matchLabels": smoke.POSTGRES_LABELS},
             "policyTypes": ["Ingress", "Egress"],
             "ingress": [{"from": pg_ingress_peers, "ports": [{"protocol": "TCP", "port": 5432}]}],
             "egress": [dns_egress],
         }},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": "standin-network", "namespace": db_ns, "labels": labels},
         "spec": {
             "podSelector": {"matchLabels": smoke.STANDIN_LABELS},
             "policyTypes": ["Ingress", "Egress"],
             "ingress": [{"from": [ns_peer(app_ns, gateway_labels), ns_peer(app_ns, worker_labels)],
                          "ports": [{"protocol": "TCP", "port": smoke.STANDIN_PORT}]}],
         }},
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": "postgres-fixture", "namespace": db_ns, "labels": labels},
         "stringData": {"admin-password": passwords["admin"], "provision.sql": sql}},
    ]
    if not is_target:
        items.append({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "db-probe-egress", "namespace": db_ns, "labels": labels},
            "spec": {
                "podSelector": {"matchLabels": DB_PROBE_LABELS},
                "policyTypes": ["Ingress", "Egress"],
                "egress": [
                    dns_egress,
                    {"to": [{"podSelector": {"matchLabels": smoke.POSTGRES_LABELS}}],
                     "ports": [{"protocol": "TCP", "port": 5432}]},
                ],
            },
        })
    items += [
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": smoke.SECRET[role], "namespace": app_ns, "labels": labels},
         "stringData": {"url": db_url(db_ns, role, passwords[role])}}
        for role in smoke.DB_LOGINS
    ]
    items += [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": smoke.AUTH_CONFIG_MAP, "namespace": app_ns, "labels": labels},
         "data": {"auth.json": json.dumps(smoke.smoke_auth_document()),
                  smoke.AUTH_CATALOG_KEY: json.dumps(catalog)}},
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": smoke.AUTH_LOGIN_KEYS_SECRET, "namespace": app_ns, "labels": labels},
         "data": {"active.key": passwords["auth_login_key"], "cursor.key": passwords["auth_cursor_key"]}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": smoke.INFERENCE_PLAIN_CONFIG_MAP, "namespace": app_ns, "labels": labels},
         "data": {"inference.json": json.dumps(drill_inference_document(app_ns, catalog)),
                  smoke.AUTH_CATALOG_KEY: json.dumps(catalog)}},
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": smoke.VAULT_KEYS_SECRET, "namespace": app_ns, "labels": labels},
         "data": vault_secret_data},
    ]
    if backup_key_b64 is not None:
        backup_keyring = json.dumps({
            "version": 1,
            "active_key_id": BACKUP_KEY_ID,
            "keys": [{"id": BACKUP_KEY_ID, "file": f"{smoke.BACKUP_KEYS_DIR}/{BACKUP_KEY_FILE}"}],
        }).encode("utf-8")
        items.append({
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": smoke.BACKUP_KEYS_SECRET, "namespace": app_ns, "labels": labels},
            "data": {"keyring.json": base64.b64encode(backup_keyring).decode("ascii"),
                     BACKUP_KEY_FILE: backup_key_b64},
        })
    if wrong_backup_key_b64 is not None:
        wrong_keyring = json.dumps({
            "version": 1,
            "active_key_id": BACKUP_KEY_ID,
            "keys": [{"id": BACKUP_KEY_ID, "file": f"{WRONG_BACKUP_KEYS_DIR}/{BACKUP_KEY_FILE}"}],
        }).encode("utf-8")
        items.append({
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": WRONG_BACKUP_SECRET, "namespace": app_ns, "labels": labels},
            "data": {"keyring.json": base64.b64encode(wrong_keyring).decode("ascii"),
                     BACKUP_KEY_FILE: wrong_backup_key_b64},
        })
    if not is_target:
        items.append({
            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": smoke.BACKUP_DEST_CLAIM, "namespace": app_ns, "labels": labels},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}},
        })
    else:
        for claim_name in (TARGET_ARTIFACTS_CLAIM, TARGET_RECOVERY_MEDIA_CLAIM, TARGET_RECOVERY_SCRATCH_CLAIM):
            items.append({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": claim_name, "namespace": app_ns, "labels": labels},
                "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}},
            })
    return {"apiVersion": "v1", "kind": "List", "items": items}


def fixture_workload_manifests(
    *, db_ns: str, postgres_image: str, standin_image: str, is_target: bool, run_id: str
) -> dict:
    """Phase 2 fixture `Deployment` and `Service` manifests applied AFTER `default-deny` policies."""
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    items: list[dict] = [
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": "postgres", "namespace": db_ns, "labels": labels},
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                  "selector": {"matchLabels": smoke.POSTGRES_LABELS},
                  "template": {"metadata": {"labels": smoke.POSTGRES_LABELS}, "spec": {
                      "automountServiceAccountToken": False, "enableServiceLinks": False,
                      "securityContext": PG_POD_SEC_CONTEXT,
                      "containers": [{
                          "name": "postgres", "image": postgres_image, "imagePullPolicy": "IfNotPresent",
                          "env": [{"name": "POSTGRES_USER", "value": "fixture_admin"},
                                  {"name": "POSTGRES_DB", "value": "fixture"},
                                  {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"},
                                  {"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {
                                      "name": "postgres-fixture", "key": "admin-password"}}}],
                          "ports": [{"name": "postgres", "containerPort": 5432}],
                          "readinessProbe": {"exec": {"command": [
                              "pg_isready", "-h", "127.0.0.1", "-U", "fixture_admin", "-d", "fixture"]},
                              "periodSeconds": 2, "failureThreshold": 2},
                          "securityContext": CONTAINER_SEC_CONTEXT,
                          "volumeMounts": [
                              {"name": "data", "mountPath": "/var/lib/postgresql"},
                              {"name": "run", "mountPath": "/run/postgresql"},
                              {"name": "tmp", "mountPath": "/tmp"},
                              {"name": "init", "mountPath": "/docker-entrypoint-initdb.d", "readOnly": True}],
                      }],
                      "volumes": [
                          {"name": "data", "emptyDir": {}},
                          {"name": "run", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                          {"name": "tmp", "emptyDir": {}},
                          {"name": "init", "secret": {"secretName": "postgres-fixture",
                                                      "items": [{"key": "provision.sql", "path": "provision.sql"}]}}],
                  }}}},
        {"apiVersion": "v1", "kind": "Service",
         "metadata": {"name": "postgres", "namespace": db_ns, "labels": labels},
         "spec": {"selector": smoke.POSTGRES_LABELS,
                  "ports": [{"name": "postgres", "port": 5432, "targetPort": "postgres"}]}},
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": smoke.STANDIN, "namespace": db_ns, "labels": labels},
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                  "selector": {"matchLabels": smoke.STANDIN_LABELS},
                  "template": {"metadata": {"labels": smoke.STANDIN_LABELS}, "spec": {
                      "automountServiceAccountToken": False, "enableServiceLinks": False,
                      "securityContext": POD_SEC_CONTEXT,
                      "containers": [{
                          "name": smoke.STANDIN, "image": standin_image, "imagePullPolicy": "Never",
                          "ports": [{"name": "http", "containerPort": smoke.STANDIN_PORT}],
                          "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"},
                                             "periodSeconds": 2, "failureThreshold": 3},
                          "securityContext": CONTAINER_SEC_CONTEXT,
                      }],
                  }}}},
        {"apiVersion": "v1", "kind": "Service",
         "metadata": {"name": smoke.STANDIN, "namespace": db_ns, "labels": labels},
         "spec": {"type": "ClusterIP", "selector": smoke.STANDIN_LABELS,
                  "ports": [{"name": "http", "port": smoke.STANDIN_PORT, "targetPort": "http"}]}},
    ]
    if not is_target:
        items.append({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": DB_PROBE, "namespace": db_ns, "labels": labels},
            "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                     "selector": {"matchLabels": DB_PROBE_LABELS},
                     "template": {"metadata": {"labels": DB_PROBE_LABELS}, "spec": {
                         "automountServiceAccountToken": False, "enableServiceLinks": False,
                         "securityContext": PG_POD_SEC_CONTEXT,
                         "containers": [{
                             "name": "probe", "image": postgres_image, "imagePullPolicy": "IfNotPresent",
                             "command": ["sleep", "3600"],
                             "securityContext": CONTAINER_SEC_CONTEXT,
                             "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                         }],
                         "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "4Mi"}}],
                     }}},
        })
    return {"apiVersion": "v1", "kind": "List", "items": items}


def stage_keyring_snippet(src_dir: str, stage_parent: str) -> str:
    return (
        "umask 077\n"
        f'stage="{stage_parent}/keys"\n'
        'mkdir -p -- "$stage" && chmod 0700 "$stage"\n'
        f'for src in "{src_dir}"/*; do\n'
        '  [ -f "$src" ] || continue\n'
        '  cp -L -- "$src" "$stage/${src##*/}" && chmod 0400 "$stage/${src##*/}"\n'
        "done\n"
    )


def staged_keyring_mounts(
    admin_ref: str, specs: list[tuple[str, str, str]]
) -> tuple[dict, list[dict], list[dict]]:
    """Build `(init_container, main_mounts, volumes)` staging each `(prefix, secret_name, mount_dir)`
    into a `Memory` `emptyDir` (`0400` files owned by UID `65532`) mounted read-only at `mount_dir`
    via `subPath: keys`, matching the absolute key paths inside `keyring.json`."""
    script = "".join(stage_keyring_snippet(f"/run/{pfx}-src", f"/run/{pfx}-stage") for pfx, _, _ in specs)
    init_mounts: list[dict] = []
    main_mounts: list[dict] = []
    volumes: list[dict] = []
    for pfx, secret_name, mount_dir in specs:
        init_mounts += [
            {"name": f"{pfx}-src", "mountPath": f"/run/{pfx}-src", "readOnly": True},
            {"name": f"{pfx}-stage", "mountPath": f"/run/{pfx}-stage"},
        ]
        main_mounts.append(
            {"name": f"{pfx}-stage", "mountPath": mount_dir, "subPath": "keys", "readOnly": True}
        )
        volumes += [
            {"name": f"{pfx}-src", "secret": {"secretName": secret_name, "defaultMode": 288}},
            {"name": f"{pfx}-stage", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
        ]
    init_container = {
        "name": "stage-keys",
        "image": admin_ref,
        "imagePullPolicy": "Never",
        "command": ["/bin/sh", "-eu", "-c", script],
        "securityContext": CONTAINER_SEC_CONTEXT,
        "volumeMounts": init_mounts,
    }
    return init_container, main_mounts, volumes


def target_isolation_probe_plan() -> list[dict]:
    """NetworkPolicy isolation probes proving both `openmettle-restore-target` and
    `openmettle-restore-target-db` are denied access to primary PostgreSQL and gateway."""
    primary_db = f"postgres.{PRIMARY_DB_NS}.svc.cluster.local"
    target_db = f"postgres.{TARGET_DB_NS}.svc.cluster.local"
    primary_gw = f"{smoke.GATEWAY_WORKLOAD}.{PRIMARY_APP_NS}.svc.cluster.local"
    gw_readyz = smoke.http_command(primary_gw, 8082, "/readyz")

    def probe(name, namespace, workload, container, command, expect, control=None, is_http=False):
        return {
            "name": name,
            "namespace": namespace,
            "workload": workload,
            "container": container,
            "command": command,
            "expect": expect,
            "control": control,
            "http": is_http,
        }

    primary_db_ctrl = "control: primary db-probe reaches primary PostgreSQL on 5432"
    primary_gw_ctrl = "control: primary worker reaches primary gateway /readyz 200"
    return [
        probe(primary_db_ctrl, PRIMARY_DB_NS, DB_PROBE, "probe", smoke.tcp_command(primary_db, 5432), "connect"),
        probe(primary_gw_ctrl, PRIMARY_APP_NS, f"{FULLNAME}-worker", "worker", gw_readyz, "connect", is_http=True),
        probe(
            "target api reaches isolated target PostgreSQL on 5432",
            TARGET_APP_NS, f"{FULLNAME}-api", "api", smoke.tcp_command(target_db, 5432), "connect",
        ),
        probe(
            "target worker reaches isolated target PostgreSQL on 5432",
            TARGET_APP_NS, f"{FULLNAME}-worker", "worker", smoke.tcp_command(target_db, 5432), "connect",
        ),
        probe(
            "target db pod denied egress to primary PostgreSQL on 5432",
            TARGET_DB_NS, "postgres", "postgres", smoke.tcp_command(primary_db, 5432), "deny", primary_db_ctrl,
        ),
        probe(
            "target api denied egress to primary PostgreSQL on 5432",
            TARGET_APP_NS, f"{FULLNAME}-api", "api", smoke.tcp_command(primary_db, 5432), "deny", primary_db_ctrl,
        ),
        probe(
            "target worker denied egress to primary PostgreSQL on 5432",
            TARGET_APP_NS, f"{FULLNAME}-worker", "worker", smoke.tcp_command(primary_db, 5432), "deny", primary_db_ctrl,
        ),
        probe(
            "target worker denied egress to primary gateway on 8082",
            TARGET_APP_NS, f"{FULLNAME}-worker", "worker", gw_readyz, "deny", primary_gw_ctrl, is_http=True,
        ),
        probe(
            "target db pod denied egress to primary gateway on 8082",
            TARGET_DB_NS, "postgres", "postgres", gw_readyz, "deny", primary_gw_ctrl, is_http=True,
        ),
    ]


def build_drill_summary(report: dict) -> dict:
    """Validate and sort the non-secret V1-31 JSON report before writing `--report`."""
    unknown = set(report) - DRILL_SUMMARY_KEYS
    if unknown:
        raise DrillFailure(f"unexpected drill summary keys: {sorted(unknown)}")
    if report.get("result") not in ("passed", "failed"):
        raise DrillFailure("drill summary result must be passed or failed")
    if report.get("classification") != "dev":
        raise DrillFailure("drill summary classification must be 'dev'")
    for role, image in report.get("images", {}).items():
        if role not in ROLES or set(image) != {"reference", "cri_image_id", "resolved_before_alias"}:
            raise DrillFailure(f"unexpected image summary for {role!r}")
        if image["reference"] != smoke.digest_reference(role, image["reference"].rpartition("@")[2]):
            raise DrillFailure(f"{role} reference is not digest-pinned")
    return {key: report[key] for key in sorted(report)}


# --- Live kind orchestrator -----------------------------------------------------------------


def _log(message: str) -> None:
    print(f"[restore-drill] {message}", file=sys.stderr, flush=True)


class RestoreDrill:
    def __init__(self, core, environ: dict, core_dir: Path, tools_dir: Path | None,
                 helm_dir: Path | None, workdir: Path):
        self.core = core
        self.core_dir = core_dir
        self.workdir = workdir
        self.context = core.check_opt_in(environ)
        self.run_id = secrets.token_hex(4)
        self.name = f"openmettle-dev-qual-{self.run_id}"
        self.node = f"{self.name}-control-plane"
        self.kubeconfig = workdir / "kubeconfig"
        self.env = smoke.smoke_environment(
            core.child_environment(environ, self.kubeconfig, self.context, tools_dir), workdir, helm_dir)
        self.runner = core.Runner(self.env)
        kube_ctx = f"kind-{self.name}"
        self.kubectl = ["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", kube_ctx]
        self.helm_base = ["helm", "--kubeconfig", str(self.kubeconfig), "--kube-context", kube_ctx]
        self.tags = {role: smoke.tag_reference(role, self.run_id) for role in ROLES}
        self.standin_image = f"{smoke.REGISTRY}/openmettle/{smoke.STANDIN}:drill-{self.run_id}"
        self.digests: dict[str, str] = {}
        self.secrets_to_redact: list[str] = []
        self.built_images: list[str] = []
        self.cluster_attempted = False
        self.report: dict = {
            "result": "failed",
            "classification": "dev",
            "core_commit": CORE_COMMIT,
            "cluster": self.name,
            "primary_namespace": PRIMARY_APP_NS,
            "target_namespace": TARGET_APP_NS,
            "tools": {
                "kind": core.KIND_VERSION,
                "kubectl": core.KUBECTL_VERSION,
                "helm": smoke.HELM_VERSION,
                "node_image": core.NODE_IMAGE,
                "postgres_image": core.POSTGRES_IMAGE,
            },
            "images": {},
            "rpo_rto": None,
            "limitations": list(DRILL_LIMITATIONS),
            "checks": [],
            "error": None,
            "cleanup_errors": [],
        }

    def run(self, argv: list, *, check=True, timeout=300, input=None):
        result = self.runner(argv, check=False, timeout=timeout, input=input)
        if check and result.returncode != 0:
            tail = smoke.redacted_tail(result.stderr.strip(), self.secrets_to_redact, smoke.STDERR_TAIL)
            raise DrillFailure(f"{' '.join(str(a) for a in argv[:3])} exited {result.returncode}"
                               + (f": {tail}" if tail else ""))
        return result

    def kube(self, *args, check=True, timeout=120, input=None):
        return self.run([*self.kubectl, *args], check=check, timeout=timeout, input=input)

    def kube_json(self, *args, timeout=120):
        return json.loads(self.kube(*args, "--output=json", timeout=timeout).stdout)

    def helm_ns(self, namespace: str, *args, timeout=360):
        return self.run([*self.helm_base, "--namespace", namespace, *args], timeout=timeout)

    def node_exec(self, *args, check=True):
        return self.run(["docker", "exec", self.node, *args], check=check)

    def expect(self, condition, message: str) -> None:
        if not condition:
            raise DrillFailure(message)

    def passed(self, name: str, **evidence) -> None:
        _log(f"PASS: {name}")
        self.report["checks"].append({"name": name, "status": "passed", **evidence})

    def wait_for(self, description: str, predicate, timeout=120, interval=1.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(interval)
        raise DrillFailure(f"timed out waiting for {description}")

    def wait_for_inference_ready(self, app_ns: str, db_ns: str) -> None:
        """Wait for api/worker/gateway Deployments AND kindnet's NetworkPolicy reconciliation loop
        for `worker -> gateway-a:8082/readyz` and `gateway-a -> sglang-standin:30000/healthz`."""
        for dep in (f"{FULLNAME}-api", f"{FULLNAME}-worker", smoke.GATEWAY_WORKLOAD):
            self.kube("--namespace", app_ns, "rollout", "status", f"deployment/{dep}",
                      "--timeout=180s", timeout=210)
        worker_to_gw = smoke.http_command(
            f"{smoke.GATEWAY_WORKLOAD}.{app_ns}.svc.cluster.local", 8082, "/readyz"
        )
        self.wait_for(
            f"{app_ns} worker -> gateway-a:8082 /readyz via NetworkPolicy",
            lambda: (
                lambda res: smoke.probe_outcome(res.returncode, res.stdout, res.stderr, True) == "connected"
            )(
                self.kube(
                    "--namespace", app_ns, "exec", f"deployment/{FULLNAME}-worker",
                    "--container", "worker", "--", *worker_to_gw,
                    check=False, timeout=smoke.PROBE_SECONDS + 30,
                )
            ),
            timeout=60, interval=1.0,
        )
        gw_to_standin = smoke.http_command(
            f"{smoke.STANDIN}.{db_ns}.svc.cluster.local", smoke.STANDIN_PORT, "/healthz"
        )
        self.wait_for(
            f"{app_ns} gateway-a -> {db_ns}/{smoke.STANDIN}:{smoke.STANDIN_PORT} /healthz via NetworkPolicy",
            lambda: (
                lambda res: smoke.probe_outcome(res.returncode, res.stdout, res.stderr, True) == "connected"
            )(
                self.kube(
                    "--namespace", app_ns, "exec", f"deployment/{smoke.GATEWAY_WORKLOAD}",
                    "--container", "gateway", "--", *gw_to_standin,
                    check=False, timeout=smoke.PROBE_SECONDS + 30,
                )
            ),
            timeout=60, interval=1.0,
        )

    def _run_diagnostics(self, db_ns: str, run_id: str) -> str:
        if not smoke.UUID.fullmatch(str(run_id)):
            return f"invalid run_id={run_id!r}"
        try:
            out = self.psql_superuser(
                db_ns,
                f"SELECT r.state || '|' || coalesce(r.wait_reason, '') || '|' || coalesce(r.cancel_reason, '')"
                f" || '|' || coalesce((SELECT string_agg(sequence::text || ':' || append_key || ':' || format"
                f" || ':' || convert_from(payload, 'UTF8'), '; ' ORDER BY sequence)"
                f" FROM openmettle.run_events WHERE run_id = r.id), '')"
                f" FROM openmettle.runs r WHERE r.id = '{run_id}'::uuid;",
            ).strip()
            return smoke.redact(out or "<no run row>", self.secrets_to_redact)
        except Exception as exc:
            return f"<diagnostic query failed: {smoke.redact(str(exc), self.secrets_to_redact)}>"

    def wait_for_run_succeeded(
        self, port: int, cookie: str, run_id: str, description: str, db_ns: str, *, timeout: int = 60
    ) -> dict:
        last_doc: dict | None = None
        last_state: str | None = None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            last_doc = self.api_json(port, cookie, "GET", f"/v1/runs/{run_id}", 200)
            last_state = last_doc.get("state")
            if last_state == "succeeded":
                return last_doc
            if last_state not in ("queued", "running", "waiting"):
                diag = self._run_diagnostics(db_ns, run_id)
                raise DrillFailure(
                    f"{description}: run {run_id} entered terminal state {last_state!r} "
                    f"(snapshot={last_doc!r}, db={diag!r})"
                )
            time.sleep(0.5)
        diag = self._run_diagnostics(db_ns, run_id)
        raise DrillFailure(
            f"timed out waiting for {description}: run {run_id} last_state={last_state!r} "
            f"(snapshot={last_doc!r}, db={diag!r})"
        )

    def preflight(self):
        self.core.check_tools(self.run)
        smoke.check_helm_version(self.run(["helm", "version", "--template", "{{ .Version }}"]).stdout)
        self.core.check_docker_context(self.run, self.context)
        self.core.check_cluster_absent(self.run, self.name)
        if self.kubeconfig.exists():
            raise smoke.Refusal("temporary kubeconfig already exists")

    def verify_identity(self):
        config = json.loads(self.run(["kubectl", "--kubeconfig", str(self.kubeconfig),
                                      "config", "view", "--output=json"]).stdout)
        nodes = [n["metadata"]["name"] for n in self.kube_json("get", "nodes")["items"]]
        label = self.run(["docker", "inspect", "--format",
                          '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', self.node]).stdout.strip()
        self.core.check_cluster_identity(config, nodes, label, self.name)
        for namespace in DRILL_NAMESPACES:
            found = self.kube("get", "namespace", namespace, "--output=json", check=False)
            if found.returncode == 0:
                labels = json.loads(found.stdout)["metadata"].get("labels", {})
                if labels.get(RUN_LABEL) != self.run_id:
                    raise smoke.Refusal(f"namespace {namespace} was not created by this drill run")

    def build_and_load_images(self):
        for role in ROLES:
            _log(f"building {self.tags[role]} from core {CORE_COMMIT[:7]}")
            self.run(["docker", "build", "--builder", "default", "--target", role,
                      "--tag", self.tags[role], str(self.core_dir)], timeout=1800)
            self.built_images.append(self.tags[role])
        standin_recipe = (self.core_dir / "Dockerfile").read_text(encoding="utf-8") + """
FROM build AS standin-build
COPY --from=fixture /standin.rs /source/src/bin/kind-standin.rs
RUN cargo build --release --locked --offline --bin kind-standin
FROM runtime AS standin-runtime
COPY --from=standin-build /source/target/release/kind-standin /usr/local/bin/kind-standin
EXPOSE 30000
ENTRYPOINT ["/usr/local/bin/kind-standin"]
"""
        self.run(["docker", "build", "--builder", "default", "--file", "-", "--target", "standin-runtime",
                  "--build-context", f"fixture={ROOT / 'tests/kind'}", "--tag", self.standin_image,
                  str(self.core_dir)], input=standin_recipe, timeout=600)
        self.built_images.append(self.standin_image)

        fixture_export = self.workdir / "drill-fixture-bin"
        fixture_recipe = (self.core_dir / "Dockerfile").read_text(encoding="utf-8") + """
FROM build AS drill-fixture-build
COPY --from=fixture /drill_fixture.rs /source/src/bin/kind-drill-fixture.rs
RUN cargo build --release --locked --offline --bin kind-drill-fixture
FROM scratch AS drill-fixture-export
COPY --from=drill-fixture-build /source/target/release/kind-drill-fixture /kind-drill-fixture
"""
        self.run(["docker", "build", "--builder", "default", "--file", "-", "--target", "drill-fixture-export",
                  "--build-context", f"fixture={ROOT / 'tests/kind'}",
                  "--output", f"type=local,dest={fixture_export}", str(self.core_dir)],
                 input=fixture_recipe, timeout=600)
        self.drill_fixture_bin = fixture_export / "kind-drill-fixture"

        _log(f"creating kind cluster {self.name} (dev)")
        self.cluster_attempted = True
        self.run(["kind", "create", "cluster", "--name", self.name, "--image", self.core.NODE_IMAGE,
                  "--kubeconfig", str(self.kubeconfig), "--wait", "180s"], timeout=900)
        self.verify_identity()
        for ref in (*self.tags.values(), self.standin_image):
            self.run(["kind", "load", "docker-image", ref, "--name", self.name], timeout=600)

    def cri_image_id(self, reference: str, check=True):
        result = self.node_exec("crictl", "inspecti", "--output", "json", reference, check=check)
        return smoke.parse_cri_image_id(result.stdout) if result.returncode == 0 else None

    def pin_digests(self):
        listing = self.node_exec("ctr", "--namespace=k8s.io", "images", "ls").stdout
        for role in ROLES:
            digest = smoke.parse_ctr_digest(listing, self.tags[role])
            reference = smoke.digest_reference(role, digest)
            before = self.cri_image_id(reference, check=False)
            if reference not in smoke.ctr_image_names(listing):
                self.node_exec("ctr", "--namespace=k8s.io", "images", "tag", self.tags[role], reference)
            resolved = self.wait_for(f"CRI to resolve {reference}",
                                     lambda r=reference: self.cri_image_id(r, check=False), timeout=30)
            self.expect(resolved == self.cri_image_id(self.tags[role]),
                        f"{role} digest reference resolves to a different image")
            self.digests[role] = digest
            self.report["images"][role] = {
                "reference": reference, "cri_image_id": resolved, "resolved_before_alias": before is not None,
            }
        self.passed("core images built and digest-pinned in containerd", roles=list(ROLES))

    def pin_postgres_client_image(self) -> tuple[dict, str]:
        parts = smoke.postgres_client_image_parts(self.core.POSTGRES_IMAGE)
        reference = f"{parts['registry']}/{parts['repository']}@{parts['digest']}"
        listing = self.node_exec("ctr", "--namespace=k8s.io", "images", "ls").stdout
        if reference not in smoke.ctr_image_names(listing):
            source = smoke.find_ctr_image_for_digest(listing, parts["digest"], preferred=self.core.POSTGRES_IMAGE)
            self.node_exec("ctr", "--namespace=k8s.io", "images", "tag", source, reference)
        self.wait_for(f"CRI to resolve {reference}",
                      lambda r=reference: self.cri_image_id(r, check=False), timeout=30)
        return parts, reference

    def new_credentials(self) -> dict[str, str]:
        creds = {
            **{k: secrets.token_hex(16) for k in ("admin", *smoke.DB_LOGINS)},
            "auth_cursor_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "auth_login_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        }
        self.secrets_to_redact.extend(creds.values())
        return creds

    def psql_superuser(self, db_ns: str, sql: str, *, dbname: str = "openmettle", single_tx: bool = True) -> str:
        tx_flags = ["--single-transaction"] if single_tx else []
        return self.kube("--namespace", db_ns, "exec", "--stdin", "deployment/postgres", "--",
                         "psql", "-v", "ON_ERROR_STOP=1", *tx_flags, "-qtA",
                         "-U", "fixture_admin", "-d", dbname, input=sql).stdout

    def standin_records(self, db_ns: str) -> list[dict]:
        fwd = smoke.PortForward(self.kubectl, self.env, f"service/{smoke.STANDIN}", smoke.STANDIN_PORT, namespace=db_ns)
        try:
            status, body = self.core.http_get(fwd.port, "/_recorded")
            self.expect(status == 200, f"{db_ns} stand-in /_recorded HTTP {status}")
            return json.loads(body)
        finally:
            fwd.close()

    def standin_mcp_records(self, db_ns: str) -> list[dict]:
        fwd = smoke.PortForward(self.kubectl, self.env, f"service/{smoke.STANDIN}", smoke.STANDIN_PORT, namespace=db_ns)
        try:
            status, body = self.core.http_get(fwd.port, "/_recorded_mcp")
            self.expect(status == 200, f"{db_ns} stand-in /_recorded_mcp HTTP {status}")
            return json.loads(body)
        finally:
            fwd.close()

    def api_call(self, port: int, cookie: str, method: str, path: str, expected_status: int, *,
                 key: str | None = None, json_body: dict | None = None,
                 raw_body: bytes = b"", boundary: str | None = None) -> tuple[dict, bytes]:
        headers = smoke.v1_headers(cookie, key=key, boundary=boundary)
        payload = raw_body
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(json_body).encode("utf-8")
        resp = smoke.http_exchange(port, method, path, headers, payload)
        return smoke.expect_v1(f"{method} {path.partition('?')[0]}", resp, expected_status)

    def api_json(self, port: int, cookie: str, method: str, path: str, expected_status: int, *,
                 key: str | None = None, json_body: dict | None = None) -> dict:
        _, body = self.api_call(port, cookie, method, path, expected_status, key=key, json_body=json_body)
        return json.loads(body)

    def upload_artifact(self, port: int, cookie: str, key: str, payload: bytes,
                        *, scope_id: str | None = None) -> dict:
        query = f"?max_bytes={smoke.ARTIFACT_MAX_BYTES}"
        if scope_id is not None:
            query += f"&scope_id={scope_id}"
        boundary = f"drill-boundary-{secrets.token_hex(4)}"
        _, body = self.api_call(
            port, cookie, "POST", f"/v1/artifacts{query}", 201,
            key=key, raw_body=smoke.multipart_form(boundary, payload), boundary=boundary,
        )
        return json.loads(body)

    def run_job(self, namespace: str, manifest: dict, *, expect_success: bool = True, timeout: int = 180) -> tuple[str, str]:
        name = manifest["metadata"]["name"]
        container_name = manifest["spec"]["template"]["spec"]["containers"][0]["name"]
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(manifest))
        try:
            deadline = time.monotonic() + timeout
            terminal: str | None = None
            reason = ""
            while time.monotonic() < deadline:
                job_doc = self.kube_json("--namespace", namespace, "get", "job", name)
                for cond in job_doc.get("status", {}).get("conditions") or ():
                    if cond.get("status") == "True" and cond.get("type") in ("Complete", "Failed"):
                        terminal = cond["type"]
                        reason = cond.get("reason") or ""
                        break
                if terminal is not None:
                    break
                time.sleep(1.0)
            pods = self.kube_json("--namespace", namespace, "get", "pods", "--selector", f"job-name={name}").get("items", [])
            stdout, stderr, pod_diag = "", "", ""
            if pods:
                pod = pods[0]
                pod_name = pod["metadata"]["name"]
                logs = self.kube("--namespace", namespace, "logs", pod_name, "--container", container_name,
                                 check=False, timeout=60)
                stdout, stderr = logs.stdout, logs.stderr
                pod_diag = json.dumps(pod.get("status", {}).get("containerStatuses") or pod.get("status", {}).get("phase"))
            expected_cond = "Complete" if expect_success else "Failed"
            if terminal != expected_cond:
                combined = "\n".join(p for p in (stdout.strip(), stderr.strip(), pod_diag) if p)
                redacted = smoke.redacted_tail(combined, self.secrets_to_redact, smoke.STDERR_TAIL)
                state_desc = f"{terminal} ({reason})" if terminal else f"timed out after {timeout}s"
                raise DrillFailure(f"Job {namespace}/{name} {state_desc}" + (f": {redacted}" if redacted else ""))
            self.expect(len(pods) == 1, f"expected one pod for Job {name}, found {len(pods)}")
            return stdout, stderr
        finally:
            self.verify_identity()
            self.kube("--namespace", namespace, "delete", "job", name, "--wait=true", timeout=120)

    def setup_primary_and_capture(self) -> dict:
        self.catalog = smoke.smoke_catalog(
            json.loads((self.core_dir / smoke.CORE_CATALOG_FIXTURE).read_text(encoding="utf-8"))
        )
        self.primary_passwords = self.new_credentials()
        self.vault_k1_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        self.vault_k2_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        self.backup_k1_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        self.wrong_backup_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        self.secrets_to_redact.extend([
            self.vault_k1_b64, self.vault_k2_b64, self.backup_k1_b64, self.wrong_backup_b64,
        ])

        # Apply Namespaces + NetworkPolicies + Secrets/ConfigMaps/PVCs FIRST, before any Deployment.
        primary_foundation = isolation_and_config_manifests(
            app_ns=PRIMARY_APP_NS, db_ns=PRIMARY_DB_NS,
            passwords=self.primary_passwords, catalog=self.catalog,
            vault_keys=[(VAULT_KEY_ID_1, VAULT_KEY_FILE_1, self.vault_k1_b64)],
            backup_key_b64=self.backup_k1_b64, wrong_backup_key_b64=None,
            is_target=False, run_id=self.run_id,
        )
        primary_workloads = fixture_workload_manifests(
            db_ns=PRIMARY_DB_NS, postgres_image=self.core.POSTGRES_IMAGE,
            standin_image=self.standin_image, is_target=False, run_id=self.run_id,
        )
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(primary_foundation))
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(primary_workloads))
        for dep in ("postgres", smoke.STANDIN, DB_PROBE):
            self.kube("--namespace", PRIMARY_DB_NS, "rollout", "status", f"deployment/{dep}",
                      "--timeout=300s", timeout=330)
        self.pg_client_parts, self.pg_client_ref = self.pin_postgres_client_image()

        primary_vals = self.workdir / "primary-values.json"
        primary_vals.write_text(json.dumps(drill_chart_values(
            self.digests, self.pg_client_parts, db_namespace=PRIMARY_DB_NS,
            artifacts_existing_claim=None, enable_backup=True,
        )), encoding="utf-8")
        self.verify_identity()
        self.helm_ns(PRIMARY_APP_NS, "install", RELEASE, str(CHART), "--values", str(primary_vals),
                     "--wait=watcher", "--timeout", smoke.HELM_TIMEOUT)
        self.wait_for_inference_ready(PRIMARY_APP_NS, PRIMARY_DB_NS)

        # Seed user_a, user_b, user_c (post-backup disabled), and user_d (pre-backup rich schedule +
        # post-backup disabled model).
        sid_a, cookie_a, hash_a = smoke.session_credential(secrets.token_bytes(64))
        sid_b, cookie_b, hash_b = smoke.session_credential(secrets.token_bytes(64))
        sid_c, cookie_c, hash_c = smoke.session_credential(secrets.token_bytes(64))
        sid_d, cookie_d, hash_d = smoke.session_credential(secrets.token_bytes(64))
        self.cookie_a_pre = cookie_a
        self.cookie_b_pre = cookie_b
        self.cookie_c_pre = cookie_c
        self.cookie_d_pre = cookie_d
        self.secrets_to_redact.extend([
            cookie_a, cookie_b, cookie_c, cookie_d,
            "secret-access-keep-1", "secret-refresh-keep-1",
            "secret-access-revoke-1", "secret-refresh-revoke-1",
        ])
        self.psql_superuser(
            PRIMARY_DB_NS,
            seed_users_sql(
                (sid_a, smoke.b64url(secrets.token_bytes(32)), hash_a),
                (sid_b, smoke.b64url(secrets.token_bytes(32)), hash_b),
                (sid_c, smoke.b64url(secrets.token_bytes(32)), hash_c),
                (sid_d, smoke.b64url(secrets.token_bytes(32)), hash_d),
            ),
        )

        # Seed a pre-backup family policy schedule with zone, quiet, study, and group-schedule
        # override on user_d (using a 1-minute quiet window 12h away from current Europe/London time
        # so inference on model `a` stays permitted pre-backup), plus a study_allow rule on model `a`.
        # Post-backup reconciliation must preserve these schedule fields when re-applying model `a` disable.
        london_now = datetime.now(ZoneInfo("Europe/London"))
        q_start = ((london_now.hour * 60 + london_now.minute) + 720) % 1440
        q_end = (q_start + 1) % 1440
        pre_quiet_window = f"{q_start // 60:02d}:{q_start % 60:02d}-{q_end // 60:02d}:{q_end % 60:02d}"
        admin_ref = self.report["images"]["admin"]["reference"]
        pri_labels = {"openmettle.dev/environment": "dev", RUN_LABEL: self.run_id}
        pre_family_script = (
            f'openmettle-admin family set-policy --user "{USER_D_IDS["user"]}" --zone "Europe/London" '
            f'--quiet "{pre_quiet_window}" --study "16:00-18:00" --override-group-schedules '
            f'--operator-id "{DRILL_OPERATOR_ID}" --request-key "drill-pre-family-policy-d" '
            '--reason "pre-backup family policy schedule for user_d"\n'
            f'openmettle-admin family set-model --user "{USER_D_IDS["user"]}" --kind study_allow '
            f'--model {_sh_quote(smoke.CATALOG_MODEL)} --enable --operator-id "{DRILL_OPERATOR_ID}" '
            '--request-key "drill-pre-family-study-allow-d" '
            '--reason "pre-backup study_allow rule for user_d"\n'
        )
        pre_family_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-primary-family-pre", "namespace": PRIMARY_APP_NS, "labels": pri_labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**pri_labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "family-pre", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", pre_family_script],
                            "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                        }],
                    },
                },
            },
        }
        self.run_job(PRIMARY_APP_NS, pre_family_job)
        pre_permits = self.psql_superuser(
            PRIMARY_DB_NS,
            f"SELECT openmettle.family_policy_permits('{USER_D_IDS['user']}'::uuid, "
            f"'{USER_D_IDS['approval']}'::uuid, '{smoke.CATALOG_MODEL}', now())::text;",
        ).strip()
        self.expect(pre_permits == "t", f"expected user_d pre-backup family schedule to permit model, got {pre_permits!r}")
        pre_family_schedule = {
            "zone": "Europe/London",
            "quiet_start": q_start,
            "quiet_end": q_end,
            "study_start": 960,
            "study_end": 1080,
            "override_group_schedules": True,
        }

        # Populate primary state over live /v1 HTTP routes.
        fwd = smoke.PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080, namespace=PRIMARY_APP_NS)
        try:
            personal_conv = self.api_json(fwd.port, cookie_a, "POST", "/v1/conversations", 201,
                                          key="drill-conv-personal", json_body={})
            run_body = smoke.run_request(personal_conv, str(uuid.uuid4()))
            admitted = self.api_json(fwd.port, cookie_a, "POST", "/v1/runs", 201,
                                     key="drill-turn-1", json_body=run_body)
            completed_run_id = admitted["run_id"]
            self.wait_for_run_succeeded(
                fwd.port, cookie_a, completed_run_id,
                "primary gateway inference turn to succeed", PRIMARY_DB_NS, timeout=60,
            )
            self.wait_for(
                "primary gateway settlement",
                lambda: smoke.evaluate_settled_round(
                    self.psql_superuser(PRIMARY_DB_NS, smoke.settled_round_sql(completed_run_id))
                ),
                timeout=30, interval=0.5,
            )

            project = self.api_json(fwd.port, cookie_a, "POST", "/v1/projects", 201,
                                    key="drill-project-1", json_body={"name": "Drill Shared Project"})
            project_id = project["project_id"]
            project_scope_id = project["scope_id"]
            self.api_json(fwd.port, cookie_a, "PUT", f"/v1/projects/{project_id}/members", 200,
                          key="drill-project-viewer-b",
                          json_body={"grantee": {"kind": "user", "grantee_id": USER_B_IDS["user"]}, "role": "viewer"})
            self.api_json(fwd.port, cookie_a, "PUT", f"/v1/projects/{project_id}/members", 200,
                          key="drill-project-viewer-c",
                          json_body={"grantee": {"kind": "user", "grantee_id": USER_C_IDS["user"]}, "role": "viewer"})
            project_conv = self.api_json(fwd.port, cookie_a, "POST", "/v1/conversations", 201,
                                         key="drill-conv-project", json_body={"scope_id": project_scope_id})
            # Share project_conv with the project so Viewer user_b can read it while non-member user_d gets 404.
            self.api_json(fwd.port, cookie_a, "PUT",
                          f"/v1/conversations/{project_conv['conversation_id']}/shares", 200,
                          key="drill-conv-project-share",
                          json_body={"grantee": {"kind": "project"}, "access": "read"})

            art_keep = self.upload_artifact(fwd.port, cookie_a, "drill-art-keep", b"drill-personal-keep-bytes\n")
            art_project = self.upload_artifact(fwd.port, cookie_a, "drill-art-proj", b"drill-project-shared-bytes\n",
                                               scope_id=project_scope_id)
            self.api_json(fwd.port, cookie_a, "PUT", f"/v1/artifacts/{art_project['artifact_id']}/shares", 200,
                          key="drill-art-proj-share",
                          json_body={"grantee": {"kind": "project"}, "access": "read"})

            art_deadline = self.upload_artifact(fwd.port, cookie_a, "drill-art-dl-v1", b"drill-retained-deadline-v1\n")
            boundary_v2 = f"drill-boundary-{secrets.token_hex(4)}"
            _, rev2_raw = self.api_call(
                fwd.port, cookie_a, "POST",
                f"/v1/artifacts/{art_deadline['artifact_id']}/revisions?max_bytes={smoke.ARTIFACT_MAX_BYTES}",
                201, key="drill-art-dl-v2",
                raw_body=smoke.multipart_form(boundary_v2, b"drill-retained-deadline-v2\n"), boundary=boundary_v2,
            )
            art_deadline_v2 = json.loads(rev2_raw)
            retained_doc = self.api_json(
                fwd.port, cookie_a, "DELETE",
                f"/v1/artifacts/{art_deadline['artifact_id']}/revisions/{art_deadline['revision_id']}",
                200, key="drill-retain-dl-v1",
            )
            self.expect(retained_doc.get("state") == "retained" and retained_doc.get("purge_after"),
                        f"expected retained revision with purge_after, got {retained_doc!r}")

            art_post_purge = self.upload_artifact(fwd.port, cookie_a, "drill-art-post-purge",
                                                  b"drill-post-backup-purge-bytes\n")
            art_stage_recover = self.upload_artifact(fwd.port, cookie_a, "drill-art-stage-recover",
                                                     b"drill-recoverable-from-staging-bytes\n")
            art_to_lose = self.upload_artifact(fwd.port, cookie_a, "drill-art-to-lose",
                                               b"drill-unrecoverable-payload-bytes\n")

            conn_keep = self.api_json(fwd.port, cookie_a, "POST", "/v1/connections", 201, key="drill-conn-keep",
                                      json_body={"provider_kind": "mcp_http", "account_id": "acct-keep",
                                                 "origin": "https://mcp-keep.example.test",
                                                 "allowed_scopes": ["tools:read"]})
            self.api_json(fwd.port, cookie_a, "POST", f"/v1/connections/{conn_keep['connection_id']}/authorize", 200,
                          key="drill-conn-keep-auth",
                          json_body={"access_token": "secret-access-keep-1",
                                     "refresh_token": "secret-refresh-keep-1",
                                     "granted_scopes": ["tools:read"]})

            conn_revoke = self.api_json(fwd.port, cookie_a, "POST", "/v1/connections", 201, key="drill-conn-revoke",
                                        json_body={"provider_kind": "mcp_http", "account_id": "acct-revoke",
                                                   "origin": "https://mcp-revoke.example.test",
                                                   "allowed_scopes": ["tools:read"]})
            self.api_json(fwd.port, cookie_a, "POST", f"/v1/connections/{conn_revoke['connection_id']}/authorize", 200,
                          key="drill-conn-revoke-auth",
                          json_body={"access_token": "secret-access-revoke-1",
                                     "refresh_token": "secret-refresh-revoke-1",
                                     "granted_scopes": ["tools:read"]})
            self.api_json(fwd.port, cookie_a, "PUT", f"/v1/connections/{conn_revoke['connection_id']}/shares", 200,
                          key="drill-conn-revoke-share",
                          json_body={"grantee": {"kind": "user", "grantee_id": USER_B_IDS["user"]}, "access": "use"})
        finally:
            fwd.close()

        # Pause primary worker briefly so drill-fixture claims, reserves 25 usage_tokens each, and parks both runs.
        self.verify_identity()
        self.kube("--namespace", PRIMARY_APP_NS, "scale", f"deployment/{FULLNAME}-worker", "--replicas=0")
        self.wait_for(
            "primary worker scaled to 0 for deterministic fixture parking",
            lambda: len(self.kube_json("--namespace", PRIMARY_APP_NS, "get", "pods", "--selector",
                                       f"app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component=worker")["items"]) == 0,
            timeout=60,
        )
        pg_pods = self.kube_json("--namespace", PRIMARY_DB_NS, "get", "pods", "--selector", "app.kubernetes.io/name=postgres")["items"]
        (primary_pg_pod,) = [p["metadata"]["name"] for p in pg_pods if not p["metadata"].get("deletionTimestamp")]
        self.verify_identity()
        self.kube("--namespace", PRIMARY_DB_NS, "cp", str(self.drill_fixture_bin), f"{primary_pg_pod}:/tmp/kind-drill-fixture")
        fixture_stdin = (
            f"postgres://openmettle_api:{self.primary_passwords['api']}@127.0.0.1/openmettle?sslmode=disable\n"
            f"postgres://openmettle_worker:{self.primary_passwords['worker']}@127.0.0.1/openmettle?sslmode=disable\n"
            f"{cookie_a}\n"
        )
        fixture_out = self.kube("--namespace", PRIMARY_DB_NS, "exec", "--stdin", primary_pg_pod, "--",
                                "/tmp/kind-drill-fixture", USER_A_IDS["user"], USER_A_IDS["approval"],
                                target_mcp_url(),
                                input=fixture_stdin).stdout.strip()
        parked = json.loads(fixture_out)
        self.verify_identity()
        self.kube("--namespace", PRIMARY_APP_NS, "scale", f"deployment/{FULLNAME}-worker", "--replicas=1")
        self.kube("--namespace", PRIMARY_APP_NS, "rollout", "status", f"deployment/{FULLNAME}-worker",
                  "--timeout=120s", timeout=150)

        # Verify pre-backup run event sequences and 25-unit quota holds before backup capture.
        pre_runs_raw = self.psql_superuser(
            PRIMARY_DB_NS,
            "SELECT r.id::text, r.last_event_sequence, qr.held_units"
            " FROM openmettle.runs r"
            " JOIN openmettle.quota_reservations qr"
            "   ON qr.run_id = r.id AND qr.gateway_request_id IS NULL AND qr.resource_kind = 'usage_tokens'"
            f" WHERE r.id IN ('{parked['waiting_run_id']}'::uuid, '{parked['intent_run_id']}'::uuid);",
        )
        pre_run_seq: dict[str, int] = {}
        for row in pre_runs_raw.splitlines():
            if row:
                rid, seq_s, held_s = row.split("|")
                self.expect(int(held_s) == 25, f"expected 25-token hold on {rid} before backup, got {held_s}")
                pre_run_seq[rid] = int(seq_s)
        self.expect(
            set(pre_run_seq) == {parked["waiting_run_id"], parked["intent_run_id"]},
            f"missing pre-backup run sequence metadata: {pre_run_seq!r}",
        )

        res_ids_raw = self.psql_superuser(
            PRIMARY_DB_NS,
            "SELECT id::text, reservation_id::text,"
            " coalesce((extract(epoch FROM purge_after) * 1000000)::bigint::text, ''),"
            " size_bytes, encode(content_digest, 'hex')"
            " FROM openmettle.artifact_revisions"
            f" WHERE id IN ('{art_to_lose['revision_id']}'::uuid, '{art_stage_recover['revision_id']}'::uuid,"
            f" '{art_post_purge['revision_id']}'::uuid, '{art_deadline['revision_id']}'::uuid);",
        )
        rev_meta = {}
        for row in res_ids_raw.splitlines():
            if row:
                rid, res_id, purge_after_us, size_s, sha_hex = row.split("|")
                rev_meta[rid] = {
                    "reservation_id": res_id,
                    "purge_after_us": purge_after_us,
                    "size_bytes": int(size_s),
                    "sha256": sha_hex,
                }

        # Capture coordinated backup via CronJob on primary.
        capture_job = "openmettle-drill-primary-backup"
        self.verify_identity()
        self.kube("--namespace", PRIMARY_APP_NS, "create", "job", capture_job, f"--from=cronjob/{smoke.BACKUP_CRONJOB}")
        self.kube("--namespace", PRIMARY_APP_NS, "wait", "--for=condition=complete",
                  f"job/{capture_job}", "--timeout=180s", timeout=210)
        cap_logs = self.kube("--namespace", PRIMARY_APP_NS, "logs", f"job/{capture_job}", "--container", "backup").stdout
        capture = smoke.parse_backup_capture_log(cap_logs, smoke.BACKUP_DEST_DIR)
        self.verify_identity()
        self.kube("--namespace", PRIMARY_APP_NS, "delete", "job", capture_job, "--wait=true", timeout=120)

        # Post-backup activity on primary: purge art_post_purge, revoke share & disconnect conn_revoke,
        # disable user_c + withdraw user_c's identity approval (Step 5b principal fixture), and
        # disable catalog model `smoke.CATALOG_MODEL` for user_d under audited family policy.
        self.psql_superuser(
            PRIMARY_DB_NS,
            "UPDATE openmettle.retention_policy SET min_grace_seconds = 0, grace_seconds = 0 WHERE id;\n"
            f"UPDATE openmettle.users SET disabled_at = clock_timestamp(), session_generation = session_generation + 1"
            f" WHERE id = '{USER_C_IDS['user']}'::uuid;\n"
            f"UPDATE openmettle.local_identity_approvals"
            f" SET active = false, access_generation = access_generation + 1,"
            f"     changed_by = 'operator:{DRILL_OPERATOR_ID}', change_reason = 'post-backup disablement'"
            f" WHERE id = '{USER_C_IDS['approval']}'::uuid;",
        )
        disabled_principals = [(USER_C_IDS["user"], USER_C_IDS["approval"])]
        disabled_family_models = [
            {
                "user_id": USER_D_IDS["user"],
                "policy": None,
                "models": [("disabled", smoke.CATALOG_MODEL, True)],
            }
        ]
        family_restrict_script = (
            f'openmettle-admin family set-model --user "{USER_D_IDS["user"]}" --kind disabled '
            f'--model {_sh_quote(smoke.CATALOG_MODEL)} --enable --operator-id "{DRILL_OPERATOR_ID}" '
            '--request-key "drill-primary-family-disable-a-1" '
            '--reason "post-backup disabled model restriction on existing family policy"\n'
        )
        family_restrict_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-primary-family-restrict", "namespace": PRIMARY_APP_NS, "labels": pri_labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**pri_labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "family-restrict", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", family_restrict_script],
                            "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                        }],
                    },
                },
            },
        }
        self.run_job(PRIMARY_APP_NS, family_restrict_job)
        family_audit = self.psql_superuser(
            PRIMARY_DB_NS,
            "SELECT details->>'grantee_id', details->>'model'"
            " FROM openmettle.authorization_audit"
            " WHERE action = 'family_policy.model_disable'"
            " ORDER BY id DESC LIMIT 1;",
        ).strip()
        self.expect(
            family_audit == f"{USER_D_IDS['user']}|{smoke.CATALOG_MODEL}",
            f"primary family_policy.model_disable audit row missing or mismatched: {family_audit!r}",
        )

        fwd = smoke.PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080, namespace=PRIMARY_APP_NS)
        try:
            self.api_call(fwd.port, cookie_a, "DELETE", f"/v1/artifacts/{art_post_purge['artifact_id']}",
                          204, key="drill-delete-post-backup")
            self.api_call(fwd.port, cookie_a, "POST",
                          f"/v1/connections/{conn_revoke['connection_id']}/shares/revoke", 204,
                          key="drill-conn-revoke-share-post",
                          json_body={"grantee": {"kind": "user", "grantee_id": USER_B_IDS["user"]}})
            disconnected = self.api_json(fwd.port, cookie_a, "POST",
                                         f"/v1/connections/{conn_revoke['connection_id']}/disconnect", 200,
                                         key="drill-conn-disconnect-post")
            self.expect(disconnected.get("state") == "disconnected", "primary disconnect did not mark disconnected")
        finally:
            fwd.close()

        self.wait_for(
            "primary worker to purge post-backup deleted revision",
            lambda: self.psql_superuser(
                PRIMARY_DB_NS,
                f"SELECT state FROM openmettle.artifact_revisions WHERE id = '{art_post_purge['revision_id']}'::uuid;",
            ).strip() == "purged",
            timeout=45, interval=1.0,
        )

        # Fence/stop primary api and worker before recording the authoritative final journal watermark
        # (`journal_seq, chain_digest`) and exporting post-backup-journal.export.
        self.verify_identity()
        for comp in ("api", "worker"):
            self.kube("--namespace", PRIMARY_APP_NS, "scale", f"deployment/{FULLNAME}-{comp}", "--replicas=0")
        for comp in ("api", "worker"):
            self.wait_for(
                f"primary {comp} scaled to 0 before final journal watermark export",
                lambda c=comp: len(self.kube_json(
                    "--namespace", PRIMARY_APP_NS, "get", "pods", "--selector",
                    f"app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component={c}"
                )["items"]) == 0,
                timeout=60,
            )

        wm_row = self.psql_superuser(PRIMARY_DB_NS, stopped_primary_watermark_sql()).strip()
        wm_seq_s, wm_digest_s = wm_row.split("|")
        stopped_primary_watermark = (int(wm_seq_s), wm_digest_s)

        export_file = f"{smoke.BACKUP_DEST_DIR}/post-backup-journal.export"
        export_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-journal-export", "namespace": PRIMARY_APP_NS,
                         "labels": {"openmettle.dev/environment": "dev", RUN_LABEL: self.run_id}},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {"openmettle.dev/environment": "dev", RUN_LABEL: self.run_id,
                                            RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "export", "image": admin_ref, "imagePullPolicy": "Never",
                            "args": ["journal", "export", export_file],
                            "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [{"name": "dest", "mountPath": smoke.BACKUP_DEST_DIR}],
                        }],
                        "volumes": [{"name": "dest", "persistentVolumeClaim": {"claimName": smoke.BACKUP_DEST_CLAIM}}],
                    },
                },
            },
        }
        self.run_job(PRIMARY_APP_NS, export_job)
        cutover_at = datetime.now(timezone.utc)

        # Bring primary api and worker back up so live cross-namespace NetworkPolicy isolation and
        # primary non-interference are verified while target recovery proceeds.
        self.verify_identity()
        for comp in ("api", "worker"):
            self.kube("--namespace", PRIMARY_APP_NS, "scale", f"deployment/{FULLNAME}-{comp}", "--replicas=1")
        for comp in ("api", "worker"):
            self.kube("--namespace", PRIMARY_APP_NS, "rollout", "status", f"deployment/{FULLNAME}-{comp}",
                      "--timeout=120s", timeout=150)

        self.passed(
            "primary state seeded, coordinated backup captured, and stopped-primary deletions/revocations exported",
            backup_run_id=capture["run_id"],
            backup_dir=Path(capture["dir"]).name,
            stopped_primary_journal_seq=stopped_primary_watermark[0],
        )
        return {
            "capture": capture,
            "export_file": export_file,
            "stopped_primary_watermark": stopped_primary_watermark,
            "disabled_principals": disabled_principals,
            "pre_family_schedule": pre_family_schedule,
            "disabled_family_models": disabled_family_models,
            "cutover_at": cutover_at,
            "personal_conv": personal_conv,
            "completed_run_id": completed_run_id,
            "project_id": project_id,
            "project_scope_id": project_scope_id,
            "project_conv": project_conv,
            "art_keep": art_keep,
            "art_project": art_project,
            "art_deadline": art_deadline,
            "art_deadline_v2": art_deadline_v2,
            "retained_purge_after": retained_doc["purge_after"],
            "art_post_purge": art_post_purge,
            "art_stage_recover": art_stage_recover,
            "art_to_lose": art_to_lose,
            "rev_meta": rev_meta,
            "conn_keep_id": conn_keep["connection_id"],
            "conn_revoke_id": conn_revoke["connection_id"],
            "parked": parked,
            "pre_run_seq": pre_run_seq,
        }

    def provision_target_and_stage_media(self, primary_state: dict) -> None:
        self.target_passwords = self.new_credentials()
        # Phase 1: Namespaces + NetworkPolicies + Secrets/ConfigMaps/PVCs FIRST.
        target_foundation = isolation_and_config_manifests(
            app_ns=TARGET_APP_NS, db_ns=TARGET_DB_NS,
            passwords=self.target_passwords, catalog=self.catalog,
            vault_keys=[
                (VAULT_KEY_ID_1, VAULT_KEY_FILE_1, self.vault_k1_b64),
                (VAULT_KEY_ID_2, VAULT_KEY_FILE_2, self.vault_k2_b64),
            ],
            backup_key_b64=self.backup_k1_b64, wrong_backup_key_b64=self.wrong_backup_b64,
            is_target=True, run_id=self.run_id,
        )
        # Phase 2: Database & stand-in Deployments AFTER default-deny policies exist.
        target_workloads = fixture_workload_manifests(
            db_ns=TARGET_DB_NS, postgres_image=self.core.POSTGRES_IMAGE,
            standin_image=self.standin_image, is_target=True, run_id=self.run_id,
        )
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(target_foundation))
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(target_workloads))
        for dep in ("postgres", smoke.STANDIN):
            self.kube("--namespace", TARGET_DB_NS, "rollout", "status", f"deployment/{dep}",
                      "--timeout=300s", timeout=330)

        # Copy only encrypted backup dir + post-backup journal export into TARGET_RECOVERY_MEDIA_CLAIM via base64 tar.
        admin_ref = self.report["images"]["admin"]["reference"]
        backup_dirname = Path(primary_state["capture"]["dir"]).name

        def transfer_pod(name: str, ns: str, claim: str, read_only: bool) -> dict:
            return {
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": name, "namespace": ns,
                             "labels": {"openmettle.dev/environment": "dev", RUN_LABEL: self.run_id}},
                "spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                    "securityContext": POD_SEC_CONTEXT,
                    "containers": [{
                        "name": "xfer", "image": admin_ref, "imagePullPolicy": "Never",
                        "command": ["/bin/sh", "-c", "sleep 300"],
                        "securityContext": CONTAINER_SEC_CONTEXT,
                        "volumeMounts": [{"name": "media", "mountPath": RECOVERY_MEDIA_DIR, "readOnly": read_only}],
                    }],
                    "volumes": [{"name": "media", "persistentVolumeClaim": {"claimName": claim, "readOnly": read_only}}],
                },
            }

        src_pod, dst_pod = "openmettle-drill-media-src", "openmettle-drill-media-dst"
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(transfer_pod(src_pod, PRIMARY_APP_NS, smoke.BACKUP_DEST_CLAIM, True)))
        self.kube("apply", "--filename", "-", input=json.dumps(transfer_pod(dst_pod, TARGET_APP_NS, TARGET_RECOVERY_MEDIA_CLAIM, False)))
        try:
            self.kube("--namespace", PRIMARY_APP_NS, "wait", "--for=condition=Ready", f"pod/{src_pod}", "--timeout=120s")
            self.kube("--namespace", TARGET_APP_NS, "wait", "--for=condition=Ready", f"pod/{dst_pod}", "--timeout=120s")
            b64_archive = self.kube(
                "--namespace", PRIMARY_APP_NS, "exec", src_pod, "--",
                "/bin/sh", "-eu", "-c",
                f'tar -C "{RECOVERY_MEDIA_DIR}" -cf - "{backup_dirname}" post-backup-journal.export | base64',
            ).stdout
            self.kube(
                "--namespace", TARGET_APP_NS, "exec", "--stdin", dst_pod, "--",
                "/bin/sh", "-eu", "-c",
                f'base64 -d | tar -C "{RECOVERY_MEDIA_DIR}" -xf -',
                input=b64_archive,
            )
            self.journal_text = self.kube(
                "--namespace", TARGET_APP_NS, "exec", dst_pod, "--",
                "cat", f"{RECOVERY_MEDIA_DIR}/post-backup-journal.export",
            ).stdout
        finally:
            self.verify_identity()
            self.kube("--namespace", PRIMARY_APP_NS, "delete", "pod", src_pod, "--wait=true", timeout=120)
            self.kube("--namespace", TARGET_APP_NS, "delete", "pod", dst_pod, "--wait=true", timeout=120)

    def exercise_uncertified_coverage_gap(self) -> None:
        """Exercise the uncertified `restore accept-coverage-gap` path against an isolated scratch
        database (`openmettle_gap`) restored from `/var/recovery/unpacked/pg.dump`, verifying
        `reauth_required`, cleared ciphertexts, deactivated shares, and audit persistence."""
        admin_ref = self.report["images"]["admin"]["reference"]
        migrate_ref = self.report["images"]["migrate"]["reference"]
        target_pg_host = f"postgres.{TARGET_DB_NS}.svc.cluster.local"
        labels = {"openmettle.dev/environment": "dev", RUN_LABEL: self.run_id}

        self.psql_superuser(
            TARGET_DB_NS,
            f"CREATE DATABASE {GAP_DB_NAME} OWNER openmettle_owner;\n" + target_db_acl_sql(GAP_DB_NAME),
            dbname="fixture",
            single_tx=False,
        )
        gap_secret = {
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": GAP_OWNER_SECRET, "namespace": TARGET_APP_NS, "labels": labels},
            "stringData": {"url": db_url(TARGET_DB_NS, "migrate", self.target_passwords["migrate"], dbname=GAP_DB_NAME)},
        }
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(gap_secret))
        try:
            pg_gap_script = (
                "umask 077\n"
                "export PGPASSFILE=/tmp/pgpass PGSSLMODE=disable PGGSSENCMODE=disable\n"
                "trap 'rm -f \"$PGPASSFILE\"' EXIT\n"
                'owner_pw="${OWNER_DB_URL#*://openmettle_owner:}"\n'
                'owner_pw="${owner_pw%%@*}"\n'
                'esc() { printf "%s" "$1" | sed \'s/[\\\\:]/\\\\&/g\'; }\n'
                f'printf "%s:5432:{GAP_DB_NAME}:openmettle_owner:%s\\n" "$(esc "{target_pg_host}")" "$(esc "$owner_pw")" > "$PGPASSFILE"\n'
                'chmod 0600 "$PGPASSFILE"\n'
                "pg_restore --format=custom --no-owner --exit-on-error "
                f'--host="{target_pg_host}" --port=5432 --username=openmettle_owner --dbname={GAP_DB_NAME} '
                f'"{UNPACKED_DIR}/pg.dump"\n'
                f'printf "GAP_JOURNAL_BEGIN\\n"; cat "{UNPACKED_DIR}/deletion-journal.bin"; printf "GAP_JOURNAL_END\\n"\n'
            )
            pg_gap_job = {
                "apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "openmettle-drill-gap-pg-restore", "namespace": TARGET_APP_NS, "labels": labels},
                "spec": {
                    "backoffLimit": 0, "activeDeadlineSeconds": 180,
                    "template": {
                        "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                        "spec": {
                            "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                            "securityContext": POD_SEC_CONTEXT,
                            "containers": [{
                                "name": "pg-restore", "image": self.pg_client_ref, "imagePullPolicy": "Never",
                                "command": ["/bin/sh", "-eu", "-c", pg_gap_script],
                                "env": [{"name": "OWNER_DB_URL",
                                         "valueFrom": {"secretKeyRef": {"name": GAP_OWNER_SECRET, "key": "url"}}}],
                                "securityContext": CONTAINER_SEC_CONTEXT,
                                "volumeMounts": [
                                    {"name": "scratch", "mountPath": RECOVERY_SCRATCH_DIR, "readOnly": True},
                                    {"name": "tmp", "mountPath": "/tmp"},
                                ],
                            }],
                            "volumes": [
                                {"name": "scratch", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_SCRATCH_CLAIM, "readOnly": True}},
                                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                            ],
                        },
                    },
                },
            }
            gap_restore_out, _ = self.run_job(TARGET_APP_NS, pg_gap_job)
            gap_journal_text = gap_restore_out.split("GAP_JOURNAL_BEGIN\n", 1)[1].split("GAP_JOURNAL_END", 1)[0]
            gap_wm = parse_journal_export_watermarks(gap_journal_text)
            gap_export_complete = should_pass_export_complete(gap_wm, None)
            self.expect(not gap_export_complete, "uncertified backup journal unexpectedly marked export_complete")

            gap_migrate_job = {
                "apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "openmettle-drill-gap-migrate", "namespace": TARGET_APP_NS, "labels": labels},
                "spec": {
                    "backoffLimit": 0, "activeDeadlineSeconds": 120,
                    "template": {
                        "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                        "spec": {
                            "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                            "securityContext": POD_SEC_CONTEXT,
                            "containers": [{
                                "name": "migrate", "image": migrate_ref, "imagePullPolicy": "Never",
                                "env": [{"name": "OPENMETTLE_MIGRATE_DATABASE_URL",
                                         "valueFrom": {"secretKeyRef": {"name": GAP_OWNER_SECRET, "key": "url"}}}],
                                "securityContext": CONTAINER_SEC_CONTEXT,
                            }],
                        },
                    },
                },
            }
            self.run_job(TARGET_APP_NS, gap_migrate_job)

            gap_lock_argv = " ".join(f'"{a}"' for a in restore_lock_args(gap_wm, export_complete=gap_export_complete))
            gap_lock_job = {
                "apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "openmettle-drill-gap-lock", "namespace": TARGET_APP_NS, "labels": labels},
                "spec": {
                    "backoffLimit": 0, "activeDeadlineSeconds": 120,
                    "template": {
                        "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                        "spec": {
                            "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                            "securityContext": POD_SEC_CONTEXT,
                            "containers": [{
                                "name": "gap-lock", "image": admin_ref, "imagePullPolicy": "Never",
                                "command": ["/bin/sh", "-eu", "-c", f"openmettle-admin {gap_lock_argv}\n"],
                                "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                         "valueFrom": {"secretKeyRef": {"name": GAP_OWNER_SECRET, "key": "url"}}}],
                                "securityContext": CONTAINER_SEC_CONTEXT,
                            }],
                        },
                    },
                },
            }
            gap_lock_out, _ = self.run_job(TARGET_APP_NS, gap_lock_job)
            gap_run_id = parse_restore_lock_run_id(gap_lock_out)

            gap_accept_argv = " ".join(
                f'"{a}"'
                for a in accept_coverage_gap_args(
                    gap_run_id,
                    DRILL_OPERATOR_ID,
                    f"drill-gap-{gap_run_id}",
                    "uncertified post-backup window during V1-31 coverage-gap check",
                )
            )
            gap_accept_script = (
                f'openmettle-admin restore replay --db-only "{UNPACKED_DIR}/deletion-journal.bin"\n'
                f"openmettle-admin {gap_accept_argv}\n"
            )
            gap_accept_job = {
                "apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "openmettle-drill-gap-accept", "namespace": TARGET_APP_NS, "labels": labels},
                "spec": {
                    "backoffLimit": 0, "activeDeadlineSeconds": 120,
                    "template": {
                        "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                        "spec": {
                            "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                            "securityContext": POD_SEC_CONTEXT,
                            "containers": [{
                                "name": "gap-accept", "image": admin_ref, "imagePullPolicy": "Never",
                                "command": ["/bin/sh", "-eu", "-c", gap_accept_script],
                                "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                         "valueFrom": {"secretKeyRef": {"name": GAP_OWNER_SECRET, "key": "url"}}}],
                                "securityContext": CONTAINER_SEC_CONTEXT,
                                "volumeMounts": [{"name": "scratch", "mountPath": RECOVERY_SCRATCH_DIR, "readOnly": True}],
                            }],
                            "volumes": [{"name": "scratch", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_SCRATCH_CLAIM, "readOnly": True}}],
                        },
                    },
                },
            }
            gap_accept_out, _ = self.run_job(TARGET_APP_NS, gap_accept_job)
            self.expect("applied restore.accept_coverage_gap" in gap_accept_out,
                        f"expected restore.accept_coverage_gap confirmation, got {gap_accept_out!r}")

            gap_sql = self.psql_superuser(
                TARGET_DB_NS,
                "SELECT (SELECT count(*) FROM openmettle.external_connections WHERE state = 'reauth_required'),"
                " (SELECT count(*) FROM openmettle.external_connections WHERE state = 'authorized'),"
                " (SELECT count(*) FROM openmettle.external_connections"
                "   WHERE encryption_key_id IS NOT NULL OR access_ciphertext IS NOT NULL OR refresh_ciphertext IS NOT NULL),"
                " (SELECT count(*) FROM openmettle.external_connection_shares WHERE active),"
                " (SELECT coverage_complete FROM openmettle.restore_reconciliation_gate),"
                " (SELECT count(*) FROM openmettle.authorization_audit WHERE action = 'restore.accept_coverage_gap');",
                dbname=GAP_DB_NAME,
            ).strip()
            self.expect(gap_sql == "2|0|0|0|t|1",
                        f"unexpected post-accept-coverage-gap SQL state: {gap_sql!r}")
            self.passed("uncertified export coverage-gap path transitions connections to reauth_required, clears ciphertexts, and deactivates shares")
        finally:
            self.verify_identity()
            self.kube("--namespace", TARGET_APP_NS, "delete", "secret", GAP_OWNER_SECRET, "--ignore-not-found=true")
            self.psql_superuser(
                TARGET_DB_NS,
                f"DROP DATABASE IF EXISTS {GAP_DB_NAME} WITH (FORCE);",
                dbname="fixture",
                single_tx=False,
            )

    def execute_target_restore(self, primary_state: dict) -> dict:
        admin_ref = self.report["images"]["admin"]["reference"]
        migrate_ref = self.report["images"]["migrate"]["reference"]
        backup_dir = f"{RECOVERY_MEDIA_DIR}/{Path(primary_state['capture']['dir']).name}"
        labels = {"openmettle.dev/environment": "dev", RUN_LABEL: self.run_id}

        # Step 1a: Positive control FIRST, then offline negative preflight checks (same vault==backup
        # path, distinct path with duplicate key bytes, wrong backup key, and tampered ciphertext).
        neg_init, neg_key_mounts, neg_key_vols = staged_keyring_mounts(
            admin_ref,
            [
                ("good-backup", smoke.BACKUP_KEYS_SECRET, smoke.BACKUP_KEYS_DIR),
                ("good-vault", smoke.VAULT_KEYS_SECRET, smoke.VAULT_KEYS_DIR),
                ("wrong-backup", WRONG_BACKUP_SECRET, WRONG_BACKUP_KEYS_DIR),
            ],
        )
        good_bk_cfg = f"{smoke.BACKUP_KEYS_DIR}/keyring.json"
        good_vt_cfg = f"{smoke.VAULT_KEYS_DIR}/keyring.json"
        wrong_bk_cfg = f"{WRONG_BACKUP_KEYS_DIR}/keyring.json"
        neg_script = (
            f'OPENMETTLE_API_VAULT_KEYS_CONFIG="{good_vt_cfg}" '
            f'openmettle-admin backup verify --backup-dir "{backup_dir}" --backup-keys-config "{good_bk_cfg}"\n'
            f'if OPENMETTLE_API_VAULT_KEYS_CONFIG="{good_bk_cfg}" '
            f'openmettle-admin backup verify --backup-dir "{backup_dir}" --backup-keys-config "{good_bk_cfg}" '
            '2>/tmp/neg-same-path.err; then\n'
            '  echo "ERROR: identical vault/backup keyring path unexpectedly succeeded" >&2; exit 1\n'
            "fi\n"
            'grep -q "distinct from VAULT_KEYS_CONFIG" /tmp/neg-same-path.err\n'
            "umask 077 && mkdir -p /tmp/dup-vault && chmod 0700 /tmp/dup-vault\n"
            f'cp -- "{smoke.BACKUP_KEYS_DIR}/{BACKUP_KEY_FILE}" /tmp/dup-vault/dup.key && chmod 0400 /tmp/dup-vault/dup.key\n'
            'printf \'{"version":1,"active_key_id":"dup-v1","keys":[{"id":"dup-v1","file":"/tmp/dup-vault/dup.key"}]}\\n\' '
            "> /tmp/dup-vault/keyring.json && chmod 0400 /tmp/dup-vault/keyring.json\n"
            'if OPENMETTLE_API_VAULT_KEYS_CONFIG=/tmp/dup-vault/keyring.json '
            f'openmettle-admin backup verify --backup-dir "{backup_dir}" --backup-keys-config "{good_bk_cfg}" '
            '2>/tmp/neg-dup-bytes.err; then\n'
            '  echo "ERROR: duplicate vault/backup key bytes unexpectedly succeeded" >&2; exit 1\n'
            "fi\n"
            'grep -q "backup key material must be distinct from vault keys" /tmp/neg-dup-bytes.err\n'
            f'if OPENMETTLE_API_VAULT_KEYS_CONFIG="{good_vt_cfg}" '
            f'openmettle-admin backup verify --backup-dir "{backup_dir}" --backup-keys-config "{wrong_bk_cfg}" '
            '2>/tmp/neg-wrong-key.err; then\n'
            '  echo "ERROR: wrong backup key unexpectedly verified" >&2; exit 1\n'
            "fi\n"
            'grep -q "backup verification failed" /tmp/neg-wrong-key.err\n'
            f'cp -a "{backup_dir}" /tmp/tampered-backup\n'
            "chmod -R u+w /tmp/tampered-backup\n"
            'size=$(wc -c < /tmp/tampered-backup/pg.dump.enc | tr -d " ")\n'
            "trunc_len=$((size - 1))\n"
            'last_hex=$(tail -c 1 /tmp/tampered-backup/pg.dump.enc | od -An -tx1 | tr -d " \\n")\n'
            'if [ "$last_hex" = "ff" ]; then repl="\\000"; else repl="\\377"; fi\n'
            'dd if=/dev/null of=/tmp/tampered-backup/pg.dump.enc bs=1 seek="$trunc_len" 2>/dev/null\n'
            'printf "$repl" >> /tmp/tampered-backup/pg.dump.enc\n'
            f'if OPENMETTLE_API_VAULT_KEYS_CONFIG="{good_vt_cfg}" '
            f'openmettle-admin backup verify --backup-dir /tmp/tampered-backup --backup-keys-config "{good_bk_cfg}" '
            '2>/tmp/neg-tamper.err; then\n'
            '  echo "ERROR: tampered pg.dump.enc unexpectedly verified" >&2; exit 1\n'
            "fi\n"
            'grep -q "backup verification failed" /tmp/neg-tamper.err\n'
            "rm -rf /tmp/dup-vault /tmp/tampered-backup /tmp/neg-*.err\n"
            'echo "preflight.negative_checks_passed"\n'
        )
        neg_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-preflight-neg", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "initContainers": [neg_init],
                        "containers": [{
                            "name": "neg", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", neg_script],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [
                                *neg_key_mounts,
                                {"name": "media", "mountPath": RECOVERY_MEDIA_DIR, "readOnly": True},
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                        }],
                        "volumes": [
                            *neg_key_vols,
                            {"name": "media", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_MEDIA_CLAIM, "readOnly": True}},
                            {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
                        ],
                    },
                },
            },
        }
        neg_stdout, _ = self.run_job(TARGET_APP_NS, neg_job)
        self.expect("preflight.negative_checks_passed" in neg_stdout, "negative preflight checks did not complete")

        # Step 1b: Offline verify + unpack into /var/recovery/unpacked and emit manifest.json.
        unpack_init, unpack_key_mounts, unpack_key_vols = staged_keyring_mounts(
            admin_ref,
            [
                ("backup", smoke.BACKUP_KEYS_SECRET, smoke.BACKUP_KEYS_DIR),
                ("vault", smoke.VAULT_KEYS_SECRET, smoke.VAULT_KEYS_DIR),
            ],
        )
        unpack_script = (
            f'rm -rf "{UNPACKED_DIR}" "{RETAINED_JOURNAL_PATH}"\n'
            f'OPENMETTLE_API_VAULT_KEYS_CONFIG="{good_vt_cfg}" '
            f'openmettle-admin backup verify --backup-dir "{backup_dir}" --backup-keys-config "{good_bk_cfg}"\n'
            f'OPENMETTLE_API_VAULT_KEYS_CONFIG="{good_vt_cfg}" '
            f'openmettle-admin backup unpack --backup-dir "{backup_dir}" --output-dir "{UNPACKED_DIR}" '
            f'--backup-keys-config "{good_bk_cfg}"\n'
            f'cp -- "{RECOVERY_MEDIA_DIR}/post-backup-journal.export" "{RETAINED_JOURNAL_PATH}"\n'
            f'chmod 0400 "{RETAINED_JOURNAL_PATH}"\n'
            f'printf "MANIFEST_JSON_BEGIN\\n"\ncat "{UNPACKED_DIR}/manifest.json"\nprintf "\\nMANIFEST_JSON_END\\n"\n'
        )
        unpack_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-verify-unpack", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "initContainers": [unpack_init],
                        "containers": [{
                            "name": "unpack", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", unpack_script],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [
                                *unpack_key_mounts,
                                {"name": "media", "mountPath": RECOVERY_MEDIA_DIR, "readOnly": True},
                                {"name": "scratch", "mountPath": RECOVERY_SCRATCH_DIR},
                            ],
                        }],
                        "volumes": [
                            *unpack_key_vols,
                            {"name": "media", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_MEDIA_CLAIM, "readOnly": True}},
                            {"name": "scratch", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_SCRATCH_CLAIM}},
                        ],
                    },
                },
            },
        }
        unpack_stdout, _ = self.run_job(TARGET_APP_NS, unpack_job)
        manifest_raw = unpack_stdout.split("MANIFEST_JSON_BEGIN\n", 1)[1].split("\nMANIFEST_JSON_END", 1)[0]
        manifest = json.loads(manifest_raw)
        manifest_summary = evaluate_manifest_preflight(
            manifest, available_vault_keys={VAULT_KEY_ID_1, VAULT_KEY_ID_2}
        )
        self.expect(manifest_summary["vault_required_key_ids"] == [VAULT_KEY_ID_1],
                    f"expected vault_required_key_ids=['vault-k1'], got {manifest_summary['vault_required_key_ids']}")
        self.expect(manifest_summary["artifact_volume_id"] is not None,
                    "expected pinned artifact_volume.volume_id in drill manifest")
        self.passed("backup preflight verified, negative tamper/key checks refused, and archive unpacked",
                    **manifest_summary)

        # Model loss of access to the encrypted recovery archive after unpack completes, while
        # keeping the independently retained selected journal on target scratch (`run_job` already
        # deleted both preflight/unpack Jobs above with `--wait=true`, releasing `pvc-protection`).
        self.verify_identity()
        self.kube(
            "--namespace", TARGET_APP_NS, "delete", "pvc",
            TARGET_RECOVERY_MEDIA_CLAIM, "--wait=true", timeout=120,
        )

        # Exercise the uncertified coverage-gap flow on an isolated scratch database before scrubbing unpacked files.
        self.exercise_uncertified_coverage_gap()

        # Step 3: Restore pg.dump with 0600 PGPASSFILE (no password in argv) + run openmettle-migrate.
        target_pg_host = f"postgres.{TARGET_DB_NS}.svc.cluster.local"
        pg_restore_script = (
            "umask 077\n"
            "export PGPASSFILE=/tmp/pgpass PGSSLMODE=disable PGGSSENCMODE=disable\n"
            "trap 'rm -f \"$PGPASSFILE\"' EXIT\n"
            'owner_pw="${OWNER_DB_URL#*://openmettle_owner:}"\n'
            'owner_pw="${owner_pw%%@*}"\n'
            'esc() { printf "%s" "$1" | sed \'s/[\\\\:]/\\\\&/g\'; }\n'
            f'printf "%s:5432:openmettle:openmettle_owner:%s\\n" "$(esc "{target_pg_host}")" "$(esc "$owner_pw")" > "$PGPASSFILE"\n'
            'chmod 0600 "$PGPASSFILE"\n'
            "pg_restore --format=custom --no-owner --exit-on-error "
            f'--host="{target_pg_host}" --port=5432 --username=openmettle_owner --dbname=openmettle '
            f'"{UNPACKED_DIR}/pg.dump"\n'
            'echo "pg_restore.completed"\n'
        )
        pg_restore_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-pg-restore", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 180,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "pg-restore", "image": self.pg_client_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", pg_restore_script],
                            "env": [{"name": "OWNER_DB_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [
                                {"name": "scratch", "mountPath": RECOVERY_SCRATCH_DIR, "readOnly": True},
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                        }],
                        "volumes": [
                            {"name": "scratch", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_SCRATCH_CLAIM, "readOnly": True}},
                            {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                        ],
                    },
                },
            },
        }
        restore_out, _ = self.run_job(TARGET_APP_NS, pg_restore_job)
        self.expect("pg_restore.completed" in restore_out, "pg_restore Job did not complete")

        migrate_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-migrate", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "migrate", "image": migrate_ref, "imagePullPolicy": "Never",
                            "env": [{"name": "OPENMETTLE_MIGRATE_DATABASE_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                        }],
                    },
                },
            },
        }
        self.run_job(TARGET_APP_NS, migrate_job)

        # Verify restored DB schema=45, owner default ACLs clean, and snapshot maintenance gate still active.
        db_post_migrate = self.psql_superuser(
            TARGET_DB_NS,
            "SELECT (SELECT max(version) FROM openmettle._sqlx_migrations WHERE success),"
            " (SELECT count(*) FROM pg_default_acl WHERE defaclrole = 'openmettle_owner'::regrole"
            "  AND defaclnamespace = 0 AND defaclobjtype = 'f'),"
            " (SELECT maintenance_active FROM openmettle.backup_maintenance_gate);",
        ).strip()
        self.expect(db_post_migrate == f"{REQUIRED_MIGRATION}|1|t",
                    f"unexpected target post-migrate DB state: {db_post_migrate!r}")

        # Step 4: Certify `--export-complete` against the stopped-primary watermark, copy artifacts
        # omitting BOTH `art_stage_recover` (removed from target PVC only, intact in staging) and
        # `art_to_lose` (removed from target PVC AND unpacked staging), prove `storage rebind` fails
        # closed for both, then replay --db-only -> recover intact staging copy -> declare truly
        # absent payload lost -> rebind -> replay -> quota verify.
        watermarks = parse_journal_export_watermarks(self.journal_text)
        self.expect(watermarks["required_seq"] > manifest_summary["journal_seq"],
                    "post-backup journal export did not advance past backup snapshot journal_seq")
        export_complete = should_pass_export_complete(
            watermarks, primary_state["stopped_primary_watermark"]
        )
        self.expect(export_complete, "stopped-primary watermark disagreed with post-backup journal export")
        lock_argv = " ".join(f'"{a}"' for a in restore_lock_args(watermarks, export_complete=export_complete))
        has_artifacts = manifest_summary["artifact_volume_id"] is not None
        recover_rev_id = primary_state["art_stage_recover"]["revision_id"]
        recover_meta = primary_state["rev_meta"][recover_rev_id]
        recover_res_id = recover_meta["reservation_id"]
        lost_rev_id = primary_state["art_to_lose"]["revision_id"]
        lost_meta = primary_state["rev_meta"][lost_rev_id]
        lost_res_id = lost_meta["reservation_id"]
        selected_journal = RETAINED_JOURNAL_PATH

        step4a_script = f'printf "LOCK_STDOUT_BEGIN\\n"; openmettle-admin {lock_argv}; printf "LOCK_STDOUT_END\\n"\n'
        if has_artifacts:
            step4a_script += (
                f'for entry in "{UNPACKED_DIR}/artifacts"/* "{UNPACKED_DIR}/artifacts"/.[!.]*; do\n'
                '  [ -e "$entry" ] || continue\n'
                f'  cp -a -- "$entry" "{smoke.ARTIFACTS_MOUNT_PATH}/"\n'
                "done\n"
                f'rm -f "{smoke.ARTIFACTS_MOUNT_PATH}/revisions/{recover_res_id}"\n'
                f'rm -f "{smoke.ARTIFACTS_MOUNT_PATH}/revisions/{lost_res_id}" "{UNPACKED_DIR}/artifacts/revisions/{lost_res_id}"\n'
                f'set +e\nopenmettle-admin storage rebind "{smoke.ARTIFACTS_MOUNT_PATH}" > /tmp/rebind.out 2> /tmp/rebind.err\nrc=$?\nset -e\n'
                'if [ "$rc" -eq 0 ]; then echo "ERROR: storage rebind succeeded despite missing payload" >&2; exit 1; fi\n'
                'printf "REBIND_STDOUT_BEGIN\\n"; cat /tmp/rebind.out; printf "REBIND_STDOUT_END\\n"\n'
                'printf "REBIND_STDERR_BEGIN\\n"; cat /tmp/rebind.err; printf "REBIND_STDERR_END\\n"\n'
            )
        step4a_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-rebind-failclosed", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "rebind", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", step4a_script],
                            "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [
                                {"name": "scratch", "mountPath": RECOVERY_SCRATCH_DIR},
                                {"name": "artifacts", "mountPath": smoke.ARTIFACTS_MOUNT_PATH},
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                        }],
                        "volumes": [
                            {"name": "scratch", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_SCRATCH_CLAIM}},
                            {"name": "artifacts", "persistentVolumeClaim": {"claimName": TARGET_ARTIFACTS_CLAIM}},
                            {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
                        ],
                    },
                },
            },
        }
        s4a_out, _ = self.run_job(TARGET_APP_NS, step4a_job)
        lock_out = s4a_out.split("LOCK_STDOUT_BEGIN\n", 1)[1].split("LOCK_STDOUT_END", 1)[0]
        restore_run_id = parse_restore_lock_run_id(lock_out)
        barrier_uuid = None
        if has_artifacts:
            rebind_out = s4a_out.split("REBIND_STDOUT_BEGIN\n", 1)[1].split("REBIND_STDOUT_END", 1)[0]
            rebind_err = s4a_out.split("REBIND_STDERR_BEGIN\n", 1)[1].split("REBIND_STDERR_END", 1)[0]
            barrier_uuid = parse_failed_rebind(rebind_out, rebind_err, [recover_res_id, lost_res_id])

        # Step 4c + 4d + Step 5c (vault status & rotate; maintenance STAYS ACTIVE until Step 5e!).
        s4b_init, s4b_key_mounts, s4b_key_vols = staged_keyring_mounts(
            admin_ref, [("vault", smoke.VAULT_KEYS_SECRET, smoke.VAULT_KEYS_DIR)]
        )
        if has_artifacts:
            assert barrier_uuid is not None
            replay_and_rebind_lines = build_step4c_reconcile_lines(
                selected_journal=selected_journal,
                artifacts_mount=smoke.ARTIFACTS_MOUNT_PATH,
                unpacked_dir=UNPACKED_DIR,
                operator_id=DRILL_OPERATOR_ID,
                barrier_uuid=barrier_uuid,
                failed_revisions=[
                    (recover_rev_id, recover_res_id, recover_meta["size_bytes"], recover_meta["sha256"]),
                    (lost_rev_id, lost_res_id, lost_meta["size_bytes"], lost_meta["sha256"]),
                ],
            )
        else:
            replay_and_rebind_lines = (
                f'openmettle-admin restore replay "{selected_journal}"\n'
                'printf "QUOTA_STAGE4_BEGIN\\n"; openmettle-admin quota verify; printf "QUOTA_STAGE4_END\\n"\n'
            )

        family_reconcile_lines = build_family_policy_reconcile_lines(
            DRILL_OPERATOR_ID, restore_run_id, primary_state["disabled_family_models"]
        )
        step4b_script = (
            replay_and_rebind_lines
            + family_reconcile_lines
            + 'printf "VAULT_BEFORE_BEGIN\\n"; openmettle-admin vault status; printf "VAULT_BEFORE_END\\n"\n'
            + f'openmettle-admin vault rotate --vault-keys "{good_vt_cfg}" '
              f'--operator-id "{DRILL_OPERATOR_ID}" --request-key "drill-vault-rotate-{restore_run_id}" '
              '--reason "rotate recovered external connections to vault-k2"\n'
            + 'printf "VAULT_AFTER_BEGIN\\n"; openmettle-admin vault status; printf "VAULT_AFTER_END\\n"\n'
        )
        step4b_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-reconcile-admin", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 180,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "initContainers": [s4b_init],
                        "containers": [{
                            "name": "reconcile", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", step4b_script],
                            "env": [
                                {"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                 "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}},
                                {"name": "OPENMETTLE_API_VAULT_KEYS_CONFIG", "value": good_vt_cfg},
                            ],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [
                                *s4b_key_mounts,
                                {"name": "scratch", "mountPath": RECOVERY_SCRATCH_DIR, "readOnly": True},
                                {"name": "artifacts", "mountPath": smoke.ARTIFACTS_MOUNT_PATH},
                            ],
                        }],
                        "volumes": [
                            *s4b_key_vols,
                            {"name": "scratch", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_SCRATCH_CLAIM, "readOnly": True}},
                            {"name": "artifacts", "persistentVolumeClaim": {"claimName": TARGET_ARTIFACTS_CLAIM}},
                        ],
                    },
                },
            },
        }
        s4b_out, _ = self.run_job(TARGET_APP_NS, step4b_job)
        if has_artifacts:
            self.expect(f"STAGE_RECOVERED {recover_rev_id}" in s4b_out,
                        f"expected staging recovery for {recover_rev_id}, got {s4b_out!r}")
            self.expect(f"DECLARED_LOST {lost_rev_id}" in s4b_out,
                        f"expected declare-lost for {lost_rev_id}, got {s4b_out!r}")
            self.expect(f"DECLARED_LOST {recover_rev_id}" not in s4b_out,
                        f"recoverable revision {recover_rev_id} was erroneously declared lost: {s4b_out!r}")
        parse_quota_verify_zero(s4b_out.split("QUOTA_STAGE4_BEGIN\n", 1)[1].split("QUOTA_STAGE4_END", 1)[0])
        vault_before = parse_vault_status(s4b_out.split("VAULT_BEFORE_BEGIN\n", 1)[1].split("VAULT_BEFORE_END", 1)[0])
        vault_after = parse_vault_status(s4b_out.split("VAULT_AFTER_BEGIN\n", 1)[1].split("VAULT_AFTER_END", 1)[0])
        self.expect(vault_before["by_key_id"] == {VAULT_KEY_ID_1: 1} and vault_before["encrypted"] == 1,
                    f"expected 1 encrypted connection on vault-k1 after replay, got {vault_before!r}")
        self.expect(vault_after["by_key_id"] == {VAULT_KEY_ID_2: 1} and vault_after["encrypted"] == 1,
                    f"expected vault rotate to re-seal onto vault-k2, got {vault_after!r}")

        # Exercise ADR 0012 trailing-sequence hazard before Step 5a:
        # 1) Insert an explicit restored row at epoch = 100 and rewind the sequence to allocate 41 (< 100).
        # 2) Run the epoch guard WITHOUT `setval` first to prove it rolls back (does NOT commit epoch 41 or
        #    increment `access_generation`).
        # 3) Run full Step 5a (`setval` + epoch guard), advancing `max(epoch)` cleanly to 101.
        self.psql_superuser(
            TARGET_DB_NS,
            f"INSERT INTO openmettle.login_provider_revisions (epoch, provider_id, revision)"
            f" OVERRIDING SYSTEM VALUE VALUES (100, '{USER_A_IDS['provider']}'::uuid, 'r1');\n"
            "SELECT setval(pg_get_serial_sequence('openmettle.login_provider_revisions', 'epoch'), 40, true);",
        )
        unrepaired_probe_sql = (
            "BEGIN;\n"
            "LOCK TABLE openmettle.login_providers IN SHARE ROW EXCLUSIVE MODE;\n"
            "LOCK TABLE openmettle.login_provider_revisions IN EXCLUSIVE MODE;\n"
            f"{provider_epoch_advance_block_sql(DRILL_OPERATOR_ID)}\n"
            "COMMIT;\n"
        )
        unrepaired_probe = self.kube(
            "--namespace", TARGET_DB_NS, "exec", "--stdin", "deployment/postgres", "--",
            "psql", "-v", "ON_ERROR_STOP=1", "-qtA", "-U", "fixture_admin", "-d", "openmettle",
            input=unrepaired_probe_sql,
            check=False,
        )
        verify_trailing_epoch_probe_failure(unrepaired_probe.returncode, unrepaired_probe.stderr)
        post_rollback_row = self.psql_superuser(
            TARGET_DB_NS,
            f"SELECT (SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id = '{USER_A_IDS['provider']}'::uuid),"
            f" (SELECT access_generation FROM openmettle.login_providers WHERE id = '{USER_A_IDS['provider']}'::uuid),"
            f" (SELECT EXISTS (SELECT 1 FROM openmettle.login_provider_revisions WHERE epoch = 41));",
        ).strip()
        self.expect(
            post_rollback_row == "100|0|f",
            f"trailing-sequence rollback left unexpected provider state: {post_rollback_row!r}",
        )

        # Step 5a, 5b & 5d.1: Run owner SQL inside target namespace as openmettle_owner via 0600 PGPASSFILE.
        psql_bin = "/usr/lib/postgresql/18/bin/psql"
        sql_text = pre_worker_owner_reconcile_sql(
            DRILL_OPERATOR_ID, disabled_principals=primary_state["disabled_principals"]
        )
        owner_sql_script = (
            "umask 077\n"
            "export PGPASSFILE=/tmp/pgpass PGSSLMODE=disable PGGSSENCMODE=disable\n"
            "trap 'rm -f \"$PGPASSFILE\"' EXIT\n"
            'owner_pw="${OWNER_DB_URL#*://openmettle_owner:}"\n'
            'owner_pw="${owner_pw%%@*}"\n'
            'esc() { printf "%s" "$1" | sed \'s/[\\\\:]/\\\\&/g\'; }\n'
            f'printf "%s:5432:openmettle:openmettle_owner:%s\\n" "$(esc "{target_pg_host}")" "$(esc "$owner_pw")" > "$PGPASSFILE"\n'
            'chmod 0600 "$PGPASSFILE"\n'
            f'{psql_bin} -X -w -P pager=off -v ON_ERROR_STOP=1 --single-transaction -qtA '
            f'-h "{target_pg_host}" -p 5432 -U openmettle_owner -d openmettle <<\'EOSQL\'\n'
            f"{sql_text}\n"
            "EOSQL\n"
        )
        owner_sql_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-pre-worker-sql", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": PG_POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "psql", "image": self.pg_client_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", owner_sql_script],
                            "env": [{"name": "OWNER_DB_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                        }],
                        "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}}],
                    },
                },
            },
        }
        sql_out, _ = self.run_job(TARGET_APP_NS, owner_sql_job)
        cancelled_count = parse_cancelled_runs_count(sql_out)
        self.expect(cancelled_count == 2,
                    f"expected 2 parked waiting runs cancelled cleanly, got {sql_out!r}")

        # Step 5d.2: Release eligible terminal-run quota holds as openmettle_worker (`SECRET['worker']`).
        worker_sql_text = worker_quota_release_sql()
        worker_sql_script = (
            "umask 077\n"
            "export PGPASSFILE=/tmp/pgpass PGSSLMODE=disable PGGSSENCMODE=disable\n"
            "trap 'rm -f \"$PGPASSFILE\"' EXIT\n"
            'worker_pw="${WORKER_DB_URL#*://openmettle_worker:}"\n'
            'worker_pw="${worker_pw%%@*}"\n'
            'esc() { printf "%s" "$1" | sed \'s/[\\\\:]/\\\\&/g\'; }\n'
            f'printf "%s:5432:openmettle:openmettle_worker:%s\\n" "$(esc "{target_pg_host}")" "$(esc "$worker_pw")" > "$PGPASSFILE"\n'
            'chmod 0600 "$PGPASSFILE"\n'
            f'{psql_bin} -X -w -P pager=off -v ON_ERROR_STOP=1 --single-transaction -qtA '
            f'-h "{target_pg_host}" -p 5432 -U openmettle_worker -d openmettle <<\'EOSQL\'\n'
            f"{worker_sql_text}\n"
            "EOSQL\n"
        )
        worker_sql_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-worker-quota-release", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": PG_POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "psql-worker", "image": self.pg_client_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", worker_sql_script],
                            "env": [{"name": "WORKER_DB_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["worker"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                        }],
                        "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}}],
                    },
                },
            },
        }
        w_sql_out, _ = self.run_job(TARGET_APP_NS, worker_sql_job)
        released_lines = [ln.strip() for ln in w_sql_out.splitlines() if ln.strip().isdigit()]
        self.expect(released_lines == ["1"],
                    f"expected 1 eligible terminal-run quota reservation released by worker, got {w_sql_out!r}")

        # Step 5e (LAST before starting workloads): release snapshot maintenance using restore_run_id-bound
        # request key, verify `backup status` reports `maintenance_active: false` and all 7 `quota verify`
        # drift counters equal `0` BEFORE scrubbing unpacked dir.
        step5e_script = build_step5e_script(
            DRILL_OPERATOR_ID, restore_run_id, has_artifacts=has_artifacts
        )
        step5e_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-release-maintenance", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "release", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c", step5e_script],
                            "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [
                                {"name": "scratch", "mountPath": RECOVERY_SCRATCH_DIR},
                                {"name": "artifacts", "mountPath": smoke.ARTIFACTS_MOUNT_PATH, "readOnly": True},
                            ],
                        }],
                        "volumes": [
                            {"name": "scratch", "persistentVolumeClaim": {"claimName": TARGET_RECOVERY_SCRATCH_CLAIM}},
                            {"name": "artifacts", "persistentVolumeClaim": {"claimName": TARGET_ARTIFACTS_CLAIM, "readOnly": True}},
                        ],
                    },
                },
            },
        }
        s5e_out, _ = self.run_job(TARGET_APP_NS, step5e_job)
        backup_status = json.loads(
            s5e_out.split("BACKUP_STATUS_BEGIN\n", 1)[1].split("BACKUP_STATUS_END", 1)[0]
        )
        self.expect(backup_status.get("maintenance_active") is False,
                    f"expected maintenance_active=false before starting target workloads, got {backup_status!r}")
        quota_pre = parse_quota_verify_zero(s5e_out.split("QUOTA_VERIFY_BEGIN\n", 1)[1].split("QUOTA_VERIFY_END", 1)[0])

        self.passed(
            "isolated target DB restored, missing payload declared lost, deletion journal replayed, vault rotated, parked runs & quotas reconciled, and maintenance released",
            rebind_barrier_recovered=has_artifacts,
            vault_rotated_to=VAULT_KEY_ID_2,
            cancelled_waiting_runs=2,
            released_terminal_run_holds=1,
            quota_verify=quota_pre,
        )

        # Step 6: Install openmettle-core chart in openmettle-restore-target and verify live invariants.
        target_vals = self.workdir / "target-values.json"
        target_vals.write_text(json.dumps(drill_chart_values(
            self.digests, self.pg_client_parts, db_namespace=TARGET_DB_NS,
            artifacts_existing_claim=TARGET_ARTIFACTS_CLAIM, enable_backup=False,
        )), encoding="utf-8")
        self.verify_identity()
        self.helm_ns(TARGET_APP_NS, "install", RELEASE, str(CHART), "--values", str(target_vals),
                     "--wait=watcher", "--timeout", smoke.HELM_TIMEOUT)
        self.wait_for_inference_ready(TARGET_APP_NS, TARGET_DB_NS)

        fwd = smoke.PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080, namespace=TARGET_APP_NS)
        try:
            status, _ = self.core.http_get(fwd.port, "/readyz")
            self.expect(status == 200, f"target /readyz HTTP {status}")
        finally:
            fwd.close()

        # Live NetworkPolicy isolation probes across target/primary app and DB namespaces.
        probe_results = []
        for p in target_isolation_probe_plan():
            res = self.kube("--namespace", p["namespace"], "exec", f"deployment/{p['workload']}",
                            "--container", p["container"], "--", *p["command"],
                            check=False, timeout=smoke.PROBE_SECONDS + 60)
            outcome = smoke.probe_outcome(res.returncode, res.stdout, res.stderr, p["http"])
            probe_results.append({k: p[k] for k in ("name", "expect", "control")} | {"outcome": outcome})
        smoke.evaluate_probes(probe_results)
        self.passed(
            "NetworkPolicy and PodSecurity isolate restore target and DB namespaces from primary",
            probes=[{"probe": r["name"], "expect": r["expect"], "outcome": r["outcome"]} for r in probe_results],
        )

        return {"manifest": manifest_summary}

    def verify_post_restore_state(
        self, primary_state: dict, recovery_meta: dict, recovery_started_at: datetime
    ) -> None:
        # Mint fresh post-restore sessions for user_a, user_b, disabled user_c, and non-member user_d.
        sid_a2, cookie_a2, hash_a2 = smoke.session_credential(secrets.token_bytes(64))
        sid_b2, cookie_b2, hash_b2 = smoke.session_credential(secrets.token_bytes(64))
        sid_c2, cookie_c2, hash_c2 = smoke.session_credential(secrets.token_bytes(64))
        sid_d2, cookie_d2, hash_d2 = smoke.session_credential(secrets.token_bytes(64))
        self.secrets_to_redact.extend([cookie_a2, cookie_b2, cookie_c2, cookie_d2])
        self.psql_superuser(
            TARGET_DB_NS,
            fresh_post_restore_session_sql(USER_A_IDS, sid_a2, smoke.b64url(secrets.token_bytes(32)), hash_a2, "target-a")
            + fresh_post_restore_session_sql(USER_B_IDS, sid_b2, smoke.b64url(secrets.token_bytes(32)), hash_b2, "target-b")
            + fresh_post_restore_session_sql(USER_C_IDS, sid_c2, smoke.b64url(secrets.token_bytes(32)), hash_c2, "target-c")
            + fresh_post_restore_session_sql(USER_D_IDS, sid_d2, smoke.b64url(secrets.token_bytes(32)), hash_d2, "target-d"),
        )

        # Give target worker 3 sweeps to prove zero unsolicited inference OR MCP write (/tools/send)
        # calls from parked runs/write intents, then fire a live positive control from the target
        # worker pod to the exact MCP destination URL to prove observation reachability.
        time.sleep(3.0)
        self.expect(self.standin_records(TARGET_DB_NS) == [],
                    "target worker emitted unsolicited upstream gateway calls after restore")
        self.expect(self.standin_mcp_records(TARGET_DB_NS) == [],
                    "target worker replayed unsolicited MCP write calls to /tools/send after restore")

        mcp_ctrl_body = json.dumps({"control": "worker-mcp-reachability"}, separators=(",", ":"))
        mcp_ctrl_res = self.kube(
            "--namespace", TARGET_APP_NS, "exec", f"deployment/{FULLNAME}-worker",
            "--container", "worker", "--",
            *mcp_post_probe_command(f"{smoke.STANDIN}.{TARGET_DB_NS}.svc.cluster.local", smoke.STANDIN_PORT, "/tools/send", mcp_ctrl_body),
            check=False, timeout=smoke.PROBE_SECONDS + 30,
        )
        self.expect(
            smoke.probe_outcome(mcp_ctrl_res.returncode, mcp_ctrl_res.stdout, mcp_ctrl_res.stderr, True) == "connected",
            f"target worker positive control POST /tools/send failed: rc={mcp_ctrl_res.returncode}, out={mcp_ctrl_res.stdout!r}, err={mcp_ctrl_res.stderr!r}",
        )
        mcp_ctrl_records = self.standin_mcp_records(TARGET_DB_NS)
        self.expect(
            len(mcp_ctrl_records) == 1 and mcp_ctrl_records[0].get("body") == {"control": "worker-mcp-reachability"},
            f"expected positive control recorded at /_recorded_mcp, got {mcp_ctrl_records!r}",
        )

        fwd = smoke.PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080, namespace=TARGET_APP_NS)
        try:
            # 1. Pre-restore session cookies AND post-backup disabled user_c's fresh session must return 401.
            for rejected_cookie in (self.cookie_a_pre, self.cookie_b_pre, self.cookie_c_pre, self.cookie_d_pre, cookie_c2):
                self.api_call(fwd.port, rejected_cookie, "GET", "/v1/quotas/personal", 401)
            self.api_call(fwd.port, cookie_c2, "GET", f"/v1/projects/{primary_state['project_id']}", 401)
            # Active non-member user_d is authenticated (200 on personal quotas), while the post-backup
            # family-policy disabled model returns 403 policy on POST /v1/runs.
            self.api_json(fwd.port, cookie_d2, "GET", "/v1/quotas/personal", 200)
            d_conv = self.api_json(fwd.port, cookie_d2, "POST", "/v1/conversations", 201,
                                   key="drill-userd-conv", json_body={})
            _, denied_model_body = self.api_call(
                fwd.port, cookie_d2, "POST", "/v1/runs", 403,
                key="drill-userd-disabled-model",
                json_body=smoke.run_request(d_conv, str(uuid.uuid4())),
            )
            self.expect(json.loads(denied_model_body).get("code") == "policy",
                        f"expected 403 policy for disabled model, got {denied_model_body!r}")

            # 2. Surviving personal conversation, completed run history, and personal artifact ownership/404 isolation.
            p_conv_id = primary_state["personal_conv"]["conversation_id"]
            p_branch_id = primary_state["personal_conv"]["branch_id"]
            self.api_json(fwd.port, cookie_a2, "GET", f"/v1/conversations/{p_conv_id}", 200)
            self.api_call(fwd.port, cookie_b2, "GET", f"/v1/conversations/{p_conv_id}", 404)
            msgs = self.api_json(fwd.port, cookie_a2, "GET",
                                 f"/v1/conversations/{p_conv_id}/branches/{p_branch_id}/messages", 200)
            self.expect(smoke.STANDIN_EXPECTED_CONTENT in json.dumps(msgs),
                        "restored personal conversation lacks pre-backup assistant message")

            keep = primary_state["art_keep"]
            keep_path = f"/v1/artifacts/{keep['artifact_id']}/revisions/{keep['revision_id']}"
            self.api_json(fwd.port, cookie_a2, "GET", keep_path, 200)
            _, keep_bytes = self.api_call(fwd.port, cookie_a2, "GET", f"{keep_path}/content", 200)
            self.expect(keep_bytes == b"drill-personal-keep-bytes\n", "corrupted surviving personal artifact bytes")
            self.api_call(fwd.port, cookie_b2, "GET", keep_path, 404)
            self.api_call(fwd.port, cookie_b2, "GET", f"{keep_path}/content", 404)

            # 3. Surviving shared project: project_conv readable by user_a & Viewer user_b (200), 404 for
            #    authenticated non-member user_d; shared artifact downloadable by user_b (200) and Viewer writes 403.
            proj_conv_id = primary_state["project_conv"]["conversation_id"]
            self.api_json(fwd.port, cookie_a2, "GET", f"/v1/conversations/{proj_conv_id}", 200)
            self.api_json(fwd.port, cookie_b2, "GET", f"/v1/conversations/{proj_conv_id}", 200)
            self.api_call(fwd.port, cookie_d2, "GET", f"/v1/conversations/{proj_conv_id}", 404)

            proj_art = primary_state["art_project"]
            proj_art_path = f"/v1/artifacts/{proj_art['artifact_id']}/revisions/{proj_art['revision_id']}"
            _, owner_proj_bytes = self.api_call(fwd.port, cookie_a2, "GET", f"{proj_art_path}/content", 200)
            self.expect(owner_proj_bytes == b"drill-project-shared-bytes\n",
                        "project owner failed to download restored shared project artifact")
            _, proj_bytes = self.api_call(fwd.port, cookie_b2, "GET", f"{proj_art_path}/content", 200)
            self.expect(proj_bytes == b"drill-project-shared-bytes\n", "viewer failed to download shared project artifact")
            self.api_call(fwd.port, cookie_d2, "GET", f"{proj_art_path}/content", 404)
            boundary_deny = f"drill-boundary-{secrets.token_hex(4)}"
            _, deny_body = self.api_call(
                fwd.port, cookie_b2, "POST",
                f"/v1/artifacts?max_bytes={smoke.ARTIFACT_MAX_BYTES}&scope_id={primary_state['project_scope_id']}",
                403, key="drill-viewer-write-denied",
                raw_body=smoke.multipart_form(boundary_deny, b"denied"), boundary=boundary_deny,
            )
            self.expect(json.loads(deny_body).get("code") == "policy", "viewer write did not return 403 policy")

            # 4. Recoverable staging payload (`art_stage_recover`): recovered intact from staging, `200` + exact
            #    bytes for owner, `404` for user_b; declared-lost payload (`art_to_lose`): `200` state="lost" +
            #    `410 Gone` `payload_lost` for owner; `404` for user_b.
            stage_rec = primary_state["art_stage_recover"]
            stage_rec_path = f"/v1/artifacts/{stage_rec['artifact_id']}/revisions/{stage_rec['revision_id']}"
            stage_rec_meta = self.api_json(fwd.port, cookie_a2, "GET", stage_rec_path, 200)
            self.expect(stage_rec_meta.get("state") == "active",
                        f"expected staging-recovered revision state='active', got {stage_rec_meta!r}")
            _, stage_rec_bytes = self.api_call(fwd.port, cookie_a2, "GET", f"{stage_rec_path}/content", 200)
            self.expect(stage_rec_bytes == b"drill-recoverable-from-staging-bytes\n",
                        "corrupted staging-recovered artifact bytes")
            self.api_call(fwd.port, cookie_b2, "GET", stage_rec_path, 404)
            self.api_call(fwd.port, cookie_b2, "GET", f"{stage_rec_path}/content", 404)

            lost = primary_state["art_to_lose"]
            lost_path = f"/v1/artifacts/{lost['artifact_id']}/revisions/{lost['revision_id']}"
            lost_meta = self.api_json(fwd.port, cookie_a2, "GET", lost_path, 200)
            self.expect(lost_meta.get("state") == "lost" and lost_meta.get("lost_at"),
                        f"declared-lost revision metadata unexpected: {lost_meta!r}")
            _, gone_body = self.api_call(fwd.port, cookie_a2, "GET", f"{lost_path}/content", 410)
            self.expect(json.loads(gone_body).get("code") == "payload_lost",
                        f"expected 410 payload_lost problem, got {gone_body!r}")
            self.api_call(fwd.port, cookie_b2, "GET", lost_path, 404)
            self.api_call(fwd.port, cookie_b2, "GET", f"{lost_path}/content", 404)

            # 5. Post-backup purged revision must remain purged (409 conflict on /content) and retained
            #    revision must preserve its exact pre-backup purge_after deadline.
            purged = primary_state["art_post_purge"]
            purged_rev_path = f"/v1/artifacts/{purged['artifact_id']}/revisions/{purged['revision_id']}"
            purged_meta = self.api_json(fwd.port, cookie_a2, "GET", purged_rev_path, 200)
            self.expect(purged_meta.get("state") == "purged",
                        f"expected post-backup deleted revision state='purged', got {purged_meta!r}")
            _, purged_content_err = self.api_call(fwd.port, cookie_a2, "GET", f"{purged_rev_path}/content", 409)
            self.expect(json.loads(purged_content_err).get("code") == "conflict",
                        f"expected 409 conflict on purged revision /content, got {purged_content_err!r}")

            dl = primary_state["art_deadline"]
            dl_meta = self.api_json(fwd.port, cookie_a2, "GET",
                                    f"/v1/artifacts/{dl['artifact_id']}/revisions/{dl['revision_id']}", 200)
            self.expect(dl_meta.get("state") == "retained"
                        and dl_meta.get("purge_after") == primary_state["retained_purge_after"],
                        f"retained purge_after drifted across restore: {dl_meta!r}")

            # 6. Connections: conn_keep stays authorized; conn_revoke share revoked (404 for user_b) and disconnected.
            ck = self.api_json(fwd.port, cookie_a2, "GET", f"/v1/connections/{primary_state['conn_keep_id']}", 200)
            cr = self.api_json(fwd.port, cookie_a2, "GET", f"/v1/connections/{primary_state['conn_revoke_id']}", 200)
            self.expect(ck.get("state") == "authorized" and cr.get("state") == "disconnected",
                        f"unexpected restored connection states: keep={ck.get('state')}, revoke={cr.get('state')}")
            self.api_call(fwd.port, cookie_b2, "GET", f"/v1/connections/{primary_state['conn_revoke_id']}", 404)

            # 7. Stale approval cannot revive ("decision": "approve" -> 409 conflict) and parked runs are cancelled.
            parked = primary_state["parked"]
            w_run = self.api_json(fwd.port, cookie_a2, "GET", f"/v1/runs/{parked['waiting_run_id']}", 200)
            i_run = self.api_json(fwd.port, cookie_a2, "GET", f"/v1/runs/{parked['intent_run_id']}", 200)
            self.expect(w_run.get("state") == "cancelled" and i_run.get("state") == "cancelled",
                        f"parked runs not cancelled on target: {w_run.get('state')}, {i_run.get('state')}")
            pending_approvals = self.api_json(fwd.port, cookie_a2, "GET",
                                              f"/v1/runs/{parked['waiting_run_id']}/approvals", 200)
            self.expect(pending_approvals.get("items") == [],
                        f"cancelled run still lists pending approvals: {pending_approvals!r}")
            _, stale_decision = self.api_call(
                fwd.port, cookie_a2, "POST",
                f"/v1/runs/{parked['waiting_run_id']}/approvals/{parked['waiting_approval_id']}/decision",
                409, key="drill-stale-approval-approve",
                json_body={"decision": "approve", "binding_digest": parked["waiting_binding_digest"]},
            )
            self.expect(json.loads(stale_decision).get("code") == "conflict",
                        f"stale approval decision did not fail with 409 conflict: {stale_decision!r}")

            # 8. Verify the pre-backup completed run's 18-token settlement survived restore on target,
            #    then execute one fresh post-restore inference turn to prove live runtime health.
            restored_settlement = smoke.evaluate_settled_round(
                self.psql_superuser(TARGET_DB_NS, smoke.settled_round_sql(primary_state["completed_run_id"]))
            )
            self.expect(
                restored_settlement is not None
                and restored_settlement.get("settled_units") == smoke.STANDIN_EXPECTED_SETTLED_UNITS,
                f"restored completed run settlement missing or mismatched on target: {restored_settlement!r}",
            )

            post_conv = self.api_json(fwd.port, cookie_a2, "POST", "/v1/conversations", 201,
                                      key="drill-post-restore-conv", json_body={})
            post_run = self.api_json(fwd.port, cookie_a2, "POST", "/v1/runs", 201,
                                     key="drill-post-restore-run",
                                     json_body=smoke.run_request(post_conv, str(uuid.uuid4())))
            self.wait_for_run_succeeded(
                fwd.port, cookie_a2, post_run["run_id"],
                "post-restore target turn to succeed", TARGET_DB_NS, timeout=60,
            )
            self.wait_for(
                "post-restore gateway settlement",
                lambda: smoke.evaluate_settled_round(
                    self.psql_superuser(TARGET_DB_NS, smoke.settled_round_sql(post_run["run_id"]))
                ),
                timeout=30, interval=0.5,
            )
        finally:
            fwd.close()

        self.expect(len(self.standin_records(TARGET_DB_NS)) == 1,
                    "expected exactly 1 upstream gateway call from the fresh post-restore turn")
        self.expect(len(self.standin_mcp_records(TARGET_DB_NS)) == 1,
                    "expected no additional MCP write calls beyond the single positive control")

        # Verify SQL invariants on target: write intent outcome_unknown (rev 1), exact post-backup
        # run_events appended in order & contiguous with runs.last_event_sequence, waiting_run quota
        # released vs intent_run 25-token quota held, disconnected ciphertext NULL, exact microsecond
        # purge_after match, restore_gate open, maintenance false.
        purged_rev_id = primary_state["art_post_purge"]["revision_id"]
        purged_res_id = primary_state["rev_meta"][purged_rev_id]["reservation_id"]
        dl_rev_id = primary_state["art_deadline"]["revision_id"]
        expected_purge_after_us = primary_state["rev_meta"][dl_rev_id]["purge_after_us"]
        w_run_id = primary_state["parked"]["waiting_run_id"]
        i_run_id = primary_state["parked"]["intent_run_id"]
        i_op_id = primary_state["parked"]["intent_operation_id"]
        w_expected_seq = primary_state["pre_run_seq"][w_run_id] + 1
        i_unresolved_seq = primary_state["pre_run_seq"][i_run_id] + 1
        i_expected_seq = primary_state["pre_run_seq"][i_run_id] + 2

        sched = primary_state["pre_family_schedule"]
        expected_family_state = (
            f"{sched['zone']}:{sched['quiet_start']}:{sched['quiet_end']}:"
            f"{sched['study_start']}:{sched['study_end']}:t:2"
        )
        sql_checks = self.psql_superuser(
            TARGET_DB_NS,
            f"SELECT (SELECT outcome || ':' || revision::text FROM openmettle.operations WHERE id = '{i_op_id}'::uuid),"
            f" (SELECT target FROM openmettle.operations WHERE id = '{i_op_id}'::uuid),"
            f" (SELECT coalesce(("
            f"    SELECT fp.zone || ':' || coalesce(fp.quiet_start_minute::text, '') || ':'"
            f"        || coalesce(fp.quiet_end_minute::text, '') || ':'"
            f"        || coalesce(fp.study_start_minute::text, '') || ':'"
            f"        || coalesce(fp.study_end_minute::text, '') || ':'"
            f"        || fp.override_group_schedules::text || ':'"
            f"        || (SELECT count(*)::text FROM openmettle.family_policy_models fpm"
            f"             WHERE fpm.policy_id = fp.id AND fpm.active AND fpm.model = '{smoke.CATALOG_MODEL}'"
            f"               AND fpm.rule_kind IN ('study_allow', 'disabled'))"
            f"      FROM openmettle.family_policies fp"
            f"     WHERE fp.grantee_kind = 'user' AND fp.grantee_user_id = '{USER_D_IDS['user']}'::uuid AND fp.active"
            f" ), '')),"
            f" (SELECT encryption_key_id IS NULL AND access_ciphertext IS NULL AND refresh_ciphertext IS NULL"
            f"    FROM openmettle.external_connections WHERE id = '{primary_state['conn_revoke_id']}'::uuid),"
            f" (SELECT (extract(epoch FROM purge_after) * 1000000)::bigint"
            f"    FROM openmettle.artifact_revisions WHERE id = '{dl_rev_id}'::uuid),"
            f" (SELECT state FROM openmettle.artifact_revisions WHERE id = '{purged_rev_id}'::uuid),"
            " (SELECT open FROM openmettle.restore_reconciliation_gate),"
            " (SELECT maintenance_active FROM openmettle.backup_maintenance_gate),"
            f" (SELECT last_event_sequence || ':' || (SELECT count(*) FROM openmettle.run_events WHERE run_id = r.id)"
            f"         || ':' || (SELECT coalesce(min(sequence), 0) FROM openmettle.run_events WHERE run_id = r.id)"
            f"         || ':' || (SELECT coalesce(max(sequence), 0) FROM openmettle.run_events WHERE run_id = r.id)"
            f"    FROM openmettle.runs r WHERE id = '{w_run_id}'::uuid),"
            f" (SELECT append_key || ':' || format FROM openmettle.run_events"
            f"    WHERE run_id = '{w_run_id}'::uuid AND sequence = {w_expected_seq}),"
            f" (SELECT last_event_sequence || ':' || (SELECT count(*) FROM openmettle.run_events WHERE run_id = r.id)"
            f"         || ':' || (SELECT coalesce(min(sequence), 0) FROM openmettle.run_events WHERE run_id = r.id)"
            f"         || ':' || (SELECT coalesce(max(sequence), 0) FROM openmettle.run_events WHERE run_id = r.id)"
            f"    FROM openmettle.runs r WHERE id = '{i_run_id}'::uuid),"
            f" (SELECT append_key FROM openmettle.run_events"
            f"    WHERE run_id = '{i_run_id}'::uuid AND sequence = {i_unresolved_seq}),"
            f" (SELECT append_key || ':' || format FROM openmettle.run_events"
            f"    WHERE run_id = '{i_run_id}'::uuid AND sequence = {i_expected_seq}),"
            f" (SELECT state || ':' || held_units::text FROM openmettle.quota_reservations"
            f"    WHERE run_id = '{w_run_id}'::uuid AND gateway_request_id IS NULL AND resource_kind = 'usage_tokens'),"
            f" (SELECT state || ':' || held_units::text FROM openmettle.quota_reservations"
            f"    WHERE run_id = '{i_run_id}'::uuid AND gateway_request_id IS NULL AND resource_kind = 'usage_tokens'),"
            f" (SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id = '{USER_A_IDS['provider']}'::uuid),"
            f" (SELECT access_generation FROM openmettle.login_providers WHERE id = '{USER_A_IDS['provider']}'::uuid);",
        ).strip()
        expected_sql = (
            f"outcome_unknown:1|{target_mcp_url()}|{expected_family_state}|t|{expected_purge_after_us}|purged|t|f|"
            f"{w_expected_seq}:{w_expected_seq}:1:{w_expected_seq}|run-terminal:openmettle.run-cancelled|"
            f"{i_expected_seq}:{i_expected_seq}:1:{i_expected_seq}|unresolved-write:{i_op_id}|"
            "run-terminal:openmettle.run-cancelled|released:0|held:25|101|1"
        )
        self.expect(
            sql_checks == expected_sql,
            f"unexpected post-restore SQL invariants: got {sql_checks!r}, expected {expected_sql!r}",
        )

        api_pods = self.kube_json("--namespace", TARGET_APP_NS, "get", "pods", "--selector",
                                  f"app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component=api")["items"]
        target_api_pod = api_pods[0]["metadata"]["name"]
        resurrected_check = self.kube(
            "--namespace", TARGET_APP_NS, "exec", target_api_pod, "--container", "api", "--",
            "test", "!", "-e", f"{smoke.ARTIFACTS_MOUNT_PATH}/revisions/{purged_res_id}",
        )
        self.expect(resurrected_check.returncode == 0, "purged artifact file resurrected on target PVC")

        # Post-restore quota verify + journal export Job on live target.
        admin_ref = self.report["images"]["admin"]["reference"]
        labels = {"openmettle.dev/environment": "dev", RUN_LABEL: self.run_id}
        post_verify_job = {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": "openmettle-drill-post-verify", "namespace": TARGET_APP_NS, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": 120,
                "template": {
                    "metadata": {"labels": {**labels, RECOVERY_DB_CLIENT_LABEL: "true"}},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                        "securityContext": POD_SEC_CONTEXT,
                        "containers": [{
                            "name": "verify", "image": admin_ref, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-eu", "-c",
                                        f'openmettle-admin quota verify "{smoke.ARTIFACTS_MOUNT_PATH}"\n'
                                        "openmettle-admin journal export /tmp/post-restore.export\n"
                                        'grep -q "artifact_revision.lost" /tmp/post-restore.export\n'],
                            "env": [{"name": "OPENMETTLE_ADMIN_DATABASE_URL",
                                     "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["migrate"], "key": "url"}}}],
                            "securityContext": CONTAINER_SEC_CONTEXT,
                            "volumeMounts": [
                                {"name": "artifacts", "mountPath": smoke.ARTIFACTS_MOUNT_PATH, "readOnly": True},
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                        }],
                        "volumes": [
                            {"name": "artifacts", "persistentVolumeClaim": {"claimName": TARGET_ARTIFACTS_CLAIM}},
                            {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
                        ],
                    },
                },
            },
        }
        pv_out, _ = self.run_job(TARGET_APP_NS, post_verify_job)
        quota_post = parse_quota_verify_zero(pv_out)

        # Confirm primary environment remained completely untouched (rev_to_lose still active & 200 on primary).
        fwd_pri = smoke.PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080, namespace=PRIMARY_APP_NS)
        try:
            lost_on_pri = primary_state["art_to_lose"]
            _, pri_bytes = self.api_call(
                fwd_pri.port, self.cookie_a_pre, "GET",
                f"/v1/artifacts/{lost_on_pri['artifact_id']}/revisions/{lost_on_pri['revision_id']}/content", 200,
            )
            self.expect(pri_bytes == b"drill-unrecoverable-payload-bytes\n",
                        "isolated restore mutated or broke primary artifact store")
        finally:
            fwd_pri.close()

        # Full RTO span: recovery_started_at (before target provisioning/media staging) -> recovery_completed_at
        # (after final post-restore HTTP/SQL acceptance, quota verify, and non-interference check).
        recovery_completed_at = datetime.now(timezone.utc)
        rpo_rto = evaluate_rpo_rto(
            recovery_meta["manifest"]["quiesced_at"],
            primary_state["cutover_at"],
            recovery_started_at,
            recovery_completed_at,
            report=self.report,
        )
        self.passed(
            "post-restore HTTP/SQL invariants, revoked principal denial, non-revival of approvals/intents, primary non-interference, and RPO/RTO bounds verified",
            quota_verify=quota_post,
            rpo_rto=rpo_rto,
        )

    def execute(self):
        self.preflight()
        self.build_and_load_images()
        self.pin_digests()
        primary_state = self.setup_primary_and_capture()
        recovery_started_at = datetime.now(timezone.utc)
        self.provision_target_and_stage_media(primary_state)
        recovery_meta = self.execute_target_restore(primary_state)
        self.verify_post_restore_state(primary_state, recovery_meta, recovery_started_at)
        self.report["result"] = "passed"

    def cleanup(self):
        if self.cluster_attempted:
            deleted = self.runner(["kind", "delete", "cluster", "--name", self.name,
                                   "--kubeconfig", str(self.kubeconfig)], check=False, timeout=300)
            if deleted.returncode != 0:
                self.report["cleanup_errors"].append(
                    f"kind delete cluster exited {deleted.returncode}: "
                    f"{smoke.redacted_tail(deleted.stderr.strip(), self.secrets_to_redact, smoke.STDERR_TAIL)}"
                )
        for image in self.built_images:
            removed = self.runner(["docker", "image", "rm", "--force", image], check=False, timeout=120)
            if removed.returncode != 0:
                self.report["cleanup_errors"].append(f"docker image rm {image} exited {removed.returncode}")


def _existing_dir(raw: str) -> Path:
    path = Path(raw)
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"not a directory: {raw}")
    return path


def _interrupt_with_cleanup(signum, _frame):
    raise KeyboardInterrupt(f"signal {signum}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-dir", type=_existing_dir, required=True,
                        help="clean openmettle-core checkout at CORE_COMMIT")
    parser.add_argument("--tools-dir", type=_existing_dir,
                        help="directory with pinned kind and kubectl on PATH first")
    parser.add_argument("--helm-dir", type=_existing_dir,
                        help="directory with pinned helm on PATH first")
    parser.add_argument("--report", type=Path, help="write the non-secret JSON summary here")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        smoke.check_core_checkout(*smoke.core_checkout_state(args.core_dir))
        core = smoke.load_core(args.core_dir)
    except smoke.Refusal as exc:
        _log(f"refused: {exc}")
        return 3

    workdir = Path(tempfile.mkdtemp(prefix="openmettle-restore-drill-"))
    drill = None
    previous_handlers = {}
    try:
        drill = RestoreDrill(core, os.environ, args.core_dir, args.tools_dir, args.helm_dir, workdir)
        for sig in smoke.CLEANUP_SIGNALS:
            previous_handlers[sig] = signal.signal(sig, _interrupt_with_cleanup)
        drill.execute()
    except Exception as exc:
        if drill is not None and isinstance(exc, (smoke.Refusal, core.Refusal)) and not drill.cluster_attempted:
            _log(f"refused: {exc}")
            return 3
        if drill is None:
            _log(f"refused: {exc}")
            return 3
        drill.report["error"] = smoke.redact(str(exc), drill.secrets_to_redact)
        _log(f"FAILED: {drill.report['error']}")
    except BaseException as exc:
        if drill is not None:
            drill.report["error"] = f"interrupted ({type(exc).__name__})"
            _log(f"FAILED: {drill.report['error']}")
        else:
            raise
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
        try:
            if drill is not None:
                drill.cleanup()
                summary = json.dumps(build_drill_summary(drill.report), indent=2) + "\n"
                smoke.assert_no_secrets(summary, drill.secrets_to_redact)
                if args.report:
                    args.report.write_text(summary, encoding="utf-8")
                sys.stdout.write(summary)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    return 0 if drill.report["result"] == "passed" and not drill.report["cleanup_errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
