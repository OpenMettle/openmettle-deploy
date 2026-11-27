"""Cluster-free unit tests for the isolated-target restore drill harness (tests/kind/restore_drill.py)."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import restore_drill  # noqa: E402
import smoke  # noqa: E402
import test_smoke  # noqa: E402

HELM = os.environ.get("HELM", "helm")
DIGESTS = {role: "sha256:" + str(i) * 64 for i, role in enumerate(smoke.ROLES, start=1)}
PG_CLIENT = {"registry": "docker.io", "repository": "library/postgres", "digest": "sha256:" + "9" * 64}
GENESIS = "0" * 64
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64

SAMPLE_JOURNAL = f"""\
openmettle.deletion_journal.export/1
origin 1795450000000000
lifecycle_origin 1795450000000100
lifecycle_baseline {GENESIS}
connection_origin 1795450000000200
1 1795450010000000 artifact_revision.purged 11111111-1111-4111-8111-111111111111 22222222-2222-4222-8222-222222222222 1795450009000000 1795450010000000 {DIGEST_A} 1 {DIGEST_B}
watermark 1795450000000000 1 {DIGEST_B} 1795450020000000
sha256 {"c" * 64}
"""


class JournalAndRebindParserTest(unittest.TestCase):
    def test_parses_all_watermarks_and_builds_restore_lock_args(self):
        wm = restore_drill.parse_journal_export_watermarks(SAMPLE_JOURNAL)
        self.assertEqual(wm["origin_us"], 1795450000000000)
        self.assertEqual(wm["lifecycle_origin_us"], 1795450000000100)
        self.assertEqual(wm["lifecycle_baseline_digest"], GENESIS)
        self.assertEqual(wm["connection_origin_us"], 1795450000000200)
        self.assertEqual(wm["required_seq"], 1)
        self.assertEqual(wm["required_digest"], DIGEST_B)

        args = restore_drill.restore_lock_args(wm, export_complete=True)
        self.assertEqual(
            args,
            [
                "restore", "lock",
                "--required-origin", "1795450000000000",
                "--required-lifecycle-origin", "1795450000000100",
                "--required-lifecycle-baseline-digest", GENESIS,
                "--required-connection-origin", "1795450000000200",
                "--required-seq", "1",
                "--required-digest", DIGEST_B,
                "--export-complete",
            ],
        )

    def test_rejects_malformed_or_unpaired_journal_headers(self):
        with self.assertRaisesRegex(restore_drill.DrillFailure, "invalid deletion journal"):
            restore_drill.parse_journal_export_watermarks("bad-header\n")
        unpaired = (
            "openmettle.deletion_journal.export/1\n"
            "origin 100\n"
            "lifecycle_origin 200\n"
            f"watermark 100 0 {GENESIS} 300\n"
            f"sha256 {GENESIS}\n"
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "unpaired"):
            restore_drill.parse_journal_export_watermarks(unpaired)

    def test_parses_failed_rebind_barrier_and_rejects_missing_failure_line(self):
        res_id = "11111111-1111-4111-8111-111111111111"
        barrier = "22222222-2222-4222-8222-222222222222"
        stdout = f"rebound 5, emptied 0, unchanged 0, quarantined 0, failed 1\nfailed {res_id}: missing revision\n"
        stderr = f"the volume stays closed; resolve what is reported and re-run with --replace-adoption-run {barrier}\n"
        self.assertEqual(restore_drill.parse_failed_rebind(stdout, stderr, res_id), barrier)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "missing revision"):
            restore_drill.parse_failed_rebind("rebound 5, failed 0\n", stderr, res_id)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "replace-adoption-run"):
            restore_drill.parse_failed_rebind(stdout, "no barrier here\n", res_id)


class QuotaVaultManifestAndRpoRtoTest(unittest.TestCase):
    def test_quota_verify_requires_all_seven_counters_zero(self):
        ok_line = (
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0\n"
        )
        parsed = restore_drill.parse_quota_verify_zero(ok_line)
        self.assertEqual(sum(parsed.values()), 0)
        bad_line = ok_line.replace("file mismatches 0", "file mismatches 1")
        with self.assertRaisesRegex(restore_drill.DrillFailure, "accounting drift non-zero"):
            restore_drill.parse_quota_verify_zero(bad_line)

    def test_parses_vault_status_output(self):
        out = "connections 2, encrypted 1\nstate authorized 1\nstate disconnected 1\nkey_id vault-k2 1\n"
        st = restore_drill.parse_vault_status(out)
        self.assertEqual(st["connections"], 2)
        self.assertEqual(st["encrypted"], 1)
        self.assertEqual(st["by_key_id"], {"vault-k2": 1})

    def test_manifest_preflight_checks_schema_and_vault_key_inventory(self):
        manifest = {
            "format": "openmettle-backup-manifest/v1",
            "backup_run_id": "33333333-3333-4333-8333-333333333333",
            "schema_version": 45,
            "quiesced_at": "2026-11-27T08:00:00.000000Z",
            "deletion_journal": {"journal_seq": 3},
            "vault_required_key_ids": ["vault-k1"],
            "artifact_volume": {"revision_count": 6},
        }
        summary = restore_drill.evaluate_manifest_preflight(
            manifest, max_schema=45, available_vault_keys={"vault-k1", "vault-k2"}
        )
        self.assertEqual(summary["schema_version"], 45)
        self.assertEqual(summary["vault_required_key_ids"], ["vault-k1"])

        with self.assertRaisesRegex(restore_drill.DrillFailure, "lacks required key IDs"):
            restore_drill.evaluate_manifest_preflight(manifest, max_schema=45, available_vault_keys={"vault-k2"})

        newer = {**manifest, "schema_version": 46}
        with self.assertRaisesRegex(restore_drill.DrillFailure, "incompatible backup schema_version"):
            restore_drill.evaluate_manifest_preflight(newer, max_schema=45)

    def test_rpo_and_rto_bounds_accept_within_targets_and_refuse_breaches(self):
        t0 = datetime(2026, 11, 27, 8, 0, 0, tzinfo=timezone.utc)
        cutover = t0 + timedelta(hours=2)
        rec_start = cutover + timedelta(minutes=1)
        rec_done = rec_start + timedelta(minutes=12)
        metrics = restore_drill.evaluate_rpo_rto(
            "2026-11-27T08:00:00.000000Z", cutover, rec_start, rec_done
        )
        self.assertTrue(metrics["rpo_met"])
        self.assertTrue(metrics["rto_met"])
        self.assertEqual(metrics["restored_data_age_seconds"], 7200.0)
        self.assertEqual(metrics["recovery_duration_seconds"], 720.0)

        with self.assertRaisesRegex(restore_drill.DrillFailure, "RPO breached"):
            restore_drill.evaluate_rpo_rto(
                "2026-11-27T08:00:00.000000Z",
                t0 + timedelta(hours=25),
                rec_start,
                rec_done,
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "RTO breached"):
            restore_drill.evaluate_rpo_rto(
                "2026-11-27T08:00:00.000000Z",
                cutover,
                rec_start,
                rec_start + timedelta(hours=5),
            )

    def test_pre_worker_sql_uses_revoked_cancel_reason_and_releases_quotas(self):
        sql = restore_drill.pre_worker_reconcile_sql(restore_drill.DRILL_OPERATOR_ID)
        self.assertIn("coalesce(r.cancel_reason, 'revoked')", sql)
        self.assertIn("openmettle.quota_release_terminal_runs", sql)
        self.assertIn("access_generation = p.access_generation + 1", sql)
        self.assertNotIn("approval_wait_id = NULL", sql)


class ChartAndManifestValuesTest(unittest.TestCase):
    def test_primary_and_target_drill_values_render_cleanly_with_helm(self):
        if shutil.which(HELM) is None:
            self.skipTest(f"{HELM} not installed")
        catalog = smoke.smoke_catalog(test_smoke.CATALOG_FIXTURE)
        self.assertIn("models", restore_drill.drill_inference_document(restore_drill.PRIMARY_APP_NS, catalog))
        for is_target in (False, True):
            vals = restore_drill.drill_chart_values(
                DIGESTS,
                PG_CLIENT,
                db_namespace=restore_drill.TARGET_DB_NS if is_target else restore_drill.PRIMARY_DB_NS,
                artifacts_existing_claim=restore_drill.TARGET_ARTIFACTS_CLAIM if is_target else None,
                enable_backup=not is_target,
            )
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
                json.dump(vals, handle)
                vals_path = handle.name
            try:
                res = subprocess.run(
                    [HELM, "template", smoke.RELEASE, str(smoke.CHART), "--values", vals_path],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                docs = [d for d in yaml.safe_load_all(res.stdout) if d]
                cronjobs = [d for d in docs if d.get("kind") == "CronJob"]
                self.assertEqual(len(cronjobs), 0 if is_target else 1)
            finally:
                Path(vals_path).unlink(missing_ok=True)

    def test_environment_manifests_enforce_pod_security_restricted_and_default_deny(self):
        catalog = smoke.smoke_catalog(test_smoke.CATALOG_FIXTURE)
        creds = {k: "x" * 32 for k in ("admin", *smoke.DB_LOGINS)}
        creds["auth_login_key"] = base64.b64encode(b"1" * 32).decode("ascii")
        creds["auth_cursor_key"] = base64.b64encode(b"2" * 32).decode("ascii")
        bundle = restore_drill.environment_manifests(
            app_ns=restore_drill.TARGET_APP_NS,
            db_ns=restore_drill.TARGET_DB_NS,
            postgres_image="postgres:18.1-bookworm@sha256:" + "9" * 64,
            standin_image="openmettle-smoke.invalid/openmettle/sglang-standin:drill-1",
            passwords=creds,
            catalog=catalog,
            vault_keys=[("vault-k1", "vault-k1.key", creds["auth_login_key"])],
            backup_key_b64=creds["auth_cursor_key"],
            wrong_backup_key_b64=creds["auth_login_key"],
            is_target=True,
            run_id="deadbeef",
        )
        ns = next(i for i in bundle["items"] if i["kind"] == "Namespace" and i["metadata"]["name"] == restore_drill.TARGET_APP_NS)
        self.assertEqual(ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")
        netpols = [i["metadata"]["name"] for i in bundle["items"] if i["kind"] == "NetworkPolicy"]
        self.assertEqual(sorted(netpols), sorted([smoke.NAMESPACE_DENY, restore_drill.RECOVERY_NETPOL]))

    def test_main_refuses_wrong_core_commit_before_creating_cluster(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        test_smoke.write_core(tmp, test_smoke.STUB_CORE)
        with mock.patch.object(smoke, "core_checkout_state", return_value=("0" * 40, "")), \
                mock.patch("sys.stderr"):
            self.assertEqual(restore_drill.main(["--core-dir", str(tmp)]), 3)


if __name__ == "__main__":
    unittest.main()
