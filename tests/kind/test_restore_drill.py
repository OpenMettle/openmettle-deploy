"""Cluster-free unit and orchestration tests for the isolated-target restore drill harness (tests/kind/restore_drill.py)."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import io
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
CORE_DIR = os.environ.get("OPENMETTLE_CORE_DIR")
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


def k8s_expand(arg: str, env_names: set[str]) -> str:
    """Simulate kubelet ExpandContainerCommandOnlyStatic (`$$` -> `$`, `$(VAR)` expansion)."""
    out: list[str] = []
    i = 0
    while i < len(arg):
        if arg[i] == "$" and i + 1 < len(arg):
            if arg[i + 1] == "$":
                out.append("$")
                i += 2
                continue
            if arg[i + 1] == "(":
                end = arg.find(")", i + 2)
                if end != -1:
                    var_name = arg[i + 2:end]
                    if var_name in env_names:
                        out.append(f"<expanded:{var_name}>")
                        i = end + 1
                        continue
        out.append(arg[i])
        i += 1
    return "".join(out)


def iter_pod_specs(doc: dict):
    """Yield `(resource_name, pod_spec)` pairs across List, Pod, Deployment, Job, and CronJob."""
    kind = doc.get("kind")
    if kind == "List":
        for item in doc.get("items", ()):
            yield from iter_pod_specs(item)
    elif kind == "Pod":
        yield doc["metadata"]["name"], doc["spec"]
    elif kind in ("Deployment", "Job"):
        yield doc["metadata"]["name"], doc["spec"]["template"]["spec"]
    elif kind == "CronJob":
        yield doc["metadata"]["name"], doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]


class JournalAndRebindParserTest(unittest.TestCase):
    def test_parses_all_watermarks_and_exercises_export_complete_vs_coverage_gap_decision(self):
        wm = restore_drill.parse_journal_export_watermarks(SAMPLE_JOURNAL)
        self.assertEqual(wm["origin_us"], 1795450000000000)
        self.assertEqual(wm["lifecycle_origin_us"], 1795450000000100)
        self.assertEqual(wm["lifecycle_baseline_digest"], GENESIS)
        self.assertEqual(wm["connection_origin_us"], 1795450000000200)
        self.assertEqual(wm["required_seq"], 1)
        self.assertEqual(wm["required_digest"], DIGEST_B)

        self.assertTrue(restore_drill.should_pass_export_complete(wm, (1, DIGEST_B)))
        self.assertFalse(restore_drill.should_pass_export_complete(wm, None))
        self.assertFalse(restore_drill.should_pass_export_complete(wm, (2, DIGEST_B)))
        self.assertFalse(restore_drill.should_pass_export_complete(wm, (1, DIGEST_A)))

        certified_args = restore_drill.restore_lock_args(wm, export_complete=True)
        self.assertIn("--export-complete", certified_args)
        uncertified_args = restore_drill.restore_lock_args(wm, export_complete=False)
        self.assertNotIn("--export-complete", uncertified_args)

        run_id = "44444444-4444-4444-8444-444444444444"
        lock_out = (
            f"restore gate closed: restore_run {run_id}, origin 1795450000000000, "
            "snapshot 0, required 1, coverage_complete false\n"
        )
        self.assertEqual(restore_drill.parse_restore_lock_run_id(lock_out), run_id)
        gap_args = restore_drill.accept_coverage_gap_args(
            run_id, restore_drill.DRILL_OPERATOR_ID, "gap-key-1", "uncertified post-export window"
        )
        self.assertEqual(
            gap_args[:4],
            ["restore", "accept-coverage-gap", "--restore-run", run_id],
        )

    def test_stopped_primary_watermark_sql_matches_core_deletion_journal_head_columns(self):
        sql = restore_drill.stopped_primary_watermark_sql()
        self.assertIn("SELECT journal_seq, encode(chain_digest, 'hex')", sql)
        self.assertIn("FROM openmettle.deletion_journal_head", sql)
        checks_yml = (smoke.ROOT / ".github" / "workflows" / "checks.yml").read_text(encoding="utf-8")
        self.assertIn("migrations/0028_retention_purge_journal.sql", checks_yml)
        if CORE_DIR:
            mig28 = (Path(CORE_DIR) / "migrations" / "0028_retention_purge_journal.sql").read_text(encoding="utf-8")
            self.assertIn("CREATE TABLE openmettle.deletion_journal_head", mig28)
            self.assertIn("journal_seq bigint NOT NULL", mig28)
            self.assertIn("chain_digest bytea NOT NULL", mig28)

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
        res_id_2 = "33333333-3333-4333-8333-333333333333"
        barrier = "22222222-2222-4222-8222-222222222222"
        stdout = (
            "rebound 5, emptied 0, unchanged 0, quarantined 0, failed 2\n"
            f"failed {res_id}: missing revision\n"
            f"failed {res_id_2}: missing revision\n"
        )
        stderr = f"the volume stays closed; resolve what is reported and re-run with --replace-adoption-run {barrier}\n"
        self.assertEqual(restore_drill.parse_failed_rebind(stdout, stderr, res_id), barrier)
        self.assertEqual(restore_drill.parse_failed_rebind(stdout, stderr, [res_id, res_id_2]), barrier)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "missing revision"):
            restore_drill.parse_failed_rebind("rebound 5, failed 0\n", stderr, res_id)
        with self.assertRaisesRegex(restore_drill.DrillFailure, res_id_2):
            restore_drill.parse_failed_rebind(f"failed {res_id}: missing revision\n", stderr, [res_id, res_id_2])
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

    def test_manifest_preflight_checks_schema_vault_keys_and_optional_store_modes(self):
        manifest = {
            "format": "openmettle-backup-manifest/v1",
            "backup_run_id": "33333333-3333-4333-8333-333333333333",
            "schema_version": 45,
            "quiesced_at": "2026-11-27T08:00:00.000000Z",
            "deletion_journal": {"journal_seq": 3},
            "vault_required_key_ids": ["vault-k1"],
            "artifact_volume": {"volume_id": "55555555-5555-4555-8555-555555555555", "revision_count": 6},
            "graphiti_neo4j": {"status": "not_provisioned"},
            "chroma": {"mode": "not_provisioned"},
        }
        summary = restore_drill.evaluate_manifest_preflight(
            manifest, max_schema=45, available_vault_keys={"vault-k1", "vault-k2"}
        )
        self.assertEqual(summary["schema_version"], 45)
        self.assertEqual(summary["vault_required_key_ids"], ["vault-k1"])
        self.assertEqual(summary["artifact_volume_id"], "55555555-5555-4555-8555-555555555555")

        storage_disabled = {**manifest, "artifact_volume": {"volume_id": None, "revision_count": 0}}
        self.assertIsNone(restore_drill.evaluate_manifest_preflight(storage_disabled)["artifact_volume_id"])

        vault_disabled = {**manifest, "vault_required_key_ids": []}
        self.assertEqual(
            restore_drill.evaluate_manifest_preflight(vault_disabled, max_schema=45, available_vault_keys=set())["vault_required_key_ids"],
            [],
        )

        with self.assertRaisesRegex(restore_drill.DrillFailure, "lacks required key IDs"):
            restore_drill.evaluate_manifest_preflight(manifest, max_schema=45, available_vault_keys={"vault-k2"})
        with self.assertRaisesRegex(restore_drill.DrillFailure, "lacks required key IDs"):
            restore_drill.evaluate_manifest_preflight(manifest, max_schema=45, available_vault_keys=set())

        newer = {**manifest, "schema_version": 46}
        with self.assertRaisesRegex(restore_drill.DrillFailure, "incompatible backup schema_version"):
            restore_drill.evaluate_manifest_preflight(newer, max_schema=45)

    def test_rpo_and_rto_bounds_record_measurements_even_on_simultaneous_breach(self):
        t0 = datetime(2026, 11, 27, 8, 0, 0, tzinfo=timezone.utc)
        cutover = t0 + timedelta(hours=2)
        rec_start = cutover + timedelta(minutes=1)
        rec_done = rec_start + timedelta(minutes=12)
        report = {}
        metrics = restore_drill.evaluate_rpo_rto(
            "2026-11-27T08:00:00.000000Z", cutover, rec_start, rec_done, report=report
        )
        self.assertEqual(report["rpo_rto"], metrics)
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

        breach_report: dict = {}
        with self.assertRaises(restore_drill.DrillFailure) as ctx:
            restore_drill.evaluate_rpo_rto(
                "2026-11-27T08:00:00.000000Z",
                t0 + timedelta(hours=25),
                rec_start,
                rec_start + timedelta(hours=5),
                report=breach_report,
            )
        self.assertIn("RPO breached", str(ctx.exception))
        self.assertIn("RTO breached", str(ctx.exception))
        recorded = breach_report["rpo_rto"]
        self.assertEqual(recorded["restored_data_age_seconds"], 90000.0)
        self.assertFalse(recorded["rpo_met"])
        self.assertEqual(recorded["recovery_duration_seconds"], 18000.0)
        self.assertFalse(recorded["rto_met"])

    def test_step4c_script_recovers_intact_staging_before_declaring_unrecoverable_lost(self):
        import hashlib
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        log_file = tmp / "admin-calls.log"
        admin_stub = bin_dir / "openmettle-admin"
        admin_stub.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{log_file}"\n',
            encoding="utf-8",
        )
        admin_stub.chmod(0o755)

        unpacked = tmp / "unpacked"
        artifacts = tmp / "artifacts"
        (unpacked / "artifacts" / "revisions").mkdir(parents=True)
        (artifacts / "revisions").mkdir(parents=True)

        rec_rev = "11111111-1111-4111-8111-111111111111"
        rec_res = "22222222-2222-4222-8222-222222222222"
        rec_bytes = b"intact-staging-payload\n"
        rec_sha = hashlib.sha256(rec_bytes).hexdigest()
        (unpacked / "artifacts" / "revisions" / rec_res).write_bytes(rec_bytes)

        lost_rev = "33333333-3333-4333-8333-333333333333"
        lost_res = "44444444-4444-4444-8444-444444444444"
        lost_bytes = b"absent-everywhere\n"
        lost_sha = hashlib.sha256(lost_bytes).hexdigest()

        barrier = "55555555-5555-4555-8555-555555555555"
        script = restore_drill.build_step4c_reconcile_lines(
            selected_journal=str(tmp / "post.export"),
            artifacts_mount=str(artifacts),
            unpacked_dir=str(unpacked),
            operator_id=restore_drill.DRILL_OPERATOR_ID,
            barrier_uuid=barrier,
            failed_revisions=[
                (rec_rev, rec_res, len(rec_bytes), rec_sha),
                (lost_rev, lost_res, len(lost_bytes), lost_sha),
            ],
        )
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}
        res = subprocess.run(["/bin/sh", "-eu", "-c", script], env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(f"STAGE_RECOVERED {rec_rev}", res.stdout)
        self.assertIn(f"DECLARED_LOST {lost_rev}", res.stdout)
        self.assertNotIn(f"DECLARED_LOST {rec_rev}", res.stdout)
        restored_path = artifacts / "revisions" / rec_res
        self.assertEqual(restored_path.read_bytes(), rec_bytes)
        self.assertEqual(restored_path.stat().st_mode & 0o777, 0o600)
        calls = log_file.read_text(encoding="utf-8")
        self.assertNotIn(rec_rev, calls)
        self.assertIn(f"storage declare-lost {artifacts} --revision {lost_rev}", calls)
        self.assertIn(f"storage rebind {artifacts} --replace-adoption-run {barrier}", calls)

    def test_owner_and_worker_reconcile_sql_follow_core_sequence_and_role_boundaries(self):
        owner_sql = restore_drill.pre_worker_owner_reconcile_sql(
            restore_drill.DRILL_OPERATOR_ID,
            disabled_principals=[(restore_drill.USER_C_IDS["user"], restore_drill.USER_C_IDS["approval"])],
        )
        self.assertIn("LOCK TABLE openmettle.login_provider_revisions IN EXCLUSIVE MODE;", owner_sql)
        self.assertIn("pg_get_serial_sequence('openmettle.login_provider_revisions', 'epoch')", owner_sql)
        self.assertIn("DO $provider_epoch$", owner_sql)
        self.assertIn("$provider_epoch$;", owner_sql)
        self.assertIn("new_epoch <= rec.prev_max_epoch", owner_sql)
        self.assertIn("coalesce(r.cancel_reason, 'revoked')", owner_sql)
        self.assertIn("SET last_event_sequence = last_event_sequence + 1", owner_sql)
        self.assertIn("access_generation = access_generation + 1", owner_sql)
        self.assertNotIn("quota_release_terminal_runs", owner_sql)
        self.assertIn("DO $restore$", owner_sql)
        self.assertIn("$restore$;", owner_sql)
        self.assertNotIn("$$", owner_sql)

        worker_sql = restore_drill.worker_quota_release_sql()
        self.assertIn("openmettle.quota_release_terminal_runs", worker_sql)
        self.assertNotIn("$$", worker_sql)

        sess_sql = restore_drill.fresh_post_restore_session_sql(
            restore_drill.USER_A_IDS, "A" * 43, "B" * 43, "a" * 64, "target-a"
        )
        self.assertIn("SELECT access_generation FROM openmettle.local_identity_approvals", sess_sql)

    def test_step5e_script_preserves_staging_on_nonzero_drift_or_active_maintenance(self):
        run_id = "77777777-7777-4777-8777-777777777777"
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        admin_stub = bin_dir / "openmettle-admin"
        env_base = {**os.environ, "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}

        def write_stub(maint_active: str, quota_line: str) -> None:
            admin_stub.write_text(
                "#!/bin/sh\n"
                'case "$1 $2" in\n'
                '  "backup release-maintenance") exit 0 ;;\n'
                f'  "backup status") printf \'{{"maintenance_active": {maint_active}}}\\n\' ;;\n'
                '  "quota verify")\n'
                '    printf "%s\\n" "$*" > "' + str(tmp / "qv-args") + '"\n'
                f'    printf "{quota_line}\\n"\n'
                "    exit 0\n"
                "    ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            admin_stub.chmod(0o755)

        unpacked = tmp / "unpacked"
        unpacked.mkdir()
        (unpacked / "manifest.json").write_text("{}", encoding="utf-8")
        script_pinned = restore_drill.build_step5e_script(
            restore_drill.DRILL_OPERATOR_ID, run_id, has_artifacts=True, unpacked_dir=str(unpacked)
        )

        # Case 1: quota verify exits 0 with pending gateway 1 -> Job MUST fail and preserve unpacked!
        write_stub(
            "false",
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 1, file mismatches 0, quarantined 0, unsettled payloads 0",
        )
        res_drift = subprocess.run(["/bin/sh", "-c", script_pinned], env=env_base, capture_output=True, text=True)
        self.assertNotEqual(res_drift.returncode, 0)
        self.assertTrue((unpacked / "manifest.json").exists(), "staging prematurely scrubbed despite pending gateway 1")

        # Case 2: maintenance_active still true -> Job MUST fail and preserve unpacked!
        write_stub(
            "true",
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0",
        )
        res_maint = subprocess.run(["/bin/sh", "-c", script_pinned], env=env_base, capture_output=True, text=True)
        self.assertNotEqual(res_maint.returncode, 0)
        self.assertTrue((unpacked / "manifest.json").exists(), "staging prematurely scrubbed despite maintenance_active=true")

        # Case 3: maintenance_active=false and all 7 counters=0 -> Job exits 0 and scrubs unpacked!
        write_stub(
            "false",
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0",
        )
        res_ok = subprocess.run(["/bin/sh", "-c", script_pinned], env=env_base, capture_output=True, text=True)
        self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
        self.assertFalse(unpacked.exists(), "staging was not scrubbed after clean release and zero drift")
        self.assertIn(smoke.ARTIFACTS_MOUNT_PATH, (tmp / "qv-args").read_text(encoding="utf-8"))

        # Case 4: storage-disabled (has_artifacts=False) omits root path argument!
        unpacked.mkdir()
        script_no_art = restore_drill.build_step5e_script(
            restore_drill.DRILL_OPERATOR_ID, run_id, has_artifacts=False, unpacked_dir=str(unpacked)
        )
        res_no_art = subprocess.run(["/bin/sh", "-c", script_no_art], env=env_base, capture_output=True, text=True)
        self.assertEqual(res_no_art.returncode, 0, res_no_art.stderr)
        self.assertEqual((tmp / "qv-args").read_text(encoding="utf-8").strip(), "quota verify")

    def test_runbook_step3_pg_restore_failure_is_not_masked_and_cleans_pgpassfile(self):
        runbook = (smoke.ROOT / "docs" / "restore-drill.md").read_text(encoding="utf-8")
        step3_section = runbook.split("## Step 3", 1)[1].split("## Step 4", 1)[0]
        step3_sh = step3_section.split("```sh\n", 1)[1].split("\n```", 1)[0]

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        pgpass = tmp / "pgpass"
        pg_restore_stub = bin_dir / "pg_restore"
        pg_restore_stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        pg_restore_stub.chmod(0o755)
        adapted = step3_sh.replace("export PGPASSFILE=/tmp/pgpass", f'export PGPASSFILE="{pgpass}"')
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "PGHOST": "postgres.example.test",
            "OWNER_PASSWORD": "sec:ret\\pw",
        }
        res = subprocess.run(["/bin/sh", "-c", adapted], env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1, "Step 3 masked pg_restore failure")
        self.assertFalse(pgpass.exists(), "EXIT trap did not remove PGPASSFILE after pg_restore failure")


class ChartAndManifestValuesTest(unittest.TestCase):
    def test_drill_inference_document_matches_adr_0043_schema_and_chart_values_render(self):
        catalog = smoke.smoke_catalog(test_smoke.CATALOG_FIXTURE)
        for ns in (restore_drill.PRIMARY_APP_NS, restore_drill.TARGET_APP_NS):
            doc = restore_drill.drill_inference_document(ns, catalog)
            self.assertEqual(doc["version"], 1)
            self.assertEqual(doc["installation"], smoke.GATEWAY_INSTALLATION)
            self.assertEqual(set(doc["routes"]), set(catalog["models"]))
            for route in doc["routes"].values():
                self.assertEqual(route["protocol"], "chat_completions")
                self.assertIn(f".{ns}.svc.cluster.local:8082/v1/chat/completions", route["endpoint"])

        if shutil.which(HELM) is None:
            self.skipTest(f"{HELM} not installed")
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
                for doc in docs:
                    for owner_name, pod_spec in iter_pod_specs(doc):
                        for c in (*pod_spec.get("initContainers", ()), *pod_spec.get("containers", ())):
                            env_names = {e["name"] for e in c.get("env", ())}
                            for field in ("command", "args"):
                                for raw_arg in c.get(field, ()):
                                    expanded = k8s_expand(raw_arg, env_names)
                                    if doc.get("kind") == "CronJob" and field == "args" and raw_arg == "cronjob-$(OPENMETTLE_BACKUP_JOB_UID)":
                                        self.assertEqual(expanded, "cronjob-<expanded:OPENMETTLE_BACKUP_JOB_UID>")
                                    else:
                                        self.assertEqual(
                                            expanded, raw_arg,
                                            f"unexpected Kubernetes command expansion in rendered {doc.get('kind')} {owner_name}/{c['name']} {field}",
                                        )
            finally:
                Path(vals_path).unlink(missing_ok=True)

        # Verify chart renders backup enabled with vault disabled without mounting vault secrets/keys.
        no_vault_vals = restore_drill.drill_chart_values(
            DIGESTS,
            PG_CLIENT,
            db_namespace=restore_drill.PRIMARY_DB_NS,
            artifacts_existing_claim=None,
            enable_backup=True,
        )
        no_vault_vals["vault"] = {"enabled": False}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(no_vault_vals, handle)
            nv_path = handle.name
        try:
            res = subprocess.run(
                [HELM, "template", smoke.RELEASE, str(smoke.CHART), "--values", nv_path],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            docs = [d for d in yaml.safe_load_all(res.stdout) if d]
            self.assertEqual(len([d for d in docs if d.get("kind") == "CronJob"]), 1)
            for doc in docs:
                for _, pod_spec in iter_pod_specs(doc):
                    for vol in pod_spec.get("volumes", ()):
                        self.assertNotIn("vault-keys", vol["name"])
        finally:
            Path(nv_path).unlink(missing_ok=True)

    def test_isolation_manifests_precede_workloads_and_enforce_pod_security_and_db_revocations(self):
        catalog = smoke.smoke_catalog(test_smoke.CATALOG_FIXTURE)
        creds = {k: "x" * 32 for k in ("admin", *smoke.DB_LOGINS)}
        creds["auth_login_key"] = base64.b64encode(b"1" * 32).decode("ascii")
        creds["auth_cursor_key"] = base64.b64encode(b"2" * 32).decode("ascii")
        foundation = restore_drill.isolation_and_config_manifests(
            app_ns=restore_drill.TARGET_APP_NS,
            db_ns=restore_drill.TARGET_DB_NS,
            passwords=creds,
            catalog=catalog,
            vault_keys=[("vault-k1", "vault-k1.key", creds["auth_login_key"])],
            backup_key_b64=creds["auth_cursor_key"],
            wrong_backup_key_b64=creds["auth_login_key"],
            is_target=True,
            run_id="deadbeef",
        )
        workloads = restore_drill.fixture_workload_manifests(
            db_ns=restore_drill.TARGET_DB_NS,
            postgres_image="postgres:18.1-bookworm@sha256:" + "9" * 64,
            standin_image="openmettle-smoke.invalid/openmettle/sglang-standin:drill-1",
            is_target=True,
            run_id="deadbeef",
        )
        # Foundation bundle must contain ZERO runnable workloads (Deployments, Pods, Jobs).
        self.assertFalse(any(i["kind"] in ("Deployment", "Pod", "Job") for i in foundation["items"]))
        for ns_name in (restore_drill.TARGET_APP_NS, restore_drill.TARGET_DB_NS):
            ns = next(i for i in foundation["items"] if i["kind"] == "Namespace" and i["metadata"]["name"] == ns_name)
            self.assertEqual(ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")
        pg_dep = next(i for i in workloads["items"] if i["kind"] == "Deployment" and i["metadata"]["name"] == "postgres")
        self.assertEqual(pg_dep["spec"]["template"]["spec"]["securityContext"]["runAsUser"], 999)
        fixture_secret = next(i for i in foundation["items"] if i["kind"] == "Secret" and i["metadata"]["name"] == "postgres-fixture")
        provision_sql = fixture_secret["stringData"]["provision.sql"]
        self.assertIn("REVOKE ALL ON DATABASE openmettle FROM PUBLIC;", provision_sql)
        self.assertIn("GRANT CONNECT ON DATABASE openmettle TO openmettle_api", provision_sql)
        self.assertIn("REVOKE ALL ON SCHEMA public FROM PUBLIC;", provision_sql)
        wrong_secret = next(
            i for i in foundation["items"]
            if i["kind"] == "Secret" and i["metadata"]["name"] == restore_drill.WRONG_BACKUP_SECRET
        )
        wrong_doc = json.loads(base64.b64decode(wrong_secret["data"]["keyring.json"]))
        self.assertEqual(wrong_doc["keys"][0]["file"], f"{restore_drill.WRONG_BACKUP_KEYS_DIR}/{smoke.BACKUP_KEY_FILE}")
        db_netpols = [
            i["metadata"]["name"] for i in foundation["items"]
            if i["kind"] == "NetworkPolicy" and i["metadata"]["namespace"] == restore_drill.TARGET_DB_NS
        ]
        self.assertEqual(sorted(db_netpols), sorted([smoke.NAMESPACE_DENY, "postgres-network", "standin-network"]))

    def test_main_refuses_wrong_core_commit_before_creating_cluster(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        test_smoke.write_core(tmp, test_smoke.STUB_CORE)
        with mock.patch.object(smoke, "core_checkout_state", return_value=("0" * 40, "")), \
                mock.patch("sys.stderr"):
            self.assertEqual(restore_drill.main(["--core-dir", str(tmp)]), 3)


class CallableOnlyRunner:
    """Mimics pinned core `Runner`: callable via `__call__` only, with NO `.run` attribute."""

    def __init__(self, dispatch):
        self._dispatch = dispatch

    def __call__(self, argv, *, input=None, check=False, timeout=None):
        return self._dispatch(list(argv), input=input, check=check, timeout=timeout)


class FakeDrillOrchestrationTest(unittest.TestCase):
    """Drives `restore_drill.main()` through preflight, execution, cleanup, and failure redaction
    using a `CallableOnlyRunner` so any `.runner.run(...)` regression fails immediately."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "Dockerfile").write_text("FROM scratch AS build\n", encoding="utf-8")
        cat_path = self.tmp / smoke.CORE_CATALOG_FIXTURE
        cat_path.parent.mkdir(parents=True, exist_ok=True)
        cat_path.write_text(json.dumps(test_smoke.CATALOG_FIXTURE), encoding="utf-8")
        self.commands: list[list[str]] = []
        self.applied_manifests: list[dict] = []
        self.fail_on_target_migrate = False
        self.job_failed_on_pre_worker_sql = False
        self.shared_artifact_readers: list[str] = []

    def _make_core(self):
        outer = self

        class FakeCore:
            KIND_VERSION = "v0.33.0"
            KUBECTL_VERSION = "v1.37.0"
            NODE_IMAGE = "kindest/node:v1.37.0@sha256:" + "8" * 64
            POSTGRES_IMAGE = "docker.io/library/postgres:18.1-bookworm@sha256:" + "9" * 64
            Refusal = smoke.Refusal
            QualificationFailure = Exception

            @staticmethod
            def check_opt_in(_env):
                return "default"

            @staticmethod
            def child_environment(env, kubeconfig, context, _tools):
                return {**env, "KUBECONFIG": str(kubeconfig), "DOCKER_CONTEXT": context}

            @staticmethod
            def check_tools(run):
                run(["kind", "version"])
                run(["kubectl", "version", "--client", "--output=json"])

            @staticmethod
            def check_docker_context(run, context):
                run(["docker", "context", "inspect", context])

            @staticmethod
            def check_cluster_absent(run, _name):
                run(["kind", "get", "clusters"])

            @staticmethod
            def check_cluster_identity(_cfg, _nodes, _label, _name):
                return None

            @staticmethod
            def http_get(_port, path):
                if path == "/readyz":
                    return 200, "{}"
                return 200, "[]"

            @staticmethod
            def Runner(_env):
                return CallableOnlyRunner(outer._dispatch)

        return FakeCore

    def _res(self, rc=0, stdout="", stderr=""):
        return subprocess.CompletedProcess([], rc, stdout, stderr)

    def _dispatch(self, argv: list[str], *, input=None, check=False, timeout=None):
        self.commands.append(argv)
        if argv[:2] == ["kind", "version"]:
            return self._res(0, "kind v0.33.0 go1.24 linux/amd64\n")
        if argv[:2] == ["kubectl", "version"]:
            return self._res(0, json.dumps({"clientVersion": {"gitVersion": "v1.37.0"}}))
        if argv[:2] == ["helm", "version"]:
            return self._res(0, smoke.HELM_VERSION)
        if argv[:3] == ["docker", "context", "inspect"]:
            return self._res(0, "[]")
        if argv[:3] == ["kind", "get", "clusters"]:
            return self._res(0, "")
        if argv[:2] == ["docker", "build"]:
            for idx, item in enumerate(argv):
                if item == "--output" and idx + 1 < len(argv):
                    dest = Path(argv[idx + 1].split("dest=", 1)[1])
                    dest.mkdir(parents=True, exist_ok=True)
                    (dest / "kind-drill-fixture").write_text("#!/bin/sh\n", encoding="utf-8")
            return self._res(0, "")
        if argv[:3] == ["kind", "create", "cluster"]:
            kc = Path(argv[argv.index("--kubeconfig") + 1])
            kc.write_text("clusters: []\n", encoding="utf-8")
            return self._res(0, "")
        if argv[:3] == ["kind", "load", "docker-image"]:
            return self._res(0, "")
        if argv[:3] == ["kind", "delete", "cluster"]:
            return self._res(0, "")
        if argv[:4] == ["docker", "image", "rm", "--force"]:
            return self._res(0, "")
        if argv[:2] == ["docker", "inspect"]:
            return self._res(0, argv[-1].removesuffix("-control-plane") + "\n")
        if argv[:2] == ["docker", "exec"]:
            sub = argv[3:]
            if sub[:3] == ["ctr", "--namespace=k8s.io", "images"] and sub[3] == "ls":
                lines = ["REF TYPE DIGEST SIZE PLATFORMS LABELS"]
                for role, d in DIGESTS.items():
                    lines.append(f"{smoke.REGISTRY}/openmettle/{role}:smoke-{self._run_id} oci {d} 1MiB linux/amd64 -")
                lines.append(f"docker.io/library/postgres:18.1-bookworm@{PG_CLIENT['digest']} oci {PG_CLIENT['digest']} 1MiB linux/amd64 -")
                return self._res(0, "\n".join(lines) + "\n")
            if sub[:3] == ["ctr", "--namespace=k8s.io", "images"] and sub[3] == "tag":
                return self._res(0, "")
            if sub[:2] == ["crictl", "inspecti"]:
                ref = sub[-1]
                for role, d in DIGESTS.items():
                    if role in ref:
                        return self._res(0, json.dumps({"status": {"id": d}}))
                return self._res(0, json.dumps({"status": {"id": PG_CLIENT["digest"]}}))
        if argv[0] == "helm":
            return self._res(0, "")
        if argv[0] == "kubectl":
            if "config" in argv and "view" in argv:
                return self._res(0, json.dumps({"contexts": []}))
            if "nodes" in argv:
                return self._res(0, json.dumps({"items": [{"metadata": {"name": f"openmettle-dev-qual-{self._run_id}-control-plane"}}]}))
            if "namespace" in argv and "get" in argv and argv[-1] == "--output=json":
                return self._res(1, "", "NotFound")
            if "apply" in argv and input:
                doc = json.loads(input)
                self.applied_manifests.append(doc)
                if doc.get("kind") == "Job":
                    self._last_job = doc["metadata"]["name"]
                    if self.fail_on_target_migrate and self._last_job == "openmettle-drill-migrate":
                        return self._res(1, "", f"fatal migrate error password={self._leak_secret}")
                return self._res(0, "")
            if "get" in argv and "job" in argv and argv[-1] == "--output=json":
                job_name = argv[argv.index("job") + 1]
                if self.job_failed_on_pre_worker_sql and job_name == "openmettle-drill-pre-worker-sql":
                    return self._res(0, json.dumps({
                        "status": {"conditions": [{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}]}
                    }))
                return self._res(0, json.dumps({
                    "status": {"conditions": [{"type": "Complete", "status": "True"}]}
                }))
            if "logs" in argv:
                return self._job_logs(argv)
            if "get" in argv and "pods" in argv:
                if any("component=worker" in a or "component=api" in a for a in argv) and self._scaled_zero:
                    return self._res(0, json.dumps({"items": []}))
                return self._res(0, json.dumps({"items": [{"metadata": {"name": "pod-1"}}]}))
            if "scale" in argv:
                self._scaled_zero = "--replicas=0" in argv
                return self._res(0, "")
            if "exec" in argv:
                return self._exec_handler(argv, input)
            return self._res(0, "")
        return self._res(0, "")

    @property
    def _run_id(self) -> str:
        for cmd in self.commands:
            if cmd[:2] == ["docker", "build"] and "--tag" in cmd:
                tag = cmd[cmd.index("--tag") + 1]
                if ":smoke-" in tag:
                    return tag.rsplit(":smoke-", 1)[1]
        return "00000000"

    def _job_logs(self, argv: list[str]):
        if any("openmettle-drill-primary-backup" in a for a in argv):
            run_id = "66666666-6666-4666-8666-666666666666"
            return self._res(
                0,
                f"backup.capture_succeeded run_id={run_id} dir=/var/backups/openmettle/backup-20261127T090000Z-{run_id} "
                f"key_id=backup-k1 bundle_digest={'e' * 64} journal_seq=2 pruned=0 skipped_unverified=0 maintenance_released=true\n",
            )
        name = getattr(self, "_last_job", "")
        if name == "openmettle-drill-preflight-neg":
            return self._res(0, "preflight.negative_checks_passed\n")
        if name == "openmettle-drill-verify-unpack":
            manifest = {
                "format": "openmettle-backup-manifest/v1",
                "backup_run_id": "66666666-6666-4666-8666-666666666666",
                "schema_version": smoke.REQUIRED_MIGRATION,
                "quiesced_at": (datetime.now(timezone.utc) - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "deletion_journal": {"journal_seq": 2},
                "vault_required_key_ids": ["vault-k1"],
                "artifact_volume": {"volume_id": "55555555-5555-4555-8555-555555555555", "revision_count": 6},
                "graphiti_neo4j": {"status": "not_provisioned"},
                "chroma": {"mode": "not_provisioned"},
            }
            return self._res(0, f"MANIFEST_JSON_BEGIN\n{json.dumps(manifest)}\nMANIFEST_JSON_END\n")
        if name == "openmettle-drill-gap-pg-restore":
            gap_journal = (
                "openmettle.deletion_journal.export/1\n"
                "origin 1795450000000000\n"
                f"watermark 1795450000000000 2 {DIGEST_A} 1795450010000000\n"
                f"sha256 {'c' * 64}\n"
            )
            return self._res(0, f"GAP_JOURNAL_BEGIN\n{gap_journal}GAP_JOURNAL_END\n")
        if name == "openmettle-drill-gap-lock":
            return self._res(
                0,
                "restore gate closed: restore_run 77777777-7777-4777-8777-777777777771, origin 1, snapshot 2, required 2, coverage_complete false\n",
            )
        if name == "openmettle-drill-gap-accept":
            return self._res(0, "applied restore.accept_coverage_gap\n")
        if name == "openmettle-drill-pg-restore":
            return self._res(0, "pg_restore.completed\n")
        if name == "openmettle-drill-rebind-failclosed":
            return self._res(
                0,
                "LOCK_STDOUT_BEGIN\n"
                "restore gate closed: restore_run 77777777-7777-4777-8777-777777777777, origin 1, snapshot 2, required 5, coverage_complete true\n"
                "LOCK_STDOUT_END\n"
                "REBIND_STDOUT_BEGIN\n"
                "rebound 5, emptied 0, unchanged 0, quarantined 0, failed 2\n"
                "failed 99999999-9999-4999-8999-999999999997: missing revision\n"
                "failed 99999999-9999-4999-8999-999999999995: missing revision\n"
                "REBIND_STDOUT_END\n"
                "REBIND_STDERR_BEGIN\n"
                "the volume stays closed; resolve what is reported and re-run with --replace-adoption-run 88888888-8888-4888-8888-888888888888\n"
                "REBIND_STDERR_END\n",
            )
        qv = (
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0\n"
        )
        if name == "openmettle-drill-reconcile-admin":
            return self._res(
                0,
                "STAGE_RECOVERED 99999999-9999-4999-8999-999999999997\n"
                "DECLARED_LOST 99999999-9999-4999-8999-999999999995\n"
                f"QUOTA_STAGE4_BEGIN\n{qv}QUOTA_STAGE4_END\n"
                "VAULT_BEFORE_BEGIN\nconnections 2, encrypted 1\nkey_id vault-k1 1\nVAULT_BEFORE_END\n"
                "VAULT_AFTER_BEGIN\nconnections 2, encrypted 1\nkey_id vault-k2 1\nVAULT_AFTER_END\n",
            )
        if name == "openmettle-drill-pre-worker-sql":
            return self._res(0, "2\n")
        if name == "openmettle-drill-worker-quota-release":
            return self._res(0, "1\n")
        if name == "openmettle-drill-release-maintenance":
            bs = json.dumps({"maintenance_active": False})
            return self._res(
                0,
                f"BACKUP_STATUS_BEGIN\n{bs}\nBACKUP_STATUS_END\n"
                f"QUOTA_VERIFY_BEGIN\n{qv}QUOTA_VERIFY_END\n",
            )
        if name == "openmettle-drill-post-verify":
            return self._res(0, qv)
        return self._res(0, "")

    def _exec_handler(self, argv: list[str], stdin_text: str | None):
        if "/tmp/kind-drill-fixture" in argv:
            if stdin_text:
                self._leak_secret = stdin_text.splitlines()[0].split("openmettle_api:", 1)[1].split("@", 1)[0]
            return self._res(0, json.dumps({
                "scope_id": "aaaa0000-0000-4000-8000-000000000001",
                "waiting_run_id": "aaaa0000-0000-4000-8000-000000000002",
                "waiting_approval_id": "aaaa0000-0000-4000-8000-000000000003",
                "waiting_binding_digest": "f" * 64,
                "intent_run_id": "aaaa0000-0000-4000-8000-000000000004",
                "intent_operation_id": "aaaa0000-0000-4000-8000-000000000005",
            }))
        if "cat" in argv and any("post-backup-journal.export" in a for a in argv):
            return self._res(
                0,
                "openmettle.deletion_journal.export/1\n"
                "origin 1795450000000000\n"
                f"watermark 1795450000000000 5 {DIGEST_B} 1795450020000000\n"
                f"sha256 {'c' * 64}\n",
            )
        if "psql" in argv and stdin_text:
            if restore_drill.GAP_DB_NAME in argv:
                return self._res(0, "2|0|0|0|t|1\n")
            if "gateway_requests" in stdin_text:
                return self._res(0, "11111111-1111-4111-8111-111111111111|handed_off|t|t|1|11|7|t|settled|0|18\n")
            if "JOIN openmettle.quota_reservations qr" in stdin_text and "last_event_sequence" in stdin_text:
                # Realistic pre-backup sequences: waiting_run=4, intent_run=5, each holding 25 usage_tokens.
                return self._res(
                    0,
                    "aaaa0000-0000-4000-8000-000000000002|4|25\n"
                    "aaaa0000-0000-4000-8000-000000000004|5|25\n",
                )
            if "FROM openmettle.artifact_revisions" in stdin_text and "WHERE id IN" in stdin_text:
                return self._res(
                    0,
                    f"99999999-9999-4999-8999-999999999993|99999999-9999-4999-8999-999999999990|1800000000000000|27|{'1' * 64}\n"
                    f"99999999-9999-4999-8999-999999999994|99999999-9999-4999-8999-999999999991||30|{'2' * 64}\n"
                    f"99999999-9999-4999-8999-999999999995|99999999-9999-4999-8999-999999999995||34|{'3' * 64}\n"
                    f"99999999-9999-4999-8999-999999999997|99999999-9999-4999-8999-999999999997||37|{'4' * 64}\n",
                )
            if "DO $provider_epoch$" in stdin_text and "setval" not in stdin_text:
                return self._res(
                    3,
                    "",
                    "ERROR: login_provider_revisions epoch 41 did not advance past previous maximum 100",
                )
            if "EXISTS (SELECT 1 FROM openmettle.login_provider_revisions WHERE epoch = 41)" in stdin_text:
                return self._res(0, "100|0|f\n")
            if "openmettle.operations" in stdin_text:
                return self._res(
                    0,
                    "outcome_unknown:1|t|1800000000000000|purged|t|f|"
                    "5:5:1:5|run-terminal:openmettle.run-cancelled|"
                    "7:7:1:7|unresolved-write:aaaa0000-0000-4000-8000-000000000005|"
                    "run-terminal:openmettle.run-cancelled|released:0|held:25|101|1\n",
                )
            if "SELECT state FROM openmettle.artifact_revisions" in stdin_text:
                return self._res(0, "purged\n")
            if "FROM openmettle.deletion_journal_head" in stdin_text:
                self.assertIn("SELECT journal_seq", stdin_text)
                return self._res(0, f"5|{DIGEST_B}\n")
            if "_sqlx_migrations" in stdin_text:
                return self._res(0, f"{smoke.REQUIRED_MIGRATION}|1|t\n")
            return self._res(0, "")
        if "timeout" in argv:
            ns = argv[argv.index("--namespace") + 1]
            target_host = argv[-2] if argv[-1].isdigit() else argv[-3]
            is_http = "/readyz" in argv
            if ns in (restore_drill.TARGET_APP_NS, restore_drill.TARGET_DB_NS) and (
                restore_drill.PRIMARY_DB_NS in target_host or restore_drill.PRIMARY_APP_NS in target_host
            ):
                return self._res(124, "", "")
            return self._res(0, "HTTP/1.1 200 OK\r\n" if is_http else "", "")
        return self._res(0, "")

    def _fake_http_exchange(self, port, method, path, headers, payload):
        v1_hdrs = {"openmettle-api-version": "1.0", "cache-control": "no-store", "content-type": "application/json"}
        prob_hdrs = {**v1_hdrs, "content-type": "application/problem+json"}
        raw_cookie = headers.get("Cookie", "").removeprefix("__Host-openmettle-session=")
        if port == 18082 and any(bad == raw_cookie for bad in getattr(self, "_stale_or_disabled_cookies", ())):
            return 401, prob_hdrs, json.dumps({"status": 401, "code": "unauthenticated"}).encode()
        if path == "/v1/quotas/personal" and method == "GET":
            if raw_cookie == getattr(self, "_cookie_d2", None):
                return 200, v1_hdrs, json.dumps({"scope_kind": "personal"}).encode()
            return 401, prob_hdrs, json.dumps({"status": 401, "code": "unauthenticated"}).encode()
        if path.startswith("/v1/projects/") and method == "GET":
            return 401, prob_hdrs, json.dumps({"status": 401, "code": "unauthenticated"}).encode()
        if path == "/v1/conversations" and method == "POST":
            body = json.loads(payload) if payload else {}
            cid = (
                "bbbb0000-0000-4000-8000-000000000099"
                if body.get("scope_id")
                else "bbbb0000-0000-4000-8000-000000000001"
            )
            return 201, v1_hdrs, json.dumps({
                "conversation_id": cid,
                "branch_id": "bbbb0000-0000-4000-8000-000000000002",
            }).encode()
        if path == "/v1/runs" and method == "POST":
            rid = "bbbb0000-0000-4000-8000-000000000010"
            self._post_restore_runs = getattr(self, "_post_restore_runs", 0) + 1
            return 201, v1_hdrs, json.dumps({"run_id": rid, "state": "queued"}).encode()
        if path.startswith("/v1/runs/") and method == "GET":
            if path.endswith("/approvals"):
                return 200, v1_hdrs, json.dumps({"items": []}).encode()
            run_id = path.rsplit("/", 1)[1]
            state = "cancelled" if run_id.startswith("aaaa0000") else "succeeded"
            return 200, v1_hdrs, json.dumps({"run_id": run_id, "state": state}).encode()
        if path.endswith("/decision") and method == "POST":
            body = json.loads(payload)
            self.assertEqual(body["decision"], "approve")
            return 409, prob_hdrs, json.dumps({"status": 409, "code": "conflict"}).encode()
        if path == "/v1/projects" and method == "POST":
            return 201, v1_hdrs, json.dumps({
                "project_id": "cccc0000-0000-4000-8000-000000000001",
                "scope_id": "cccc0000-0000-4000-8000-000000000002",
            }).encode()
        if ("/members" in path or "/shares" in path) and method == "PUT":
            return 200, v1_hdrs, b"{}"
        if path.endswith("/shares/revoke") or (method == "DELETE" and "/revisions/" not in path):
            return 204, {"openmettle-api-version": "1.0", "cache-control": "no-store"}, b""
        if path.startswith("/v1/artifacts") and method == "POST":
            if "drill-viewer-write-denied" == headers.get("Idempotency-Key"):
                return 403, prob_hdrs, json.dumps({"status": 403, "code": "policy"}).encode()
            key = headers.get("Idempotency-Key", "")
            mapping = {
                "drill-art-keep": ("99999999-9999-4999-8999-999999999981", "99999999-9999-4999-8999-999999999991"),
                "drill-art-proj": ("99999999-9999-4999-8999-999999999982", "99999999-9999-4999-8999-999999999992"),
                "drill-art-dl-v1": ("99999999-9999-4999-8999-999999999983", "99999999-9999-4999-8999-999999999993"),
                "drill-art-dl-v2": ("99999999-9999-4999-8999-999999999983", "99999999-9999-4999-8999-999999999996"),
                "drill-art-post-purge": ("99999999-9999-4999-8999-999999999984", "99999999-9999-4999-8999-999999999994"),
                "drill-art-stage-recover": ("99999999-9999-4999-8999-999999999987", "99999999-9999-4999-8999-999999999997"),
                "drill-art-to-lose": ("99999999-9999-4999-8999-999999999985", "99999999-9999-4999-8999-999999999995"),
            }
            aid, rid = mapping[key]
            return 201, v1_hdrs, json.dumps({"artifact_id": aid, "revision_id": rid, "state": "active"}).encode()
        if "/revisions/" in path and method == "DELETE":
            return 200, v1_hdrs, json.dumps({"state": "retained", "purge_after": "2026-12-04T08:00:00Z"}).encode()
        if path == "/v1/connections" and method == "POST":
            cid = (
                "dddd0000-0000-4000-8000-000000000001"
                if headers.get("Idempotency-Key") == "drill-conn-keep"
                else "dddd0000-0000-4000-8000-000000000002"
            )
            return 201, v1_hdrs, json.dumps({"connection_id": cid, "state": "pending_auth"}).encode()
        if path.endswith("/authorize") and method == "POST":
            return 200, v1_hdrs, json.dumps({"state": "authorized"}).encode()
        if path.endswith("/disconnect") and method == "POST":
            return 200, v1_hdrs, json.dumps({"state": "disconnected"}).encode()
        if path.startswith("/v1/conversations/") and method == "GET":
            if path.endswith("/messages"):
                return 200, v1_hdrs, json.dumps({"items": [{"content": smoke.STANDIN_EXPECTED_CONTENT}]}).encode()
            if "bbbb0000-0000-4000-8000-000000000099" in path:
                if raw_cookie == getattr(self, "_cookie_d2", None):
                    return 404, prob_hdrs, json.dumps({"status": 404, "code": "not_found"}).encode()
                return 200, v1_hdrs, json.dumps({"conversation_id": "bbbb0000-0000-4000-8000-000000000099"}).encode()
            if raw_cookie == self._cookie_b2:
                return 404, prob_hdrs, json.dumps({"status": 404, "code": "not_found"}).encode()
            return 200, v1_hdrs, json.dumps({"conversation_id": "bbbb0000-0000-4000-8000-000000000001"}).encode()
        if path.startswith("/v1/artifacts/") and method == "GET":
            if port == 18081 and "99999999-9999-4999-8999-999999999995/content" in path:
                return 200, {**v1_hdrs, "content-type": "text/plain"}, b"drill-unrecoverable-payload-bytes\n"
            if raw_cookie == getattr(self, "_cookie_d2", None):
                return 404, prob_hdrs, json.dumps({"status": 404, "code": "not_found"}).encode()
            if raw_cookie == self._cookie_b2 and (
                "99999999-9999-4999-8999-999999999981" in path
                or "99999999-9999-4999-8999-999999999985" in path
                or "99999999-9999-4999-8999-999999999987" in path
            ):
                return 404, prob_hdrs, json.dumps({"status": 404, "code": "not_found"}).encode()
            if "99999999-9999-4999-8999-999999999991/content" in path:
                return 200, {**v1_hdrs, "content-type": "text/plain"}, b"drill-personal-keep-bytes\n"
            if "99999999-9999-4999-8999-999999999997/content" in path:
                return 200, {**v1_hdrs, "content-type": "text/plain"}, b"drill-recoverable-from-staging-bytes\n"
            if "99999999-9999-4999-8999-999999999992/content" in path:
                self.shared_artifact_readers.append(raw_cookie)
                return 200, {**v1_hdrs, "content-type": "text/plain"}, b"drill-project-shared-bytes\n"
            if "99999999-9999-4999-8999-999999999995/content" in path:
                return 410, prob_hdrs, json.dumps({"status": 410, "code": "payload_lost"}).encode()
            if "99999999-9999-4999-8999-999999999995" in path:
                return 200, v1_hdrs, json.dumps({"state": "lost", "lost_at": "2026-11-27T09:05:00Z"}).encode()
            if "99999999-9999-4999-8999-999999999994/content" in path:
                return 409, prob_hdrs, json.dumps({"status": 409, "code": "conflict"}).encode()
            if "99999999-9999-4999-8999-999999999994" in path:
                return 200, v1_hdrs, json.dumps({"state": "purged"}).encode()
            if "99999999-9999-4999-8999-999999999993" in path:
                return 200, v1_hdrs, json.dumps({"state": "retained", "purge_after": "2026-12-04T08:00:00Z"}).encode()
            return 200, v1_hdrs, json.dumps({"state": "active"}).encode()
        if path.startswith("/v1/connections/") and method == "GET":
            if raw_cookie == self._cookie_b2:
                return 404, prob_hdrs, json.dumps({"status": 404, "code": "not_found"}).encode()
            state = "authorized" if path.endswith("0001") else "disconnected"
            return 200, v1_hdrs, json.dumps({"state": state}).encode()
        raise AssertionError(f"unhandled HTTP exchange: {method} {path}")

    def _run_drill(self) -> tuple[int, dict]:
        self._scaled_zero = False
        self._leak_secret = "not-yet-set"
        outer = self

        class FakePF:
            def __init__(self, _kubectl, _env, target, _port, namespace=None):
                if target.endswith(smoke.STANDIN):
                    self.port = 18090
                elif namespace == restore_drill.PRIMARY_APP_NS:
                    self.port = 18081
                else:
                    self.port = 18082

            def close(self):
                return None

        session_counter = {"n": 0}
        orig_cred = smoke.session_credential

        def tracked_session_cred(raw):
            sid, cookie, sh = orig_cred(raw)
            session_counter["n"] += 1
            # 1..4 are pre-restore sessions (a,b,c,d); 5..8 are post-restore sessions (a2,b2,c2,d2),
            # where 5 is owner user_a, 6 is Viewer user_b, 7 is disabled user_c, and 8 is non-member user_d.
            if session_counter["n"] in (1, 2, 3, 4, 7):
                outer._stale_or_disabled_cookies = (*getattr(outer, "_stale_or_disabled_cookies", ()), cookie)
            elif session_counter["n"] == 5:
                outer._cookie_a2 = cookie
            elif session_counter["n"] == 6:
                outer._cookie_b2 = cookie
            elif session_counter["n"] == 8:
                outer._cookie_d2 = cookie
            return sid, cookie, sh

        def fake_standin_get(port, path):
            if port == 18090 and path == "/_recorded":
                if getattr(outer, "_post_restore_runs", 0) >= 2:
                    return 200, json.dumps([{"ok": True}])
                return 200, "[]"
            return 200, "{}"

        fake_core = self._make_core()
        fake_core.http_get = staticmethod(fake_standin_get)
        report_file = self.tmp / "drill-report.json"
        with mock.patch.object(smoke, "core_checkout_state", return_value=(smoke.CORE_COMMIT, "")), \
                mock.patch.object(smoke, "load_core", return_value=fake_core), \
                mock.patch.object(smoke, "PortForward", FakePF), \
                mock.patch.object(smoke, "http_exchange", side_effect=self._fake_http_exchange), \
                mock.patch.object(smoke, "session_credential", side_effect=tracked_session_cred), \
                mock.patch.object(restore_drill.time, "sleep"), \
                mock.patch("sys.stdout", new=io.StringIO()), \
                mock.patch("sys.stderr", new=io.StringIO()):
            rc = restore_drill.main(["--core-dir", str(self.tmp), "--report", str(report_file)])
        return rc, json.loads(report_file.read_text(encoding="utf-8"))

    def test_full_orchestration_passes_and_applies_policies_before_workloads(self):
        rc, summary = self._run_drill()
        self.assertEqual(rc, 0, summary.get("error"))
        self.assertEqual(summary["result"], "passed")
        self.assertEqual(summary["classification"], "dev")
        self.assertTrue(summary["rpo_rto"]["rpo_met"])
        self.assertTrue(summary["rto"]["rto_met"] if "rto" in summary else summary["rpo_rto"]["rto_met"])
        # First kubectl apply must be the primary foundation list (Namespaces + NetworkPolicies, zero Deployments)
        # strictly before the second kubectl apply (primary Deployments).
        self.assertEqual(self.applied_manifests[0]["kind"], "List")
        self.assertFalse(any(i["kind"] == "Deployment" for i in self.applied_manifests[0]["items"]))
        self.assertTrue(any(i["kind"] == "NetworkPolicy" for i in self.applied_manifests[0]["items"]))
        self.assertTrue(any(i["kind"] == "Deployment" for i in self.applied_manifests[1]["items"]))
        # Shared project artifact must be downloaded and verified by BOTH owner (cookie_a2) and Viewer (cookie_b2):
        self.assertEqual(self.shared_artifact_readers, [self._cookie_a2, self._cookie_b2])
        # Simulate Kubernetes kubelet ExpandContainerCommandOnlyStatic across EVERY container and initContainer
        # command/args in every applied manifest so `$$` -> `$` or `$(ENV_VAR)` can never silently mutate scripts/SQL.
        pre_worker_delivered_sql = None
        for manifest in self.applied_manifests:
            for owner_name, pod_spec in iter_pod_specs(manifest):
                for c in (*pod_spec.get("initContainers", ()), *pod_spec.get("containers", ())):
                    env_names = {e["name"] for e in c.get("env", ())}
                    for field in ("command", "args"):
                        for raw_arg in c.get(field, ()):
                            expanded = k8s_expand(raw_arg, env_names)
                            self.assertEqual(
                                expanded, raw_arg,
                                f"Kubernetes command expansion mutated {owner_name}/{c['name']} {field}",
                            )
                            if owner_name == "openmettle-drill-pre-worker-sql" and "EOSQL" in expanded:
                                pre_worker_delivered_sql = expanded.split("<<'EOSQL'\n", 1)[1].rsplit("\nEOSQL\n", 1)[0]
        self.assertIsNotNone(pre_worker_delivered_sql)
        self.assertIn("DO $restore$", pre_worker_delivered_sql)
        self.assertIn("$restore$;", pre_worker_delivered_sql)
        self.assertIn("DO $provider_epoch$", pre_worker_delivered_sql)
        self.assertNotIn("DO $\n", pre_worker_delivered_sql)

        # Runbook invariants: recoverable payload check before declare-lost, vault-disabled support,
        # ADR 0012 sequence sync + epoch check, OPENMETTLE_ADMIN_DATABASE_URL bound via database.migrate.existingSecret
        # + database.migrate.key, /etc/openmettle/db-ca/ca.crt with O_NOFOLLOW staging, tagged $restore$ SQL
        # delimiter, and Step 5e storage-disabled branch + set -eu + maintenance_active==false gate.
        runbook = (smoke.ROOT / "docs" / "restore-drill.md").read_text(encoding="utf-8")
        self.assertIn("OPENMETTLE_ADMIN_DATABASE_URL", runbook)
        self.assertIn("vault.enabled: false", runbook)
        self.assertIn("database.migrate.key", runbook)
        self.assertNotIn("(key: url)", runbook)
        self.assertNotIn("database.migrate.existingSecret, key `url`", runbook)
        self.assertIn("/etc/openmettle/db-ca/ca.crt", runbook)
        self.assertNotIn("/etc/openmettle/pg-ca", runbook)
        self.assertIn("O_NOFOLLOW", runbook)
        self.assertIn("PGSSLMODE=verify-full", runbook)
        self.assertIn("PGSSLROOTCERT=", runbook)
        self.assertIn("PGGSSENCMODE=disable", runbook)
        self.assertIn("DO $provider_epoch$", runbook)
        self.assertIn("pg_get_serial_sequence('openmettle.login_provider_revisions', 'epoch')", runbook)
        self.assertIn("DO $restore$", runbook)
        self.assertNotIn("DO $$", runbook)
        self.assertIn("ARTIFACT_VOLUME_ID", runbook)
        self.assertIn("sha256sum", runbook)
        self.assertIn('"maintenance_active"[[:space:]]*:[[:space:]]*false', runbook)
        # Verify uncertified coverage-gap scenario was also exercised:
        check_names = [c["name"] for c in summary["checks"]]
        self.assertTrue(any("coverage-gap" in n for n in check_names))
        self.assertTrue(any(cmd[:3] == ["kind", "delete", "cluster"] for cmd in self.commands))
        self.assertTrue(any(cmd[:4] == ["docker", "image", "rm", "--force"] for cmd in self.commands))

    def test_failed_job_reports_redacted_pod_logs_without_waiting_for_complete_timeout(self):
        self.job_failed_on_pre_worker_sql = True
        rc, summary = self._run_drill()
        self.assertEqual(rc, 1)
        self.assertEqual(summary["result"], "failed")
        self.assertIn("Job openmettle-restore-target/openmettle-drill-pre-worker-sql Failed (BackoffLimitExceeded)", summary["error"])
        self.assertNotIn(self._leak_secret, json.dumps(summary))

    def test_failure_redacts_credentials_and_still_cleans_up_cluster_and_images(self):
        self.fail_on_target_migrate = True
        rc, summary = self._run_drill()
        self.assertEqual(rc, 1)
        self.assertEqual(summary["result"], "failed")
        self.assertNotIn(self._leak_secret, json.dumps(summary))
        self.assertIn("[redacted]", summary["error"])
        self.assertTrue(any(cmd[:3] == ["kind", "delete", "cluster"] for cmd in self.commands))


if __name__ == "__main__":
    unittest.main()
