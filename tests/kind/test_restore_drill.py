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
    def test_parses_all_watermarks_and_exercises_export_complete_vs_coverage_gap_decision(self):
        wm = restore_drill.parse_journal_export_watermarks(SAMPLE_JOURNAL)
        self.assertEqual(wm["origin_us"], 1795450000000000)
        self.assertEqual(wm["lifecycle_origin_us"], 1795450000000100)
        self.assertEqual(wm["lifecycle_baseline_digest"], GENESIS)
        self.assertEqual(wm["connection_origin_us"], 1795450000000200)
        self.assertEqual(wm["required_seq"], 1)
        self.assertEqual(wm["required_digest"], DIGEST_B)

        # Certified only when stopped-primary (seq, digest) matches exactly:
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

    def test_owner_and_worker_reconcile_sql_follow_core_sequence_and_role_boundaries(self):
        owner_sql = restore_drill.pre_worker_owner_reconcile_sql(
            restore_drill.DRILL_OPERATOR_ID,
            disabled_principals=[(restore_drill.USER_C_IDS["user"], restore_drill.USER_C_IDS["approval"])],
        )
        self.assertIn("coalesce(r.cancel_reason, 'revoked')", owner_sql)
        self.assertIn("SET last_event_sequence = last_event_sequence + 1", owner_sql)
        self.assertIn("access_generation = access_generation + 1", owner_sql)
        self.assertNotIn("quota_release_terminal_runs", owner_sql)

        worker_sql = restore_drill.worker_quota_release_sql()
        self.assertIn("openmettle.quota_release_terminal_runs", worker_sql)

        sess_sql = restore_drill.fresh_post_restore_session_sql(
            restore_drill.USER_A_IDS, "A" * 43, "B" * 43, "a" * 64, "target-a"
        )
        self.assertIn("SELECT access_generation FROM openmettle.local_identity_approvals", sess_sql)


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

    def test_environment_manifests_enforce_pod_security_default_deny_and_target_db_revocations(self):
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
        for ns_name in (restore_drill.TARGET_APP_NS, restore_drill.TARGET_DB_NS):
            ns = next(i for i in bundle["items"] if i["kind"] == "Namespace" and i["metadata"]["name"] == ns_name)
            self.assertEqual(ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")
        pg_dep = next(i for i in bundle["items"] if i["kind"] == "Deployment" and i["metadata"]["name"] == "postgres")
        self.assertEqual(pg_dep["spec"]["template"]["spec"]["securityContext"]["runAsUser"], 999)
        fixture_secret = next(i for i in bundle["items"] if i["kind"] == "Secret" and i["metadata"]["name"] == "postgres-fixture")
        provision_sql = fixture_secret["stringData"]["provision.sql"]
        self.assertIn("REVOKE ALL ON DATABASE openmettle FROM PUBLIC;", provision_sql)
        self.assertIn("GRANT CONNECT ON DATABASE openmettle TO openmettle_api", provision_sql)
        self.assertIn("REVOKE ALL ON SCHEMA public FROM PUBLIC;", provision_sql)
        wrong_secret = next(
            i for i in bundle["items"]
            if i["kind"] == "Secret" and i["metadata"]["name"] == restore_drill.WRONG_BACKUP_SECRET
        )
        wrong_doc = json.loads(base64.b64decode(wrong_secret["data"]["keyring.json"]))
        self.assertEqual(wrong_doc["keys"][0]["file"], f"{restore_drill.WRONG_BACKUP_KEYS_DIR}/{smoke.BACKUP_KEY_FILE}")
        db_netpols = [
            i["metadata"]["name"] for i in bundle["items"]
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
        self.fail_on_target_migrate = False

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
                if doc.get("kind") == "Job":
                    self._last_job = doc["metadata"]["name"]
                    if self.fail_on_target_migrate and self._last_job == "openmettle-drill-migrate":
                        # Leak a secret in stderr to prove redaction!
                        return self._res(1, "", f"fatal migrate error password={self._leak_secret}")
                return self._res(0, "")
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
        if name == "openmettle-drill-pg-restore":
            return self._res(0, "pg_restore.completed\n")
        if name == "openmettle-drill-rebind-failclosed":
            return self._res(
                0,
                "LOCK_STDOUT_BEGIN\n"
                "restore gate closed: restore_run 77777777-7777-4777-8777-777777777777, origin 1, snapshot 2, required 5, coverage_complete true\n"
                "LOCK_STDOUT_END\n"
                "REBIND_STDOUT_BEGIN\n"
                "rebound 5, emptied 0, unchanged 0, quarantined 0, failed 1\n"
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
                f"QUOTA_STAGE4_BEGIN\n{qv}QUOTA_STAGE4_END\n"
                "VAULT_BEFORE_BEGIN\nconnections 2, encrypted 1\nkey_id vault-k1 1\nVAULT_BEFORE_END\n"
                "VAULT_AFTER_BEGIN\nconnections 2, encrypted 1\nkey_id vault-k2 1\nVAULT_AFTER_END\n",
            )
        if name == "openmettle-drill-pre-worker-sql":
            return self._res(0, "2\n")
        if name == "openmettle-drill-worker-quota-release":
            return self._res(0, "1\n")
        if name == "openmettle-drill-release-maintenance":
            return self._res(0, f"QUOTA_VERIFY_BEGIN\n{qv}QUOTA_VERIFY_END\n")
        if name == "openmettle-drill-post-verify":
            return self._res(0, qv)
        return self._res(0, "")

    def _exec_handler(self, argv: list[str], stdin_text: str | None):
        if "/tmp/kind-drill-fixture" in argv:
            # Capture the API DB password from stdin so failure test can verify secret redaction!
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
            if "gateway_requests" in stdin_text:
                return self._res(0, "11111111-1111-4111-8111-111111111111|handed_off|t|t|1|11|7|t|settled|0|18\n")
            if "FROM openmettle.artifact_revisions" in stdin_text and "WHERE id IN" in stdin_text:
                return self._res(
                    0,
                    "99999999-9999-4999-8999-999999999993|99999999-9999-4999-8999-999999999990|1800000000000000\n"
                    "99999999-9999-4999-8999-999999999994|99999999-9999-4999-8999-999999999991|\n"
                    "99999999-9999-4999-8999-999999999995|99999999-9999-4999-8999-999999999995|\n",
                )
            if "openmettle.operations" in stdin_text:
                return self._res(
                    0,
                    "outcome_unknown:1|1|t|1800000000000000|purged|t|f|2:2:1:2|3:3:1:3|released:0|held:25\n",
                )
            if "SELECT state FROM openmettle.artifact_revisions" in stdin_text:
                return self._res(0, "purged\n")
            if "FROM openmettle.deletion_journal_head" in stdin_text:
                return self._res(0, f"5|{DIGEST_B}\n")
            if "_sqlx_migrations" in stdin_text:
                return self._res(0, f"{smoke.REQUIRED_MIGRATION}|1|t\n")
            return self._res(0, "")
        if "timeout" in argv:
            # NetworkPolicy probe: deny primary_db/primary_gw from target namespaces, connect otherwise.
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
            return 401, prob_hdrs, json.dumps({"status": 401, "code": "unauthenticated"}).encode()
        if path.startswith("/v1/projects/") and method == "GET":
            return 401, prob_hdrs, json.dumps({"status": 401, "code": "unauthenticated"}).encode()
        if path == "/v1/conversations" and method == "POST":
            return 201, v1_hdrs, json.dumps({
                "conversation_id": "bbbb0000-0000-4000-8000-000000000001",
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
            if raw_cookie == self._cookie_b2:
                return 404, prob_hdrs, json.dumps({"status": 404, "code": "not_found"}).encode()
            return 200, v1_hdrs, json.dumps({"conversation_id": "bbbb0000-0000-4000-8000-000000000001"}).encode()
        if path.startswith("/v1/artifacts/") and method == "GET":
            # Primary non-interference check on port 18081 vs target port 18082:
            if port == 18081 and "99999999-9999-4999-8999-999999999995/content" in path:
                return 200, {**v1_hdrs, "content-type": "text/plain"}, b"drill-unrecoverable-payload-bytes\n"
            if raw_cookie == self._cookie_b2 and ("99999999-9999-4999-8999-999999999981" in path or "99999999-9999-4999-8999-999999999985" in path):
                return 404, prob_hdrs, json.dumps({"status": 404, "code": "not_found"}).encode()
            if "99999999-9999-4999-8999-999999999991/content" in path:
                return 200, {**v1_hdrs, "content-type": "text/plain"}, b"drill-personal-keep-bytes\n"
            if "99999999-9999-4999-8999-999999999992/content" in path:
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
            if session_counter["n"] in (1, 2, 3, 6):
                outer._stale_or_disabled_cookies = (*getattr(outer, "_stale_or_disabled_cookies", ()), cookie)
            elif session_counter["n"] == 5:
                outer._cookie_b2 = cookie
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

    def test_full_orchestration_passes_and_cleans_up_via_callable_only_runner(self):
        rc, summary = self._run_drill()
        self.assertEqual(rc, 0, summary.get("error"))
        self.assertEqual(summary["result"], "passed")
        self.assertEqual(summary["classification"], "dev")
        self.assertTrue(summary["rpo_rto"]["rpo_met"])
        self.assertTrue(summary["rpo_rto"]["rto_met"])
        self.assertTrue(any(cmd[:3] == ["kind", "delete", "cluster"] for cmd in self.commands))
        self.assertTrue(any(cmd[:4] == ["docker", "image", "rm", "--force"] for cmd in self.commands))

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
