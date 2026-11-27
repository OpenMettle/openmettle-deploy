"""Cluster-free unit and orchestration tests for the isolated-target restore drill harness (tests/kind/restore_drill.py)."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
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
DEFAULT_LOST_REVISION_ID = "99999999-9999-4999-8999-999999999995"
DEFAULT_FIXTURE_SCOPE_ID = "22222222-2222-4222-8222-222222222222"
DEFAULT_LOST_CONTENT_DIGEST = hashlib.sha256(b"drill-unrecoverable-payload-bytes\n").hexdigest()


def build_six_record_journal_fixture(
    lost_entity: str = DEFAULT_LOST_REVISION_ID,
    scope_id: str = DEFAULT_FIXTURE_SCOPE_ID,
    *,
    purged_content_digest: str = DIGEST_A,
    lost_content_digest: str = DEFAULT_LOST_CONTENT_DIGEST,
) -> tuple[list[str], list[str], bytes]:
    """Build a six-record deletion journal fixture with valid `deletion_journal_digest` chains."""
    conn_id = "11111111-1111-4111-8111-111111111115"
    conn_disconnect_digest = hashlib.sha256(f"disconnect:{conn_id}:1".encode("utf-8")).hexdigest()
    specs = [
        (1, 1795450010000000, "artifact_revision.purged", "11111111-1111-4111-8111-111111111111", scope_id, None, 1795450009000000, 1795450010000000, purged_content_digest, 1),
        (2, 1795450011000000, "artifact_revision.retained", "11111111-1111-4111-8111-111111111112", scope_id, 1795450011000000, 1795450020000000, None, DIGEST_A, 1),
        (3, 1795450012000000, "artifact_revision.deadline_adjusted", "11111111-1111-4111-8111-111111111112", scope_id, 1795450011000000, 1795450025000000, None, DIGEST_A, 2),
        (4, 1795450013000000, "artifact_revision.restored", "11111111-1111-4111-8111-111111111112", scope_id, None, None, None, DIGEST_A, None),
        (5, 1795450014000000, "external_connection.disconnected", conn_id, scope_id, None, None, None, conn_disconnect_digest, 1),
        (6, 1795450015000000, "artifact_revision.lost", lost_entity, scope_id, None, None, 1795450015000000, lost_content_digest, None),
    ]
    records: list[str] = []
    chains: list[str] = []
    prev = GENESIS
    for seq, at_us, kind, entity, scope, r_us, a_us, p_us, c_dig, pol in specs:
        chain = restore_drill.compute_journal_record_chain_digest(
            prev,
            seq=seq,
            kind=kind,
            entity=entity,
            scope=scope,
            recorded_us=at_us,
            retained_us=r_us,
            after_us=a_us,
            purged_us=p_us,
            content_digest=c_dig,
            policy_rev=pol,
        )
        pol_s = "-" if pol is None else str(pol)
        a_s = "-" if a_us is None else str(a_us)
        p_s = "-" if p_us is None else str(p_us)
        if kind == "artifact_revision.purged":
            records.append(f"{seq} {at_us} {kind} {entity} {scope} {a_s} {p_s} {c_dig} {pol_s} {chain}")
        else:
            r_s = "-" if r_us is None else str(r_us)
            records.append(f"{seq} {at_us} {kind} {entity} {scope} {a_s} {p_s} {c_dig} {pol_s} {chain} {r_s}")
        chains.append(chain)
        prev = chain
    body = (
        "\n".join([
            "openmettle.deletion_journal.export/1",
            "origin 1795450000000000",
            "lifecycle_origin 1795450010500000",
            f"lifecycle_baseline {GENESIS}",
            "connection_origin 1795450010600000",
            *records,
            f"watermark 1795450000000000 6 {chains[-1]} 1795450025000000",
        ])
        + "\n"
    )
    body_b = body.encode("utf-8")
    raw_bytes = body_b + f"sha256 {hashlib.sha256(body_b).hexdigest()}\n".encode("ascii")
    return records, chains, raw_bytes


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

    def test_parses_labelled_cancelled_runs_count_ignoring_setval_output(self):
        self.assertEqual(restore_drill.parse_cancelled_runs_count("100\ncancelled_runs=2\n"), 2)
        self.assertEqual(restore_drill.parse_cancelled_runs_count("  cancelled_runs=0  \n"), 0)
        for bad_out in ("100\n2\n", "100\n", "cancelled_runs=2\ncancelled_runs=2\n", ""):
            with self.assertRaisesRegex(restore_drill.DrillFailure, "cancelled_runs"):
                restore_drill.parse_cancelled_runs_count(bad_out)

    def test_verify_trailing_epoch_probe_failure_requires_pg_guard_diagnostic(self):
        restore_drill.verify_trailing_epoch_probe_failure(
            3,
            "ERROR:  login_provider_revisions epoch 41 did not advance past previous maximum 100",
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "epoch guard diagnostic"):
            restore_drill.verify_trailing_epoch_probe_failure(
                0,
                "ERROR:  login_provider_revisions epoch 41 did not advance past previous maximum 100",
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "epoch guard diagnostic"):
            restore_drill.verify_trailing_epoch_probe_failure(
                1,
                "error: unable to upgrade connection: container not found",
            )

    def test_verify_persisted_post_restore_journal_checks_sha256_watermark_and_lost_records(self):
        rev_lost = DEFAULT_LOST_REVISION_ID
        scope_id = DEFAULT_FIXTURE_SCOPE_ID
        expected_lost = [(rev_lost, scope_id, DEFAULT_LOST_CONTENT_DIGEST)]
        hdr = {
            "expected_origin_us": 1795450000000000,
            "expected_lifecycle_origin_us": 1795450010500000,
            "expected_lifecycle_baseline_digest": GENESIS,
            "expected_connection_origin_us": 1795450010600000,
        }

        def make_export_bytes(
            records: list[str],
            *,
            seq: int,
            tail_chain: str,
            with_lifecycle: bool = True,
            baseline_lines: list[str] = (),
            baseline_digest: str = GENESIS,
            eol: str = "\n",
            sum_eol: str = "\n",
        ) -> bytes:
            lines = ["openmettle.deletion_journal.export/1", "origin 1795450000000000"]
            if with_lifecycle:
                lines.extend(["lifecycle_origin 1795450010500000", f"lifecycle_baseline {baseline_digest}", *baseline_lines])
            lines.extend(["connection_origin 1795450010600000", *records, f"watermark 1795450000000000 {seq} {tail_chain} 1795450025000000"])
            body = eol.join(lines) + eol
            body_b = body.encode("utf-8")
            trailer = f"sha256 {hashlib.sha256(body_b).hexdigest()}{sum_eol}".encode("ascii")
            return body_b + trailer

        base_records, chains, valid = build_six_record_journal_fixture(rev_lost, scope_id)
        min_digest = chains[4]
        self.assertEqual(chains[0], "15cf6556c7336ea2839a714d64201432a08031de004b90a6eec4d2f7caee26c1")
        # Round-trip via base64 even with `\r\n` log line-ending normalization.
        b64_log = base64.encodebytes(valid).decode("ascii").replace("\n", "\r\n").replace("\r\n", "\n")
        decoded_valid = restore_drill.decode_base64_export_bytes(b64_log)
        wm = restore_drill.verify_persisted_post_restore_journal(
            decoded_valid,
            **hdr,
            min_seq=5,
            expected_min_digest=min_digest,
            expected_lost_revisions=expected_lost,
        )
        self.assertEqual(wm["required_seq"], 6)
        self.assertEqual(wm["required_digest"], chains[-1])

        with self.assertRaisesRegex(restore_drill.DrillFailure, "raw bytes"):
            restore_drill.verify_persisted_post_restore_journal(
                valid.decode("utf-8"),  # type: ignore[arg-type]
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # Mismatched recovery headers (including None vs non-None) MUST fail:
        with self.assertRaisesRegex(restore_drill.DrillFailure, "lifecycle_origin mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **{**hdr, "expected_lifecycle_origin_us": 1795450010500999},
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "lifecycle_origin mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **{**hdr, "expected_lifecycle_origin_us": None, "expected_lifecycle_baseline_digest": None},
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "lifecycle_baseline mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **{**hdr, "expected_lifecycle_baseline_digest": DIGEST_B},
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "connection_origin mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **{**hdr, "expected_connection_origin_us": 1795450010600999},
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "connection_origin mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **{**hdr, "expected_connection_origin_us": None},
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # CRLF regression: stored CRLF export transferred safely over base64 + text logs still fails SHA-256!
        crlf_stored = valid.replace(b"\n", b"\r\n")
        crlf_b64_through_text_runner = base64.encodebytes(crlf_stored).decode("ascii").replace("\r\n", "\n")
        decoded_crlf = restore_drill.decode_base64_export_bytes(crlf_b64_through_text_runner)
        self.assertEqual(decoded_crlf, crlf_stored)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "sha256 checksum mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                decoded_crlf,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # Even if CRLF bytes carry a matching SHA-256 over the CRLF body, CR bytes in body MUST fail closed.
        crlf_rehashed = make_export_bytes(base_records, seq=6, tail_chain=chains[-1], eol="\r\n", sum_eol="\n")
        with self.assertRaisesRegex(restore_drill.DrillFailure, "carriage returns"):
            restore_drill.verify_persisted_post_restore_journal(
                crlf_rehashed,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        tampered = valid.replace(rev_lost.encode("ascii"), b"99999999-9999-4999-8999-999999999999")
        with self.assertRaisesRegex(restore_drill.DrillFailure, "sha256 checksum mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                tampered,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # Baseline canonical integer parsing & hashing (`01` and `+1` accepted and hashed as `1`, not raw text):
        b_ent = "11111111-1111-4111-8111-111111111199"
        canonical_b_digest = hashlib.sha256(
            f"{GENESIS}:{b_ent}:{scope_id}:purging:1795450001000000:1795450002000000:1795450030000000:{DIGEST_A}:1".encode("utf-8")
        ).hexdigest()
        raw_text_b_digest = hashlib.sha256(
            f"{GENESIS}:{b_ent}:{scope_id}:purging:1795450001000000:1795450002000000:01795450030000000:{DIGEST_A}:01".encode("utf-8")
        ).hexdigest()
        for pol_text, purg_text in (("01", "01795450030000000"), ("+1", "+1795450030000000")):
            b_line = f"baseline {b_ent} {scope_id} purging 1795450001000000 1795450002000000 {purg_text} {DIGEST_A} {pol_text}"
            ok_baseline = make_export_bytes(
                base_records, seq=6, tail_chain=chains[-1], baseline_lines=[b_line], baseline_digest=canonical_b_digest
            )
            wm_b = restore_drill.verify_persisted_post_restore_journal(
                ok_baseline,
                **{**hdr, "expected_lifecycle_baseline_digest": canonical_b_digest},
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )
            self.assertEqual(wm_b["lifecycle_baseline_digest"], canonical_b_digest)

        bad_baseline = make_export_bytes(
            base_records,
            seq=6,
            tail_chain=chains[-1],
            baseline_lines=[f"baseline {b_ent} {scope_id} purging 1795450001000000 1795450002000000 01795450030000000 {DIGEST_A} 01"],
            baseline_digest=raw_text_b_digest,
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "lifecycle baseline digest mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                bad_baseline,
                **{**hdr, "expected_lifecycle_baseline_digest": raw_text_b_digest},
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # Divergent pre-watermark history (different chain digest at min_seq=5) MUST fail certified checkpoint check:
        _, alt_chains, alt_valid = build_six_record_journal_fixture(
            rev_lost, scope_id, purged_content_digest=DIGEST_B
        )
        self.assertNotEqual(alt_chains[4], min_digest)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "digest at certified seq 5 mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                alt_valid,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # Loss recorded at or before min_seq MUST NOT satisfy a post-watermark declared loss:
        lost_at_seq5_chain = restore_drill.compute_journal_record_chain_digest(
            chains[3],
            seq=5,
            kind="artifact_revision.lost",
            entity=rev_lost,
            scope=scope_id,
            recorded_us=1795450014000000,
            purged_us=1795450014000000,
            content_digest=DEFAULT_LOST_CONTENT_DIGEST,
            policy_rev=None,
        )
        other_rev = "99999999-9999-4999-8999-999999999999"
        lost_at_seq6_chain = restore_drill.compute_journal_record_chain_digest(
            lost_at_seq5_chain,
            seq=6,
            kind="artifact_revision.lost",
            entity=other_rev,
            scope=scope_id,
            recorded_us=1795450015000000,
            purged_us=1795450015000000,
            content_digest=DEFAULT_LOST_CONTENT_DIGEST,
            policy_rev=None,
        )
        pre_wm_lost_export = make_export_bytes(
            [
                *base_records[:4],
                f"5 1795450014000000 artifact_revision.lost {rev_lost} {scope_id} - 1795450014000000 {DEFAULT_LOST_CONTENT_DIGEST} - {lost_at_seq5_chain} -",
                f"6 1795450015000000 artifact_revision.lost {other_rev} {scope_id} - 1795450015000000 {DEFAULT_LOST_CONTENT_DIGEST} - {lost_at_seq6_chain} -",
            ],
            seq=6,
            tail_chain=lost_at_seq6_chain,
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "missing post-watermark artifact_revision.lost"):
            restore_drill.verify_persisted_post_restore_journal(
                pre_wm_lost_export,
                **hdr,
                min_seq=5,
                expected_min_digest=lost_at_seq5_chain,
                expected_lost_revisions=expected_lost,
            )

        # Restored revision returning to `active` cannot later take `deadline_adjusted` without re-retaining,
        # whereas `restored` -> `purged` (seq <= lifecycle_origin) or fresh `retained` -> `purged` is allowed:
        adj_after_restore_chain = restore_drill.compute_journal_record_chain_digest(
            chains[-1],
            seq=7,
            kind="artifact_revision.deadline_adjusted",
            entity="11111111-1111-4111-8111-111111111112",
            scope=scope_id,
            recorded_us=1795450016000000,
            retained_us=1795450011000000,
            after_us=1795450026000000,
            content_digest=DIGEST_A,
            policy_rev=3,
        )
        adj_after_restore_bytes = make_export_bytes(
            [
                *base_records,
                f"7 1795450016000000 artifact_revision.deadline_adjusted 11111111-1111-4111-8111-111111111112 {scope_id} 1795450026000000 - {DIGEST_A} 3 {adj_after_restore_chain} 1795450011000000",
            ],
            seq=7,
            tail_chain=adj_after_restore_chain,
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "requires current retained state"):
            restore_drill.verify_persisted_post_restore_journal(
                adj_after_restore_bytes,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        purged_after_restore_chain = restore_drill.compute_journal_record_chain_digest(
            chains[-1],
            seq=7,
            kind="artifact_revision.purged",
            entity="11111111-1111-4111-8111-111111111112",
            scope=scope_id,
            recorded_us=1795450016000000,
            after_us=1795450025000000,
            purged_us=1795450016000000,
            content_digest=DIGEST_A,
            policy_rev=2,
        )
        purged_after_restore_bytes = make_export_bytes(
            [
                *base_records,
                f"7 1795450016000000 artifact_revision.purged 11111111-1111-4111-8111-111111111112 {scope_id} 1795450025000000 1795450016000000 {DIGEST_A} 2 {purged_after_restore_chain}",
            ],
            seq=7,
            tail_chain=purged_after_restore_chain,
        )
        wm_purged_after_restore = restore_drill.verify_persisted_post_restore_journal(
            purged_after_restore_bytes,
            **hdr,
            min_seq=5,
            expected_min_digest=min_digest,
            expected_lost_revisions=expected_lost,
        )
        self.assertEqual(wm_purged_after_restore["required_seq"], 7)

        # Expected scope_id / content_digest mismatch on artifact_revision.lost MUST fail:
        with self.assertRaisesRegex(restore_drill.DrillFailure, "metadata mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=[(rev_lost, scope_id, DIGEST_A)],
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "metadata mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=[(rev_lost, "33333333-3333-4333-8333-333333333333", DEFAULT_LOST_CONTENT_DIGEST)],
            )

        # Long zero-padded decimal integers (>4300 digits) match Rust i64::from_str, and true overflow raises DrillFailure:
        zero_padded_seq = ("+" + ("0" * 5000) + "1")
        long_seq_records = [f"{zero_padded_seq} " + base_records[0].split(" ", 1)[1], *base_records[1:]]
        long_seq_bytes = make_export_bytes(long_seq_records, seq=6, tail_chain=chains[-1])
        self.assertEqual(
            restore_drill.verify_persisted_post_restore_journal(
                long_seq_bytes,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )["required_seq"],
            6,
        )
        long_wm_text = (
            "openmettle.deletion_journal.export/1\n"
            f"origin {'0' * 5000}1\n"
            f"watermark +{'0' * 5000}1 {'0' * 5000}0 {GENESIS} 2\n"
            f"sha256 {GENESIS}\n"
        )
        self.assertEqual(restore_drill.parse_journal_export_watermarks(long_wm_text)["origin_us"], 1)
        overflow_wm_text = (
            "openmettle.deletion_journal.export/1\n"
            f"origin 1{'0' * 5000}\n"
            f"watermark 1 0 {GENESIS} 2\n"
            f"sha256 {GENESIS}\n"
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "out-of-range"):
            restore_drill.parse_journal_export_watermarks(overflow_wm_text)

        # Bad chain digest on record 1 even with matching watermark & file sha256 MUST fail replay parity:
        bad_chain = make_export_bytes(
            [f"1 1795450010000000 artifact_revision.purged 11111111-1111-4111-8111-111111111111 {scope_id} 1795450009000000 1795450010000000 {DIGEST_A} 1 {DIGEST_A}"],
            seq=1,
            tail_chain=DIGEST_A,
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "chain digest mismatch"):
            restore_drill.verify_persisted_post_restore_journal(
                bad_chain,
                **hdr,
                min_seq=0,
                expected_min_digest=GENESIS,
                expected_lost_revisions=[],
            )

        # Retained Review #15 malformed fixture (starts at seq 6, omits lifecycle_origin, '-' for purged_us):
        malformed_combined = make_export_bytes(
            [f"6 1795450015000000 artifact_revision.lost {rev_lost} {scope_id} - - {DIGEST_A} - {DIGEST_B} -"],
            seq=6,
            tail_chain=DIGEST_B,
            with_lifecycle=False,
        )
        with self.assertRaises(restore_drill.DrillFailure):
            restore_drill.verify_persisted_post_restore_journal(
                malformed_combined,
                expected_origin_us=1795450000000000,
                expected_lifecycle_origin_us=None,
                expected_lifecycle_baseline_digest=None,
                expected_connection_origin_us=1795450010600000,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # Individual Export::parse rejection cases:
        no_lifecycle = make_export_bytes([base_records[-1]], seq=6, tail_chain=chains[-1], with_lifecycle=False)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "missing lifecycle_origin"):
            restore_drill.verify_persisted_post_restore_journal(
                no_lifecycle,
                expected_origin_us=1795450000000000,
                expected_lifecycle_origin_us=None,
                expected_lifecycle_baseline_digest=None,
                expected_connection_origin_us=1795450010600000,
                min_seq=0,
                expected_min_digest=GENESIS,
                expected_lost_revisions=expected_lost,
            )

        seq_gap = make_export_bytes([base_records[-1]], seq=6, tail_chain=chains[-1], with_lifecycle=True)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "out of sequence"):
            restore_drill.verify_persisted_post_restore_journal(
                seq_gap,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        missing_purged_us = make_export_bytes(
            [*base_records[:-1], f"6 1795450015000000 artifact_revision.lost {rev_lost} {scope_id} - - {DIGEST_A} - {DIGEST_B} -"],
            seq=6,
            tail_chain=DIGEST_B,
            with_lifecycle=True,
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "malformed artifact_revision.lost"):
            restore_drill.verify_persisted_post_restore_journal(
                missing_purged_us,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        # Post-lifecycle purged without baseline/prior retained MUST fail replay parity:
        missing_retained_chain = restore_drill.compute_journal_record_chain_digest(
            GENESIS,
            seq=1,
            kind="artifact_revision.purged",
            entity="11111111-1111-4111-8111-111111111111",
            scope=scope_id,
            recorded_us=1795450010600000,
            after_us=1795450009000000,
            purged_us=1795450010600000,
            content_digest=DIGEST_A,
            policy_rev=1,
        )
        post_lc_purged = make_export_bytes(
            [
                f"1 1795450010600000 artifact_revision.purged 11111111-1111-4111-8111-111111111111 {scope_id} 1795450009000000 1795450010600000 {DIGEST_A} 1 {missing_retained_chain}"
            ],
            seq=1,
            tail_chain=missing_retained_chain,
        )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "lacks baseline or prior retained commitment"):
            restore_drill.verify_persisted_post_restore_journal(
                post_lc_purged,
                **hdr,
                min_seq=0,
                expected_min_digest=GENESIS,
                expected_lost_revisions=[],
            )

        _, _, other_valid = build_six_record_journal_fixture(other_rev, scope_id)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "missing post-watermark artifact_revision.lost"):
            restore_drill.verify_persisted_post_restore_journal(
                other_valid,
                **hdr,
                min_seq=5,
                expected_min_digest=min_digest,
                expected_lost_revisions=expected_lost,
            )

        with self.assertRaisesRegex(restore_drill.DrillFailure, "did not advance past 6"):
            restore_drill.verify_persisted_post_restore_journal(
                valid,
                **hdr,
                min_seq=6,
                expected_min_digest=chains[-1],
                expected_lost_revisions=expected_lost,
            )


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
        media_parent = tmp / "media_parent"
        media = media_parent / "openmettle"
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
            recovery_media_dir=str(media),
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

        # Negative test 1: an intact unreadable staging file MUST abort reconciliation rather than
        # falling through to `storage declare-lost`.
        rec_staging_path = unpacked / "artifacts" / "revisions" / rec_res
        if os.geteuid() != 0:
            (artifacts / "revisions" / rec_res).unlink(missing_ok=True)
            log_file.write_text("", encoding="utf-8")
            rec_staging_path.chmod(0o000)
            try:
                res_unreadable = subprocess.run(
                    ["/bin/sh", "-eu", "-c", script], env=env, capture_output=True, text=True
                )
            finally:
                rec_staging_path.chmod(0o600)
            self.assertNotEqual(res_unreadable.returncode, 0)
            self.assertIn("unreadable or not a regular file", res_unreadable.stderr)
            self.assertNotIn("storage declare-lost", log_file.read_text(encoding="utf-8"))

        # Negative test 2: a failing sha256sum probe on a readable staging file MUST stop
        # reconciliation rather than masking exit status and calling `storage declare-lost`.
        (artifacts / "revisions" / rec_res).unlink(missing_ok=True)
        log_file.write_text("", encoding="utf-8")
        sha_stub = bin_dir / "sha256sum"
        sha_stub.write_text("#!/bin/sh\necho 'sha256sum: simulated read I/O error' >&2\nexit 1\n", encoding="utf-8")
        sha_stub.chmod(0o755)
        try:
            res_sha_fail = subprocess.run(["/bin/sh", "-eu", "-c", script], env=env, capture_output=True, text=True)
            self.assertNotEqual(res_sha_fail.returncode, 0)
            self.assertNotIn("storage declare-lost", log_file.read_text(encoding="utf-8"))
        finally:
            sha_stub.unlink()

        # Negative test 3: if the staging revisions directory itself lacks read/search permission
        # as non-root, directory checks MUST fail closed rather than letting `[ -e "$cand" ]` return
        # false on an intact file and invoke `storage declare-lost`.
        rev_dir = unpacked / "artifacts" / "revisions"
        if os.geteuid() != 0:
            (artifacts / "revisions" / rec_res).unlink(missing_ok=True)
            log_file.write_text("", encoding="utf-8")
            rev_dir.chmod(0o000)
            try:
                res_dir_unreadable = subprocess.run(
                    ["/bin/sh", "-eu", "-c", script], env=env, capture_output=True, text=True
                )
            finally:
                rev_dir.chmod(0o700)
            self.assertNotEqual(res_dir_unreadable.returncode, 0)
            self.assertIn("staging revisions directory", res_dir_unreadable.stderr)
            self.assertIn("inaccessible", res_dir_unreadable.stderr)
            self.assertNotIn("storage declare-lost", log_file.read_text(encoding="utf-8"))

        # Negative test 4: if any encrypted backup archive copy remains reachable under `recovery_media_dir`,
        # OR `recovery_media_dir` itself or any ancestor directory is inaccessible as non-root,
        # `storage declare-lost` MUST be refused before executing.
        (artifacts / "revisions" / rec_res).unlink(missing_ok=True)
        (media / "backup-20261127T090000Z-66666666-6666-4666-8666-666666666666").mkdir(parents=True)
        if os.geteuid() != 0:
            log_file.write_text("", encoding="utf-8")
            media_parent.chmod(0o000)
            try:
                res_parent_unreadable = subprocess.run(
                    ["/bin/sh", "-eu", "-c", script], env=env, capture_output=True, text=True
                )
            finally:
                media_parent.chmod(0o700)
            self.assertNotEqual(res_parent_unreadable.returncode, 0)
            self.assertIn("recovery media ancestor", res_parent_unreadable.stderr)
            self.assertIn("inaccessible", res_parent_unreadable.stderr)
            self.assertNotIn("storage declare-lost", log_file.read_text(encoding="utf-8"))

            log_file.write_text("", encoding="utf-8")
            media.chmod(0o000)
            try:
                res_media_unreadable = subprocess.run(
                    ["/bin/sh", "-eu", "-c", script], env=env, capture_output=True, text=True
                )
            finally:
                media.chmod(0o700)
            self.assertNotEqual(res_media_unreadable.returncode, 0)
            self.assertIn("recovery media directory", res_media_unreadable.stderr)
            self.assertIn("inaccessible", res_media_unreadable.stderr)
            self.assertNotIn("storage declare-lost", log_file.read_text(encoding="utf-8"))
        log_file.write_text("", encoding="utf-8")
        res_avail = subprocess.run(["/bin/sh", "-eu", "-c", script], env=env, capture_output=True, text=True)
        self.assertNotEqual(res_avail.returncode, 0)
        self.assertIn("remains available", res_avail.stderr)
        self.assertNotIn("storage declare-lost", log_file.read_text(encoding="utf-8"))

    def test_family_policy_reconcile_lines_validates_and_renders_cli_commands(self):
        import re as _re
        import shlex
        run_id = "77777777-7777-4777-8777-777777777777"
        uid = restore_drill.USER_D_IDS["user"]

        def run_simulated_family_cli(script_text: str, *, initial_policy: dict | None = None, initial_models: dict | None = None):
            """Simulate `openmettle-core`'s `openmettle-admin family` state machine (`UNCHANGED`,
            missing policy `NotFound`, `KEY_REUSED`, and idempotent `Replayed` no-op)."""
            policies: dict[str, dict] = {}
            if initial_policy is not None:
                policies[uid] = dict(initial_policy)
            models: dict[tuple[str, str, str], bool] = dict(initial_models or {})
            audit: dict[tuple[str, str], tuple] = {}
            emitted_keys: list[str] = []

            def replay(lines_to_run: list[str]) -> None:
                for line in lines_to_run:
                    tokens = shlex.split(line)
                    self.assertEqual(tokens[:2], ["openmettle-admin", "family"])
                    sub = tokens[2]
                    op_id = tokens[tokens.index("--operator-id") + 1]
                    req_key = tokens[tokens.index("--request-key") + 1]
                    target_uid = tokens[tokens.index("--user") + 1]
                    self.assertLessEqual(len(req_key.encode("utf-8")), 128)
                    emitted_keys.append(req_key)

                    if sub == "set-policy":
                        zone = tokens[tokens.index("--zone") + 1]
                        quiet = tokens[tokens.index("--quiet") + 1] if "--quiet" in tokens else None
                        study = tokens[tokens.index("--study") + 1] if "--study" in tokens else None
                        override = "--override-group-schedules" in tokens
                        details = ("set", target_uid, zone, quiet, study, override)
                        if (op_id, req_key) in audit:
                            self.assertEqual(audit[(op_id, req_key)], details)
                            continue
                        audit[(op_id, req_key)] = details
                        cur = policies.get(target_uid)
                        if (
                            cur is not None
                            and cur["active"]
                            and (cur["zone"], cur["quiet"], cur["study"], cur["override"])
                            == (zone, quiet, study, override)
                        ):
                            raise AssertionError(f"UNCHANGED set-policy on {target_uid}: {details!r}")
                        policies[target_uid] = {
                            "active": True,
                            "zone": zone,
                            "quiet": quiet,
                            "study": study,
                            "override": override,
                        }
                    elif sub == "clear-policy":
                        details = ("clear", target_uid)
                        if (op_id, req_key) in audit:
                            self.assertEqual(audit[(op_id, req_key)], details)
                            continue
                        audit[(op_id, req_key)] = details
                        cur = policies.get(target_uid)
                        if cur is None or not cur["active"]:
                            raise AssertionError(f"UNCHANGED clear-policy on {target_uid}")
                        cur["active"] = False
                    elif sub == "set-model":
                        kind = tokens[tokens.index("--kind") + 1]
                        model = tokens[tokens.index("--model") + 1]
                        has_enable = "--enable" in tokens
                        has_disable = "--disable" in tokens
                        self.assertNotEqual(has_enable, has_disable)
                        active = has_enable
                        details = ("model", target_uid, kind, model, active)
                        if (op_id, req_key) in audit:
                            self.assertEqual(audit[(op_id, req_key)], details)
                            continue
                        audit[(op_id, req_key)] = details
                        if target_uid not in policies:
                            raise AssertionError(f"family policy target not found for {target_uid}")
                        if models.get((target_uid, kind, model), False) == active:
                            raise AssertionError(f"UNCHANGED set-model on {(target_uid, kind, model, active)!r}")
                        models[(target_uid, kind, model)] = active
                    else:
                        raise AssertionError(f"unexpected subcommand: {sub!r}")

            raw_lines = [ln for ln in script_text.splitlines() if ln.strip()]
            replay(raw_lines)
            # Second pass verifies script retry is a pure idempotent replay across all steps.
            key_count_first = len(emitted_keys)
            replay(raw_lines)
            return policies, models, emitted_keys[:key_count_first]

        # 1) Model-only post-backup change on an already-restored policy emits ONLY set-model so
        # existing quiet/study/override schedule fields are preserved untouched.
        model_only = restore_drill.build_family_policy_reconcile_lines(
            restore_drill.DRILL_OPERATOR_ID,
            run_id,
            [{"user_id": uid, "policy": None, "models": [("disabled", "a", True)]}],
        )
        self.assertNotIn("family set-policy", model_only)
        self.assertIn("openmettle-admin family set-model --user", model_only)
        self.assertIn("--kind disabled --model 'a' --enable", model_only)
        pol1, mod1, keys1 = run_simulated_family_cli(
            model_only,
            initial_policy={"active": True, "zone": "Europe/London", "quiet": "22:00-07:00", "study": "16:00-18:00", "override": True},
        )
        self.assertEqual(pol1[uid]["quiet"], "22:00-07:00")
        self.assertTrue(mod1[(uid, "disabled", "a")])
        self.assertEqual(len(keys1), 1)

        # 2) Model toggle returning to backup state (`allowed` -> `disable a` -> `enable a`):
        # must replay both steps with distinct keys so `set-model --disable` does not fail with UNCHANGED.
        toggle_back = restore_drill.build_family_policy_reconcile_lines(
            restore_drill.DRILL_OPERATOR_ID,
            run_id,
            [{"user_id": uid, "policy": None, "models": [("disabled", "a", True), ("disabled", "a", False)]}],
        )
        tb_lines = [ln for ln in toggle_back.splitlines() if ln.strip()]
        self.assertEqual(len(tb_lines), 2)
        self.assertIn("--kind disabled --model 'a' --enable", tb_lines[0])
        self.assertIn("--kind disabled --model 'a' --disable", tb_lines[1])
        _, mod2, keys2 = run_simulated_family_cli(
            toggle_back,
            initial_policy={"active": True, "zone": "UTC", "quiet": None, "study": None, "override": False},
        )
        self.assertEqual(len(set(keys2)), 2)
        self.assertFalse(mod2[(uid, "disabled", "a")])

        # 3) Triple model toggle (`disable -> enable -> disable`): 3 commands with 3 distinct keys.
        triple_toggle = restore_drill.build_family_policy_reconcile_lines(
            restore_drill.DRILL_OPERATOR_ID,
            run_id,
            [{"user_id": uid, "policy": None, "models": [("disabled", "a", True), ("disabled", "a", False), ("disabled", "a", True)]}],
        )
        tt_lines = [ln for ln in triple_toggle.splitlines() if ln.strip()]
        self.assertEqual(len(tt_lines), 3)
        _, mod3, keys3 = run_simulated_family_cli(
            triple_toggle,
            initial_policy={"active": True, "zone": "UTC", "quiet": None, "study": None, "override": False},
        )
        self.assertEqual(len(set(keys3)), 3)
        self.assertTrue(mod3[(uid, "disabled", "a")])

        # 4) Schedule toggle returning to backup value (`UTC` -> `Europe/London` + `22:00-07:00` -> `UTC`):
        # emits both transitions in order with distinct keys so neither hits UNCHANGED.
        schedule_revert = restore_drill.build_family_policy_reconcile_lines(
            restore_drill.DRILL_OPERATOR_ID,
            run_id,
            [
                {"user_id": uid, "policy": {"zone": "Europe/London", "quiet": "22:00-07:00"}, "models": []},
                {"user_id": uid, "policy": {"zone": "UTC"}, "models": []},
            ],
        )
        sr_lines = [ln for ln in schedule_revert.splitlines() if ln.strip()]
        self.assertEqual(len(sr_lines), 2)
        self.assertIn('--zone "Europe/London" --quiet "22:00-07:00"', sr_lines[0])
        self.assertIn('--zone "UTC"', sr_lines[1])
        pol4, _, keys4 = run_simulated_family_cli(
            schedule_revert,
            initial_policy={"active": True, "zone": "UTC", "quiet": None, "study": None, "override": False},
        )
        self.assertEqual(len(set(keys4)), 2)
        self.assertEqual(pol4[uid], {"active": True, "zone": "UTC", "quiet": None, "study": None, "override": False})

        # 5) Post-backup policy creation -> model rule -> policy clearance:
        # must preserve set-policy before set-model and clear-policy at the end (never NotFound).
        for entries in (
            [
                {
                    "user_id": uid,
                    "policy": {
                        "zone": "Europe/London",
                        "quiet": "22:00-07:00",
                        "study": "16:00-18:00",
                        "override_group_schedules": True,
                    },
                    "models": [("disabled", "a", True)],
                },
                {"user_id": uid, "policy": "clear", "models": []},
            ],
            [
                {
                    "user_id": uid,
                    "policy": {
                        "zone": "Europe/London",
                        "quiet": "22:00-07:00",
                        "study": "16:00-18:00",
                        "override_group_schedules": True,
                    },
                    "models": [],
                },
                {"user_id": uid, "policy": None, "models": [("disabled", "a", True)]},
                {"user_id": uid, "policy": "clear", "models": []},
            ],
        ):
            create_model_clear = restore_drill.build_family_policy_reconcile_lines(
                restore_drill.DRILL_OPERATOR_ID, run_id, entries
            )
            cmc_lines = [ln for ln in create_model_clear.splitlines() if ln.strip()]
            self.assertEqual(len(cmc_lines), 3)
            self.assertIn("family set-policy", cmc_lines[0])
            self.assertIn('--zone "Europe/London" --quiet "22:00-07:00" --study "16:00-18:00" --override-group-schedules', cmc_lines[0])
            self.assertIn("family set-model", cmc_lines[1])
            self.assertIn("family clear-policy", cmc_lines[2])
            pol5, mod5, keys5 = run_simulated_family_cli(create_model_clear, initial_policy=None)
            self.assertEqual(len(set(keys5)), 3)
            self.assertFalse(pol5[uid]["active"])
            self.assertEqual(pol5[uid]["zone"], "Europe/London")
            self.assertTrue(mod5[(uid, "disabled", "a")])

        # Boundary tests: valid model names of 31, 32, and 256 UTF-8 bytes, spaces/quotes, and `$`
        # sequences (`price$$tier`, `$(OPENMETTLE_ADMIN_DATABASE_URL)`) MUST stay <= 128 bytes for
        # --request-key, remain deterministic per (run, seq, user, kind, model, bit), survive both
        # kubelet command expansion and `/bin/sh` execution unchanged, and round-trip via shlex.
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            captured_args = tmp_path / "captured.argv"
            admin_stub = bin_dir / "openmettle-admin"
            admin_stub.write_text(
                "#!/bin/sh\n"
                f'printf "%s\\0" "$@" > "{captured_args}"\n',
                encoding="utf-8",
            )
            admin_stub.chmod(0o755)
            stub_env = {**os.environ, "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}
            for model_name in (
                "m" * 31,
                "m" * 32,
                "m" * 256,
                "$" * 256,
                " padded'model ",
                "price$$tier",
                "$$$",
                "$(OPENMETTLE_ADMIN_DATABASE_URL)",
                "$'$$'$(OPENMETTLE_ADMIN_DATABASE_URL)",
            ):
                cmd_line = restore_drill.build_family_policy_reconcile_lines(
                    restore_drill.DRILL_OPERATOR_ID,
                    run_id,
                    [{"user_id": uid, "policy": None, "models": [("disabled", model_name, True)]}],
                )
                expanded = k8s_expand(cmd_line, {"OPENMETTLE_ADMIN_DATABASE_URL"})
                self.assertEqual(expanded, cmd_line)
                tokens = shlex.split(expanded.strip())
                self.assertEqual(tokens[tokens.index("--model") + 1], model_name)
                rkey = tokens[tokens.index("--request-key") + 1]
                self.assertLessEqual(len(rkey.encode("utf-8")), 128)
                self.assertRegex(rkey, _re.compile(r"^restore-fm-" + _re.escape(run_id) + r"-[0-9a-f]{32}$"))
                sh_res = subprocess.run(
                    ["/bin/sh", "-eu", "-c", expanded],
                    env=stub_env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(sh_res.returncode, 0, sh_res.stderr)
                argv = [tok for tok in captured_args.read_bytes().decode("utf-8").split("\0")[:-1]]
                self.assertEqual(argv[argv.index("--model") + 1], model_name)
                self.assertEqual(
                    cmd_line,
                    restore_drill.build_family_policy_reconcile_lines(
                        restore_drill.DRILL_OPERATOR_ID,
                        run_id,
                        [{"user_id": uid, "policy": None, "models": [("disabled", model_name, True)]}],
                    ),
                )

        for bad_model in ("", "m" * 257, "bad\nmodel", "bad\x00model"):
            with self.assertRaisesRegex(restore_drill.DrillFailure, "invalid family policy model name"):
                restore_drill.build_family_policy_reconcile_lines(
                    restore_drill.DRILL_OPERATOR_ID,
                    run_id,
                    [{"user_id": uid, "policy": None, "models": [("disabled", bad_model, True)]}],
                )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "invalid family policy models sequence"):
            restore_drill.build_family_policy_reconcile_lines(
                restore_drill.DRILL_OPERATOR_ID,
                run_id,
                [{"user_id": uid, "policy": None, "models": "disabled"}],
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "invalid family policy timezone"):
            restore_drill.build_family_policy_reconcile_lines(
                restore_drill.DRILL_OPERATOR_ID,
                run_id,
                [{"user_id": uid, "policy": {"zone": "UTC;id"}, "models": []}],
            )
        with self.assertRaisesRegex(restore_drill.DrillFailure, "invalid family policy quiet window"):
            restore_drill.build_family_policy_reconcile_lines(
                restore_drill.DRILL_OPERATOR_ID,
                run_id,
                [{"user_id": uid, "policy": {"zone": "UTC", "quiet": "22:00-22:00"}, "models": []}],
            )

    def test_mcp_post_probe_command_shapes_http_post(self):
        cmd = restore_drill.mcp_post_probe_command(
            "sglang-standin.openmettle-restore-target-db.svc.cluster.local",
            30000,
            "/tools/send",
            '{"control":"worker-mcp-reachability"}',
        )
        self.assertEqual(cmd[:4], ["timeout", str(smoke.PROBE_SECONDS), "bash", "-c"])
        self.assertEqual(cmd[-4:], [
            "sglang-standin.openmettle-restore-target-db.svc.cluster.local",
            "30000",
            "/tools/send",
            '{"control":"worker-mcp-reachability"}',
        ])

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
        self.assertIn("SELECT 'cancelled_runs=' || count(*)", owner_sql)
        self.assertIn("DO $login_admission$", owner_sql)
        self.assertIn("$login_admission$;", owner_sql)
        self.assertIn("FROM openmettle.login_admission", owner_sql)
        self.assertIn("WHERE NOT session_issued", owner_sql)
        self.assertIn("DO $restore$", owner_sql)
        self.assertIn("$restore$;", owner_sql)
        self.assertNotIn("$$", owner_sql)
        with self.assertRaisesRegex(restore_drill.DrillFailure, "expected_login_limit"):
            restore_drill.pre_worker_owner_reconcile_sql(
                restore_drill.DRILL_OPERATOR_ID, expected_login_limit=0
            )

        seed_sql = restore_drill.seed_users_sql(
            ("A" * 43, "B" * 43, "a" * 64),
            ("C" * 43, "D" * 43, "b" * 64),
            ("E" * 43, "F" * 43, "c" * 64),
            ("G" * 43, "H" * 43, "d" * 64),
        )
        self.assertIn(f"outstanding_limit = {restore_drill.LOGIN_ADMISSION_LIMIT}", seed_sql)
        self.assertIn("decode(repeat('ab', 59), 'hex'), false, false", seed_sql)

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
        retained_journal = tmp / "post-backup-journal.export"
        retained_journal.write_text("openmettle.deletion_journal.export/1\n", encoding="utf-8")
        retained_journal.chmod(0o400)
        script_pinned = restore_drill.build_step5e_script(
            restore_drill.DRILL_OPERATOR_ID,
            run_id,
            has_artifacts=True,
            unpacked_dir=str(unpacked),
            retained_journal=str(retained_journal),
        )

        # Case 1: quota verify exits 0 with pending gateway 1 -> Job MUST fail and preserve unpacked & journal!
        write_stub(
            "false",
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 1, file mismatches 0, quarantined 0, unsettled payloads 0",
        )
        res_drift = subprocess.run(["/bin/sh", "-c", script_pinned], env=env_base, capture_output=True, text=True)
        self.assertNotEqual(res_drift.returncode, 0)
        self.assertTrue((unpacked / "manifest.json").exists(), "staging prematurely scrubbed despite pending gateway 1")
        self.assertTrue(retained_journal.exists(), "retained journal prematurely scrubbed despite pending gateway 1")

        # Case 2: maintenance_active still true -> Job MUST fail and preserve unpacked & journal!
        write_stub(
            "true",
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0",
        )
        res_maint = subprocess.run(["/bin/sh", "-c", script_pinned], env=env_base, capture_output=True, text=True)
        self.assertNotEqual(res_maint.returncode, 0)
        self.assertTrue((unpacked / "manifest.json").exists(), "staging prematurely scrubbed despite maintenance_active=true")
        self.assertTrue(retained_journal.exists(), "retained journal prematurely scrubbed despite maintenance_active=true")

        # Case 3: maintenance_active=false and all 7 counters=0 -> Job exits 0 and scrubs unpacked + retained journal!
        write_stub(
            "false",
            "storage mismatches 0, budget mismatches 0, settlement mismatches 0, "
            "pending gateway 0, file mismatches 0, quarantined 0, unsettled payloads 0",
        )
        res_ok = subprocess.run(["/bin/sh", "-c", script_pinned], env=env_base, capture_output=True, text=True)
        self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
        self.assertFalse(unpacked.exists(), "staging was not scrubbed after clean release and zero drift")
        self.assertFalse(retained_journal.exists(), "retained journal was not scrubbed after clean release and zero drift")
        self.assertIn(smoke.ARTIFACTS_MOUNT_PATH, (tmp / "qv-args").read_text(encoding="utf-8"))

        # Case 4: storage-disabled (has_artifacts=False) omits root path argument!
        unpacked.mkdir()
        retained_journal.write_text("openmettle.deletion_journal.export/1\n", encoding="utf-8")
        retained_journal.chmod(0o400)
        script_no_art = restore_drill.build_step5e_script(
            restore_drill.DRILL_OPERATOR_ID,
            run_id,
            has_artifacts=False,
            unpacked_dir=str(unpacked),
            retained_journal=str(retained_journal),
        )
        res_no_art = subprocess.run(["/bin/sh", "-c", script_no_art], env=env_base, capture_output=True, text=True)
        self.assertEqual(res_no_art.returncode, 0, res_no_art.stderr)
        self.assertFalse(retained_journal.exists())
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

    def test_runbook_step5b_and_step6_family_and_coverage_gap_contracts(self):
        import re as _re
        import textwrap
        runbook = (smoke.ROOT / "docs" / "restore-drill.md").read_text(encoding="utf-8")
        step5b = runbook.split("### 5b.", 1)[1].split("### 5c.", 1)[0]
        step6 = runbook.split("## Step 6", 1)[1].split("## Drill cadence", 1)[0]

        for forbidden in ("MAX(id)", "ORDER BY id ASC", "WHERE id >"):
            self.assertNotIn(forbidden, step5b)
        self.assertIn("restored-audit-ids.txt", step5b)
        self.assertIn("Fail closed", step5b)
        self.assertIn("openmettle.login_admission", step5b)
        self.assertIn("NOT lt.session_issued", step5b)
        self.assertNotIn("/tmp/post-restore.export", runbook)
        self.assertIn("details->>'restore_run_id' = '<RESTORE_RUN_UUID>'", step6)
        self.assertIn("openmettle.login_admission.outstanding_limit", step6)
        self.assertIn("outstanding_unissued < outstanding_limit", step6)
        self.assertIn("outstanding_limit IS NULL", step6)
        self.assertIn("Unconfigured", step6)
        self.assertIn("post-restore-$RESTORE_RUN_UUID.export", step6)
        self.assertIn("artifact_revision.lost", step6)
        self.assertIn("Checks completable immediately", step6)
        self.assertIn("Checks requiring a newly authenticated", step6)
        self.assertIn("openmettle.local_sessions", step6)
        self.assertIn("closed_signin_pending_auth_verification", step6)
        self.assertIn("docs/operator/login-admission-limit.psql", step6)
        self.assertIn("503 Service Unavailable", step6)
        self.assertIn("404 Not Found", step6)
        self.assertIn("openmettle.user_capability_grants", step6)
        self.assertIn("openmettle.user_capability_denies", step6)
        self.assertIn("openmettle.platform_capability_denies", step6)
        self.assertIn("openmettle.grant_assignments", step6)
        self.assertIn("openmettle.grant_changes", step6)
        self.assertIn("worker.inference.enabled: true", step6)
        self.assertIn("worker.inference.enabled: false", step6)
        self.assertIn("queue_expired", step6)
        self.assertIn("POST /v1/runs/{run_id}/cancel", step6)
        self.assertIn("browser.paths.initiation", step6)
        self.assertIn("browser.origin", step6)
        self.assertIn("GET /auth/native/authorize?...", step6)
        self.assertIn("POST /auth/native/authorize", step6)
        self.assertIn("200 OK", step6)
        self.assertNotIn("`active.key`", runbook)
        self.assertNotIn("`cursor.key`", runbook)
        self.assertIn("login.keys.active.path", runbook)
        self.assertIn("cursor_keys.active.path", runbook)
        self.assertIn("login-active.key", runbook)
        self.assertIn("catalog_file", step6)
        self.assertIn("admission_limits", step6)
        self.assertIn('code: "provisioning"', step6)
        self.assertIn("GET /v1/runs/{run_id}/approvals", step6)
        self.assertIn('{"items": []}', step6)

        m_sh = _re.search(r"```sh\n(.*?)\n[ \t]*```", step5b, _re.DOTALL)
        self.assertIsNotNone(m_sh)
        step5b_sh = textwrap.dedent(m_sh.group(1))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            calls_path = tmp_path / "admin-calls.jsonl"
            admin_stub = bin_dir / "openmettle-admin"
            admin_stub.write_text(
                f"#!{sys.executable}\n"
                "import json, sys\n"
                f"with open({str(calls_path)!r}, 'a', encoding='utf-8') as f:\n"
                "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n",
                encoding="utf-8",
            )
            admin_stub.chmod(0o755)
            if shutil.which("sha256sum") is None:
                sha_stub = bin_dir / "sha256sum"
                sha_stub.write_text(
                    f"#!{sys.executable}\n"
                    "import hashlib, sys\n"
                    "print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest() + '  -')\n",
                    encoding="utf-8",
                )
                sha_stub.chmod(0o755)

            uid = restore_drill.USER_D_IDS["user"]
            common_env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
                "RESTORE_RUN_UUID": "77777777-7777-4777-8777-777777777777",
                "OPERATOR_UUID": restore_drill.DRILL_OPERATOR_ID,
                "GRANTEE_KIND": "user",
                "GRANTEE_ID": uid,
            }
            cases = [
                {
                    "ACTION": "family_policy.model_disable",
                    "AUDIT_ROW_UUID": "88888888-8888-4888-8888-888888888881",
                    "RULE_KIND": "disabled",
                    "MODEL_NAME": "price$$tier",
                    "RULE_ACTIVE": "true",
                },
                {
                    "ACTION": "family_policy.model_enable",
                    "AUDIT_ROW_UUID": "88888888-8888-4888-8888-888888888882",
                    "RULE_KIND": "disabled",
                    "MODEL_NAME": "price$$tier",
                    "RULE_ACTIVE": "false",
                },
                {
                    "ACTION": "family_policy.set",
                    "AUDIT_ROW_UUID": "88888888-8888-4888-8888-888888888883",
                    "POLICY_TZ": "Europe/London",
                    "QUIET_WINDOW": "22:00-07:00",
                    "STUDY_WINDOW": "",
                    "OVERRIDE_SCHEDULES": "false",
                },
                {
                    "ACTION": "family_policy.set",
                    "AUDIT_ROW_UUID": "88888888-8888-4888-8888-888888888884",
                    "POLICY_TZ": "UTC",
                    "QUIET_WINDOW": "",
                    "STUDY_WINDOW": "16:00-18:00",
                    "OVERRIDE_SCHEDULES": "true",
                },
                {
                    "ACTION": "family_policy.clear",
                    "AUDIT_ROW_UUID": "88888888-8888-4888-8888-888888888885",
                },
            ]
            for extra in cases:
                res = subprocess.run(
                    ["/bin/sh", "-c", step5b_sh],
                    env={**common_env, **extra},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(res.returncode, 0, res.stderr)

            bad_res = subprocess.run(
                ["/bin/sh", "-c", step5b_sh],
                env={
                    **common_env,
                    "ACTION": "family_policy.model_enable",
                    "AUDIT_ROW_UUID": "88888888-8888-4888-8888-888888888886",
                    "RULE_KIND": "disabled",
                    "MODEL_NAME": "a",
                    "RULE_ACTIVE": "maybe",
                },
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad_res.returncode, 0)

            invocations = [json.loads(ln) for ln in calls_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(invocations), 5)
            self.assertIn("--enable", invocations[0])
            self.assertNotIn("--disable", invocations[0])
            self.assertEqual(invocations[0][invocations[0].index("--model") + 1], "price$$tier")
            self.assertIn("--disable", invocations[1])
            self.assertNotIn("--enable", invocations[1])
            self.assertNotEqual(
                invocations[0][invocations[0].index("--request-key") + 1],
                invocations[1][invocations[1].index("--request-key") + 1],
            )
            self.assertIn("--quiet", invocations[2])
            self.assertNotIn("--study", invocations[2])
            self.assertNotIn("--override-group-schedules", invocations[2])
            self.assertNotIn("--quiet", invocations[3])
            self.assertIn("--study", invocations[3])
            self.assertIn("--override-group-schedules", invocations[3])
            self.assertEqual(invocations[4][:4], ["family", "clear-policy", "--user", uid])


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
        standin_np = next(
            i for i in foundation["items"]
            if i["kind"] == "NetworkPolicy" and i["metadata"]["name"] == "standin-network"
        )
        peers = standin_np["spec"]["ingress"][0]["from"]
        self.assertEqual(len(peers), 2)
        components = sorted(p["podSelector"]["matchLabels"]["app.kubernetes.io/component"] for p in peers)
        self.assertEqual(components, [smoke.GATEWAY_COMPONENT, "worker"])

    def test_main_refuses_wrong_core_commit_before_creating_cluster(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        test_smoke.write_core(tmp, test_smoke.STUB_CORE)
        with mock.patch.object(smoke, "core_checkout_state", return_value=("0" * 40, "")), \
                mock.patch("sys.stderr"):
            self.assertEqual(restore_drill.main(["--core-dir", str(tmp)]), 3)

    def test_isolation_probe_plan_denies_both_target_namespaces_to_both_primary_endpoints(self):
        plan = restore_drill.target_isolation_probe_plan()
        controls = {p["name"]: p for p in plan if p["expect"] == "connect"}
        db_ctrl = next(n for n in controls if "PostgreSQL" in n)
        gw_ctrl = next(n for n in controls if "gateway" in n)
        denies = {(p["namespace"], p["workload"], p["control"]): p for p in plan if p["expect"] == "deny"}
        self.assertEqual(controls[db_ctrl]["namespace"], restore_drill.PRIMARY_DB_NS)
        self.assertEqual(controls[gw_ctrl]["namespace"], restore_drill.PRIMARY_APP_NS)
        self.assertTrue(controls[gw_ctrl]["http"])

        # Both target namespaces (`openmettle-restore-target` and `openmettle-restore-target-db`)
        # MUST be denied access to BOTH primary PostgreSQL (5432) and primary gateway (8082).
        for ns, workload in (
            (restore_drill.TARGET_DB_NS, "postgres"),
            (restore_drill.TARGET_APP_NS, f"{restore_drill.FULLNAME}-worker"),
        ):
            self.assertIn((ns, workload, db_ctrl), denies)
            self.assertIn((ns, workload, gw_ctrl), denies)
            self.assertTrue(denies[(ns, workload, gw_ctrl)]["http"])
        self.assertIn((restore_drill.TARGET_APP_NS, f"{restore_drill.FULLNAME}-api", db_ctrl), denies)


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
        self.live_objects: set[tuple[str, str, str]] = set()
        self.media_lifecycle: list[str] = []
        self.post_export_lifecycle: list[str] = []
        self.target_settlement_events: list[str] = []
        self.fail_on_target_migrate = False
        self.job_failed_on_pre_worker_sql = False
        self.transport_fail_on_epoch_probe = False
        self.missing_restored_settlement_on_target = False
        self.unsolicited_mcp_on_startup = False
        self.shared_artifact_readers: list[str] = []
        self.mcp_standin_records: list[dict] = []
        self.denied_model_requests: list[str] = []
        self.forced_run_poll_state: str | None = None
        self.forced_run_diag_row: str = "failed|||1:run.failed:openmettle.run-failed:{\"reason\":\"test-upstream-timeout\"}"

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
                    if self._last_job == "openmettle-drill-reconcile-admin":
                        self.media_lifecycle.append("applied-reconcile-admin")
                    if self._last_job == "openmettle-drill-read-post-export":
                        self.post_export_lifecycle.append("applied-read-post-export")
                    if self.fail_on_target_migrate and self._last_job == "openmettle-drill-migrate":
                        return self._res(1, "", f"fatal migrate error password={self._leak_secret}")
                self._record_applied(doc)
                return self._res(0, "")
            if "create" in argv and "job" in argv:
                ns = argv[argv.index("--namespace") + 1] if "--namespace" in argv else ""
                job_name = argv[argv.index("job") + 1]
                self.live_objects.add((ns, "job", job_name))
                return self._res(0, "")
            if "delete" in argv:
                ns = argv[argv.index("--namespace") + 1] if "--namespace" in argv else ""
                del_idx = argv.index("delete")
                res_kind = argv[del_idx + 1]
                names = [a for a in argv[del_idx + 2:] if not a.startswith("-")]
                ignore_missing = "--ignore-not-found=true" in argv
                for obj_name in names:
                    key = (ns, res_kind, obj_name)
                    if key not in self.live_objects:
                        if not ignore_missing:
                            return self._res(
                                1, "", f'Error from server (NotFound): {res_kind} "{obj_name}" not found'
                            )
                    else:
                        self.live_objects.remove(key)
                        if res_kind == "pvc" and obj_name == restore_drill.TARGET_RECOVERY_MEDIA_CLAIM:
                            self.media_lifecycle.append("deleted-media-pvc")
                        if res_kind == "job" and obj_name == "openmettle-drill-post-verify":
                            self.post_export_lifecycle.append("deleted-post-verify-job")
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

    def _record_applied(self, doc: dict) -> None:
        kind = doc.get("kind")
        if kind == "List":
            for item in doc.get("items", ()):
                self._record_applied(item)
            return
        kind_map = {
            "Job": "job",
            "Pod": "pod",
            "PersistentVolumeClaim": "pvc",
            "Secret": "secret",
            "ConfigMap": "configmap",
            "Deployment": "deployment",
            "Service": "service",
            "NetworkPolicy": "networkpolicy",
            "Namespace": "namespace",
        }
        mapped = kind_map.get(kind)
        if mapped:
            meta = doc.get("metadata", {})
            self.live_objects.add((meta.get("namespace", ""), mapped, meta["name"]))

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
            return self._res(0, "100\ncancelled_runs=2\n")
        if name == "openmettle-drill-worker-quota-release":
            return self._res(0, "1\n")
        if name == "openmettle-drill-primary-family-pre":
            return self._res(0, "applied family_policy.set\napplied family_policy.model_study_allow\n")
        if name == "openmettle-drill-primary-family-restrict":
            return self._res(0, "applied family_policy.model_disable\n")
        if name == "openmettle-drill-release-maintenance":
            bs = json.dumps({"maintenance_active": False})
            return self._res(
                0,
                f"BACKUP_STATUS_BEGIN\n{bs}\nBACKUP_STATUS_END\n"
                f"QUOTA_VERIFY_BEGIN\n{qv}QUOTA_VERIFY_END\n",
            )
        if name == "openmettle-drill-post-verify":
            return self._res(0, qv)
        if name == "openmettle-drill-read-post-export":
            _, _, raw_export = build_six_record_journal_fixture()
            return self._res(0, base64.encodebytes(raw_export).decode("ascii"))
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
            _, chains, _ = build_six_record_journal_fixture()
            return self._res(
                0,
                "openmettle.deletion_journal.export/1\n"
                "origin 1795450000000000\n"
                "lifecycle_origin 1795450010500000\n"
                f"lifecycle_baseline {GENESIS}\n"
                "connection_origin 1795450010600000\n"
                f"watermark 1795450000000000 5 {chains[4]} 1795450020000000\n"
                f"sha256 {'c' * 64}\n",
            )
        if "psql" in argv and stdin_text:
            if restore_drill.GAP_DB_NAME in argv:
                if "restore.accept_coverage_gap" in stdin_text:
                    self.assertIn("details->>'restore_run_id'", stdin_text)
                return self._res(0, "2|0|0|0|t|1\n")
            if "gateway_requests" in stdin_text:
                ns = argv[argv.index("--namespace") + 1]
                if ns == restore_drill.TARGET_DB_NS:
                    if "bbbb0000-0000-4000-8000-000000000010" in stdin_text:
                        self.target_settlement_events.append("psql:bbbb0000-0000-4000-8000-000000000010")
                        if self.missing_restored_settlement_on_target:
                            return self._res(0, "")
                    elif "bbbb0000-0000-4000-8000-000000000020" in stdin_text:
                        self.target_settlement_events.append("psql:bbbb0000-0000-4000-8000-000000000020")
                return self._res(0, "11111111-1111-4111-8111-111111111111|handed_off|t|t|1|11|7|t|settled|0|18\n")
            if "JOIN openmettle.quota_reservations qr" in stdin_text and "last_event_sequence" in stdin_text:
                # Realistic pre-backup sequences: waiting_run=4, intent_run=5, each holding 25 usage_tokens.
                return self._res(
                    0,
                    "aaaa0000-0000-4000-8000-000000000002|4|25\n"
                    "aaaa0000-0000-4000-8000-000000000004|5|25\n",
                )
            if "FROM openmettle.artifact_revisions" in stdin_text and "WHERE id IN" in stdin_text:
                scope_id = DEFAULT_FIXTURE_SCOPE_ID
                return self._res(
                    0,
                    f"99999999-9999-4999-8999-999999999993|{scope_id}|99999999-9999-4999-8999-999999999990|1800000000000000|27|{'1' * 64}\n"
                    f"99999999-9999-4999-8999-999999999994|{scope_id}|99999999-9999-4999-8999-999999999991||30|{'2' * 64}\n"
                    f"{DEFAULT_LOST_REVISION_ID}|{scope_id}|{DEFAULT_LOST_REVISION_ID}||34|{DEFAULT_LOST_CONTENT_DIGEST}\n"
                    f"99999999-9999-4999-8999-999999999997|{scope_id}|99999999-9999-4999-8999-999999999997||37|{'4' * 64}\n",
                )
            if "DO $provider_epoch$" in stdin_text and "setval" not in stdin_text:
                if self.transport_fail_on_epoch_probe:
                    return self._res(1, "", "error: unable to upgrade connection")
                return self._res(
                    3,
                    "",
                    "ERROR: login_provider_revisions epoch 41 did not advance past previous maximum 100",
                )
            if "FROM openmettle.authorization_audit" in stdin_text and "family_policy.model_disable" in stdin_text:
                self.assertIn("drill-primary-family-disable-a-1", stdin_text)
                self.assertNotIn("ORDER BY id", stdin_text)
                return self._res(0, f"{restore_drill.USER_D_IDS['user']}|{smoke.CATALOG_MODEL}\n")
            if "EXISTS (SELECT 1 FROM openmettle.login_provider_revisions WHERE epoch = 41)" in stdin_text:
                return self._res(0, "100|0|f\n")
            if "family_policy_permits(" in stdin_text:
                self.assertIn("::text", stdin_text)
                return self._res(0, "true\n")
            if "FROM openmettle.runs r WHERE r.id =" in stdin_text and "openmettle.run_events" in stdin_text:
                return self._res(0, self.forced_run_diag_row + "\n")
            if "openmettle.operations" in stdin_text:
                import re as _re
                self.assertIn("fp.override_group_schedules::text", stdin_text)
                self.assertIn("details->>'restore_run_id'", stdin_text)
                self.assertIn("FROM openmettle.login_admission", stdin_text)
                pre_job = next(
                    d for d in self.applied_manifests
                    if d.get("kind") == "Job" and d["metadata"]["name"] == "openmettle-drill-primary-family-pre"
                )
                pre_cmd = pre_job["spec"]["template"]["spec"]["containers"][0]["command"][-1]
                qm = _re.search(r'--quiet "(\d{2}):(\d{2})-(\d{2}):(\d{2})"', pre_cmd)
                self.assertIsNotNone(qm)
                q_start = int(qm.group(1)) * 60 + int(qm.group(2))
                q_end = int(qm.group(3)) * 60 + int(qm.group(4))
                return self._res(
                    0,
                    f"outcome_unknown:1|{restore_drill.target_mcp_url()}|Europe/London:{q_start}:{q_end}:960:1080:true:2|t|1800000000000000|purged|t|t|0|f|"
                    "5:5:1:5|run-terminal:openmettle.run-cancelled|"
                    "7:7:1:7|unresolved-write:aaaa0000-0000-4000-8000-000000000005|"
                    "run-terminal:openmettle.run-cancelled|released:0|held:25|101|1|64:1:63\n",
                )
            if "SELECT state FROM openmettle.artifact_revisions" in stdin_text:
                return self._res(0, "purged\n")
            if "FROM openmettle.deletion_journal_head" in stdin_text:
                self.assertIn("SELECT journal_seq", stdin_text)
                _, chains, _ = build_six_record_journal_fixture()
                return self._res(0, f"5|{chains[4]}\n")
            if "_sqlx_migrations" in stdin_text:
                return self._res(0, f"{smoke.REQUIRED_MIGRATION}|1|t\n")
            return self._res(0, "")
        if "timeout" in argv:
            ns = argv[argv.index("--namespace") + 1]
            if "/tools/send" in argv:
                target_host = argv[-4]
                if ns in (restore_drill.TARGET_APP_NS, restore_drill.TARGET_DB_NS) and (
                    restore_drill.PRIMARY_DB_NS in target_host or restore_drill.PRIMARY_APP_NS in target_host
                ):
                    return self._res(124, "", "")
                self.mcp_standin_records.append({"body": json.loads(argv[-1])})
                return self._res(0, "HTTP/1.1 200 OK\r\n", "")
            target_host = argv[-2] if argv[-1].isdigit() else argv[-3]
            is_http = "/readyz" in argv or "/healthz" in argv
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
            if raw_cookie == getattr(self, "_cookie_d2", None):
                return 201, v1_hdrs, json.dumps({
                    "conversation_id": "bbbb0000-0000-4000-8000-0000000000d1",
                    "branch_id": "bbbb0000-0000-4000-8000-0000000000d2",
                }).encode()
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
            if raw_cookie == getattr(self, "_cookie_d2", None):
                self.denied_model_requests.append(smoke.CATALOG_MODEL)
                return 403, prob_hdrs, json.dumps({"status": 403, "code": "policy"}).encode()
            key = headers.get("Idempotency-Key", "")
            if key == "drill-post-restore-run":
                rid = "bbbb0000-0000-4000-8000-000000000020"
                self.target_settlement_events.append("http:post-restore-run")
            else:
                rid = "bbbb0000-0000-4000-8000-000000000010"
            self._post_restore_runs = getattr(self, "_post_restore_runs", 0) + 1
            return 201, v1_hdrs, json.dumps({"run_id": rid, "state": "queued"}).encode()
        if path.startswith("/v1/runs/") and method == "GET":
            if path.endswith("/approvals"):
                return 200, v1_hdrs, json.dumps({"items": []}).encode()
            run_id = path.rsplit("/", 1)[1]
            if self.forced_run_poll_state is not None and not run_id.startswith("aaaa0000"):
                if isinstance(self.forced_run_poll_state, list):
                    state = self.forced_run_poll_state.pop(0) if len(self.forced_run_poll_state) > 1 else self.forced_run_poll_state[0]
                else:
                    state = self.forced_run_poll_state
                if hasattr(self, "_fake_clock"):
                    self._fake_clock["t"] += 25.0
            else:
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
        self._stale_or_disabled_cookies = ()
        self._cookie_a2 = None
        self._cookie_b2 = None
        self._cookie_d2 = None
        self._post_restore_runs = 0
        self.commands.clear()
        self.applied_manifests.clear()
        self.live_objects.clear()
        self.media_lifecycle.clear()
        self.target_settlement_events.clear()
        self.mcp_standin_records = (
            [{"body": {"tool": "drill.send"}}] if self.unsolicited_mcp_on_startup else []
        )
        self.denied_model_requests.clear()
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
            if port == 18090 and path == "/_recorded_mcp":
                return 200, json.dumps(outer.mcp_standin_records)
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
        self.assertIn("unresolved_deletion_coverage_gap", runbook)
        self.assertIn("openmettle-admin family set-model", runbook)
        self.assertIn("openmettle-admin quota verify /var/lib/openmettle/artifacts", runbook)
        self.assertNotIn("/tmp/post-restore.export", runbook)
        self.assertIn('openmettle-admin journal export "/var/backups/openmettle/post-restore-$RESTORE_RUN_UUID.export"', runbook)
        self.assertIn('[ ! -r "$cand" ]', runbook)
        self.assertEqual(self.post_export_lifecycle, ["deleted-post-verify-job", "applied-read-post-export"])
        post_verify_job = next(
            d for d in self.applied_manifests
            if d.get("kind") == "Job" and d["metadata"]["name"] == "openmettle-drill-post-verify"
        )
        post_verify_pod = post_verify_job["spec"]["template"]["spec"]
        self.assertIn(restore_drill.POST_RESTORE_EXPORT_DIR, post_verify_pod["containers"][0]["command"][-1])
        self.assertNotIn("/tmp", post_verify_pod["containers"][0]["command"][-1])
        read_export_job = next(
            d for d in self.applied_manifests
            if d.get("kind") == "Job" and d["metadata"]["name"] == "openmettle-drill-read-post-export"
        )
        read_export_pod = read_export_job["spec"]["template"]["spec"]
        self.assertEqual(read_export_pod["containers"][0]["command"][0], "base64")
        self.assertNotIn("env", read_export_pod["containers"][0])
        self.assertTrue(read_export_pod["containers"][0]["volumeMounts"][0]["readOnly"])
        self.assertTrue(read_export_pod["volumes"][0]["persistentVolumeClaim"]["readOnly"])
        self.assertEqual(
            read_export_pod["volumes"][0]["persistentVolumeClaim"]["claimName"],
            restore_drill.TARGET_POST_RESTORE_EXPORT_CLAIM,
        )
        # Verify uncertified coverage-gap scenario was also exercised:
        check_names = [c["name"] for c in summary["checks"]]
        self.assertTrue(any("coverage-gap" in n for n in check_names))
        self.assertEqual(self.denied_model_requests, [smoke.CATALOG_MODEL])
        self.assertEqual(self.mcp_standin_records, [{"body": {"control": "worker-mcp-reachability"}}])
        self.assertTrue(any(cmd[:3] == ["kind", "delete", "cluster"] for cmd in self.commands))
        self.assertTrue(any(cmd[:4] == ["docker", "image", "rm", "--force"] for cmd in self.commands))
        self.assertTrue(
            any(
                cmd[0] == "kubectl"
                and "--namespace" in cmd
                and restore_drill.TARGET_APP_NS in cmd
                and "delete" in cmd
                and "pvc" in cmd
                and restore_drill.TARGET_RECOVERY_MEDIA_CLAIM in cmd
                and "--wait=true" in cmd
                for cmd in self.commands
            )
        )
        self.assertEqual(self.media_lifecycle, ["deleted-media-pvc", "applied-reconcile-admin"])
        reconcile_job = next(
            d for d in self.applied_manifests
            if d.get("kind") == "Job" and d["metadata"]["name"] == "openmettle-drill-reconcile-admin"
        )
        reconcile_pod = reconcile_job["spec"]["template"]["spec"]
        self.assertFalse(
            any(
                v.get("persistentVolumeClaim", {}).get("claimName") == restore_drill.TARGET_RECOVERY_MEDIA_CLAIM
                for v in reconcile_pod.get("volumes", ())
            )
        )
        self.assertIn(
            restore_drill.RETAINED_JOURNAL_PATH,
            reconcile_pod["containers"][0]["command"][-1],
        )
        pre_family_job = next(
            d for d in self.applied_manifests
            if d.get("kind") == "Job" and d["metadata"]["name"] == "openmettle-drill-primary-family-pre"
        )
        pre_family_cmd = pre_family_job["spec"]["template"]["spec"]["containers"][0]["command"][-1]
        self.assertIn('--zone "Europe/London"', pre_family_cmd)
        self.assertIn("--quiet", pre_family_cmd)
        self.assertIn('--study "16:00-18:00"', pre_family_cmd)
        self.assertIn("--override-group-schedules", pre_family_cmd)
        self.assertIn("--kind study_allow", pre_family_cmd)

        post_restrict_job = next(
            d for d in self.applied_manifests
            if d.get("kind") == "Job" and d["metadata"]["name"] == "openmettle-drill-primary-family-restrict"
        )
        post_restrict_cmd = post_restrict_job["spec"]["template"]["spec"]["containers"][0]["command"][-1]
        self.assertNotIn("family set-policy", post_restrict_cmd)
        self.assertIn("family set-model", post_restrict_cmd)

        self.assertNotIn("family set-policy", reconcile_pod["containers"][0]["command"][-1])
        self.assertIn("family set-model", reconcile_pod["containers"][0]["command"][-1])
        self.assertEqual(
            self.target_settlement_events,
            [
                "psql:bbbb0000-0000-4000-8000-000000000010",
                "http:post-restore-run",
                "psql:bbbb0000-0000-4000-8000-000000000020",
            ],
        )

    def test_terminal_and_timed_out_run_polling_report_last_state_and_diagnostics(self):
        self.forced_run_poll_state = "failed"
        rc_fail, sum_fail = self._run_drill()
        self.assertEqual(rc_fail, 1)
        self.assertIn("entered terminal state 'failed'", sum_fail["error"])
        self.assertIn("test-upstream-timeout", sum_fail["error"])

        # Non-terminal `cancelling` MUST continue polling until `cancelled` + `run-terminal` arrive.
        self.forced_run_poll_state = ["cancelling", "cancelled"]
        self.forced_run_diag_row = "cancelled||revoked|1:run-terminal:openmettle.run-cancelled:{\"reason\":\"revoked\"}"
        rc_cancelling, sum_cancelling = self._run_drill()
        self.assertEqual(rc_cancelling, 1)
        self.assertIn("entered terminal state 'cancelled'", sum_cancelling["error"])
        self.assertIn("openmettle.run-cancelled", sum_cancelling["error"])

        self._fake_clock = {"t": 1000.0}
        self.forced_run_poll_state = "queued"
        self.forced_run_diag_row = "queued|||1:run.created:openmettle.run-created:{}"
        with mock.patch.object(restore_drill.time, "monotonic", side_effect=lambda: self._fake_clock["t"]):
            rc_to, sum_to = self._run_drill()
        self.assertEqual(rc_to, 1)
        self.assertIn("timed out waiting for primary gateway inference turn to succeed", sum_to["error"])
        self.assertIn("last_state='queued'", sum_to["error"])
        self.assertIn("openmettle.run-created", sum_to["error"])

    def test_unsolicited_mcp_write_replay_on_startup_fails_drill(self):
        self.unsolicited_mcp_on_startup = True
        rc, summary = self._run_drill()
        self.assertEqual(rc, 1)
        self.assertEqual(summary["result"], "failed")
        self.assertIn("unsolicited MCP write calls", summary["error"])

    def test_missing_restored_prebackup_settlement_on_target_fails_before_new_turn(self):
        self.missing_restored_settlement_on_target = True
        rc, summary = self._run_drill()
        self.assertEqual(rc, 1)
        self.assertEqual(summary["result"], "failed")
        self.assertIn("restored completed run settlement missing", summary["error"])
        self.assertNotIn("http:post-restore-run", self.target_settlement_events)

    def test_trailing_epoch_probe_rejects_unrelated_transport_failure(self):
        self.transport_fail_on_epoch_probe = True
        rc, summary = self._run_drill()
        self.assertEqual(rc, 1)
        self.assertEqual(summary["result"], "failed")
        self.assertIn("epoch guard diagnostic", summary["error"])

    def test_stateful_kubectl_fake_rejects_duplicate_checked_deletion(self):
        rc, summary = self._run_drill()
        self.assertEqual(rc, 0, summary.get("error"))
        dup_pvc = self._dispatch([
            "kubectl", "--namespace", restore_drill.TARGET_APP_NS,
            "delete", "pvc", restore_drill.TARGET_RECOVERY_MEDIA_CLAIM, "--wait=true",
        ])
        self.assertEqual(dup_pvc.returncode, 1)
        self.assertIn("NotFound", dup_pvc.stderr)
        dup_job = self._dispatch([
            "kubectl", "--namespace", restore_drill.TARGET_APP_NS,
            "delete", "job", "openmettle-drill-verify-unpack", "--wait=true",
        ])
        self.assertEqual(dup_job.returncode, 1)
        self.assertIn("NotFound", dup_job.stderr)
        ignored = self._dispatch([
            "kubectl", "--namespace", restore_drill.TARGET_APP_NS,
            "delete", "job", "openmettle-drill-verify-unpack", "--ignore-not-found=true",
        ])
        self.assertEqual(ignored.returncode, 0)

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
