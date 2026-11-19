"""Cluster-free tests for the kind smoke harness (tests/kind/smoke.py).

They cover guards, digest parsing, fixture and values derivation, event evaluation and the
published summary. They do not create a cluster and are not evidence that the chart installs;
only a dispatched `kind-smoke` run is. Set OPENMETTLE_CORE_DIR to a directory holding core's
tests/kubernetes/qualify.py at CORE_COMMIT to also exercise the imported core guards. CI does.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DIGEST = {role: "sha256:" + str(i) * 64 for i, role in enumerate(smoke.ROLES, start=1)}
PASSWORDS = {"admin": "a" * 32, "api": "b" * 32, "worker": "c" * 32, "migrate": "d" * 32}
CORE_DIR = os.environ.get("OPENMETTLE_CORE_DIR")
HELM = os.environ.get("HELM", "helm")

# Representative `ctr --namespace=k8s.io images ls` output after `kind load docker-image`.
CTR_LISTING = f"""REF                                                        TYPE                                    DIGEST {' ' * 60}SIZE     PLATFORMS   LABELS
import-2026-11-19@{DIGEST['api']} application/vnd.oci.image.index.v1+json {DIGEST['api']} 40.1 MiB linux/amd64 io.cri-containerd.image=managed
openmettle-smoke.invalid/openmettle/api:smoke-0a1b2c3d application/vnd.oci.image.index.v1+json {DIGEST['api']} 40.1 MiB linux/amd64 io.cri-containerd.image=managed
openmettle-smoke.invalid/openmettle/worker:smoke-0a1b2c3d application/vnd.oci.image.index.v1+json {DIGEST['worker']} 40.0 MiB linux/amd64 io.cri-containerd.image=managed
openmettle-smoke.invalid/openmettle/migrate:smoke-0a1b2c3d application/vnd.oci.image.index.v1+json not-a-digest 39.0 MiB linux/amd64 -
"""

STUB_CORE = '''
KIND_VERSION = "v0"; KUBECTL_VERSION = "v0"; NODE_IMAGE = "node"; POSTGRES_IMAGE = "postgres"
class Refusal(Exception): pass
class QualificationFailure(Exception): pass
class Runner:
    def __init__(self, env): raise AssertionError("no command may run after a refusal")
def http_get(port, path): raise AssertionError("unused")
def check_opt_in(environ): raise Refusal("stub refuses: not opted in")
check_tools = check_docker_context = check_cluster_absent = check_cluster_identity = http_get
def child_environment(environ, kubeconfig, context, tools_dir): return dict(environ)
'''


def write_core(directory: Path, source: str) -> Path:
    path = directory / smoke.CORE_MODULE
    path.parent.mkdir(parents=True)
    path.write_text(source)
    return directory


def event(reason, uid="", name="openmettle-core-migrate", kind="Job", when="2026-11-19T10:00:00Z",
          message=""):
    return {"reason": reason, "lastTimestamp": when, "message": message,
            "involvedObject": {"kind": kind, "name": name, "uid": uid}}


class CoreCheckoutTest(unittest.TestCase):
    def test_accepts_pinned_clean_checkout(self):
        smoke.check_core_checkout(smoke.CORE_COMMIT + "\n", "")

    def test_refuses_other_commit(self):
        with self.assertRaisesRegex(smoke.Refusal, "must be at"):
            smoke.check_core_checkout("0" * 40, "")

    def test_refuses_missing_head(self):
        with self.assertRaisesRegex(smoke.Refusal, "found nothing"):
            smoke.check_core_checkout("", "")

    def test_refuses_local_changes(self):
        with self.assertRaisesRegex(smoke.Refusal, "local changes"):
            smoke.check_core_checkout(smoke.CORE_COMMIT, " M Dockerfile\n")


class LoadCoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_refuses_missing_module(self):
        with self.assertRaisesRegex(smoke.Refusal, "not found"):
            smoke.load_core(self.tmp)

    def test_refuses_module_without_required_names(self):
        write_core(self.tmp, "KIND_VERSION = 'v0'\n")
        with self.assertRaisesRegex(smoke.Refusal, "lacks .*NODE_IMAGE"):
            smoke.load_core(self.tmp)

    def test_loads_without_writing_bytecode_into_checkout(self):
        write_core(self.tmp, STUB_CORE)
        module = smoke.load_core(self.tmp)
        self.assertEqual(module.NODE_IMAGE, "node")
        self.assertEqual([p.name for p in (self.tmp / "tests" / "kubernetes").iterdir()], ["qualify.py"])


class MainRefusalTest(unittest.TestCase):
    """main() refuses with exit 3 and runs no tool before every guard passes."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        write_core(self.tmp, STUB_CORE)

    def test_wrong_core_commit_refuses_before_loading_core(self):
        with mock.patch.object(smoke, "core_checkout_state", return_value=("0" * 40, "")), \
                mock.patch.object(smoke, "load_core") as load, \
                mock.patch("sys.stderr"):
            self.assertEqual(smoke.main(["--core-dir", str(self.tmp)]), 3)
        load.assert_not_called()

    def test_core_guard_refusal_creates_nothing(self):
        with mock.patch.object(smoke, "core_checkout_state", return_value=(smoke.CORE_COMMIT, "")), \
                mock.patch.object(smoke.subprocess, "run") as run, \
                mock.patch.object(smoke.subprocess, "Popen") as popen, \
                mock.patch("sys.stderr"):
            report = self.tmp / "report.json"
            self.assertEqual(smoke.main(["--core-dir", str(self.tmp), "--report", str(report)]), 3)
        run.assert_not_called()
        popen.assert_not_called()
        self.assertFalse(report.exists())

    def test_core_checkout_state_reads_git(self):
        if shutil.which("git") is None:
            self.skipTest("git not on PATH")
        head, porcelain = smoke.core_checkout_state(ROOT)
        self.assertRegex(head.strip(), r"^[0-9a-f]{40}$")
        self.assertIsInstance(porcelain, str)

    def test_arguments_must_be_directories(self):
        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                smoke.parse_args([])
            with self.assertRaises(SystemExit):
                smoke.parse_args(["--core-dir", str(self.tmp / "missing")])
            with self.assertRaises(SystemExit):
                smoke.parse_args(["--core-dir", str(self.tmp), "--helm-dir", str(self.tmp / "missing")])
        args = smoke.parse_args(["--core-dir", str(self.tmp), "--tools-dir", str(self.tmp)])
        self.assertTrue(args.core_dir.is_absolute())
        self.assertIsNone(args.helm_dir)


class EnvironmentTest(unittest.TestCase):
    def test_strips_inherited_helm_settings_and_isolates_homes(self):
        env = smoke.smoke_environment(
            {"PATH": "/usr/bin", "HELM_KUBECONTEXT": "prod", "HELM_NAMESPACE": "x", "HELM_DRIVER": "sql",
             "HOME": "/home/u"}, Path("/tmp/run"), Path("/opt/helm"))
        self.assertFalse({"HELM_KUBECONTEXT", "HELM_NAMESPACE", "HELM_DRIVER"} & set(env))
        self.assertEqual(env["HELM_CONFIG_HOME"], "/tmp/run/helm/config")
        self.assertEqual(env["HELM_CACHE_HOME"], "/tmp/run/helm/cache")
        self.assertEqual(env["HELM_DATA_HOME"], "/tmp/run/helm/data")
        self.assertTrue(env["PATH"].startswith("/opt/helm" + os.pathsep))

    def test_helm_version_pin(self):
        smoke.check_helm_version("v4.3.0\n")
        with self.assertRaises(smoke.Refusal):
            smoke.check_helm_version("v4.2.1")


class DigestTest(unittest.TestCase):
    def test_reads_target_digest_of_exact_name(self):
        name = "openmettle-smoke.invalid/openmettle/api:smoke-0a1b2c3d"
        self.assertEqual(smoke.parse_ctr_digest(CTR_LISTING, name), DIGEST["api"])

    def test_missing_or_duplicate_name_fails(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "found 0"):
            smoke.parse_ctr_digest(CTR_LISTING, "openmettle-smoke.invalid/openmettle/api:other")
        doubled = CTR_LISTING + CTR_LISTING.splitlines()[2] + "\n"
        with self.assertRaisesRegex(smoke.SmokeFailure, "found 2"):
            smoke.parse_ctr_digest(doubled, "openmettle-smoke.invalid/openmettle/api:smoke-0a1b2c3d")

    def test_malformed_digest_fails(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "no sha256"):
            smoke.parse_ctr_digest(CTR_LISTING, "openmettle-smoke.invalid/openmettle/migrate:smoke-0a1b2c3d")

    def test_header_is_not_an_image(self):
        with self.assertRaises(smoke.SmokeFailure):
            smoke.parse_ctr_digest(CTR_LISTING, "REF")

    def test_cri_image_id(self):
        self.assertEqual(smoke.parse_cri_image_id(json.dumps({"status": {"id": DIGEST["api"]}})), DIGEST["api"])
        for output in ("", "{}", json.dumps({"status": {"id": "sha256:abc"}}), json.dumps({"status": None})):
            with self.subTest(output=output), self.assertRaises(smoke.SmokeFailure):
                smoke.parse_cri_image_id(output)

    def test_references(self):
        self.assertEqual(smoke.digest_reference("api", DIGEST["api"]),
                         f"openmettle-smoke.invalid/openmettle/api@{DIGEST['api']}")
        self.assertEqual(smoke.tag_reference("worker", "0a1b2c3d"),
                         "openmettle-smoke.invalid/openmettle/worker:smoke-0a1b2c3d")
        for role, digest in (("gpu", DIGEST["api"]), ("api", "latest"), ("api", "sha256:" + "A" * 64),
                             ("api", DIGEST["api"] + "0")):
            with self.subTest(role=role, digest=digest), self.assertRaises(smoke.SmokeFailure):
                smoke.digest_reference(role, digest)

    def test_registry_never_resolves(self):
        """RFC 6761 .invalid: a mistaken pull can never reach a real registry."""
        self.assertTrue(smoke.REGISTRY.endswith(".invalid"))


class ValuesTest(unittest.TestCase):
    def test_values_pin_every_image_by_digest_without_pulling(self):
        values = smoke.smoke_values(DIGEST, worker_replicas=2)
        self.assertEqual(values["images"]["pullPolicy"], "Never")
        for role in smoke.ROLES:
            self.assertEqual(values["images"][role]["digest"], DIGEST[role])
            self.assertEqual(values["database"][role], {"existingSecret": smoke.SECRET[role]})
        self.assertEqual(values["worker"], {"replicas": 2})
        self.assertNotIn("api", values)

    def test_values_require_every_valid_digest_and_bounded_replicas(self):
        for digests in ({k: v for k, v in DIGEST.items() if k != "migrate"}, {**DIGEST, "api": "latest"}):
            with self.subTest(digests=digests), self.assertRaises(smoke.SmokeFailure):
                smoke.smoke_values(digests, 1)
        for replicas in (0, 3):
            with self.subTest(replicas=replicas), self.assertRaises(smoke.SmokeFailure):
                smoke.smoke_values(DIGEST, replicas)

    def test_helm_bound_matches_migration_deadline(self):
        values = smoke.smoke_values(DIGEST, 1)["migration"]
        attempt_ms = sum(values["settings"].values())
        self.assertGreater(values["activeDeadlineSeconds"] * 1000, attempt_ms)
        self.assertGreaterEqual(int(smoke.HELM_TIMEOUT.rstrip("s")), values["activeDeadlineSeconds"])

    def test_chart_accepts_smoke_values(self):
        """The values the smoke installs pass the chart schema and render guards."""
        if shutil.which(HELM) is None:
            self.skipTest("helm not on PATH")
        with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
            json.dump(smoke.smoke_values(DIGEST, 2), handle)
            handle.flush()
            result = subprocess.run([HELM, "template", smoke.RELEASE, str(smoke.CHART), "--values", handle.name],
                                    capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        for role in smoke.ROLES:
            self.assertIn(f'image: "{smoke.digest_reference(role, DIGEST[role])}"', result.stdout)
        for name in smoke.expected_release_objects():
            self.assertIn(f"name: {name.split('/')[1]}\n", result.stdout.replace('"', ""))


class FixtureTest(unittest.TestCase):
    def setUp(self):
        self.items = smoke.fixture_manifests("postgres@sha256:" + "e" * 64, PASSWORDS, "0a1b2c3d")["items"]

    def find(self, kind, name):
        matches = [i for i in self.items if i["kind"] == kind and i["metadata"]["name"] == name]
        self.assertEqual(len(matches), 1, f"{kind}/{name}")
        return matches[0]

    def test_app_namespace_enforces_restricted(self):
        labels = self.find("Namespace", smoke.APP_NAMESPACE)["metadata"]["labels"]
        self.assertEqual(labels["pod-security.kubernetes.io/enforce"], "restricted")
        self.assertEqual(labels[smoke.RUN_LABEL], "0a1b2c3d")
        self.assertEqual(labels["openmettle.dev/environment"], "dev")

    def test_every_object_is_labelled_for_this_run(self):
        for item in self.items:
            self.assertEqual(item["metadata"]["labels"][smoke.RUN_LABEL], "0a1b2c3d", item["metadata"]["name"])

    def test_test_creates_one_url_secret_per_role(self):
        for role in smoke.ROLES:
            secret = self.find("Secret", smoke.SECRET[role])
            self.assertEqual(secret["metadata"]["namespace"], smoke.APP_NAMESPACE)
            url = secret["stringData"]["url"]
            self.assertRegex(url, rf"^postgres://{smoke.DB_ROLE[role]}:{PASSWORDS[role]}@[^/]+/openmettle"
                                  r"\?sslmode=disable$")
        owner = PASSWORDS["migrate"]
        holders = [i["metadata"]["name"] for i in self.items if owner in json.dumps(i)]
        self.assertEqual(sorted(holders), sorted([smoke.SECRET["migrate"], "postgres-fixture"]))

    def test_provisioning_follows_core_readme(self):
        fixture = self.find("Secret", "postgres-fixture")
        self.assertEqual(fixture["metadata"]["namespace"], smoke.DB_NAMESPACE)
        sql = fixture["stringData"]["provision.sql"]
        for role in smoke.ROLES:
            self.assertIn(f"CREATE ROLE {smoke.DB_ROLE[role]} LOGIN PASSWORD '{PASSWORDS[role]}';", sql)
        self.assertIn("CREATE DATABASE openmettle OWNER openmettle_owner;", sql)
        self.assertNotRegex(sql, r"SUPERUSER|CREATEROLE|CREATEDB|GRANT")

    def test_postgres_uses_given_image_and_secret_password(self):
        container = self.find("Deployment", "postgres")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["image"], "postgres@sha256:" + "e" * 64)
        self.assertNotIn(PASSWORDS["admin"], json.dumps(container))


class EvaluationTest(unittest.TestCase):
    def test_job_completions_one_per_uid_oldest_first(self):
        events = [event("Completed", "u2", when="2026-11-19T10:05:00Z"),
                  event("Completed", "u1", when="2026-11-19T10:01:00Z"),
                  event("Completed", "u1", when="2026-11-19T10:00:30Z"),
                  event("SuccessfulCreate", "u3"),
                  event("Completed", "u4", name="other-job"),
                  event("Completed", "u5", kind="Pod"),
                  event("Completed", "")]
        runs = smoke.job_completions(events, "openmettle-core-migrate")
        self.assertEqual([r.isoformat() for r in runs], ["2026-11-19T10:00:30+00:00", "2026-11-19T10:05:00+00:00"])

    def test_event_time_falls_back_and_requires_a_timestamp(self):
        self.assertEqual(smoke.event_time({"eventTime": "2026-11-19T10:00:00.123456Z"}).microsecond, 123456)
        with self.assertRaises(smoke.SmokeFailure):
            smoke.event_time({})

    def test_images_reported_present_matches_both_kubelet_messages(self):
        refs = [smoke.digest_reference(r, DIGEST[r]) for r in smoke.ROLES]
        events = [event("Pulled", message=f'Container image "{refs[0]}" already present on machine'),
                  event("Pulled", message=f'Container image "{refs[1]}" already present on machine and can be '
                                          "accessed by the pod"),
                  event("Failed", message=f'Container image "{refs[2]}" is not present with pull policy of Never')]
        self.assertEqual(smoke.images_reported_present(events, refs), sorted(refs[:2]))

    def test_unexpected_resources_flags_devices_and_claims(self):
        pod = {"spec": {"containers": [{"resources": {"requests": {"cpu": "1", "memory": "1Mi"},
                                                      "limits": {"nvidia.com/gpu": "1"}}}],
                        "initContainers": [{"resources": {"claims": [{"name": "gpu"}]}}],
                        "resourceClaims": [{"name": "gpu"}]}}
        self.assertEqual(smoke.unexpected_resources([pod]),
                         ["container.claims", "nvidia.com/gpu", "pod.resourceClaims"])
        clean = {"spec": {"containers": [{"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}}}]}}
        self.assertEqual(smoke.unexpected_resources([clean]), [])

    def test_release_objects(self):
        self.assertEqual(smoke.expected_release_objects(), [
            "Deployment/openmettle-core-api", "Deployment/openmettle-core-worker", "Service/openmettle-core-api",
            "ServiceAccount/openmettle-core-api", "ServiceAccount/openmettle-core-worker"])
        items = [{"kind": "Service", "metadata": {"name": "b"}}, {"kind": "Deployment", "metadata": {"name": "a"}}]
        self.assertEqual(smoke.object_names(items), ["Deployment/a", "Service/b"])


class SummaryTest(unittest.TestCase):
    def report(self, **overrides):
        report = {"result": "passed", "classification": "dev", "core_commit": smoke.CORE_COMMIT,
                  "cluster": "openmettle-dev-qual-0a1b2c3d", "release": smoke.RELEASE,
                  "namespace": smoke.APP_NAMESPACE, "tools": {"helm": smoke.HELM_VERSION},
                  "images": {r: {"reference": smoke.digest_reference(r, DIGEST[r]), "cri_image_id": DIGEST[r],
                                 "resolved_before_alias": False} for r in smoke.ROLES},
                  "checks": [{"check": "x"}]}
        report.update(overrides)
        return report

    def test_summary_has_fixed_keys_and_digest_references(self):
        summary = smoke.build_summary(self.report())
        self.assertEqual(list(summary), sorted(summary))
        self.assertLessEqual(set(summary), smoke.SUMMARY_KEYS)
        text = json.dumps(summary)
        self.assertNotRegex(text, r"postgres://|password")
        smoke.assert_no_secrets(text, PASSWORDS.values())

    def test_summary_rejects_unknown_keys_and_results(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "unexpected summary keys"):
            smoke.build_summary(self.report(passwords=PASSWORDS))
        with self.assertRaises(smoke.SmokeFailure):
            smoke.build_summary(self.report(result="skipped"))

    def test_summary_rejects_tag_references_and_extra_image_fields(self):
        tagged = self.report()
        tagged["images"]["api"]["reference"] = "openmettle-smoke.invalid/openmettle/api:latest"
        with self.assertRaises(smoke.SmokeFailure):
            smoke.build_summary(tagged)
        extra = self.report()
        extra["images"]["api"]["url"] = "x"
        with self.assertRaises(smoke.SmokeFailure):
            smoke.build_summary(extra)

    def test_secret_guard_and_redaction(self):
        with self.assertRaises(smoke.SmokeFailure):
            smoke.assert_no_secrets(f"error: {PASSWORDS['api']}", PASSWORDS.values())
        smoke.assert_no_secrets("anything", ["", None])
        self.assertEqual(smoke.redact(f"url with {PASSWORDS['api']}", PASSWORDS.values()), "url with [redacted]")


class PinsTest(unittest.TestCase):
    def test_core_commit_matches_ci_and_fixture(self):
        for workflow in ("checks.yml", "kind-smoke.yml"):
            text = (ROOT / ".github" / "workflows" / workflow).read_text()
            self.assertEqual(re.findall(r"CORE_COMMIT: ([0-9a-f]{40})", text), [smoke.CORE_COMMIT], workflow)
        self.assertTrue((ROOT / "tests" / "fixtures" / f"core-{smoke.CORE_COMMIT[:7]}").is_dir())

    def test_helm_version_matches_installer(self):
        text = (ROOT / "tests" / "chart" / "install-tools.sh").read_text()
        self.assertIn(f"HELM_VERSION={smoke.HELM_VERSION}\n", text)


@unittest.skipUnless(CORE_DIR, "set OPENMETTLE_CORE_DIR to core tests/kubernetes/qualify.py at CORE_COMMIT")
class CoreGuardTest(unittest.TestCase):
    """The guards imported from core at CORE_COMMIT refuse unsafe contexts."""

    @classmethod
    def setUpClass(cls):
        cls.core = smoke.load_core(Path(CORE_DIR))

    def test_imports_and_pins(self):
        for name in smoke.CORE_IMPORTS:
            self.assertTrue(hasattr(self.core, name), name)
        self.assertRegex(self.core.NODE_IMAGE, r"^kindest/node:v[0-9.]+@sha256:[0-9a-f]{64}$")
        self.assertRegex(self.core.POSTGRES_IMAGE, r"@sha256:[0-9a-f]{64}$")

    def test_refuses_without_opt_in_or_with_unsafe_docker_selection(self):
        good = {"OPENMETTLE_K8S_QUALIFICATION": "isolated-dev", "OPENMETTLE_K8S_DOCKER_CONTEXT": "default"}
        self.assertEqual(self.core.check_opt_in(good), "default")
        for bad in ({}, {**good, "OPENMETTLE_K8S_QUALIFICATION": "yes"},
                    {**good, "OPENMETTLE_K8S_DOCKER_CONTEXT": ""}, {**good, "DOCKER_HOST": "tcp://remote:2376"},
                    {**good, "DOCKER_CONTEXT": "prod"}):
            with self.subTest(env=bad), self.assertRaises(self.core.Refusal):
                self.core.check_opt_in(bad)

    def test_refuses_remote_docker_context(self):
        def run(args, **_):
            return mock.Mock(stdout=json.dumps([{"Endpoints": {"docker": {"Host": "ssh://builder"}}}]))
        with self.assertRaises(self.core.Refusal):
            self.core.check_docker_context(run, "remote")

    def test_refuses_existing_or_foreign_cluster_name(self):
        def run(args, **_):
            return mock.Mock(stdout="openmettle-dev-qual-0a1b2c3d\n")
        with self.assertRaises(self.core.Refusal):
            self.core.check_cluster_absent(run, "openmettle-dev-qual-0a1b2c3d")
        with self.assertRaises(self.core.Refusal):
            self.core.check_cluster_absent(run, "production")

    def test_child_environment_cannot_reach_an_inherited_cluster(self):
        inherited = {"PATH": "/usr/bin", "KUBECONFIG": "/home/u/.kube/config", "DOCKER_HOST": "tcp://x",
                     "KIND_CLUSTER_NAME": "prod", "HELM_KUBECONTEXT": "prod", "BUILDX_BUILDER": "remote"}
        env = smoke.smoke_environment(
            self.core.child_environment(inherited, Path("/tmp/run/kubeconfig"), "default", None),
            Path("/tmp/run"), None)
        self.assertEqual(env["KUBECONFIG"], "/tmp/run/kubeconfig")
        self.assertEqual(env["DOCKER_CONTEXT"], "default")
        for name in ("DOCKER_HOST", "KIND_CLUSTER_NAME", "HELM_KUBECONTEXT", "BUILDX_BUILDER"):
            self.assertNotIn(name, env)

    def test_cluster_identity_refuses_foreign_kubeconfig(self):
        name = "openmettle-dev-qual-0a1b2c3d"
        config = {"current-context": f"kind-{name}", "contexts": [{"name": f"kind-{name}"}],
                  "clusters": [{"name": f"kind-{name}", "cluster": {"server": "https://127.0.0.1:41234"}}]}
        self.core.check_cluster_identity(config, [f"{name}-control-plane"], name, name)
        remote = json.loads(json.dumps(config))
        remote["clusters"][0]["cluster"]["server"] = "https://k8s.example.test:6443"
        with self.assertRaises(self.core.Refusal):
            self.core.check_cluster_identity(remote, [f"{name}-control-plane"], name, name)
        with self.assertRaises(self.core.Refusal):
            self.core.check_cluster_identity(config, ["worker-1"], name, name)


if __name__ == "__main__":
    unittest.main()
