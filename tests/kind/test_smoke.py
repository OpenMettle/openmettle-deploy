"""Cluster-free tests for the kind smoke harness (tests/kind/smoke.py).

They cover guards, digest parsing, fixture and values derivation, event evaluation, the
published summary and the orchestration (ordering, refusals, cleanup, redaction and every scenario
assertion) against a recording fake cluster. They do not create a cluster and are not evidence that
the chart installs; only a `kind-smoke` workflow run is. Set OPENMETTLE_CORE_DIR to a directory holding core's
tests/kubernetes/qualify.py at CORE_COMMIT to also exercise the imported core guards. CI does.
"""
import io
import json
import os
import re
import shutil
import signal
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


def git(directory, *args):
    subprocess.run(["git", "-C", str(directory), "-c", "core.hooksPath=/dev/null", "-c", "user.name=smoke",
                    "-c", "user.email=smoke@example.invalid", "-c", "commit.gpgsign=false", *args],
                   check=True, capture_output=True, text=True)


@unittest.skipIf(shutil.which("git") is None, "git not on PATH")
class CoreCheckoutStateTest(unittest.TestCase):
    """core_checkout_state reads HEAD and every change, including ignored files, and fails closed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        git(self.tmp, "init", "--quiet")
        (self.tmp / ".gitignore").write_text("build/\n")
        git(self.tmp, "add", ".gitignore")
        git(self.tmp, "commit", "--quiet", "--message", "fixture")

    def test_clean_checkout(self):
        head, porcelain = smoke.core_checkout_state(self.tmp)
        self.assertRegex(head.strip(), r"^[0-9a-f]{40}$")
        self.assertEqual(porcelain, "")

    def test_ignored_and_untracked_files_are_changes(self):
        for path in ("build/context.txt", "untracked.txt"):
            with self.subTest(path=path):
                (self.tmp / path).parent.mkdir(exist_ok=True)
                (self.tmp / path).write_text("x")
                _, porcelain = smoke.core_checkout_state(self.tmp)
                self.assertIn(path.split("/")[0], porcelain)
                with self.assertRaisesRegex(smoke.Refusal, "local changes"):
                    smoke.check_core_checkout(smoke.CORE_COMMIT, porcelain)
                (self.tmp / path).unlink()

    def test_git_errors_refuse(self):
        not_a_repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, not_a_repo)
        with self.assertRaisesRegex(smoke.Refusal, "rev-parse HEAD failed"):
            smoke.core_checkout_state(not_a_repo)
        failing = [mock.Mock(returncode=0, stdout=smoke.CORE_COMMIT + "\n"), mock.Mock(returncode=128, stdout="")]
        with mock.patch.object(smoke.subprocess, "run", side_effect=failing), \
                self.assertRaisesRegex(smoke.Refusal, "status --porcelain --ignored failed"):
            smoke.core_checkout_state(self.tmp)


# --- Orchestration against a recording fake cluster ----------------------------------------------

IMAGE_ID = {role: "sha256:" + "f" * 63 + str(i) for i, role in enumerate(smoke.ROLES, start=1)}
DNS_IP, PEER_IP = "10.244.0.2", "10.244.0.9"
DATABASE_HOST = f"postgres.{smoke.DB_NAMESPACE}.svc.cluster.local"
API_HOST = f"{smoke.FULLNAME}-api.{smoke.APP_NAMESPACE}.svc.cluster.local"
MUTATING = (("helm", "install"), ("helm", "upgrade"), ("helm", "uninstall"), ("kubectl", "apply"))


class FakeCluster:
    """Answers every command smoke.py runs as a healthy kind cluster would, and records them.

    `doctors` rewrite single observations; each is called as doctor(args, result) and may return a
    replacement result. `unknown` collects commands the fake does not model.
    """

    def __init__(self):
        self.calls = []
        self.unknown = []
        self.doctors = []
        self.passwords = {}
        self.namespaces = {}
        self.ctr = {}
        self.built = set()
        self.name = None
        self.revision = 0
        self.installed = False
        self.replicas = {"api": 1, "worker": 1}
        self.generation = {"api": 1, "worker": 1}
        self.readyz = 200
        self.core = self.make_core()

    def make_core(self):
        fake = self

        class Refusal(Exception):
            pass

        class QualificationFailure(Exception):
            pass

        def check_cluster_identity(config, nodes, label, name):
            fake.calls.append(["IDENTITY"])
            if config.get("current-context") != f"kind-{name}" or nodes != [f"{name}-control-plane"] \
                    or label != name:
                raise Refusal("identity mismatch")

        def runner(env):
            return fake

        return mock.Mock(
            spec=list(smoke.CORE_IMPORTS), KIND_VERSION="v0", KUBECTL_VERSION="v0", NODE_IMAGE="node",
            POSTGRES_IMAGE="postgres@sha256:" + "e" * 64, Refusal=Refusal, QualificationFailure=QualificationFailure,
            Runner=runner, http_get=lambda port, path: (fake.readyz, ""),
            check_opt_in=lambda environ: "default", check_tools=lambda run: None,
            check_docker_context=lambda run, context: None, check_cluster_absent=lambda run, name: None,
            check_cluster_identity=check_cluster_identity,
            child_environment=lambda environ, kubeconfig, context, tools: dict(environ))

    # Runner protocol: the same signature and failure message as core's Runner.
    def __call__(self, args, *, input=None, check=True, timeout=600):
        args = list(args)
        self.calls.append(args)
        returncode, stdout, stderr = self.respond(args, input)
        result = subprocess.CompletedProcess(args, returncode, stdout, stderr)
        for doctor in self.doctors:
            result = doctor(args, result) or result
        if check and result.returncode != 0:
            raise self.core.QualificationFailure(
                f"{' '.join(args[:4])} ... exited {result.returncode}: {result.stderr.strip()[-2000:]}")
        return result

    def commands(self, *prefix):
        """Recorded commands, with kubectl and helm connection flags removed, that start with prefix."""
        return [c for c in map(self.strip, self.calls) if c[:len(prefix)] == list(prefix)]

    @staticmethod
    def strip(args):
        if args[0] == "kubectl" and "--context" in args:
            return ["kubectl", *args[args.index("--context") + 2:]]
        if args[0] == "kubectl" and "--kubeconfig" in args:
            return ["kubectl", *args[args.index("--kubeconfig") + 2:]]
        if args[0] == "helm" and "--kube-context" in args:
            rest = args[args.index("--kube-context") + 2:]
            return ["helm", *(rest[2:] if rest[:1] == ["--namespace"] else rest)]
        return args

    # responses
    def respond(self, args, input):
        if args[:2] == ["helm", "version"]:
            return 0, "v4.3.0\n", ""
        if args[:2] == ["docker", "build"]:
            self.built.add(args[args.index("--tag") + 1])
            return 0, "", ""
        if args[:3] == ["docker", "image", "rm"]:
            return (0, "", "") if args[3] in self.built else (1, "", f"No such image: {args[3]}")
        if args[:3] == ["kind", "create", "cluster"]:
            self.name = args[args.index("--name") + 1]
            Path(args[args.index("--kubeconfig") + 1]).write_text("synthetic")
            return 0, "", ""
        if args[:3] == ["kind", "load", "docker-image"]:
            role = args[3].split("/")[2].split(":")[0]
            self.ctr[args[3]] = DIGEST[role]
            self.ctr[f"import-2026-11-19@{DIGEST[role]}"] = DIGEST[role]
            return 0, "", ""
        if args[:3] == ["kind", "delete", "cluster"]:
            return 0, "", ""
        if args[:2] == ["docker", "inspect"]:
            return 0, f"{self.name}\n", ""
        if args[:2] == ["docker", "exec"]:
            return self.node(args[3:])
        if args[0] == "kubectl":
            return self.kubectl(self.strip(args)[1:], input)
        if args[0] == "helm":
            return self.helm(self.strip(args)[1:])
        self.unknown.append(args)
        return 1, "", "unmodelled command"

    def node(self, args):
        if args[:4] == ["ctr", "--namespace=k8s.io", "images", "ls"]:
            rows = [f"{name} application/vnd.oci.image.index.v1+json {digest} 40 MiB linux/amd64 -"
                    for name, digest in sorted(self.ctr.items())]
            return 0, "\n".join(["REF TYPE DIGEST SIZE PLATFORMS LABELS", *rows]) + "\n", ""
        if args[:4] == ["ctr", "--namespace=k8s.io", "images", "tag"]:
            if args[5] in self.ctr:
                return 1, "", "image already exists"
            self.ctr[args[5]] = self.ctr[args[4]]
            return 0, "", ""
        if args[:2] == ["crictl", "inspecti"]:
            digest = self.ctr.get(args[-1])
            if digest is None:
                return 1, "", "no such image"
            role = next(r for r in smoke.ROLES if DIGEST[r] == digest)
            return 0, json.dumps({"status": {"id": IMAGE_ID[role]}}), ""
        if args[:2] == ["crictl", "ps"]:
            role = args[args.index("--id") + 1].split("-")[1]
            return 0, json.dumps({"containers": [{"id": "c", "imageRef": IMAGE_ID[role]}]}), ""
        self.unknown.append(args)
        return 1, "", "unmodelled node command"

    def pod(self, component, index):
        name = f"{smoke.FULLNAME}-{component}-{index}"
        return {"metadata": {"name": name, "labels": {"app.kubernetes.io/instance": smoke.RELEASE,
                                                      "app.kubernetes.io/component": component}},
                "spec": {"containers": [{"name": component, "imagePullPolicy": "Never",
                                         "image": smoke.digest_reference(component, DIGEST[component]),
                                         "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}}}]},
                "status": {"conditions": [{"type": "Ready", "status": "True"}],
                           "containerStatuses": [{"restartCount": 0, "containerID": f"containerd://cid-{component}-"
                                                                                    f"{index}",
                                                  "imageID": f"import-2026-11-19@{DIGEST[component]}"}]}}

    def probe(self, args):
        """`kubectl exec deployment/<workload> ... -- timeout N bash -c <script> <host> <port> [path]`.

        Models the chart's policies under the namespace deny-all: release pods reach only the
        database; only the decoy peer reaches the API; pods in the database namespace are unrestricted.
        """
        workload = args[1].split("/", 1)[1]
        command = args[args.index("--") + 1:]
        host, port, http = command[5], int(command[6]), len(command) > 7
        if workload.startswith(smoke.FULLNAME):
            allowed = (host, port) == (DATABASE_HOST, 5432)
        elif host == API_HOST:
            allowed = workload == smoke.PEER
        else:
            allowed = True
        if not allowed:
            return smoke.TIMEOUT_EXIT, "", ""
        return 0, "HTTP/1.1 200 OK\r\n" if http else "", ""

    @staticmethod
    def running_pod(name, ip):
        return {"metadata": {"name": name}, "status": {"phase": "Running", "podIP": ip}}

    def network_policies(self):
        names = [f"NetworkPolicy/{smoke.NAMESPACE_DENY}"]
        if self.installed:
            names += smoke.release_network_policies()
        return self.items(names)

    def pods(self, component=None):
        if not self.installed:
            return []
        components = [component] if component else list(smoke.WORKLOADS)
        return [self.pod(c, i) for c in components if c in self.replicas for i in range(self.replicas[c])]

    @staticmethod
    def items(names):
        return [{"kind": n.split("/")[0], "metadata": {"name": n.split("/")[1]}} for n in names]

    def kubectl(self, args, input):
        ok = lambda data: (0, json.dumps(data) if not isinstance(data, str) else data, "")  # noqa: E731
        listing = lambda items: ok({"kind": "List", "items": items})  # noqa: E731
        if args[:2] == ["config", "view"]:
            return ok({"current-context": f"kind-{self.name}", "contexts": [{"name": f"kind-{self.name}"}]})
        if args[:2] == ["get", "nodes"]:
            return listing([{"metadata": {"name": f"{self.name}-control-plane"}}])
        if args[:2] == ["get", "namespace"]:
            if args[2] not in self.namespaces:
                return 1, "", f'namespaces "{args[2]}" not found'
            return ok({"metadata": {"name": args[2], "labels": self.namespaces[args[2]]}})
        if args[:3] == ["apply", "--filename", "-"]:
            for item in json.loads(input)["items"]:
                if item["kind"] == "Namespace":
                    self.namespaces[item["metadata"]["name"]] = item["metadata"]["labels"]
                if item["metadata"]["name"] == "postgres-fixture":
                    self.passwords["admin"] = item["stringData"]["admin-password"]
                if item["kind"] == "Secret" and "url" in item.get("stringData", {}):
                    role = next(r for r in smoke.ROLES if smoke.SECRET[r] == item["metadata"]["name"])
                    self.passwords[role] = item["stringData"]["url"].split(":")[2].split("@")[0]
            return 0, "applied", ""
        if args[:2] == ["create", "--dry-run=server"]:
            return 1, "", f'pods "psa-probe" is forbidden: {smoke.PSA_DENIAL}:latest": allowPrivilegeEscalation'
        if args[:1] != ["--namespace"]:
            if args[:3] == ["get", "pods", "--all-namespaces"]:
                return ok("NAME READY\n")
            self.unknown.append(args)
            return 1, "", "unmodelled kubectl command"
        namespace, args = args[1], args[2:]
        selector = args[args.index("--selector") + 1] if "--selector" in args else ""
        if args[:1] == ["exec"] and "timeout" in args:
            return self.probe(args)
        if namespace == smoke.DB_NAMESPACE:
            if args[:2] == ["rollout", "status"]:
                return 0, "rolled out", ""
            if args[:1] == ["exec"]:
                return 0, "20261101000000|t|aa|2026-11-19 10:01:00\n20261102000000|t|bb|2026-11-19 10:01:00\n", ""
            if args[:2] == ["get", "events"]:
                return ok("No events")
            if args[:2] == ["get", "pods"] and selector == f"app.kubernetes.io/name={smoke.PEER}":
                return listing([self.running_pod(f"{smoke.PEER}-0", PEER_IP)])
        if namespace == "kube-system" and args[:2] == ["get", "pods"] and selector == smoke.DNS_SELECTOR:
            return listing([self.running_pod("coredns-1", DNS_IP), self.running_pod("coredns-0", DNS_IP)])
        if args[:2] == ["get", "networkpolicies"]:
            return listing(self.network_policies())
        if args[:2] == ["get", "deployment"]:
            component = args[2].rsplit("-", 1)[1]
            return ok({"metadata": {"name": args[2], "generation": self.generation[component],
                                    "creationTimestamp": "2026-11-19T10:01:30Z"},
                       "status": {"readyReplicas": self.replicas[component]}})
        if args[:2] == ["get", "pods"]:
            component = selector.partition("app.kubernetes.io/component=")[2] or None
            return listing(self.pods(component))
        if args[:2] == ["get", "job"]:
            return ok("")
        if args[:2] == ["get", "events"] and "--sort-by=.lastTimestamp" in args:
            return ok("LAST SEEN TYPE REASON\n")
        if args[:2] == ["get", "events"]:
            selectors = args[args.index("--field-selector") + 1] if "--field-selector" in args else ""
            if selectors == "involvedObject.kind=Job":
                return listing([{"reason": "Completed", "lastTimestamp": f"2026-11-19T10:0{r}:00Z", "message": "",
                                 "involvedObject": {"kind": "Job", "name": f"{smoke.FULLNAME}-migrate",
                                                    "uid": f"job-{r}"}} for r in range(1, self.revision + 1)])
            if selectors == "reason=Pulled":
                return listing([{"reason": "Pulled", "message": f'Container image '
                                 f'"{smoke.digest_reference(r, DIGEST[r])}" already present on machine'}
                                for r in smoke.ROLES])
        if args[:1] == ["get"] and args[1] in (smoke.INVENTORY_KINDS, smoke.RELEASE_KINDS):
            return listing(self.items(smoke.expected_release_objects()) if self.installed else [])
        if args[:3] == ["get", "--filename", "-"]:
            return listing(self.items(smoke.expected_release_objects()))
        if args[:2] == ["get", smoke.OPTIONAL_KINDS]:
            return listing([])
        if args[:2] in (["get", "secrets"], ["get", "endpointslices"]):
            if selector == smoke.RUN_LABEL:
                return listing(self.items(f"Secret/{smoke.SECRET[r]}" for r in smoke.ROLES))
            return listing([])
        if args[:1] == ["logs"]:
            return ok("log line\n")
        self.unknown.append(args)
        return 1, "", "unmodelled kubectl command"

    def helm(self, args):
        if args[0] in ("install", "upgrade"):
            values = json.loads(Path(args[args.index("--values") + 1]).read_text())
            replicas = values["worker"]["replicas"]
            if self.installed and replicas != self.replicas["worker"]:
                self.generation["worker"] += 1
            self.replicas["worker"] = replicas
            self.installed, self.revision = True, self.revision + 1
            return 0, "", ""
        if args[:1] == ["list"]:
            return 0, json.dumps([{"name": smoke.RELEASE, "status": "deployed", "revision": str(self.revision)}]
                                 if self.installed else []), ""
        if args[:2] == ["get", "manifest"]:
            return 0, "---\n# Source: openmettle-core/templates/api-service.yaml\n", ""
        if args[:1] == ["uninstall"]:
            self.installed = False
            return 0, "", ""
        self.unknown.append(args)
        return 1, "", "unmodelled helm command"


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakePortForward:
    def __init__(self, kubectl, env, target, port):
        self.port = port

    def close(self):
        pass


def matches(args, match):
    """True if the command line contains every substring in `match`."""
    line = " ".join(args)
    return all(m in line for m in match)


def doctor_json(match, mutate, when=lambda: True):
    """A doctor that rewrites the successful JSON output of commands matching `match`."""
    def doctor(args, result):
        if result.returncode or not matches(args, match) or not when():
            return None
        try:
            data = json.loads(result.stdout)
        except ValueError:
            return None
        mutate(data)
        return subprocess.CompletedProcess(args, result.returncode, json.dumps(data), result.stderr)
    return doctor


def doctor_output(match, returncode=0, stdout="", stderr=""):
    def doctor(args, result):
        if matches(args, match):
            return subprocess.CompletedProcess(args, returncode, stdout, stderr)
    return doctor


class OrchestrationTest(unittest.TestCase):
    """main() and Smoke against a recording fake cluster: ordering, refusals, cleanup and reporting."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.fake = FakeCluster()

    def run_main(self):
        """Run main() against the fake; return (exit status, report, stderr)."""
        report = self.tmp / "report.json"
        report.unlink(missing_ok=True)
        stderr = io.StringIO()
        with mock.patch.object(smoke, "core_checkout_state", return_value=(smoke.CORE_COMMIT, "")), \
                mock.patch.object(smoke, "load_core", return_value=self.fake.core), \
                mock.patch.object(smoke, "PortForward", FakePortForward), \
                mock.patch.object(smoke, "time", FakeClock()), \
                mock.patch.object(smoke.subprocess, "run", side_effect=AssertionError("real subprocess")), \
                mock.patch.object(smoke.subprocess, "Popen", side_effect=AssertionError("real subprocess")), \
                mock.patch("sys.stderr", stderr):
            status = smoke.main(["--core-dir", str(self.tmp), "--report", str(report)])
        return status, json.loads(report.read_text()), stderr.getvalue()

    def assert_cleaned_up(self, built=smoke.ROLES, cluster=True):
        deleted = [c[4] for c in self.fake.commands("kind", "delete", "cluster", "--name")]
        self.assertEqual(deleted, [self.fake.name] if cluster else [])
        removed = [c[3] for c in self.fake.commands("docker", "image", "rm")]
        self.assertEqual(sorted(removed), sorted(r for r in self.fake.built if r.split("/")[2].split(":")[0] in built))
        self.assertEqual(len(removed), len(built))

    def test_passes_on_a_healthy_cluster(self):
        status, report, _ = self.run_main()
        self.assertEqual(self.fake.unknown, [])
        self.assertEqual((status, report["result"]), (0, "passed"), report.get("error"))
        self.assertEqual(len(report["checks"]), 9)
        netpol_check = next(c for c in report["checks"] if "NetworkPolicy enforced" in c["check"])
        self.assertEqual(netpol_check["namespace_policies"],
                         sorted([f"NetworkPolicy/{smoke.NAMESPACE_DENY}", *smoke.release_network_policies()]))
        self.assertEqual(len(netpol_check["probes"]), len(smoke.probe_plan(DNS_IP, PEER_IP)))
        self.assertIn("networkpolicies", smoke.RELEASE_KINDS.split(","))
        self.assertIn("networkpolicies", smoke.INVENTORY_KINDS.split(","))
        self.assertNotIn("networkpolicies", smoke.OPTIONAL_KINDS.split(","))
        self.assertNotIn("error", report)
        self.assert_cleaned_up()
        self.assertEqual([c[1:3] for c in self.fake.commands("helm") if c[1] in ("install", "upgrade", "uninstall")],
                         [["install", smoke.RELEASE], ["upgrade", smoke.RELEASE], ["upgrade", smoke.RELEASE],
                          ["uninstall", smoke.RELEASE]])
        for role in smoke.ROLES:
            self.assertEqual(report["images"][role], {"reference": smoke.digest_reference(role, DIGEST[role]),
                                                      "cri_image_id": IMAGE_ID[role],
                                                      "resolved_before_alias": False})

    def test_identity_is_verified_immediately_before_every_mutation(self):
        """Only verify_identity's own namespace-ownership reads may separate it from the change."""
        self.run_main()
        mutations = 0
        previous = None
        for call in map(FakeCluster.strip, self.fake.calls):
            if tuple(call[:2]) in MUTATING:
                self.assertEqual(previous, ["IDENTITY"], f"{call[:2]} ran without an identity check just before")
                mutations += 1
            if call[:3] != ["kubectl", "get", "namespace"]:
                previous = call
        self.assertEqual(mutations, 5)  # apply, install, upgrade, upgrade, uninstall

    def test_namespace_from_another_run_is_refused_before_any_change(self):
        self.fake.namespaces[smoke.APP_NAMESPACE] = {smoke.RUN_LABEL: "ffffffff"}
        status, report, _ = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn(f"namespace {smoke.APP_NAMESPACE} was not created by this run", report["error"])
        self.assertEqual([c for c in self.fake.calls if tuple(FakeCluster.strip(c)[:2]) in MUTATING], [])
        self.assert_cleaned_up()

    def test_failure_exits_1_cleans_up_and_reports_a_redacted_error(self):
        """The password straddles the 2000-character tail core's Runner would keep."""
        def fail_rollout(args, result):
            if "rollout" in args:
                password = self.fake.passwords["api"]
                stderr = "A" * 100 + password + "B" * (smoke.STDERR_TAIL - 16)
                return subprocess.CompletedProcess(args, 1, "", stderr)
        self.fake.doctors.append(fail_rollout)
        status, report, stderr = self.run_main()
        self.assertEqual((status, report["result"]), (1, "failed"))
        self.assertRegex(report["error"], r"exited 1: A+\[redacted\]B+$")
        for password in self.fake.passwords.values():
            self.assertNotIn(password[16:], json.dumps(report))
            self.assertNotIn(password[16:], stderr)
        self.assert_cleaned_up()
        self.assertEqual(len(self.fake.commands("kubectl", "--namespace", smoke.APP_NAMESPACE, "logs")), 1)

    def test_a_failure_message_quoting_an_observation_is_redacted(self):
        def leak(args, result):
            if args[-3:] == ["list", "--output", "json"]:
                return subprocess.CompletedProcess(args, 0, json.dumps(
                    [{"name": self.fake.passwords["migrate"], "status": "deployed", "revision": "1"}]), "")
        self.fake.doctors.append(leak)
        status, report, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn("unexpected Helm release state: [{'name': '[redacted]'", report["error"])
        self.assertNotIn(self.fake.passwords["migrate"], stderr)

    def test_diagnostics_are_redacted_before_truncation(self):
        def leak(args, result):
            if "logs" in args:
                password = self.fake.passwords["worker"]
                stdout = "A" * 100 + password + "B" * (smoke.DIAGNOSTIC_TAIL["stdout"] - 16)
                stderr = "C" * 100 + password + "D" * (smoke.DIAGNOSTIC_TAIL["stderr"] - 16)
                return subprocess.CompletedProcess(args, 0, stdout, stderr)
        self.fake.doctors += [leak, doctor_output(["--field-selector", "reason=Pulled"], stdout=json.dumps(
            {"items": []}))]
        status, _, stderr = self.run_main()
        self.assertEqual(status, 1)
        password = self.fake.passwords["worker"]
        self.assertIn("B" * 100, stderr)
        self.assertNotIn(password[16:], stderr)

    def test_published_report_passes_the_secret_guard(self):
        with mock.patch.object(smoke, "assert_no_secrets", wraps=smoke.assert_no_secrets) as guard:
            status, report, _ = self.run_main()
        self.assertEqual(status, 0)
        (text, values), _ = guard.call_args
        self.assertEqual(json.loads(text), report)
        self.assertEqual(sorted(values), sorted(self.fake.passwords.values()))
        self.assertEqual(len(self.fake.passwords), 4)

    def test_cleanup_failure_fails_a_passing_run(self):
        self.fake.doctors.append(doctor_output(["kind", "delete"], returncode=1))
        status, report, _ = self.run_main()
        self.assertEqual((status, report["result"]), (1, "failed"))
        self.assertEqual(report["cleanup_errors"], [f"kind delete cluster --name {self.fake.name} --kubeconfig "
                                                    f"{self.fake.calls[-4][-1]}: failed"])

    def test_build_failure_removes_only_built_images(self):
        self.fake.doctors.append(doctor_output(["build", "worker"], returncode=1, stderr="build failed"))
        status, report, _ = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn("docker build", report["error"])
        self.assertNotIn("cleanup_errors", report)
        self.assertEqual(self.fake.commands("kind", "create"), [])
        self.assert_cleaned_up(built=("api",), cluster=False)

    def test_termination_signals_still_clean_up(self):
        for sig in smoke.CLEANUP_SIGNALS:
            with self.subTest(signal=sig.name):
                self.fake = FakeCluster()
                before = signal.getsignal(sig)

                def terminate(args, result, sig=sig):
                    if args[:3] == ["kind", "load", "docker-image"]:
                        signal.raise_signal(sig)
                self.fake.doctors.append(terminate)
                status, report, _ = self.run_main()
                self.assertEqual((status, report["error"]), (1, f"interrupted: {sig.name}"))
                self.assertEqual(len(self.fake.commands("kind", "load")), 1)
                self.assert_cleaned_up()
                self.assertIs(signal.getsignal(sig), before)

    def test_existing_digest_name_is_not_tagged_again(self):
        """A digest name containerd already holds is used as is (resolved_before_alias)."""
        def preloaded(args, result):
            if args[:3] == ["kind", "load", "docker-image"] and "api" in args[3]:
                self.fake.ctr[smoke.digest_reference("api", DIGEST["api"])] = DIGEST["api"]
        self.fake.doctors.append(preloaded)
        status, report, _ = self.run_main()
        self.assertEqual(status, 0, report.get("error"))
        self.assertTrue(report["images"]["api"]["resolved_before_alias"])
        tagged = [c[-1] for c in self.fake.commands("docker", "exec") if c[5:7] == ["images", "tag"]]
        self.assertEqual(tagged, [smoke.digest_reference(r, DIGEST[r]) for r in ("worker", "migrate")])

    def test_reference_resolving_before_the_name_exists_is_still_named(self):
        """CRI resolving the digest reference does not mean containerd holds that name."""
        reference = smoke.digest_reference("api", DIGEST["api"])

        def resolves_early(args, result):
            if args[-2:] == ["json", reference]:
                return subprocess.CompletedProcess(args, 0, json.dumps({"status": {"id": IMAGE_ID["api"]}}), "")
        self.fake.doctors.append(resolves_early)
        status, report, _ = self.run_main()
        self.assertEqual(status, 0, report.get("error"))
        self.assertTrue(report["images"]["api"]["resolved_before_alias"])
        tagged = [c[-1] for c in self.fake.commands("docker", "exec") if c[5:7] == ["images", "tag"]]
        self.assertEqual(tagged, [smoke.digest_reference(r, DIGEST[r]) for r in smoke.ROLES])

    def test_each_assertion_fails_on_a_doctored_observation(self):
        fake_ref = lambda: self.fake  # noqa: E731 - doctors read the fake of the current subtest
        revision = lambda n: (lambda: fake_ref().revision == n)  # noqa: E731
        other = "sha256:" + "9" * 64
        api, worker = f"{smoke.FULLNAME}-api", f"{smoke.FULLNAME}-worker"

        def first_item(key, value):
            return lambda data: data["items"][0].__setitem__(key, value)

        def pod_status(update):
            return lambda data: [update(p) for p in data["items"]]

        def alias_elsewhere(args, result):
            if args[-2:] == ["images", "ls"] and "@sha256" in result.stdout:
                lines = [line.replace(f" {DIGEST['api']} ", f" {other} ")
                         if line.startswith(smoke.REGISTRY) and "@" in line.split()[0] else line
                         for line in result.stdout.splitlines()]
                return subprocess.CompletedProcess(args, 0, "\n".join(lines), "")

        def migrate_completed_late(data):
            data["metadata"]["creationTimestamp"] = "2026-11-19T10:00:00Z"

        def job_events(keep):
            return doctor_json(["involvedObject.kind=Job"], lambda data: data.__setitem__(
                "items", [e for e in data["items"] if keep(e)]))

        cases = {
            "digest name points elsewhere": (alias_elsewhere, "digest name does not point at"),
            "digest reference resolves elsewhere": (doctor_json(
                ["inspecti", smoke.digest_reference("api", DIGEST["api"])],
                lambda data: data["status"].__setitem__("id", other)), "resolves to a different image"),
            "release revision": (doctor_json(["list --output json"], lambda data: data[0].__setitem__(
                "revision", "9")), "unexpected Helm release state"),
            "pod not Ready": (doctor_json(["get pods --selector"], pod_status(lambda p: p["status"].__setitem__(
                "conditions", [{"type": "Ready", "status": "False"}]))), "pod is not Ready"),
            "container restarted": (doctor_json(["get pods --selector"], pod_status(
                lambda p: p["status"]["containerStatuses"][0].__setitem__("restartCount", 1))),
                "container restarted"),
            "pull policy": (doctor_json(["get pods --selector"], pod_status(
                lambda p: p["spec"]["containers"][0].__setitem__("imagePullPolicy", "IfNotPresent"))),
                "with pullPolicy Never"),
            "tag reference": (doctor_json(["get pods --selector"], pod_status(
                lambda p: p["spec"]["containers"][0].__setitem__("image", "x:latest"))), "with pullPolicy Never"),
            "no container id": (doctor_json(["get pods --selector"], pod_status(
                lambda p: p["status"]["containerStatuses"][0].pop("containerID"))), "has no containerd id"),
            "running image id": (doctor_json(["ps", "--id"], lambda data: data["containers"][0].__setitem__(
                "imageRef", other)), "container runs image"),
            "migrate Job remains": (doctor_output(["get job", "--ignore-not-found"], stdout="job.batch/x\n"),
                                    "migrate Job remains"),
            "readyz": (lambda args, result: setattr(fake_ref(), "readyz", 503), "API /readyz 200"),
            "install ready replicas": (doctor_json([f"deployment {worker} --output=json"], lambda data: data["status"].__setitem__(
                "readyReplicas", 0), when=revision(1)), "install ready replicas"),
            "two completions on install": (doctor_json(["involvedObject.kind=Job"], lambda data: data["items"].append(
                {**data["items"][0], "involvedObject": {**data["items"][0]["involvedObject"], "uid": "extra"}})),
                "expected one completed migrate Job after install"),
            "failed migration": (doctor_output(["exec", "deployment/postgres", "psql"], stdout="1|f|aa|t\n"),
                                 "failed entry"),
            "no migration history": (doctor_output(["exec", "deployment/postgres", "psql"], stdout=""),
                                     "migration history is empty"),
            "migrate after Deployments": (doctor_json([f"deployment {api} --output=json"], migrate_completed_late),
                                          "completed after the Deployments"),
            "image pulled": (doctor_json(["reason=Pulled"], first_item(
                "message", f'Successfully pulled image "{smoke.digest_reference("api", DIGEST["api"])}"')),
                "did not report every digest reference"),
            "migrate pods linger": (doctor_json(["app.kubernetes.io/component=migrate"], lambda data: data.__setitem__(
                "items", [fake_ref().pod("api", 9)])), "migrate hook pods to be removed"),
            "extra release object": (doctor_json([smoke.INVENTORY_KINDS],
                                                 lambda data: data["items"].append(
                                                     {"kind": "ConfigMap", "metadata": {"name": "x"}})),
                                     "release objects:"),
            "extra manifest object": (doctor_json(["get --filename -"], lambda data: data[
                "items"].append({"kind": "NetworkPolicy", "metadata": {"name": "x"}})), "release manifest objects"),
            "optional object": (doctor_json([smoke.OPTIONAL_KINDS], lambda data: data["items"].append(
                {"kind": "Ingress", "metadata": {"name": "x"}})), "optional objects present"),
            "other release": (doctor_json(["list --all-namespaces --output json"], lambda data: data.append(
                {"name": "other", "status": "failed", "revision": "1"})), "other Helm releases"),
            "foreign pod": (doctor_json(["get pods --output=json"], lambda data: data["items"].append(
                {**fake_ref().pod("api", 5), "metadata": {"name": "x", "labels": {}}})), "pods outside api/worker"),
            "optional resource": (doctor_json(["get pods --output=json"], pod_status(
                lambda p: p["spec"]["containers"][0]["resources"]["requests"].__setitem__("nvidia.com/gpu", "1"))),
                "pods request optional resources"),
            "namespace not restricted": (doctor_json([f"namespace {smoke.APP_NAMESPACE} --output=json"], lambda data: data[
                "metadata"]["labels"].__setitem__("pod-security.kubernetes.io/enforce", "baseline"),
                when=lambda: fake_ref().revision == 1 and fake_ref().installed), "does not enforce restricted"),
            "probe admitted": (doctor_output(["--dry-run=server"], returncode=0, stdout="pod/psa-probe created"),
                               "was not rejected"),
            "missing namespace default-deny": (doctor_json(
                ["get networkpolicies --output=json"],
                lambda data: data.__setitem__("items", [i for i in data["items"]
                                                        if i["metadata"]["name"] != smoke.NAMESPACE_DENY])),
                "app namespace NetworkPolicy objects:"),
            "no running CoreDNS pod": (doctor_json(
                ["--namespace kube-system", smoke.DNS_SELECTOR],
                lambda data: data.__setitem__("items", [])),
                "no Running CoreDNS pod with an IP"),
            "no running netpol-peer pod": (doctor_json(
                [f"app.kubernetes.io/name={smoke.PEER}"],
                lambda data: data.__setitem__("items", [])),
                f"no Running {smoke.PEER} pod with an IP"),
            "unenforced egress policy": (doctor_output(
                ["exec", f"deployment/{api}", PEER_IP], returncode=0, stdout=""),
                "NetworkPolicy is not enforced in this cluster"),
            "unenforced API ingress": (doctor_output(
                ["exec", "deployment/postgres", API_HOST], returncode=0, stdout="HTTP/1.1 200 OK\r\n"),
                "NetworkPolicy is not enforced in this cluster"),
            "blocked allowed egress": (doctor_output(
                ["exec", f"deployment/{api}", DATABASE_HOST], returncode=smoke.TIMEOUT_EXIT),
                "allowed path failed: api egress to the database peer by DNS name"),
            "control probe failed": (doctor_output(
                ["exec", "deployment/postgres", PEER_IP], returncode=smoke.TIMEOUT_EXIT),
                "its control did not connect, so the denial is not evidence"),
            "inconclusive denied probe": (doctor_output(
                ["exec", f"deployment/{worker}", PEER_IP], returncode=1, stderr="error: unable to upgrade connection"),
                "was inconclusive (inconclusive)"),
            "extra release networkpolicy": (doctor_json(
                [smoke.INVENTORY_KINDS],
                lambda data: data["items"].append({"kind": "NetworkPolicy", "metadata": {"name": "extra"}})),
                "release objects:"),
            "networkpolicy residue after uninstall": (doctor_json(
                [smoke.RELEASE_KINDS],
                lambda data: data["items"].append({"kind": "NetworkPolicy", "metadata": {"name": "leftover"}})),
                "release objects to be removed"),
            "scale ready replicas": (doctor_json([f"deployment {worker} --output=json"], lambda data: data["status"].__setitem__(
                "readyReplicas", 1), when=revision(2)), "scale ready replicas"),
            "API pod replaced": (doctor_json(["app.kubernetes.io/component=api"], pod_status(
                lambda p: p["metadata"].__setitem__("name", "replaced")), when=revision(2)), "API pod was replaced"),
            "upgrade skipped migrate": (job_events(lambda e: e["involvedObject"]["uid"] != "job-2"),
                                        "^upgrade did not run the migrate hook"),
            "repeated upgrade skipped migrate": (job_events(lambda e: e["involvedObject"]["uid"] != "job-3"),
                                                 "repeated upgrade did not run the migrate hook"),
            "identical upgrade rolled": (doctor_json([f"deployment {worker} --output=json"], lambda data: data[
                "metadata"].__setitem__("generation", 7), when=revision(3)), "identical upgrade replaced pods"),
            "uninstall residue": (doctor_json([smoke.RELEASE_KINDS], lambda data: data["items"].append(
                {"kind": "Pod", "metadata": {"name": "x"}})), "release objects to be removed"),
            "release listed after uninstall": (doctor_json(["list --output json"], lambda data: data.append(
                {"name": smoke.RELEASE, "status": "uninstalling", "revision": "3"}),
                when=lambda: not fake_ref().installed), "Helm still lists a release"),
            "test-owned Secret removed": (doctor_json([f"--selector {smoke.RUN_LABEL} "], lambda data: data["items"].pop()),
                                          "test-owned Secrets after uninstall"),
        }
        # History changes only after the install was observed: compare against the first reading.
        readings = []

        def history_changes(args, result):
            if "deployment/postgres" in args and "exec" in args and "psql" in args:
                readings.append(1)
                if len(readings) > 1:
                    return subprocess.CompletedProcess(args, 0, "1|t|changed|t\n", "")

        def history_changes_on_repeat(args, result):
            if "deployment/postgres" in args and "exec" in args and "psql" in args and fake_ref().revision == 3:
                return subprocess.CompletedProcess(args, 0, "1|t|changed|t\n", "")
        cases["upgrade changed history"] = (history_changes, "migration history changed on a same-digest upgrade")
        cases["repeated upgrade changed history"] = (history_changes_on_repeat,
                                                     "migration history changed on a repeated upgrade")
        for name, (doctor, message) in cases.items():
            with self.subTest(name):
                self.fake = FakeCluster()
                self.fake.doctors.append(doctor)
                readings.clear()
                status, report, _ = self.run_main()
                self.assertEqual((status, report["result"]), (1, "failed"))
                if message.startswith("^"):
                    self.assertRegex(report["error"], message)
                else:
                    self.assertIn(message, report["error"])
                self.assert_cleaned_up()


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

    def test_every_reference_uses_a_registry_that_never_resolves(self):
        """RFC 6761 .invalid: a mistaken pull can never reach a real registry."""
        hosts = {smoke.tag_reference(r, "0a1b2c3d").split("/")[0] for r in smoke.ROLES}
        hosts |= {smoke.digest_reference(r, DIGEST[r]).split("/")[0] for r in smoke.ROLES}
        hosts |= {image["registry"] for role, image in smoke.smoke_values(DIGEST, 1)["images"].items()
                  if role in smoke.ROLES}
        self.assertEqual(hosts, {"openmettle-smoke.invalid"})


class ValuesTest(unittest.TestCase):
    def test_values_pin_every_image_by_digest_without_pulling(self):
        values = smoke.smoke_values(DIGEST, worker_replicas=2)
        self.assertEqual(values["images"]["pullPolicy"], "Never")
        for role in smoke.ROLES:
            self.assertEqual(values["images"][role]["digest"], DIGEST[role])
            self.assertEqual(values["database"][role], {"existingSecret": smoke.SECRET[role]})
        self.assertEqual(values["worker"], {"replicas": 2})
        self.assertNotIn("api", values)
        self.assertEqual(values["networkPolicy"], {
            "api": {"ingressFrom": [smoke.database_namespace_peer(smoke.PEER_LABELS)]},
            "database": {"to": [smoke.database_namespace_peer(smoke.POSTGRES_LABELS)]},
        })

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
        # The non-hook objects the chart renders are exactly what the smoke expects in the release.
        rendered = []
        for document in result.stdout.split("\n---"):
            if "helm.sh/hook:" in document:
                continue
            kind = re.search(r"^kind: (\S+)$", document, re.MULTILINE)
            name = re.search(r"^  name: \"?([^\"\n]+)\"?$", document, re.MULTILINE)
            if kind:
                rendered.append(f"{kind.group(1)}/{name.group(1)}")
        self.assertEqual(sorted(rendered), smoke.expected_release_objects())


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

    def test_app_namespace_has_default_deny_network_policy(self):
        policy = self.find("NetworkPolicy", smoke.NAMESPACE_DENY)
        self.assertEqual(policy["metadata"]["namespace"], smoke.APP_NAMESPACE)
        self.assertNotIn("app.kubernetes.io/instance", policy["metadata"]["labels"])
        self.assertEqual(policy["spec"], {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})

    def test_decoy_peer_uses_postgres_image_and_distinct_labels(self):
        peer = self.find("Deployment", smoke.PEER)
        self.assertEqual(peer["metadata"]["namespace"], smoke.DB_NAMESPACE)
        self.assertEqual(peer["spec"]["selector"]["matchLabels"], smoke.PEER_LABELS)
        self.assertNotEqual(smoke.PEER_LABELS, smoke.POSTGRES_LABELS)
        pod_spec = peer["spec"]["template"]["spec"]
        self.assertFalse(pod_spec["automountServiceAccountToken"])
        self.assertFalse(pod_spec["enableServiceLinks"])
        container = pod_spec["containers"][0]
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

    def test_a_real_pull_is_not_already_present(self):
        ref = smoke.digest_reference("api", DIGEST["api"])
        pulled = [event("Pulled", message=f'Successfully pulled image "{ref}" in 1.2s (1.2s including waiting). '
                                          "Image size: 42 bytes.")]
        self.assertEqual(smoke.images_reported_present(pulled, [ref]), [])

    def test_unexpected_resources_flags_devices_and_claims(self):
        pod = {"spec": {"containers": [{"resources": {"requests": {"cpu": "1", "memory": "1Mi"},
                                                      "limits": {"nvidia.com/gpu": "1"}}}],
                        "initContainers": [{"resources": {"claims": [{"name": "gpu"}]}}],
                        "resourceClaims": [{"name": "gpu"}]}}
        self.assertEqual(smoke.unexpected_resources([pod]),
                         ["container.claims", "nvidia.com/gpu", "pod.resourceClaims"])
        clean = {"spec": {"containers": [{"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}}}]}}
        self.assertEqual(smoke.unexpected_resources([clean]), [])

    def test_object_names(self):
        items = [{"kind": "Service", "metadata": {"name": "b"}}, {"kind": "Deployment", "metadata": {"name": "a"}}]
        self.assertEqual(smoke.object_names(items), ["Deployment/a", "Service/b"])


class NetworkPolicyProbeTest(unittest.TestCase):
    def test_probe_plan_covers_allowed_and_denied_paths_with_controls(self):
        plan = smoke.probe_plan(DNS_IP, PEER_IP)
        by_name = {p["name"]: p for p in plan}
        self.assertEqual(len(by_name), len(plan))
        connect_probes = [p for p in plan if p["expect"] == "connect"]
        deny_probes = [p for p in plan if p["expect"] == "deny"]
        self.assertGreaterEqual(len(connect_probes), 5)
        self.assertGreaterEqual(len(deny_probes), 5)
        for p in deny_probes:
            control = by_name.get(p["control"])
            self.assertIsNotNone(control, p["name"])
            self.assertEqual(control["expect"], "connect", p["name"])
        for p in plan:
            # Host and port are positional args, never interpolated into the bash script string.
            script = p["command"][4]
            self.assertNotIn(DNS_IP, script)
            self.assertNotIn(PEER_IP, script)
            self.assertNotIn(DATABASE_HOST, script)
            self.assertNotIn(API_HOST, script)

    def test_probe_outcome_classifies_tcp_and_http_results(self):
        self.assertEqual(smoke.probe_outcome(0, "", "", http=False), "connected")
        self.assertEqual(smoke.probe_outcome(smoke.TIMEOUT_EXIT, "", "", http=False), "timeout")
        for err in ("Connection refused", "No route to host", "Network is unreachable"):
            with self.subTest(err=err):
                self.assertEqual(smoke.probe_outcome(1, "", f"bash: connect: {err}\n", http=False), "rejected")
        # kubectl Go errors use lowercase "connection refused" and must stay inconclusive.
        for err in ("", "error: unable to upgrade connection", "dial tcp 127.0.0.1:6443: connect: connection refused"):
            with self.subTest(inconclusive=err):
                self.assertEqual(smoke.probe_outcome(1, "", err, http=False), "inconclusive")
        self.assertEqual(smoke.probe_outcome(0, "HTTP/1.1 200 OK\r\n", "", http=True), "connected")
        self.assertEqual(smoke.probe_outcome(0, "HTTP/1.0 200 OK\r\n", "", http=True), "connected")
        self.assertEqual(smoke.probe_outcome(0, "HTTP/1.1 503 Service Unavailable\r\n", "", http=True),
                         "unexpected-response")
        self.assertEqual(smoke.probe_outcome(0, "", "", http=True), "unexpected-response")

    def test_evaluate_probes_accepts_timeouts_and_rejections(self):
        results = [
            {"name": "ctrl", "expect": "connect", "control": None, "outcome": "connected"},
            {"name": "drop", "expect": "deny", "control": "ctrl", "outcome": "timeout"},
            {"name": "reject", "expect": "deny", "control": "ctrl", "outcome": "rejected"},
        ]
        smoke.evaluate_probes(results)

    def test_evaluate_probes_failures(self):
        with self.assertRaisesRegex(smoke.SmokeFailure, "no NetworkPolicy probes ran"):
            smoke.evaluate_probes([])
        with self.assertRaisesRegex(smoke.SmokeFailure, "NetworkPolicy is not enforced.*leak"):
            smoke.evaluate_probes([
                {"name": "ctrl", "expect": "connect", "control": None, "outcome": "connected"},
                {"name": "leak", "expect": "deny", "control": "ctrl", "outcome": "connected"},
            ])
        with self.assertRaisesRegex(smoke.SmokeFailure, "allowed path failed: db \(timeout\)"):
            smoke.evaluate_probes([
                {"name": "db", "expect": "connect", "control": None, "outcome": "timeout"},
            ])
        with self.assertRaisesRegex(smoke.SmokeFailure, "its control did not connect, so the denial is not evidence"):
            smoke.evaluate_probes([
                {"name": "ctrl", "expect": "connect", "control": None, "outcome": "timeout"},
                {"name": "deny", "expect": "deny", "control": "ctrl", "outcome": "timeout"},
            ])
        with self.assertRaisesRegex(smoke.SmokeFailure, "has no control probe"):
            smoke.evaluate_probes([
                {"name": "deny", "expect": "deny", "control": "missing", "outcome": "timeout"},
            ])
        with self.assertRaisesRegex(smoke.SmokeFailure, "was inconclusive \(inconclusive\)"):
            smoke.evaluate_probes([
                {"name": "ctrl", "expect": "connect", "control": None, "outcome": "connected"},
                {"name": "deny", "expect": "deny", "control": "ctrl", "outcome": "inconclusive"},
            ])
        with self.assertRaisesRegex(smoke.SmokeFailure, "unexpected expectation"):
            smoke.evaluate_probes([
                {"name": "weird", "expect": "ignore", "control": None, "outcome": "timeout"},
            ])

    def test_running_pod_ip_selects_first_running_non_terminating_pod(self):
        pods = [
            {"metadata": {"name": "a-pending"}, "status": {"phase": "Pending", "podIP": "10.0.0.1"}},
            {"metadata": {"name": "b-term", "deletionTimestamp": "2026-11-19T10:00:00Z"},
             "status": {"phase": "Running", "podIP": "10.0.0.2"}},
            {"metadata": {"name": "c-no-ip"}, "status": {"phase": "Running"}},
            {"metadata": {"name": "z-running"}, "status": {"phase": "Running", "podIP": "10.0.0.9"}},
            {"metadata": {"name": "d-running"}, "status": {"phase": "Running", "podIP": "10.0.0.4"}},
        ]
        self.assertEqual(smoke.running_pod_ip(pods, "CoreDNS"), "10.0.0.4")
        with self.assertRaisesRegex(smoke.SmokeFailure, "no Running CoreDNS pod with an IP"):
            smoke.running_pod_ip(pods[:3], "CoreDNS")


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

    def test_redacts_before_truncating(self):
        """A password straddling the cut must not leave its tail in the output."""
        password = PASSWORDS["api"]
        text = "A" * 100 + password + "B" * (2000 - 16)
        self.assertEqual(len(text) - 2000, 116)  # the cut falls inside the password
        tail = smoke.redacted_tail(text, PASSWORDS.values(), 2000)
        self.assertNotIn(password[16:], tail)
        self.assertEqual(len(tail), 2000)

    def test_ctr_image_names(self):
        self.assertEqual(smoke.ctr_image_names(CTR_LISTING), {
            f"import-2026-11-19@{DIGEST['api']}", *(f"openmettle-smoke.invalid/openmettle/{r}:smoke-0a1b2c3d"
                                                   for r in smoke.ROLES)})

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

    def test_pins(self):
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


class CriContainerImageIdTests(unittest.TestCase):
    ID = "sha256:" + "a" * 64

    def test_reads_the_image_id_of_the_single_container(self):
        for container in ({"imageId": self.ID}, {"image": {"image": self.ID}},
                          {"imageRef": self.ID}, {"image": {"image": "repo:tag"}, "imageRef": self.ID}):
            with self.subTest(container=container):
                self.assertEqual(smoke.parse_cri_container_image_id(
                    json.dumps({"containers": [container]})), self.ID)

    def test_refuses_missing_ambiguous_or_malformed_output(self):
        for output in ("not json", json.dumps({}), json.dumps({"containers": []}),
                       json.dumps({"containers": [{"imageId": self.ID}, {"imageId": self.ID}]}),
                       json.dumps({"containers": [{"imageRef": "docker.io/library/import@sha256:" + "b" * 64}]})):
            with self.subTest(output=output[:40]):
                with self.assertRaises(smoke.SmokeFailure):
                    smoke.parse_cri_container_image_id(output)


if __name__ == "__main__":
    unittest.main()
