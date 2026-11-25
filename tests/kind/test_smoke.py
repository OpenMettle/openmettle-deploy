"""Cluster-free tests for the kind smoke harness (tests/kind/smoke.py).

They cover guards, digest parsing, fixture and values derivation, event evaluation, the
published summary and the orchestration (ordering, refusals, cleanup, redaction and every scenario
assertion) against a recording fake cluster. They do not create a cluster and are not evidence that
the chart installs; only a `kind-smoke` workflow run is. Set OPENMETTLE_CORE_DIR to a directory holding core's
tests/kubernetes/qualify.py at CORE_COMMIT to also exercise the imported core guards. CI does.
"""
import base64
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DIGEST = {role: "sha256:" + str(i) * 64 for i, role in enumerate(smoke.ROLES, start=1)}
PASSWORDS = {"admin": "a" * 32, "api": "b" * 32, "worker": "c" * 32, "migrate": "d" * 32, "issuance": "g" * 32,
             "gateway": "h" * 32,
             "auth_cursor_key": base64.b64encode(b"c" * 32).decode("ascii"),
             "auth_login_key": base64.b64encode(b"k" * 32).decode("ascii")}
# `helm get hooks` for the release: the migrate ServiceAccount, NetworkPolicy and Job, abridged.
# The shape smoke_catalog() and smoke_inference_document() rely on in core's
# tests/fixtures/conversation-catalog-v1.json; the real fixture is read from the pinned core checkout.
_PIN_A = {"provider": "synthetic-provider", "revision": "profile-a/1", "checkpoint": "fixture-a",
          "template": "template/1", "parser": "parser/1", "runtime": "runtime/1", "gateway": "gateway/1"}
_PIN_B = {**_PIN_A, "provider": "synthetic-other", "revision": "profile-b/1", "checkpoint": "fixture-b"}
CATALOG_FIXTURE = {"version": 1, "revision": "catalog/1",
                   "models": {"a": {"pin": _PIN_A, "output_limit": 4096}, "b": {"pin": _PIN_B}},
                   "presets": {"study": {"model": "a", "revision": "study/1"}}}
HOOKS = f"""---
# Source: openmettle-core/templates/migrate-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: {smoke.FULLNAME}-migrate
spec:
  template:
    spec:
      containers:
        - name: migrate
          env:
            - name: OPENMETTLE_MIGRATE_DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: "{smoke.SECRET['migrate']}"
                  key: "url"
"""


def issuance_env():
    """The api container's issuance env as the API server returns it (optional unset)."""
    return [{"name": smoke.ISSUANCE_URL_ENV,
             "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["issuance"], "key": "url"}}},
            {"name": smoke.ISSUANCE_POOL_ENV, "value": smoke.ISSUANCE_POOL}]
CORE_DIR = os.environ.get("OPENMETTLE_CORE_DIR")
HELM = os.environ.get("HELM", "helm")

# Representative `ctr --namespace=k8s.io images ls` output after `kind load docker-image`.
CTR_LISTING = f"""REF                                                        TYPE                                    DIGEST {' ' * 60}SIZE     PLATFORMS   LABELS
import-2026-11-19@{DIGEST['api']} application/vnd.oci.image.index.v1+json {DIGEST['api']} 40.1 MiB linux/amd64 io.cri-containerd.image=managed
openmettle-smoke.invalid/openmettle/api:smoke-0a1b2c3d application/vnd.oci.image.index.v1+json {DIGEST['api']} 40.1 MiB linux/amd64 io.cri-containerd.image=managed
openmettle-smoke.invalid/openmettle/worker:smoke-0a1b2c3d application/vnd.oci.image.index.v1+json {DIGEST['worker']} 40.0 MiB linux/amd64 io.cri-containerd.image=managed
openmettle-smoke.invalid/openmettle/migrate:smoke-0a1b2c3d application/vnd.oci.image.index.v1+json not-a-digest 39.0 MiB linux/amd64 -
openmettle-smoke.invalid/openmettle/gateway:smoke-0a1b2c3d application/vnd.oci.image.index.v1+json {DIGEST['gateway']} 40.2 MiB linux/amd64 io.cri-containerd.image=managed
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


def session_hash(cookie: str) -> tuple:
    """(session id, secret hash hex) of a browser cookie, framed as core sessions.rs, written here
    independently of smoke.session_credential."""
    session_id, _, secret = cookie.partition(".")
    raw = base64.urlsafe_b64decode(secret + "=")
    framed = b"openmettle/session-secret/1\x00"
    for field in (session_id.encode(), raw):
        framed += struct.pack(">Q", len(field)) + field
    return session_id, hashlib.sha256(framed).hexdigest()


def parse_form(content_type: str, body: bytes) -> dict:
    """{part name: (filename, media type, bytes)} of a multipart/form-data body."""
    boundary = content_type.partition("multipart/form-data; boundary=")[2].encode()
    assert boundary and body.endswith(b"--" + boundary + b"--\r\n"), body
    parts = {}
    for chunk in body.split(b"--" + boundary)[1:-1]:
        assert chunk.startswith(b"\r\n") and chunk.endswith(b"\r\n"), chunk
        head, _, data = chunk[2:-2].partition(b"\r\n\r\n")
        name = re.search(rb'name="([^"]+)"', head).group(1).decode()
        filename = re.search(rb'filename="([^"]+)"', head)
        media = re.search(rb"Content-Type: (\S+)", head).group(1).decode()
        parts[name] = (filename and filename.group(1).decode(), media, data)
    return parts


class FakeArtifacts:
    """The /v1 artifact routes over a fake port-forward: session check, idempotent multipart uploads,
    revision metadata and single byte ranges. `doctor(method, path, headers, response)` may replace
    a response."""

    def __init__(self, cluster):
        self.cluster = cluster
        self.calls = []
        self.uploads = {}
        self.revisions = {}  # revision id -> (document, payload)
        self.runs = {}  # idempotency key -> (request body, run document)
        self.standin_records = []
        self.doctor = None

    @property
    def runs_state(self):
        states = {}
        for _, run in self.runs.values():
            states[run["state"]] = states.get(run["state"], 0) + 1
        return states

    @staticmethod
    def reply(status, document, content_type="application/json", extra=None):
        headers = {"openmettle-api-version": "1.0", "cache-control": "no-store", "content-type": content_type,
                   **(extra or {})}
        return status, headers, json.dumps(document).encode()

    def problem(self, status, code, extra=None):
        return self.reply(status, {"type": "about:blank", "title": "t", "status": status, "detail": "d",
                                   "code": code, "request_id": "11111111-1111-4111-8111-111111111111"},
                          "application/problem+json", extra)

    def __call__(self, port, method, path, headers, body=b""):
        self.calls.append((port, method, path, dict(headers)))
        if port == smoke.STANDIN_PORT and (method, path) == ("GET", "/_recorded"):
            response = (200, {"content-type": "application/json"}, json.dumps(self.standin_records).encode())
            return (self.doctor and self.doctor(method, path, headers, response)) or response
        cookie = headers.get("Cookie", "").partition(f"{smoke.SESSION_COOKIE}=")[2]
        if cookie:
            self.cluster.passwords["session"] = cookie
        if not self.cluster.profile_enabled:
            response = (404, {}, b"")  # without auth no /v1 route is mounted
        elif self.cluster.session is None or headers.get("Origin") != smoke.AUTH_ORIGIN \
                or session_hash(cookie) != self.cluster.session:
            response = self.problem(401, "unauthenticated")
        else:
            response = self.route(method, path, headers, body)
        return (self.doctor and self.doctor(method, path, headers, response)) or response

    def route(self, method, path, headers, body):
        route, _, query = path.partition("?")
        segments = route.split("/")[1:]
        if method == "POST" and segments[:2] == ["v1", "artifacts"] and segments[3:] in ([], ["revisions"]):
            form = parse_form(headers["Content-Type"], body)
            request = (route, query, form["file"], form["metadata"][2])
            key = (route, headers["Idempotency-Key"])
            if key in self.uploads:
                previous, document = self.uploads[key]
                return self.reply(201, document) if previous == request else self.problem(409, "idempotency_conflict")
            filename, media, payload = form["file"]
            artifact = segments[2] if len(segments) > 2 else f"00000000-0000-4000-8000-{len(self.uploads) + 1:012x}"
            number = 1 + sum(d["artifact_id"] == artifact for d, _ in self.revisions.values())
            document = {"artifact_id": artifact, "revision_id": f"00000000-0000-4000-9000-{len(self.revisions) + 1:012x}",
                        "revision": str(number), "scope_kind": "personal",
                        "scope_id": "00000000-0000-4000-a000-000000000001", "project_id": None,
                        "media_type": media, "size_bytes": str(len(payload)),
                        "sha256": hashlib.sha256(payload).hexdigest(), "display_name": filename,
                        "state": "active", "created_at": "2026-11-20T10:00:00Z"}
            self.uploads[key] = (request, document)
            self.revisions[document["revision_id"]] = (document, payload)
            return self.reply(201, document)
        if method == "GET" and len(segments) in (5, 6) and segments[3] == "revisions" \
                and segments[4] in self.revisions:
            document, payload = self.revisions[segments[4]]
            if len(segments) == 5:
                return self.reply(200, document)
            total = len(payload)
            content = {"openmettle-api-version": "1.0", "cache-control": "no-store", "content-type": document["media_type"],
                       "accept-ranges": "bytes", "x-content-type-options": "nosniff",
                       "content-disposition": f"attachment; filename*=UTF-8''{document['display_name']}"}
            first, _, last = headers.get("Range", "").removeprefix("bytes=").partition("-")
            if not first:
                return 200, {**content, "content-length": str(total)}, payload
            first, last = int(first), min(int(last or total - 1), total - 1)
            if first >= total:
                return self.problem(416, "range_not_satisfiable", {"content-range": f"bytes */{total}"})
            return 206, {**content, "content-length": str(last - first + 1),
                         "content-range": f"bytes {first}-{last}/{total}"}, payload[first:last + 1]
        if (method, route) == ("GET", "/v1/models"):
            return self.reply(200, {"items": [{"model_id": m} for m in ("a", "b")], "page_info": {}})
        if (method, route) == ("POST", "/v1/conversations") and json.loads(body) == {}:
            return self.reply(201, {"conversation_id": "00000000-0000-4000-b000-000000000001",
                                    "branch_id": "00000000-0000-4000-b000-000000000002",
                                    "scope_id": "00000000-0000-4000-a000-000000000001"})
        if (method, route) == ("POST", "/v1/runs") and headers.get("Content-Type") == "application/json":
            request = json.loads(body)
            key = headers["Idempotency-Key"]
            if key in self.runs:
                previous, run = self.runs[key]
                return self.reply(200, run) if previous == request else self.problem(409, "idempotency_conflict")
            if request["proposal"]["selection"] != {"preset": smoke.CATALOG_PRESET}:
                return self.problem(400, "validation")
            run = {"run_id": f"00000000-0000-4000-c000-{len(self.runs) + 1:012x}",
                   "conversation_id": request["conversation_id"],
                   "state": "succeeded" if key.startswith("kind-smoke-gw-run-") else "queued"}
            if key.startswith("kind-smoke-gw-run-"):
                req_id = f"00000000-0000-4000-d000-{len(self.standin_records) + 1:012x}"
                self.cluster.gateway_settlements[run["run_id"]] = req_id
                self.standin_records.append({
                    "headers": {"x-request-id": [req_id], "content-type": ["application/json"]},
                    "body": {"model": smoke.CATALOG_MODEL, "cache_salt": "a" * 64},
                })
            self.runs[key] = (request, run)
            return self.reply(201, run)
        if method == "GET" and len(segments) == 3 and segments[:2] == ["v1", "runs"]:
            for _, run in self.runs.values():
                if run["run_id"] == segments[2]:
                    return self.reply(200, run)
        if method == "GET" and len(segments) == 6 and segments[:2] == ["v1", "conversations"] \
                and segments[3] == "branches" and segments[5] == "messages":
            return self.reply(200, {"items": [{
                "role": "assistant",
                "parts": [{"kind": "text", "text": smoke.STANDIN_EXPECTED_CONTENT}],
                "input_count": str(smoke.STANDIN_EXPECTED_PROMPT_TOKENS),
                "output_count": str(smoke.STANDIN_EXPECTED_COMPLETION_TOKENS),
            }]})
        if method == "POST" and segments[:2] == ["v1", "runs"] and segments[3:] == ["cancel"]:
            for _, run in self.runs.values():
                if run["run_id"] == segments[2]:
                    run["state"] = "cancelled"
                    return self.reply(200, run)
        return self.problem(404, "not_found")


RUN_ID = "00000000-0000-4000-8000-000000000001"


class IngressResponse(io.BytesIO):
    def __init__(self, status, body=b"", *, stream=False, delays=None):
        super().__init__(body)
        self.status = status
        self.stream = stream
        self.delays = delays or {}

    def getheaders(self):
        headers = {"Cache-Control": "no-store", "OpenMettle-API-Version": "1.0", "Content-Type": "application/json"}
        if self.stream:
            headers.update({"Content-Type": "text/event-stream", "X-Accel-Buffering": "no"})
        return headers.items()

    def readline(self, size=-1):
        smoke.time.sleep(self.delays.get(self.tell(), 0))
        return super().readline(size)


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
        self.profile_enabled = False
        self.gateway_mode = None
        self.inference_fixtures_applied = False
        self.artifacts_pvc_created = False
        self.healthz = 200
        self.readyz = 200
        self.auth_http_overrides = {}
        self.run_admission = ["t" if expected else "f" for _, expected in smoke.RUN_ADMISSION_CHECKS]
        self.gateway_schema = ["t" if expected else "f" for _, expected in smoke.GATEWAY_SCHEMA_CHECKS]
        self.gateway_settlements = {}
        self.fresh_bootstrap = "t|t"
        self.session = None  # (session id, secret hash hex) as seeded
        self.replaced = False
        self.admitted_at = None
        self.resumes = []
        self.artifacts = FakeArtifacts(self)
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
            Runner=runner, http_get=fake.http_get,
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
        if args[:1] == ["openssl"]:
            if "-out" in args:
                Path(args[args.index("-out") + 1]).write_text(
                    "-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n", encoding="utf-8")
            return 0, "", ""
        if args[:2] == ["docker", "build"] and "admission-export" in args:
            return 0, "", ""
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
            if role == smoke.STANDIN:
                return 0, "", ""
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

    def http_get(self, _port, path):
        if path in self.auth_http_overrides:
            return self.auth_http_overrides[path]
        if path == "/healthz":
            return self.healthz, ""
        if path == "/readyz":
            return self.readyz, ""
        if not self.profile_enabled:
            return 404, ""
        if path == "/auth/session":
            return 403, "session origin refused\n"
        if path == "/auth/native/session":
            return 403, "native sign-in refused\n"
        if path == "/v1/capabilities":
            return 401, json.dumps({
                "type": "about:blank",
                "title": "Unauthorized",
                "status": 401,
                "detail": "A valid OpenMettle application session is required.",
                "code": "unauthenticated",
                "request_id": "11111111-1111-4111-8111-111111111111",
            })
        return 404, ""

    def ingress_get(self, port, context, path, headers, *, timeout=smoke.HTTP_TIMEOUT, host=smoke.INGRESS_HOST):
        assert port == 8443
        if host == smoke.GATEWAY_TLS_HOST:
            assert path == "/readyz"
            return IngressResponse(200)
        if path == "/readyz":
            return IngressResponse(200)
        assert headers["Cookie"] == f"{smoke.SESSION_COOKIE}={self.passwords['session']}"
        assert headers["Origin"] == smoke.AUTH_ORIGIN
        created = {"run_id": RUN_ID, "sequence": "1", "type_version": 1, "type": "run.created",
                   "data": {}, "occurred_at": "2026-11-21T12:00:00Z"}
        expired = {**created, "sequence": "2", "type": "run.failed", "data": {"reason": "queue_expired"}}
        if path == f"/v1/runs/{RUN_ID}":
            cursor = "end" if self.expired else "start"
            return IngressResponse(200, json.dumps({"run_id": RUN_ID, "state": "failed" if self.expired else "queued",
                                                   "terminal": expired if self.expired else None,
                                                   "resume_cursor": cursor, "last_sequence": "2" if self.expired else "1"}).encode())
        assert path == f"/v1/runs/{RUN_ID}/events"
        after = headers.get("Last-Event-ID")
        self.resumes.append((self.replaced, after))
        beat = b": heartbeat\n\n"
        def frame(cursor, event):
            return f"id: {cursor}\ndata: {json.dumps(event)}\n\n".encode()
        if after == "end" and self.expired:
            return IngressResponse(204)
        if after == "start":
            if self.replaced:
                return IngressResponse(200, beat + frame("end", expired), stream=True,
                                       delays={len(beat): smoke.QUEUE_TIMEOUT_SECONDS - 30})
            return IngressResponse(200, beat * 3, stream=True, delays={len(beat): 15, 2 * len(beat): 15})
        assert after is None
        return IngressResponse(200, beat + frame("start", created) + (frame("end", expired) if self.expired else b""),
                               stream=True)

    @property
    def expired(self):
        return self.admitted_at is not None and smoke.time.monotonic() >= self.admitted_at + smoke.QUEUE_TIMEOUT_SECONDS

    def database(self, sql):
        """`psql` on stdin in the fixture database: migration history, migrations 19/20/37 grants,
        fresh-install markers, session seed and settled gateway requests."""
        if "openmettle._sqlx_migrations" in sql:
            return 0, "".join(f"{v}|t|{v:02x}|2026-11-19 10:01:00\n" for v in range(17, 38)), ""
        if sql == smoke.FRESH_BOOTSTRAP_SQL:
            return 0, self.fresh_bootstrap + "\n", ""
        if "xmin::text" in sql:
            state, terminals = ("failed", 1) if self.expired else ("queued", 0)
            return 0, f"{RUN_ID}|{state}|12|1234|t|{terminals}\n", ""
        if sql == smoke.run_admission_sql():
            return 0, "|".join(self.run_admission) + "\n", ""
        if sql == smoke.gateway_schema_sql():
            return 0, "|".join(self.gateway_schema) + "\n", ""
        if "FROM openmettle.gateway_requests q" in sql:
            match = re.search(r"WHERE q\.run_id = '([0-9a-f-]+)'::uuid", sql)
            req_id = self.gateway_settlements.get(match.group(1)) if match else None
            if not req_id:
                return 0, "", ""
            return 0, (f"{req_id}|handed_off|t|t|1|{smoke.STANDIN_EXPECTED_PROMPT_TOKENS}|"
                       f"{smoke.STANDIN_EXPECTED_COMPLETION_TOKENS}|t|settled|0|"
                       f"{smoke.STANDIN_EXPECTED_SETTLED_UNITS}\n"), ""
        seeded = re.search(r"SELECT '([A-Za-z0-9_-]{43})', decode\('([0-9a-f]{64})', 'hex'\)", sql)
        if seeded and "INSERT INTO openmettle.local_sessions" in sql and "personal_limit_bytes" in sql \
                and "VALUES ('personal', 'usage_tokens', " in sql:
            self.session = seeded.groups()
            return 0, "", ""
        self.unknown.append(["psql", sql])
        return 1, "", "unmodelled SQL"

    def pod(self, component, index):
        name = f"{smoke.FULLNAME}-{component}-{index}"
        if component == smoke.GATEWAY_COMPONENT:
            container = {"name": "gateway", "imagePullPolicy": "Never",
                         "image": smoke.digest_reference("gateway", DIGEST["gateway"]),
                         "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}},
                         "env": [
                             {"name": "OPENMETTLE_GATEWAY_DATABASE_URL",
                              "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["gateway"], "key": "url"}}},
                             {"name": "OPENMETTLE_GATEWAY_MODEL", "value": smoke.CATALOG_MODEL},
                             {"name": "OPENMETTLE_GATEWAY_CACHE_MODE", "value": "scoped"},
                         ]}
            spec = {"containers": [container], "securityContext": {"runAsNonRoot": True}}
            return {"metadata": {"name": name, "uid": f"{name}-{self.gateway_mode}",
                                 "labels": {"app.kubernetes.io/instance": smoke.RELEASE,
                                            "app.kubernetes.io/component": component}},
                    "spec": spec,
                    "status": {"conditions": [{"type": "Ready", "status": "True"}],
                               "containerStatuses": [{"restartCount": 0, "containerID": f"containerd://cid-gateway-{index}",
                                                      "imageID": f"import-2026-11-19@{DIGEST['gateway']}"}]}}
        container = {"name": component, "imagePullPolicy": "Never",
                     "image": smoke.digest_reference(component, DIGEST[component]),
                     "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}}}
        spec = {"containers": [container]}
        if self.profile_enabled:
            spec["securityContext"] = {"fsGroup": 65532}
            spec["volumes"] = [{"name": "artifacts",
                                "persistentVolumeClaim": {"claimName": smoke.ARTIFACTS_CLAIM}}]
            container["volumeMounts"] = [{"name": "artifacts", "mountPath": smoke.ARTIFACTS_MOUNT_PATH}]
            container["env"] = [{"name": f"OPENMETTLE_{component.upper()}_ARTIFACTS_DIR",
                                 "value": smoke.ARTIFACTS_MOUNT_PATH}]
            if component == "api":
                spec["volumes"] += [
                    {"name": "auth-config", "configMap": {
                        "name": smoke.AUTH_CONFIG_MAP, "defaultMode": 420,
                        "items": [{"key": "auth.json", "path": "auth.json"},
                                  {"key": smoke.AUTH_CATALOG_KEY, "path": smoke.AUTH_CATALOG_KEY}]}},
                    {"name": "auth-login-keys", "secret": {
                        "secretName": smoke.AUTH_LOGIN_KEYS_SECRET,
                        "defaultMode": smoke.AUTH_SECRET_MODE}},
                ]
                container["volumeMounts"] += [
                    {"name": "auth-config", "mountPath": smoke.AUTH_CONFIG_DIR, "readOnly": True},
                    {"name": "auth-login-keys", "mountPath": smoke.AUTH_KEYS_DIR, "readOnly": True},
                ]
                container["env"] += [{"name": "OPENMETTLE_API_AUTH_CONFIG",
                                      "value": smoke.AUTH_CONFIG_PATH}, *issuance_env()]
            if component == "worker" and self.gateway_mode is not None:
                cm_name = (smoke.INFERENCE_TLS_CONFIG_MAP if self.gateway_mode == "tls"
                           else smoke.INFERENCE_PLAIN_CONFIG_MAP)
                spec["volumes"].append({"name": "inference-config", "configMap": {
                    "name": cm_name, "items": [{"key": "inference.json", "path": "inference.json"},
                                               {"key": smoke.AUTH_CATALOG_KEY, "path": smoke.AUTH_CATALOG_KEY}]}})
                container["volumeMounts"].append({"name": "inference-config", "mountPath": smoke.INFERENCE_CONFIG_DIR,
                                                  "readOnly": True})
                if self.gateway_mode == "tls":
                    spec["volumes"].append({"name": "inference-ca", "configMap": {
                        "name": smoke.INFERENCE_CA_CONFIG_MAP, "items": [{"key": "ca.crt", "path": "ca.crt"}]}})
                    container["volumeMounts"].append({"name": "inference-ca", "mountPath": smoke.INFERENCE_CA_DIR,
                                                      "readOnly": True})
                container["env"] += [
                    {"name": "OPENMETTLE_WORKER_POLL_MS", "value": "100"},
                    {"name": "OPENMETTLE_WORKER_INFERENCE_CONFIG", "value": smoke.INFERENCE_CONFIG_PATH},
                    {"name": "OPENMETTLE_WORKER_RUN_SLOTS", "value": "2"},
                    {"name": "OPENMETTLE_WORKER_LEASE_MS", "value": "30000"},
                    {"name": "OPENMETTLE_WORKER_EXECUTION_TIMEOUT_MS", "value": "60000"},
                    {"name": "OPENMETTLE_WORKER_EXECUTING_PER_ACTOR", "value": "2"},
                    {"name": "OPENMETTLE_WORKER_EXECUTING_PER_SCOPE", "value": "4"},
                ]
        return {"metadata": {"name": name, "uid": f"{name}-{self.replaced}", "labels": {"app.kubernetes.io/instance": smoke.RELEASE,
                                                      "app.kubernetes.io/component": component}},
                "spec": spec,
                "status": {"conditions": [{"type": "Ready", "status": "True"}],
                           "containerStatuses": [{"restartCount": 0, "containerID": f"containerd://cid-{component}-"
                                                                                    f"{index}",
                                                  "imageID": f"import-2026-11-19@{DIGEST[component]}"}]}}

    def probe(self, args):
        """`kubectl exec deployment/<workload> ... -- timeout N bash -c <script> <host> <port> [path]`.

        Models the chart's policies under the namespace deny-all: release pods reach only configured
        egress peers; only configured ingress peers reach API or gateway; database-namespace pods are unrestricted.
        """
        workload = args[1].split("/", 1)[1]
        command = args[args.index("--") + 1:]
        host, port, http = command[5], int(command[6]), len(command) > 7
        gw_host = f"{smoke.GATEWAY_WORKLOAD}.{smoke.APP_NAMESPACE}.svc.cluster.local"
        if (host, port) == ("127.0.0.1", 8082) and workload == smoke.GATEWAY_WORKLOAD:
            allowed = True
        elif (host, port) == (gw_host, 8082):
            allowed = workload == f"{smoke.FULLNAME}-worker" and self.gateway_mode == "plain"
        elif (host, port) == (smoke.GATEWAY_TLS_HOST, 8443):
            allowed = (not workload.startswith(smoke.FULLNAME)) or (
                workload == f"{smoke.FULLNAME}-worker" and self.gateway_mode == "tls")
        elif workload.startswith(smoke.FULLNAME):
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
        if args[:2] == ["apply", "-f"] and args[-1].endswith("/ingress.yaml"):
            return ok("configured")
        if args[:3] == ["apply", "--filename", "-"]:
            for item in json.loads(input)["items"]:
                if item["kind"] == "Namespace":
                    self.namespaces[item["metadata"]["name"]] = item["metadata"]["labels"]
                if item["metadata"]["name"] == "postgres-fixture":
                    self.passwords["admin"] = item["stringData"]["admin-password"]
                if item["kind"] == "Secret" and "url" in item.get("stringData", {}):
                    role = next(r for r in smoke.DB_LOGINS if smoke.SECRET[r] == item["metadata"]["name"])
                    self.passwords[role] = item["stringData"]["url"].split(":")[2].split("@")[0]
                if item["kind"] == "Secret" and item["metadata"]["name"] == smoke.AUTH_LOGIN_KEYS_SECRET:
                    self.passwords["auth_cursor_key"] = item["data"]["cursor.key"]
                    self.passwords["auth_login_key"] = item["data"]["active.key"]
                if item["kind"] == "ConfigMap" and item["metadata"]["name"] == smoke.INFERENCE_PLAIN_CONFIG_MAP:
                    self.inference_fixtures_applied = True
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
        if namespace == smoke.APP_NAMESPACE and args[:1] == ["exec"] and smoke.AUTH_CHECK_BINARY in args:
            return 0, smoke.AUTH_CHECK_OK, ""
        if namespace == smoke.APP_NAMESPACE and args[:1] == ["exec"] and "stat" in args:
            return 0, "".join(f"{smoke.ARTIFACTS_MOUNT_PATH}/{d}|directory|2700|65532\n"
                              for d in smoke.ARTIFACT_SUBDIRS), ""
        if namespace == smoke.APP_NAMESPACE:
            if args[:3] == ["create", "secret", "tls"]:
                return ok("created")
            if args[:3] == ["rollout", "restart", f"deployment/{smoke.FULLNAME}-api"]:
                self.replaced = True
                return ok("restarted")
        if namespace == smoke.DB_NAMESPACE:
            if args[:2] == ["get", "pods"] and selector == "app.kubernetes.io/name=postgres":
                return listing([self.running_pod("postgres-0", "10.0.0.1")])
            if args[:1] == ["cp"] and args[-1] == "postgres-0:/tmp/kind-admit":
                return ok("copied")
            if args[:1] == ["exec"] and "/tmp/kind-admit" in args:
                assert input.startswith("postgres://openmettle_api:") and args[-2] == smoke.RUN_KEY
                self.admitted_at = smoke.time.monotonic()
                return ok(RUN_ID)
            if args[:2] == ["rollout", "status"]:
                return 0, "rolled out", ""
            if args[:1] == ["exec"]:
                return self.database(input)
            if args[:2] == ["get", "events"]:
                return ok("No events")
            if args[:2] == ["get", "pods"] and selector == f"app.kubernetes.io/name={smoke.PEER}":
                return listing([self.running_pod(f"{smoke.PEER}-0", PEER_IP)])
        if namespace == "kube-system" and args[:2] == ["get", "pods"] and selector == smoke.DNS_SELECTOR:
            return listing([self.running_pod("coredns-1", DNS_IP), self.running_pod("coredns-0", DNS_IP)])
        if args[:2] == ["rollout", "status"]:
            return 0, "rolled out", ""
        if args[:2] == ["get", "networkpolicies"]:
            return listing(self.network_policies())
        if args[:2] == ["get", "pvc,pdb"]:
            return ok("NAME\n")
        if args[:3] == ["get", "poddisruptionbudget", smoke.API_PDB]:
            healthy = self.replicas["api"]
            return ok({"metadata": {"name": smoke.API_PDB},
                       "spec": {"maxUnavailable": 1, "unhealthyPodEvictionPolicy": "AlwaysAllow"},
                       "status": {"currentHealthy": healthy, "disruptionsAllowed": max(0, healthy - 1)}})
        if args[:3] == ["get", "persistentvolumeclaim", smoke.ARTIFACTS_CLAIM]:
            return ok({"metadata": {"name": smoke.ARTIFACTS_CLAIM,
                                    "annotations": {"helm.sh/resource-policy": "keep"}},
                       "status": {"phase": "Bound"}})
        if args[:2] == ["get", "persistentvolumeclaims"]:
            names = [f"PersistentVolumeClaim/{smoke.ARTIFACTS_CLAIM}"] if self.artifacts_pvc_created else []
            return listing(self.items(names))
        if args[:2] == ["get", "deployment"]:
            component = (smoke.GATEWAY_COMPONENT if args[2] == smoke.GATEWAY_WORKLOAD
                         else args[2].rsplit("-", 1)[1])
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
        if args[:2] in (["get", "secrets"], ["get", "configmaps,secrets,networkpolicies"],
                        ["get", "endpointslices"]):
            if selector == smoke.RUN_LABEL:
                owned = [f"Secret/{smoke.AUTH_LOGIN_KEYS_SECRET}",
                         *(f"Secret/{smoke.SECRET[r]}" for r in smoke.DB_LOGINS)]
                if args[1] == "configmaps,secrets,networkpolicies":
                    owned.extend([f"ConfigMap/{smoke.AUTH_CONFIG_MAP}",
                                  f"NetworkPolicy/{smoke.NAMESPACE_DENY}"])
                    if self.inference_fixtures_applied:
                        owned.extend([f"ConfigMap/{smoke.INFERENCE_PLAIN_CONFIG_MAP}",
                                      f"ConfigMap/{smoke.INFERENCE_TLS_CONFIG_MAP}",
                                      f"ConfigMap/{smoke.INFERENCE_CA_CONFIG_MAP}"])
                return listing(self.items(owned))
            return listing([])
        if args[:1] == ["logs"]:
            if "--container" in args:
                role = args[args.index("--container") + 1]
                lines = [json.dumps({"timestamp": "2026-11-19T10:04:00.000000Z", "level": "INFO",
                                     "event": "process.started", "role": role})]
                if role == "api":
                    lines.append(json.dumps({
                        "timestamp": "2026-11-19T10:04:01.000000Z", "level": "DEBUG",
                        "event": "http.request.completed", "request_id": "11111111-1111-4111-8111-111111111111",
                        "http.route": "/readyz", "http.request.method": "GET",
                        "http.response.status_code": 200, "duration_us": 42}))
                return 0, "\n".join(lines) + "\n", ""
            return ok("log line\n")
        self.unknown.append(args)
        return 1, "", "unmodelled kubectl command"

    def helm(self, args):
        if args[0] in ("install", "upgrade"):
            values = json.loads(Path(args[args.index("--values") + 1]).read_text())
            worker_replicas = values["worker"]["replicas"]
            api_replicas = values.get("api", {}).get("replicas", 1)
            profile = bool(values.get("storage", {}).get("artifacts", {}).get("enabled"))
            gw_mode = None
            if values.get("gateways"):
                gw_mode = ("tls" if values.get("worker", {}).get("inference", {}).get("caBundle", {}).get("enabled")
                           else "plain")
            if self.installed and (worker_replicas != self.replicas["worker"] or profile != self.profile_enabled
                                   or gw_mode != self.gateway_mode):
                self.generation["worker"] += 1
            if self.installed and (api_replicas != self.replicas["api"] or profile != self.profile_enabled):
                self.generation["api"] += 1
            self.replicas["worker"] = worker_replicas
            self.replicas["api"] = api_replicas
            if gw_mode is not None:
                self.replicas[smoke.GATEWAY_COMPONENT] = 1
                self.generation[smoke.GATEWAY_COMPONENT] = self.generation.get(smoke.GATEWAY_COMPONENT, 0) + 1
            else:
                self.replicas.pop(smoke.GATEWAY_COMPONENT, None)
            self.profile_enabled = profile
            self.gateway_mode = gw_mode
            if profile:
                self.artifacts_pvc_created = True
            self.installed, self.revision = True, self.revision + 1
            return 0, "", ""
        if args[:1] == ["list"]:
            return 0, json.dumps([{"name": smoke.RELEASE, "status": "deployed", "revision": str(self.revision)}]
                                 if self.installed else []), ""
        if args[:2] == ["get", "manifest"]:
            return 0, "---\n# Source: openmettle-core/templates/api-service.yaml\n", ""
        if args[:2] == ["get", "hooks"]:
            return 0, HOOKS, ""
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
    """A Service keeps its port; pod `<name>-<index>` gets 9000 + index, so callers can tell pods apart."""

    def __init__(self, kubectl, env, target, port, namespace=smoke.APP_NAMESPACE):
        if namespace == smoke.DB_NAMESPACE:
            assert (target, port) in ((f"deployment/{smoke.INGRESS_CLASS}", 8443),
                                      (f"service/{smoke.STANDIN}", smoke.STANDIN_PORT))
            self.port = port
            return
        self.port = port if target.startswith("service/") else 9000 + int(target.rsplit("-", 1)[1])

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


class HttpDoctor:
    """A FakeArtifacts doctor: for responses `when(method, path, request headers, response)` selects,
    rewrites the JSON document, the response headers or the body, or replaces the response."""

    def __init__(self, when, document=None, *, headers=None, body=None, replace=None):
        self.when, self.document, self.headers, self.body, self.replace = when, document, headers, body, replace

    def __call__(self, method, path, request_headers, response):
        if not self.when(method, path, request_headers, response):
            return None
        if self.replace:
            return self.replace(response)
        status, headers, payload = response[0], dict(response[1]), response[2]
        if self.document:
            document = json.loads(payload)
            self.document(document, payload)
            payload = json.dumps(document).encode()
        if self.headers:
            self.headers(headers)
        if self.body:
            payload = self.body(payload)
        return status, headers, payload


class OrchestrationTest(unittest.TestCase):
    """main() and Smoke against a recording fake cluster: ordering, refusals, cleanup and reporting."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.fake = FakeCluster()

    def run_main(self):
        """Run main() against the fake; return (exit status, report, stderr)."""
        (self.tmp / "Dockerfile").write_text("FROM synthetic AS build\n")
        fixture = self.tmp / smoke.CORE_CATALOG_FIXTURE
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(json.dumps(CATALOG_FIXTURE))
        report = self.tmp / "report.json"
        report.unlink(missing_ok=True)
        stderr = io.StringIO()
        with mock.patch.object(smoke, "core_checkout_state", return_value=(smoke.CORE_COMMIT, "")), \
                mock.patch.object(smoke, "load_core", return_value=self.fake.core), \
                mock.patch.object(smoke, "PortForward", FakePortForward), \
                mock.patch.object(smoke, "ingress_get", self.fake.ingress_get), \
                mock.patch.object(smoke.ssl, "create_default_context"), \
                mock.patch.object(smoke, "http_exchange", self.fake.artifacts), \
                mock.patch.object(smoke, "time", FakeClock()), \
                mock.patch.object(smoke.subprocess, "run", side_effect=AssertionError("real subprocess")), \
                mock.patch.object(smoke.subprocess, "Popen", side_effect=AssertionError("real subprocess")), \
                mock.patch("sys.stderr", stderr):
            status = smoke.main(["--core-dir", str(self.tmp), "--report", str(report)])
        return status, json.loads(report.read_text()), stderr.getvalue()

    def assert_cleaned_up(self, built=None, cluster=True):
        deleted = [c[4] for c in self.fake.commands("kind", "delete", "cluster", "--name")]
        self.assertEqual(deleted, [self.fake.name] if cluster else [])
        removed = [c[3] for c in self.fake.commands("docker", "image", "rm")]
        if built is None:
            self.assertEqual(sorted(removed), sorted(self.fake.built))
        else:
            self.assertEqual(sorted(removed), sorted(r for r in self.fake.built if r.split("/")[2].split(":")[0] in built))
            self.assertEqual(len(removed), len(built))

    def test_passes_on_a_healthy_cluster(self):
        status, report, _ = self.run_main()
        self.assertEqual(self.fake.unknown, [])
        self.assertEqual((status, report["result"]), (0, "passed"), report.get("error"))
        self.assertEqual(len(report["checks"]), 13)
        self.assertEqual(self.fake.resumes, [(False, None), (False, "start"), (True, "start"),
                                             (True, None), (True, "end")])
        self.assertEqual(next(c["quiet_seconds"] for c in report["checks"] if "quiet_seconds" in c), 30)
        netpol_check = next(c for c in report["checks"] if "NetworkPolicy enforced" in c["check"])
        self.assertEqual(netpol_check["namespace_policies"],
                         sorted([f"NetworkPolicy/{smoke.NAMESPACE_DENY}", *smoke.release_network_policies()]))
        self.assertEqual(len(netpol_check["probes"]), len(smoke.probe_plan(DNS_IP, PEER_IP)))
        profile_check = next(c for c in report["checks"] if "enabled-profile upgrade" in c["check"])
        self.assertEqual(profile_check["ready_replicas"], {"api": 2, "worker": 1})
        self.assertEqual((profile_check["healthz"], profile_check["readyz"]), (200, 200))
        self.assertEqual(profile_check["pdb"], {"name": smoke.API_PDB, "max_unavailable": 1,
                                                "current_healthy": 2, "disruptions_allowed": 1})
        optional_check = next(c for c in report["checks"] if "no optional package present" in c["check"])
        self.assertEqual(optional_check["unmounted_http"],
                         {"/auth/session": 404, "/auth/native/session": 404, "/v1/capabilities": 404})
        quota_names = [f"{m} {p}" for m, p in smoke.QUOTA_ROUTES]
        self.assertEqual(optional_check["unmounted_quota_routes"], dict.fromkeys(quota_names, 404))
        self.assertEqual(profile_check["quota_routes"], dict.fromkeys(quota_names, 401))
        # Both profiles send every quota route through the API Service with no session, Origin or key.
        quota_calls = [c for c in self.fake.artifacts.calls if c[2].startswith(("/v1/quotas", "/v1/projects", "/v1/admin"))]
        self.assertEqual([(port, method, path, headers) for port, method, path, headers in quota_calls],
                         [(8080, m, p, {}) for m, p in smoke.QUOTA_ROUTES] * 2)
        self.assertEqual(optional_check["issuance"], {"api_pods": 1, "api_issuance_env": False, "issuance_pool": None,
                                                      "worker_isolated": True, "migrate_isolated": True})
        self.assertEqual(profile_check["issuance"], {"api_pods": 2, "api_issuance_env": True, "issuance_pool": "2",
                                                     "worker_isolated": True, "migrate_isolated": True})
        install_check = next(c for c in report["checks"] if c["check"].startswith("install by digest"))
        self.assertEqual(install_check["latest_version"], smoke.REQUIRED_MIGRATION)
        self.assertEqual(install_check["run_admission"], {"dispatch_lock_singleton": True,
                                                          "privileges_checked": len(smoke.RUN_ADMISSION_CHECKS) - 1})
        self.assertEqual(install_check["gateway_schema"], {"gateway_function_only": True,
                                                           "superseded_tables_absent": True,
                                                           "checks": len(smoke.GATEWAY_SCHEMA_CHECKS)})
        self.assertEqual(install_check["fresh_bootstrap"], {"metering_and_overrides_enforced": True,
                                                            "artifact_volume_unpinned_auto_pin_allowed": True})
        self.assertEqual(profile_check["artifacts"], {
            "session": "synthetic browser session (cookie channel)", "api_pods": 2, "revisions": 2,
            "idempotent_retry": "same revision from the other replica",
            "downloads": {"full_bytes": len(smoke.ARTIFACT_PAYLOADS[1]), "range": "bytes=0-9", "range_status": 206,
                          "unsatisfiable_status": 416}})
        # Writes alternate between the two API pods; every read goes to the pod that did not write.
        artifact_calls = [c for c in self.fake.artifacts.calls if c[2].startswith("/v1/artifacts")]
        self.assertEqual([(port, method, path.split("?")[0].count("/")) for port, method, path, _ in artifact_calls],
                         [(9000, "POST", 2), (9001, "POST", 2), (9000, "POST", 4), (9001, "GET", 5),
                          (9001, "GET", 6), (9001, "GET", 6), (9001, "GET", 6)])
        self.assertEqual([h.get("Range") for *_, h in artifact_calls][-3:],
                         [None, "bytes=0-9", smoke.UNSATISFIABLE_RANGE])
        # The idempotent retry used another boundary under the same key; the revision a new key.
        keys = [(h.get("Idempotency-Key"), h.get("Content-Type")) for *_, h in artifact_calls[:3]]
        self.assertEqual([k for k, _ in keys], ["kind-smoke-create", "kind-smoke-create", "kind-smoke-revision"])
        self.assertNotEqual(keys[0][1], keys[1][1])
        self.assertEqual(len(self.fake.artifacts.revisions), 2)
        self.assertEqual(profile_check["run_admission_http"], {
            "models": ["a", "b"], "admitted": "queued", "replay": "same run", "cancelled": "cancelled"})
        run_calls = [c for c in self.fake.artifacts.calls if c[2].startswith(("/v1/models", "/v1/conversations",
                                                                             "/v1/runs"))]
        self.assertEqual([(port, method, path.rsplit("/", 1)[-1], headers.get("Idempotency-Key"))
                          for port, method, path, headers in run_calls[:5]],
                         [(9000, "GET", "models", None),
                          (9000, "POST", "conversations", smoke.HTTP_RUN_KEYS["conversation"]),
                          (9000, "POST", "runs", smoke.HTTP_RUN_KEYS["run"]),
                          (9000, "POST", "runs", smoke.HTTP_RUN_KEYS["run"]),
                          (9000, "POST", "cancel", smoke.HTTP_RUN_KEYS["cancel"])])
        self.assertEqual(self.fake.artifacts.runs_state, {"cancelled": 1, "succeeded": 2})
        plain_gw = next(c for c in report["checks"] if "(plain topology" in c["check"])
        tls_gw = next(c for c in report["checks"] if "(tls topology" in c["check"])
        self.assertEqual(plain_gw["mounts"], {"mode": "plain", "worker_pods": 1, "gateway_pods": 1, "ca_mounted": False})
        self.assertEqual(tls_gw["mounts"], {"mode": "tls", "worker_pods": 1, "gateway_pods": 1, "ca_mounted": True})
        for gw_check in (plain_gw, tls_gw):
            self.assertEqual(gw_check["turn"], {
                "run_state": "succeeded",
                "assistant_content": smoke.STANDIN_EXPECTED_CONTENT,
                "settlement": {"prompt_tokens": 11, "completion_tokens": 7, "settled_units": 18},
                "upstream": {"model": smoke.CATALOG_MODEL, "authorization_stripped": True, "cache_salt_len": 64},
            })
        self.assertEqual(len(self.fake.commands("helm", "get", "hooks", smoke.RELEASE)), 2)
        self.assertEqual(profile_check["pvc"], {"claim": smoke.ARTIFACTS_CLAIM, "phase": "Bound",
                                                "mount_path": smoke.ARTIFACTS_MOUNT_PATH, "mounted_pods": 3,
                                                "store_subdirectories": ["staging", "revisions"]})
        stats = [c for c in self.fake.commands("kubectl") if "exec" in c and "stat" in c]
        self.assertEqual(sorted(c[c.index("--container") + 1] for c in stats), ["api", "api", "worker"])
        self.assertEqual(profile_check["auth"], {
            "api_pods": 2, "config_path": smoke.AUTH_CONFIG_PATH, "catalog_path": smoke.AUTH_CATALOG_PATH,
            "keys_dir": smoke.AUTH_KEYS_DIR, "secret_mode": smoke.AUTH_SECRET_MODE, "worker_isolated": True,
            "checked_pods": 2,
            "routes": {"/auth/session": 403, "/auth/native/session": 403,
                       "/v1/capabilities": 401, "v1_error_code": "unauthenticated"},
        })
        self.assertEqual(profile_check["logs"]["api"]["pods"], 2)
        self.assertGreaterEqual(profile_check["logs"]["api"]["debug_http_events"], 1)
        self.assertEqual(profile_check["logs"]["worker"]["pods"], 1)
        uninstall_check = next(c for c in report["checks"] if "uninstall leaves no release objects" in c["check"])
        self.assertEqual(uninstall_check["kept_pvcs"], [f"PersistentVolumeClaim/{smoke.ARTIFACTS_CLAIM}"])
        self.assertIn("networkpolicies", smoke.RELEASE_KINDS.split(","))
        self.assertIn("poddisruptionbudgets", smoke.RELEASE_KINDS.split(","))
        self.assertIn("networkpolicies", smoke.INVENTORY_KINDS.split(","))
        self.assertNotIn("networkpolicies", smoke.OPTIONAL_KINDS.split(","))
        self.assertNotIn("error", report)
        self.assert_cleaned_up(built=(*smoke.ROLES, smoke.STANDIN))
        self.assertEqual([c[1:3] for c in self.fake.commands("helm") if c[1] in ("install", "upgrade", "uninstall")],
                         [["install", smoke.RELEASE], ["upgrade", smoke.RELEASE], ["upgrade", smoke.RELEASE],
                          ["upgrade", smoke.RELEASE], ["upgrade", smoke.RELEASE], ["upgrade", smoke.RELEASE],
                          ["uninstall", smoke.RELEASE]])
        for role in smoke.ROLES:
            self.assertEqual(report["images"][role], {"reference": smoke.digest_reference(role, DIGEST[role]),
                                                      "cri_image_id": IMAGE_ID[role],
                                                      "resolved_before_alias": False})

    def test_ingress_retries_during_rollout_and_checks_replacements_before_resuming(self):
        get = self.fake.ingress_get
        statuses = iter([504, 502, 200, 503, 200])
        observed = []

        def record_pods(args, result):
            if self.fake.replaced and "pods" in args and "--selector" in args:
                observed.append("pods")

        def ingress(port, context, path, headers, **kwargs):
            if self.fake.replaced and kwargs.get("host", smoke.INGRESS_HOST) == smoke.INGRESS_HOST:
                observed.append(path)
                if path == "/readyz":
                    status = next(statuses)
                    if status == 504:
                        smoke.time.sleep(3)  # Traefik's upstream dial timeout
                    return IngressResponse(status)
            return get(port, context, path, headers, **kwargs)

        self.fake.doctors.append(record_pods)
        self.fake.ingress_get = ingress
        status, report, _ = self.run_main()
        self.assertEqual(status, 0, report.get("error"))
        self.assertEqual(observed[:7], ["/readyz"] * 3 + ["pods", "/readyz", "/readyz", f"/v1/runs/{RUN_ID}/events"])

    def test_persistent_ingress_timeout_fails_within_rollout_probe_budget(self):
        get = self.fake.ingress_get
        attempts = []

        def ingress(port, context, path, headers, *, timeout=smoke.HTTP_TIMEOUT):
            if self.fake.replaced and path == "/readyz":
                attempts.append((smoke.time.monotonic(), timeout))
                smoke.time.sleep(timeout)
                raise TimeoutError
            return get(port, context, path, headers, timeout=timeout)

        self.fake.ingress_get = ingress
        status, report, _ = self.run_main()
        self.assertEqual(status, 1)
        self.assertEqual(report["error"], "HTTPS ingress lost the API during its rolling restart")
        self.assertGreater(len(attempts), 1)
        last_start, last_timeout = attempts[-1]
        self.assertLessEqual(last_start + last_timeout - attempts[0][0], 5)
        self.assertFalse(any(replaced for replaced, _ in self.fake.resumes))

    def test_identity_is_verified_immediately_before_every_mutation(self):
        """Only verify_identity's own namespace-ownership reads may separate it from the change."""
        self.run_main()
        mutations = 0
        previous = None
        for call in map(FakeCluster.strip, self.fake.calls):
            ingress_mutation = (call[:2] == ["kubectl", "--namespace"]
                                and (call[3:6] in (["create", "secret", "tls"], ["rollout", "restart", f"deployment/{smoke.FULLNAME}-api"])
                                     or call[3:4] == ["cp"] or "/tmp/kind-admit" in call))
            if tuple(call[:2]) in MUTATING or ingress_mutation:
                self.assertEqual(previous, ["IDENTITY"], f"{call[:2]} ran without an identity check just before")
                mutations += 1
            if call[:3] != ["kubectl", "get", "namespace"]:
                previous = call
        self.assertEqual(mutations, 16)  # includes gateway stand-in, gateway TLS secret, inference fixtures and rev 5/6 upgrades

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
        self.assertTrue(self.fake.commands("kubectl", "--namespace", smoke.DB_NAMESPACE, "logs", "--selector",
                                           "app=smoke-traefik", "--tail=50"))
        self.assertIn("B" * 100, stderr)
        self.assertNotIn(password[16:], stderr)

    def test_published_report_passes_the_secret_guard(self):
        with mock.patch.object(smoke, "assert_no_secrets", wraps=smoke.assert_no_secrets) as guard:
            status, report, _ = self.run_main()
        self.assertEqual(status, 0)
        (text, values), _ = guard.call_args
        self.assertEqual(json.loads(text), report)
        self.assertEqual(sorted(values), sorted(self.fake.passwords.values()))
        self.assertEqual(len(self.fake.passwords), 9)
        self.assertIn("issuance", self.fake.passwords)
        self.assertIn("gateway", self.fake.passwords)
        self.assertEqual(len(self.fake.passwords["session"]), 87)

    def test_a_v1_failure_echoing_the_session_cookie_is_redacted(self):
        def echo(method, path, headers, response):
            if path.startswith("/v1/artifacts"):
                return 500, response[1], ("echo " + headers["Cookie"]).encode()
        self.fake.artifacts.doctor = echo
        status, report, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertIn("HTTP 500, expected 201", report["error"])
        self.assertIn("[redacted]", report["error"])
        self.assertNotIn(self.fake.passwords["session"], json.dumps(report) + stderr)
        self.assert_cleaned_up()

    def test_cleanup_failure_fails_a_passing_run(self):
        self.fake.doctors.append(doctor_output(["kind", "delete"], returncode=1))
        status, report, _ = self.run_main()
        self.assertEqual((status, report["result"]), (1, "failed"))
        delete_cmd = self.fake.commands("kind", "delete", "cluster")[0]
        self.assertEqual(report["cleanup_errors"], [f"{' '.join(delete_cmd)}: failed"])

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
        self.assertEqual(tagged, [smoke.digest_reference(r, DIGEST[r]) for r in ("worker", "migrate", "gateway")])

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
            "default-deny removed by uninstall": (doctor_json(
                ["get configmaps,secrets,networkpolicies", smoke.RUN_LABEL],
                lambda data: data.__setitem__("items", [i for i in data["items"]
                                                        if i["metadata"]["name"] != smoke.NAMESPACE_DENY])),
                "test-owned objects after uninstall:"),
            "test-owned auth ConfigMap removed by uninstall": (doctor_json(
                ["get configmaps,secrets,networkpolicies", smoke.RUN_LABEL],
                lambda data: data.__setitem__("items", [i for i in data["items"]
                                                        if i["metadata"]["name"] != smoke.AUTH_CONFIG_MAP])),
                "test-owned objects after uninstall:"),
            "default install exposes auth route": (
                lambda args, result: fake_ref().auth_http_overrides.__setitem__("/auth/session", (200, "ok")),
                "API /auth/session 404"),
            "enabled-profile auth config check fails": (doctor_output(
                [smoke.AUTH_CHECK_BINARY], returncode=78, stderr="auth configuration error\n"),
                "exited 78"),
            "enabled-profile worker leaks auth env": (doctor_json(
                ["app.kubernetes.io/component=worker"],
                pod_status(lambda p: p["spec"]["containers"][0].__setitem__(
                    "env", [{"name": "OPENMETTLE_WORKER_AUTH_CONFIG", "value": smoke.AUTH_CONFIG_PATH}])),
                when=revision(4)), "worker container must not receive AUTH_CONFIG env"),
            "migration history before required migration": (doctor_output(
                ["exec", "--stdin", "deployment/postgres", "psql"], stdout="1|t|aa|t\n36|t|bb|t\n"),
                f"before migration {smoke.REQUIRED_MIGRATION}"),
            "gateway schema privilege violation": (
                lambda args, result: fake_ref().gateway_schema.__setitem__(0, "f"),
                "migration 37 gateway boundary"),
            "gateway plain topology leaks to api": (doctor_output(
                ["exec", f"deployment/{api}", f"{smoke.GATEWAY_WORKLOAD}.{smoke.APP_NAMESPACE}.svc.cluster.local"],
                returncode=0, stdout="HTTP/1.1 200 OK\r\n"),
                "NetworkPolicy is not enforced"),
            "gateway tls topology allows direct worker": (
                lambda args, result: (subprocess.CompletedProcess(args, 0, "HTTP/1.1 200 OK\r\n", "")
                                      if fake_ref().revision == 6
                                      and matches(args, ["exec", f"deployment/{worker}",
                                                         f"{smoke.GATEWAY_WORKLOAD}.{smoke.APP_NAMESPACE}.svc.cluster.local"])
                                      else None),
                "NetworkPolicy is not enforced"),
            "gateway tls topology leaks to egress-unrestricted postgres": (
                lambda args, result: (subprocess.CompletedProcess(args, 0, "HTTP/1.1 200 OK\r\n", "")
                                      if fake_ref().revision == 6
                                      and matches(args, ["exec", "deployment/postgres",
                                                         f"{smoke.GATEWAY_WORKLOAD}.{smoke.APP_NAMESPACE}.svc.cluster.local"])
                                      else None),
                "NetworkPolicy is not enforced"),
            "gateway leaks Authorization to stand-in": (HttpDoctor(
                lambda m, p, h, r: (m, p) == ("GET", "/_recorded"),
                lambda doc, body: doc[-1]["headers"].__setitem__("authorization", ["Bearer leaked"])),
                "leaked Authorization header"),
            "upgraded rather than fresh quota markers": (
                lambda args, result: setattr(fake_ref(), "fresh_bootstrap", "f|t"),
                "fresh-install quota and artifact-volume markers are 'f|t'"),
            "default install mounts a quota route": (HttpDoctor(
                lambda m, p, h, r: m == "PUT" and not fake_ref().profile_enabled,
                replace=lambda r: fake_ref().artifacts.problem(401, "unauthenticated")),
                f"unmounted PUT /v1/admin/scopes/{smoke.QUOTA_SCOPE}/quotas/usage_tokens: HTTP 401, expected 404"),
            "quota summary served without a session": (HttpDoctor(
                lambda m, p, h, r: p == "/v1/quotas/personal" and fake_ref().profile_enabled,
                replace=lambda r: FakeArtifacts.reply(200, {"items": []})),
                "GET /v1/quotas/personal: HTTP 200, expected 401"),
            "quota revoke refusal with another code": (HttpDoctor(
                lambda m, p, h, r: p.endswith("/revoke") and fake_ref().profile_enabled,
                lambda doc, body: doc.__setitem__("code", "forbidden")),
                "/quotas/usage_tokens/revoke: unexpected 401 problem"),
            "run_dispatch_lock singleton row missing": (
                lambda args, result: fake_ref().run_admission.__setitem__(0, "f"),
                f"(SELECT count(*) = 1 AND bool_and(id AND NOT lock_guard) FROM {smoke.RUN_DISPATCH_LOCK}) "
                "is 'f', expected 't'"),
            "api can read run_dispatch_lock": (
                lambda args, result: fake_ref().run_admission.__setitem__(-2, "t"),
                f"has_any_column_privilege('openmettle_api', '{smoke.RUN_DISPATCH_LOCK}', 'SELECT') is 't'"),
            "worker lacks the lock_guard column grant": (
                lambda args, result: fake_ref().run_admission.__setitem__(2, "f"),
                "migrations 19/20 role boundary"),
            "migration 19 privilege query truncated": (
                lambda args, result: fake_ref().run_admission.__delitem__(slice(3, None)),
                "migrations 19/20 privilege query returned"),
            "run admission without a catalog": (HttpDoctor(
                lambda m, p, h, r: (m, p) == ("POST", "/v1/runs"),
                replace=lambda r: fake_ref().artifacts.problem(503, "provisioning")),
                "POST /v1/runs: HTTP 503, expected 201"),
            "models page omits the catalog model": (HttpDoctor(
                lambda m, p, h, r: p == "/v1/models",
                lambda doc, body: doc.__setitem__("items", [])),
                "GET /v1/models does not list catalog model 'a'"),
            "run retry admits another run": (HttpDoctor(
                lambda m, p, h, r: p == "/v1/runs" and r[0] == 200,
                lambda doc, body: doc.__setitem__("run_id", "00000000-0000-4000-8000-0000000000ff")),
                "the exact retry did not replay the same queued run"),
            "v1 session rejected": (
                lambda args, result: setattr(fake_ref(), "session", None) if fake_ref().session else None,
                "POST /v1/artifacts: HTTP 401, expected 201"),
            "artifact upload sha256 differs": (HttpDoctor(
                lambda m, p, h, r: m == "POST" and p.startswith("/v1/artifacts"),
                lambda doc, body: doc.__setitem__("sha256", "0" * 64)),
                "artifact revision 1:"),
            "artifact retry creates another revision": (HttpDoctor(
                lambda m, p, h, r: smoke.ARTIFACT_BOUNDARIES[1] in h.get("Content-Type", ""),
                lambda doc, body: doc.__setitem__("revision_id", "00000000-0000-4000-9000-0000000000ff")),
                "idempotent artifact upload retry did not return the same artifact and revision"),
            "artifact revision 2 on another artifact": (HttpDoctor(
                lambda m, p, h, r: m == "POST" and p.split("?")[0].endswith("/revisions"),
                lambda doc, body: doc.__setitem__("artifact_id", "00000000-0000-4000-8000-0000000000ff")),
                "revision 2 did not append a new revision to the same artifact"),
            "revision metadata differs": (HttpDoctor(
                lambda m, p, h, r: m == "GET" and p.startswith("/v1/artifacts") and not p.endswith("/content"),
                lambda doc, body: doc.__setitem__("created_at", "2026-11-20T11:00:00Z")),
                "revision 2 metadata differs from its upload response"),
            "v1 response lacks no-store": (HttpDoctor(
                lambda m, p, h, r: m == "GET" and p.startswith("/v1/artifacts"),
                headers=lambda hs: hs.pop("cache-control")),
                "missing OpenMettle-API-Version 1.0 or Cache-Control no-store"),
            "download lacks nosniff": (HttpDoctor(
                lambda m, p, h, r: p.endswith("/content") and "Range" not in h,
                headers=lambda hs: hs.pop("x-content-type-options")), "full download:"),
            "download serves other bytes": (HttpDoctor(
                lambda m, p, h, r: p.endswith("/content") and "Range" not in h, body=lambda b: b[::-1]),
                "full download:"),
            "range ignored": (HttpDoctor(
                lambda m, p, h, r: h.get("Range") == "bytes=0-9",
                replace=lambda r: (200, r[1], smoke.ARTIFACT_PAYLOADS[1])), "HTTP 200, expected 206"),
            "range serves the wrong slice": (HttpDoctor(
                lambda m, p, h, r: h.get("Range") == "bytes=0-9", body=lambda b: b[1:] + b"x"),
                "range download:"),
            "unsatisfiable range without Content-Range": (HttpDoctor(
                lambda m, p, h, r: h.get("Range") == smoke.UNSATISFIABLE_RANGE,
                headers=lambda hs: hs.pop("content-range")), "unsatisfiable range:"),
            "unsatisfiable range wrong code": (HttpDoctor(
                lambda m, p, h, r: h.get("Range") == smoke.UNSATISFIABLE_RANGE,
                lambda doc, body: doc.__setitem__("code", "validation")), "unsatisfiable range:"),
            "default install api receives issuance env": (doctor_json(
                ["app.kubernetes.io/component=api"],
                pod_status(lambda p: p["spec"]["containers"][0].__setitem__("env", issuance_env())),
                when=revision(1)), "without auth"),
            "default install migrate hook receives issuance URL": (doctor_output(
                ["get", "hooks"], stdout=HOOKS + f"            - name: {smoke.ISSUANCE_URL_ENV}\n"),
                "migrate hook Job must not receive the issuance credential"),
            "release hooks without the migrate Job": (doctor_output(["get", "hooks"], stdout="---\n"),
                                                      "release hooks do not contain the migrate Job"),
            "enabled-profile api lacks issuance URL": (doctor_json(
                ["app.kubernetes.io/component=api"],
                pod_status(lambda p: p["spec"]["containers"][0].__setitem__("env", [
                    e for e in p["spec"]["containers"][0]["env"] if e["name"] != smoke.ISSUANCE_URL_ENV])),
                when=revision(4)), "api container issuance env is"),
            "enabled-profile issuance URL optional": (doctor_json(
                ["app.kubernetes.io/component=api"],
                pod_status(lambda p: [e["valueFrom"]["secretKeyRef"].__setitem__("optional", True)
                                      for e in p["spec"]["containers"][0]["env"] if e["name"] == smoke.ISSUANCE_URL_ENV]),
                when=revision(4)), "is not a required reference"),
            "enabled-profile worker receives issuance URL": (doctor_json(
                ["app.kubernetes.io/component=worker"],
                pod_status(lambda p: p["spec"]["containers"][0]["env"].append(issuance_env()[0])),
                when=revision(4)), "worker pod must not receive the issuance credential"),
            "enabled-profile migrate hook mounts issuance Secret": (doctor_output(
                ["get", "hooks"], stdout=HOOKS.replace(smoke.SECRET["migrate"], smoke.SECRET["issuance"])),
                "migrate hook Job must not receive the issuance credential"),
            "test-owned issuance Secret removed by uninstall": (doctor_json(
                ["get configmaps,secrets,networkpolicies", smoke.RUN_LABEL],
                lambda data: data.__setitem__("items", [i for i in data["items"]
                                                        if i["metadata"]["name"] != smoke.SECRET["issuance"]])),
                "test-owned objects after uninstall:"),
            "enabled-profile v1 capabilities wrong problem code": (
                lambda args, result: (fake_ref().auth_http_overrides.__setitem__(
                    "/v1/capabilities", (401, json.dumps({"status": 401, "code": "wrong"})))
                    if fake_ref().profile_enabled else None),
                "unexpected /v1/capabilities problem body"),
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
            "test-owned Secret removed": (doctor_json(
                [f"--selector {smoke.RUN_LABEL} "],
                lambda data: data.__setitem__("items", [i for i in data["items"] if i["metadata"]["name"] != smoke.SECRET["api"]])),
                "test-owned objects after uninstall:"),
            "enabled-profile ready replicas": (doctor_json(
                [f"deployment {api} --output=json"], lambda data: data["status"].__setitem__("readyReplicas", 1),
                when=revision(4)), "enabled-profile ready replicas"),
            "enabled-profile skipped migrate": (job_events(lambda e: e["involvedObject"]["uid"] != "job-4"),
                                                "enabled-profile upgrade did not run the migrate hook"),
            "enabled-profile healthz": (lambda args, result: setattr(fake_ref(), "healthz", 503),
                                        "API /healthz 200"),
            "enabled-profile pdb wrong maxUnavailable": (doctor_json(
                ["get poddisruptionbudget", smoke.API_PDB],
                lambda data: data["spec"].__setitem__("maxUnavailable", 2)),
                "PodDisruptionBudget maxUnavailable is 2"),
            "enabled-profile pdb zero disruptionsAllowed": (doctor_json(
                ["get poddisruptionbudget", smoke.API_PDB],
                lambda data: data["status"].__setitem__("disruptionsAllowed", 0)),
                "API PodDisruptionBudget disruptionsAllowed >= 1"),
            "enabled-profile pvc not Bound": (doctor_json(
                ["get persistentvolumeclaim", smoke.ARTIFACTS_CLAIM],
                lambda data: data["status"].__setitem__("phase", "Pending")),
                "is not Bound"),
            "enabled-profile pvc missing mount": (doctor_json(
                ["app.kubernetes.io/component=worker"],
                pod_status(lambda p: p["spec"]["containers"][0].__setitem__("volumeMounts", [])),
                when=revision(4)), "worker container does not mount artifacts"),
            "enabled-profile api lacks ARTIFACTS_DIR": (doctor_json(
                ["app.kubernetes.io/component=api"],
                pod_status(lambda p: p["spec"]["containers"][0].__setitem__("env", [
                    e for e in p["spec"]["containers"][0]["env"] if "ARTIFACTS" not in e["name"]])),
                when=revision(4)), "api container lacks OPENMETTLE_API_ARTIFACTS_DIR"),
            "enabled-profile store subdirectory missing": (doctor_output(
                ["exec", " stat --format="], returncode=1, stderr="stat: cannot statx: No such file or directory\n"),
                "exited 1"),
            "enabled-profile store subdirectory world-readable": (doctor_output(
                ["exec", " stat --format="], stdout=f"{smoke.ARTIFACTS_MOUNT_PATH}/staging|directory|755|65532\n"
                                         f"{smoke.ARTIFACTS_MOUNT_PATH}/revisions|directory|700|65532\n"),
                "expected a 0700 directory owned by 65532"),
            "enabled-profile non-JSON stderr": (doctor_output(
                ["logs", "--container api"], returncode=0, stdout="plain text log line\n"),
                "api stderr emitted non-JSON log line"),
            "enabled-profile forbidden message log field": (doctor_output(
                ["logs", "--container worker"], returncode=0,
                stdout=json.dumps({"timestamp": "2026-11-19T10:04:00Z", "level": "INFO",
                                   "event": "process.started", "role": "worker", "message": "oops"}) + "\n"),
                "forbidden ADR 0024 'message' field"),
            "enabled-profile api missing debug http log": (doctor_output(
                ["logs", "--container api"], returncode=0,
                stdout=json.dumps({"timestamp": "2026-11-19T10:04:00Z", "level": "INFO",
                                   "event": "process.started", "role": "api"}) + "\n"),
                "api ADR 0024 JSON structured logs"),
            "enabled-profile worker missing process.started": (doctor_output(
                ["logs", "--container worker"], returncode=0, stdout=""),
                "worker ADR 0024 JSON structured logs"),
            "pdb residue after uninstall": (doctor_json(
                [smoke.RELEASE_KINDS],
                lambda data: data["items"].append({"kind": "PodDisruptionBudget", "metadata": {"name": "leftover"}})),
                "release objects to be removed"),
            "kept artifact PVC deleted by uninstall": (doctor_json(
                ["get persistentvolumeclaims"], lambda data: data.__setitem__("items", []),
                when=lambda: not fake_ref().installed), "kept artifact PVC after uninstall:"),
        }
        # History changes only after the install was observed: compare against the first reading.
        readings = []

        def history_read(args, result):
            """A psql read of the migration history; other psql reads (grants, seed, settlement UUIDs) are not."""
            first = result.stdout.split("|", 1)[0]
            return "psql" in args and first.isdigit()

        def history_changes(args, result):
            if history_read(args, result):
                readings.append(1)
                if len(readings) > 1:
                    return subprocess.CompletedProcess(args, 0, "1|t|changed|t\n", "")

        def history_changes_on_repeat(args, result):
            if history_read(args, result) and fake_ref().revision == 3:
                return subprocess.CompletedProcess(args, 0, "1|t|changed|t\n", "")
        cases["upgrade changed history"] = (history_changes, "migration history changed on a same-digest upgrade")
        def history_changes_on_profile(args, result):
            if history_read(args, result) and fake_ref().revision == 4:
                return subprocess.CompletedProcess(args, 0, "1|t|changed|t\n", "")
        cases["repeated upgrade changed history"] = (history_changes_on_repeat,
                                                     "migration history changed on a repeated upgrade")
        cases["enabled-profile changed history"] = (history_changes_on_profile,
                                                    "migration history changed on enabled-profile upgrade")
        for name, (doctor, message) in cases.items():
            with self.subTest(name):
                self.fake = FakeCluster()
                if isinstance(doctor, HttpDoctor):
                    self.fake.artifacts.doctor = doctor
                else:
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
        for role in smoke.DEFAULT_ROLES:
            self.assertEqual(values["images"][role]["digest"], DIGEST[role])
        self.assertNotIn("gateway", values["images"])
        # Without auth or gateways neither issuance nor gateway Secret is configured (the chart refuses them).
        self.assertEqual(values["database"],
                         {role: {"existingSecret": smoke.SECRET[role]} for role in smoke.DEFAULT_ROLES})
        self.assertEqual(values["worker"], {"replicas": 2})
        self.assertNotIn("api", values)
        self.assertNotIn("gateways", values)
        self.assertEqual(values["networkPolicy"], {
            "api": {"ingressFrom": [smoke.database_namespace_peer(smoke.PEER_LABELS)]},
            "database": {"to": [smoke.database_namespace_peer(smoke.POSTGRES_LABELS)]},
        })

    def test_values_require_every_valid_digest_and_bounded_replicas(self):
        for digests in ({k: v for k, v in DIGEST.items() if k != "migrate"},
                        {k: v for k, v in DIGEST.items() if k != "gateway"},
                        {**DIGEST, "api": "latest"}):
            with self.subTest(digests=digests), self.assertRaises(smoke.SmokeFailure):
                smoke.smoke_values(digests, 1)
        for replicas in (0, 3):
            with self.subTest(replicas=replicas), self.assertRaises(smoke.SmokeFailure):
                smoke.smoke_values(DIGEST, replicas)
        with self.assertRaises(smoke.SmokeFailure):
            smoke.smoke_values(DIGEST, 1, gateway_mode="plain")
        with self.assertRaises(smoke.SmokeFailure):
            smoke.smoke_values(DIGEST, 1, enabled_profile=True, gateway_mode="other")

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
        self.assertNotIn("ISSUANCE", result.stdout)
        self.assertNotIn("OPENMETTLE_GATEWAY_", result.stdout)
        for role in smoke.DEFAULT_ROLES:
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

    def test_values_enabled_profile(self):
        values = smoke.smoke_values(DIGEST, worker_replicas=1, enabled_profile=True)
        self.assertEqual(values["api"], {"replicas": 2, "podDisruptionBudget": {"enabled": True, "maxUnavailable": 1}})
        self.assertEqual(values["worker"], {"replicas": 1, "sweepMs": 1000})
        self.assertEqual(values["ingress"]["tls"], [{"secretName": smoke.TLS_SECRET, "hosts": [smoke.INGRESS_HOST]}])
        self.assertEqual(values["networkPolicy"]["api"]["ingressFrom"], [smoke.database_namespace_peer({"app": smoke.INGRESS_CLASS})])
        self.assertEqual(values["telemetry"], {"logging": {"format": "json", "level": "debug"}})
        self.assertEqual(values["storage"], {"artifacts": {"enabled": True, "size": "64Mi",
                                                           "accessModes": ["ReadWriteOnce"]}})
        self.assertEqual(values["auth"], {
            "enabled": True,
            "configMapName": smoke.AUTH_CONFIG_MAP,
            "configKey": "auth.json",
            "catalogKey": smoke.AUTH_CATALOG_KEY,
            "loginKeysSecretName": smoke.AUTH_LOGIN_KEYS_SECRET,
        })
        self.assertEqual(values["networkPolicy"]["api"]["oidc"], {
            "to": [{"ipBlock": {"cidr": smoke.AUTH_OIDC_CIDR}}],
            "port": 443,
        })
        self.assertEqual(values["database"], {role: {"existingSecret": smoke.SECRET[role]}
                                              for role in ("api", "worker", "migrate", "issuance")})

    def test_values_and_chart_accept_gateway_plain_and_tls(self):
        """Both gateway_mode='plain' and 'tls' produce valid chart values and render cleanly via Helm."""
        if shutil.which(HELM) is None:
            self.skipTest("helm not on PATH")
        for mode, port, cm in (("plain", 8082, smoke.INFERENCE_PLAIN_CONFIG_MAP),
                               ("tls", 8443, smoke.INFERENCE_TLS_CONFIG_MAP)):
            with self.subTest(mode=mode):
                values = smoke.smoke_values(DIGEST, 1, enabled_profile=True, gateway_mode=mode)
                self.assertEqual(values["images"]["gateway"]["digest"], DIGEST["gateway"])
                self.assertEqual(values["database"]["gateway"], {"existingSecret": smoke.SECRET["gateway"]})
                self.assertEqual(values["worker"]["pollMs"], 100)
                self.assertEqual(values["worker"]["inference"]["configMapName"], cm)
                self.assertEqual(values["networkPolicy"]["worker"]["inference"]["port"], port)
                if mode == "tls":
                    self.assertTrue(values["worker"]["inference"]["caBundle"]["enabled"])
                    self.assertIn("ingressFrom", values["gateways"][smoke.GATEWAY_NAME]["networkPolicy"])
                else:
                    self.assertNotIn("caBundle", values["worker"]["inference"])
                    self.assertNotIn("ingressFrom", values["gateways"][smoke.GATEWAY_NAME]["networkPolicy"])
                with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
                    json.dump(values, handle)
                    handle.flush()
                    result = subprocess.run([HELM, "template", smoke.RELEASE, str(smoke.CHART),
                                             "--values", handle.name],
                                            capture_output=True, text=True, timeout=120, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'name: {smoke.GATEWAY_WORKLOAD}', result.stdout)
                self.assertIn("name: OPENMETTLE_WORKER_INFERENCE_CONFIG", result.stdout)
                self.assertIn("name: OPENMETTLE_GATEWAY_DATABASE_URL", result.stdout)
                if mode == "tls":
                    self.assertIn(smoke.INFERENCE_CA_DIR, result.stdout)
                else:
                    self.assertNotIn(smoke.INFERENCE_CA_DIR, result.stdout)

    def test_chart_accepts_enabled_profile_smoke_values(self):
        """The enabled-profile values pass chart schema and render guards and emit PDB, PVC and LOG_* env."""
        if shutil.which(HELM) is None:
            self.skipTest("helm not on PATH")
        with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
            json.dump(smoke.smoke_values(DIGEST, 1, enabled_profile=True), handle)
            handle.flush()
            result = subprocess.run([HELM, "template", smoke.RELEASE, str(smoke.CHART), "--values", handle.name],
                                    capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kind: PodDisruptionBudget", result.stdout)
        self.assertIn("kind: PersistentVolumeClaim", result.stdout)
        self.assertIn("helm.sh/resource-policy: keep", result.stdout)
        self.assertIn(smoke.ARTIFACTS_MOUNT_PATH, result.stdout)
        self.assertIn("name: OPENMETTLE_API_AUTH_CONFIG", result.stdout)
        self.assertIn(f"path: {smoke.AUTH_CATALOG_KEY}", result.stdout)
        self.assertNotIn("OPENMETTLE_WORKER_AUTH_CONFIG", result.stdout)
        self.assertNotIn("OPENMETTLE_MIGRATE_AUTH_CONFIG", result.stdout)
        self.assertIn(smoke.AUTH_CONFIG_DIR, result.stdout)
        self.assertIn(smoke.AUTH_KEYS_DIR, result.stdout)
        self.assertEqual(result.stdout.count(f"name: {smoke.ISSUANCE_URL_ENV}"), 1)
        self.assertEqual(result.stdout.count(f'name: "{smoke.SECRET["issuance"]}"'), 1)
        self.assertIn(f'name: {smoke.ISSUANCE_POOL_ENV}\n              value: "{smoke.ISSUANCE_POOL}"', result.stdout)
        for prefix in ("OPENMETTLE_API_", "OPENMETTLE_WORKER_", "OPENMETTLE_MIGRATE_"):
            self.assertIn(f"name: {prefix}LOG_FORMAT", result.stdout)
            self.assertIn(f"name: {prefix}LOG_LEVEL", result.stdout)


class EnabledProfileChecksTest(unittest.TestCase):
    def test_evaluate_pdb(self):
        pdb = {"metadata": {"name": smoke.API_PDB},
               "spec": {"maxUnavailable": 1, "unhealthyPodEvictionPolicy": "AlwaysAllow"},
               "status": {"currentHealthy": 2, "disruptionsAllowed": 1}}
        self.assertEqual(smoke.evaluate_pdb(pdb), {"name": smoke.API_PDB, "max_unavailable": 1,
                                                   "current_healthy": 2, "disruptions_allowed": 1})
        pending = json.loads(json.dumps(pdb))
        pending["status"]["disruptionsAllowed"] = 0
        self.assertIsNone(smoke.evaluate_pdb(pending))
        for bad in (
            {**pdb, "metadata": {"name": "wrong"}},
            {**pdb, "spec": {"maxUnavailable": 2, "unhealthyPodEvictionPolicy": "AlwaysAllow"}},
            {**pdb, "spec": {"maxUnavailable": 1, "unhealthyPodEvictionPolicy": "IfHealthyBudget"}},
        ):
            with self.assertRaises(smoke.SmokeFailure):
                smoke.evaluate_pdb(bad)

    def test_check_artifacts_pvc(self):
        pvc = {"metadata": {"name": smoke.ARTIFACTS_CLAIM, "annotations": {"helm.sh/resource-policy": "keep"}},
               "status": {"phase": "Bound"}}
        def make_pod(role):
            return {"spec": {"securityContext": {"fsGroup": 65532},
                             "volumes": [{"name": "artifacts",
                                          "persistentVolumeClaim": {"claimName": smoke.ARTIFACTS_CLAIM}}],
                             "containers": [{"name": role, "volumeMounts": [
                                 {"name": "artifacts", "mountPath": smoke.ARTIFACTS_MOUNT_PATH}], "env": [
                                 {"name": f"OPENMETTLE_{role.upper()}_ARTIFACTS_DIR",
                                  "value": smoke.ARTIFACTS_MOUNT_PATH}]}]}}
        pods = {"api": [make_pod("api"), make_pod("api")], "worker": [make_pod("worker")]}
        self.assertEqual(smoke.check_artifacts_pvc(pvc, pods),
                         {"claim": smoke.ARTIFACTS_CLAIM, "phase": "Bound",
                          "mount_path": smoke.ARTIFACTS_MOUNT_PATH, "mounted_pods": 3})
        with self.assertRaises(smoke.SmokeFailure):
            smoke.check_artifacts_pvc({**pvc, "status": {"phase": "Pending"}}, pods)
        with self.assertRaises(smoke.SmokeFailure):
            smoke.check_artifacts_pvc({**pvc, "metadata": {"name": smoke.ARTIFACTS_CLAIM, "annotations": {}}}, pods)
        bad_pod = make_pod("worker")
        bad_pod["spec"]["securityContext"]["fsGroup"] = 1000
        with self.assertRaises(smoke.SmokeFailure):
            smoke.check_artifacts_pvc(pvc, {"api": pods["api"], "worker": [bad_pod]})
        no_vol = make_pod("worker")
        no_vol["spec"]["volumes"] = []
        with self.assertRaises(smoke.SmokeFailure):
            smoke.check_artifacts_pvc(pvc, {"api": pods["api"], "worker": [no_vol]})
        for env in ([], [{"name": "OPENMETTLE_WORKER_ARTIFACTS_DIR", "value": "/tmp"}],
                    [{"name": "OPENMETTLE_API_ARTIFACTS_DIR", "value": smoke.ARTIFACTS_MOUNT_PATH}]):
            wrong_env = make_pod("worker")
            wrong_env["spec"]["containers"][0]["env"] = env
            with self.subTest(env=env), self.assertRaisesRegex(smoke.SmokeFailure, "OPENMETTLE_WORKER_ARTIFACTS_DIR"):
                smoke.check_artifacts_pvc(pvc, {"api": pods["api"], "worker": [wrong_env]})

    def test_artifact_dirs(self):
        self.assertEqual(smoke.artifact_dirs_command(),
                         ["stat", "--format=%n|%F|%a|%u", f"{smoke.ARTIFACTS_MOUNT_PATH}/staging",
                          f"{smoke.ARTIFACTS_MOUNT_PATH}/revisions"])
        def listing(*rows):
            return "".join(f"{smoke.ARTIFACTS_MOUNT_PATH}/{'|'.join(row)}\n" for row in rows)
        for good in (listing(("staging", "directory", "700", "65532"), ("revisions", "directory", "700", "65532")),
                     listing(("staging", "directory", "2700", "65532"), ("revisions", "directory", "2700", "65532"))):
            self.assertIsNone(smoke.evaluate_artifact_dirs("pod", good))
        bad = {
            "empty": "",
            "one directory": listing(("staging", "directory", "700", "65532")),
            "reordered": listing(("revisions", "directory", "700", "65532"), ("staging", "directory", "700", "65532")),
            "symlink": listing(("staging", "symbolic link", "777", "65532"), ("revisions", "directory", "700", "65532")),
            "group readable": listing(("staging", "directory", "700", "65532"), ("revisions", "directory", "750", "65532")),
            "root owned": listing(("staging", "directory", "700", "0"), ("revisions", "directory", "700", "65532")),
            "bad mode": listing(("staging", "directory", "rwx", "65532"), ("revisions", "directory", "700", "65532")),
            "extra field": listing(("staging", "directory", "700", "65532", "x"),
                                   ("revisions", "directory", "700", "65532")),
        }
        for name, output in bad.items():
            with self.subTest(name), self.assertRaises(smoke.SmokeFailure):
                smoke.evaluate_artifact_dirs("pod", output)

    def test_structured_logs_validation(self):
        started_api = json.dumps({"timestamp": "2026-11-19T10:04:00Z", "level": "INFO",
                                  "event": "process.started", "role": "api"})
        http_debug = json.dumps({"timestamp": "2026-11-19T10:04:01Z", "level": "DEBUG",
                                 "event": "http.request.completed", "http.route": "/healthz",
                                 "http.request.method": "GET", "http.response.status_code": 200,
                                 "duration_us": 12})
        summary = smoke.evaluate_structured_logs(
            "api", {"api-0": started_api + "\n" + http_debug + "\n", "api-1": started_api + "\n"},
            require_debug_http=True)
        self.assertEqual(summary, {"pods": 2, "lines": 3, "debug_http_events": 1})
        self.assertIsNone(smoke.evaluate_structured_logs("api", {"api-0": started_api}, require_debug_http=True))
        self.assertIsNone(smoke.evaluate_structured_logs("worker", {"worker-0": ""}))
        for bad in (
            "not json",
            "[]",
            json.dumps({"timestamp": "t", "level": "INFO", "event": "x", "message": "forbidden"}),
            json.dumps({"timestamp": "t", "level": "INFO", "event": "x", "unknown": 1}),
            json.dumps({"timestamp": "t", "level": "TRACE", "event": "x"}),
            json.dumps({"level": "INFO", "event": "x"}),
            json.dumps({"timestamp": "t", "level": "INFO"}),
        ):
            with self.subTest(bad=bad), self.assertRaises(smoke.SmokeFailure):
                smoke.parse_structured_logs(bad, "api")

    def test_check_auth_mounts_and_worker_isolation(self):
        def api_pod():
            return {"spec": {
                "securityContext": {"fsGroup": 65532},
                "volumes": [
                    {"name": "auth-config", "configMap": {
                        "name": smoke.AUTH_CONFIG_MAP, "defaultMode": 420,
                        "items": [{"key": "auth.json", "path": "auth.json"},
                                  {"key": smoke.AUTH_CATALOG_KEY, "path": smoke.AUTH_CATALOG_KEY}]}},
                    {"name": "auth-login-keys", "secret": {
                        "secretName": smoke.AUTH_LOGIN_KEYS_SECRET, "defaultMode": smoke.AUTH_SECRET_MODE}},
                ],
                "containers": [{"name": "api", "volumeMounts": [
                    {"name": "auth-config", "mountPath": smoke.AUTH_CONFIG_DIR, "readOnly": True},
                    {"name": "auth-login-keys", "mountPath": smoke.AUTH_KEYS_DIR, "readOnly": True},
                ], "env": [{"name": "OPENMETTLE_API_AUTH_CONFIG", "value": smoke.AUTH_CONFIG_PATH}]}],
            }}

        def worker_pod():
            return {"spec": {"securityContext": {"fsGroup": 65532}, "volumes": [],
                             "containers": [{"name": "worker", "volumeMounts": [], "env": []}]}}

        summary = smoke.check_auth_mounts({"api": [api_pod(), api_pod()], "worker": [worker_pod()]})
        self.assertEqual(summary, {
            "api_pods": 2, "config_path": smoke.AUTH_CONFIG_PATH, "catalog_path": smoke.AUTH_CATALOG_PATH,
            "keys_dir": smoke.AUTH_KEYS_DIR, "secret_mode": smoke.AUTH_SECRET_MODE, "worker_isolated": True,
        })
        no_catalog = api_pod()
        no_catalog["spec"]["volumes"][0]["configMap"]["items"].pop()
        with self.assertRaisesRegex(smoke.SmokeFailure, "does not project the model catalog"):
            smoke.check_auth_mounts({"api": [no_catalog], "worker": [worker_pod()]})
        bad_mode = api_pod()
        bad_mode["spec"]["volumes"][1]["secret"]["defaultMode"] = 420
        with self.assertRaisesRegex(smoke.SmokeFailure, "mode 0440"):
            smoke.check_auth_mounts({"api": [bad_mode], "worker": [worker_pod()]})
        rw_mount = api_pod()
        rw_mount["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
        with self.assertRaisesRegex(smoke.SmokeFailure, "read-only"):
            smoke.check_auth_mounts({"api": [rw_mount], "worker": [worker_pod()]})
        wrong_container = api_pod()
        wrong_container["spec"]["containers"][0]["name"] = "sidecar"
        with self.assertRaisesRegex(smoke.SmokeFailure, "no container named 'api'"):
            smoke.check_auth_mounts({"api": [wrong_container], "worker": [worker_pod()]})
        leak_vol = worker_pod()
        leak_vol["spec"]["volumes"] = [{"name": "auth-login-keys"}]
        with self.assertRaisesRegex(smoke.SmokeFailure, "worker pod must not attach auth volumes"):
            smoke.check_auth_mounts({"api": [api_pod()], "worker": [leak_vol]})

    def test_check_issuance_env_default_and_enabled(self):
        def pod(role, env):
            return {"spec": {"containers": [{"name": role, "env": env}]}}

        base = [{"name": "OPENMETTLE_API_BIND", "value": "0.0.0.0:8080"}]
        worker = pod("worker", [{"name": "OPENMETTLE_WORKER_BIND", "value": "0.0.0.0:8081"}])
        self.assertEqual(smoke.check_issuance_env({"api": [pod("api", base)], "worker": [worker]}, HOOKS, enabled=False),
                         {"api_pods": 1, "api_issuance_env": False, "issuance_pool": None,
                          "worker_isolated": True, "migrate_isolated": True})
        enabled = pod("api", base + issuance_env())
        self.assertEqual(smoke.check_issuance_env({"api": [enabled, enabled], "worker": [worker]}, HOOKS, enabled=True),
                         {"api_pods": 2, "api_issuance_env": True, "issuance_pool": "2",
                          "worker_isolated": True, "migrate_isolated": True})
        explicit = pod("api", base + issuance_env())
        explicit["spec"]["containers"][0]["env"][1]["valueFrom"]["secretKeyRef"]["optional"] = False
        smoke.check_issuance_env({"api": [explicit], "worker": [worker]}, HOOKS, enabled=True)

        def api_with(mutate):
            env = base + issuance_env()
            mutate(env)
            return pod("api", env)

        failures = {
            "without auth": ({"api": [enabled], "worker": [worker]}, HOOKS, False),
            "issuance env is": ({"api": [pod("api", base)], "worker": [worker]}, HOOKS, True),
            "required reference": ({"api": [api_with(lambda e: e[1]["valueFrom"]["secretKeyRef"].__setitem__(
                "optional", True))], "worker": [worker]}, HOOKS, True),
            "Secret openmettle-issuance-database key url": ({"api": [api_with(lambda e: e[1]["valueFrom"][
                "secretKeyRef"].__setitem__("name", smoke.SECRET["api"]))], "worker": [worker]}, HOOKS, True),
            "is not a required": ({"api": [api_with(lambda e: e.__setitem__(1, {
                "name": smoke.ISSUANCE_URL_ENV, "value": "postgres://x"}))], "worker": [worker]}, HOOKS, True),
            "DB_MAX_CONNECTIONS is not 2": ({"api": [api_with(lambda e: e[2].__setitem__("value", "4"))],
                                             "worker": [worker]}, HOOKS, True),
            "worker pod must not": ({"api": [enabled], "worker": [pod("worker", issuance_env()[:1])]}, HOOKS, True),
            "worker pod must not receive": ({"api": [pod("api", base)], "worker": [pod("worker", [
                {"name": "OPENMETTLE_WORKER_DATABASE_URL",
                 "valueFrom": {"secretKeyRef": {"name": smoke.SECRET["issuance"], "key": "url"}}}])]}, HOOKS, False),
            "migrate hook Job must not": ({"api": [enabled], "worker": [worker]},
                                          HOOKS + f"            - name: {smoke.ISSUANCE_URL_ENV}\n", True),
            "do not contain the migrate Job": ({"api": [enabled], "worker": [worker]}, "", True),
            "no container named 'api'": ({"api": [pod("sidecar", base)], "worker": [worker]}, HOOKS, False),
            "pods are required": ({"api": [enabled], "worker": []}, HOOKS, True),
        }
        for message, (pods_by_role, hooks, flag) in failures.items():
            with self.subTest(message), self.assertRaisesRegex(smoke.SmokeFailure, re.escape(message)):
                smoke.check_issuance_env(pods_by_role, hooks, enabled=flag)

    def test_evaluate_mounted_auth_http(self):
        good = {
            "/auth/session": (403, "session origin refused\n"),
            "/auth/native/session": (403, "native sign-in refused\n"),
            "/v1/capabilities": (401, json.dumps({"status": 401, "code": "unauthenticated"})),
        }
        self.assertEqual(smoke.evaluate_mounted_auth_http(good), {
            "/auth/session": 403, "/auth/native/session": 403,
            "/v1/capabilities": 401, "v1_error_code": "unauthenticated",
        })
        for bad in (
            {**good, "/auth/session": (404, "")},
            {**good, "/auth/native/session": (404, "")},
            {**good, "/v1/capabilities": (404, "")},
            {**good, "/v1/capabilities": (401, "not json")},
            {**good, "/v1/capabilities": (401, json.dumps({"status": 401, "code": "other"}))},
        ):
            with self.subTest(bad=bad), self.assertRaises(smoke.SmokeFailure):
                smoke.evaluate_mounted_auth_http(bad)


def revision_document(payload=smoke.ARTIFACT_PAYLOADS[0], revision=1):
    return {"artifact_id": "00000000-0000-4000-8000-000000000001", "revision_id": "00000000-0000-4000-9000-000000000001",
            "revision": str(revision), "scope_kind": "personal", "scope_id": "00000000-0000-4000-a000-000000000001",
            "project_id": None, "media_type": "text/plain", "size_bytes": str(len(payload)),
            "sha256": hashlib.sha256(payload).hexdigest(), "display_name": "smoke.txt", "state": "active",
            "created_at": "2026-11-20T10:00:00Z"}


class RunAdmissionTest(unittest.TestCase):
    def test_query_reads_every_check_in_one_row(self):
        sql = smoke.run_admission_sql()
        self.assertTrue(sql.startswith("SELECT ") and sql.endswith(";"))
        for expression, _ in smoke.RUN_ADMISSION_CHECKS:
            self.assertIn(expression, sql)
        self.assertNotIn("FROM openmettle.runs", sql)

    def test_checks_cover_migration_19_grants_and_api_denials(self):
        checks = dict(smoke.RUN_ADMISSION_CHECKS)
        lock = smoke.RUN_DISPATCH_LOCK
        self.assertIs(checks[f"has_column_privilege('openmettle_worker', '{lock}', 'lock_guard', 'UPDATE')"], True)
        self.assertIs(checks[f"has_table_privilege('openmettle_worker', '{lock}', 'UPDATE')"], False)
        for column in ("actor_approval_id", "round_limit", "queue_expires_at"):
            self.assertIs(checks[f"has_column_privilege('openmettle_api', 'openmettle.runs', '{column}', 'INSERT')"],
                          True)
        for privilege in ("SELECT", "UPDATE"):
            self.assertIs(checks[f"has_any_column_privilege('openmettle_api', '{lock}', '{privilege}')"], False)

    def test_migration_20_column_grants(self):
        checks = dict(smoke.RUN_ADMISSION_CHECKS)
        for role, writable in (("openmettle_worker", {"lease_expires_at", "execution_expires_at", "cancel_reason"}),
                               ("openmettle_api", {"cancel_reason"})):
            for column in ("lease_expires_at", "execution_expires_at", "cancel_reason"):
                self.assertIs(checks[f"has_column_privilege('{role}', 'openmettle.runs', '{column}', 'UPDATE')"],
                              column in writable)

    def test_evaluate(self):
        good = "|".join("t" if value else "f" for _, value in smoke.RUN_ADMISSION_CHECKS)
        self.assertEqual(smoke.evaluate_run_admission(good + "\n"),
                         {"dispatch_lock_singleton": True, "privileges_checked": len(smoke.RUN_ADMISSION_CHECKS) - 1})
        flipped = good.split("|")
        flipped[-1] = "t"
        with self.assertRaisesRegex(smoke.SmokeFailure, r"'UPDATE'\) is 't', expected 'f'"):
            smoke.evaluate_run_admission("|".join(flipped))
        for output in ("", good + "|t", good.rsplit("|", 1)[0]):
            with self.assertRaisesRegex(smoke.SmokeFailure, "privilege query returned"):
                smoke.evaluate_run_admission(output)
        # psql prints NULL (an empty dispatch-lock table under bool_and) as an empty field.
        with self.assertRaisesRegex(smoke.SmokeFailure, "is '', expected 't'"):
            smoke.evaluate_run_admission("|" + good.split("|", 1)[1])


class IngressReplayTest(unittest.TestCase):
    def test_sse_frames_require_the_complete_wire_contract(self):
        source = io.BytesIO(b': heartbeat\n\nid: c_1\ndata: {"sequence":"1"}\n\n')
        self.assertEqual(smoke.sse_frame(source), "heartbeat")
        self.assertEqual(smoke.sse_frame(source), ("c_1", {"sequence": "1"}))
        self.assertIsNone(smoke.sse_frame(source))
        for body in (b": hi\n\n", b": heartbeat\n", b"id: \n", b"id: c=\n", b"id: " + b"x"*513 + b"\n",
                     b"id: c\ndata: {}\n", b"id: c\nevent: run.failed\n\n", b"id: c\ndata: []\n\n",
                     b"id: c\ndata: {\n\n", b"id: c\ndata: " + b"x"*131080 + b"\n\n"):
            with self.subTest(length=len(body), prefix=body[:20]), self.assertRaises(smoke.SmokeFailure):
                smoke.sse_frame(io.BytesIO(body))

    def test_only_ordered_events_of_this_run_are_accepted_before_the_deadline(self):
        event = {"run_id": RUN_ID, "sequence": "2", "type": "run.failed", "type_version": 1,
                 "occurred_at": "2026-11-21T00:00:00Z", "data": {"reason": "queue_expired"}}
        def next_item(item, deadline=5):
            frame = io.BytesIO(f"id: end\ndata: {json.dumps(item)}\n\n".encode())
            return smoke.expect_event(frame, RUN_ID, 2, "run.failed", event["data"], deadline=deadline)
        with mock.patch.object(smoke, "time", FakeClock()):
            self.assertEqual(next_item(event), ("end", event))
            for change in ({"run_id": ""}, {"sequence": "1"}, {"sequence": "3"}, {"type": "run.cancelled"},
                           {"data": {}}, {"type_version": True}, {"occurred_at": None}):
                with self.subTest(change=change), self.assertRaises(smoke.SmokeFailure):
                    next_item({**event, **change})
            with self.assertRaisesRegex(smoke.SmokeFailure, "timed out"):
                next_item(event, deadline=0)

    def test_quiet_window_rejects_buffered_or_missing_heartbeats_and_duplicate_events(self):
        beat = b": heartbeat\n\n"
        for body, delay in ((beat * 2, {0: 30}), (beat * 2, {0: 15}), (beat, {0: 15}),
                            (b"id: start\ndata: {}\n\n", {})):
            with self.subTest(body=body, delay=delay), mock.patch.object(smoke, "time", FakeClock()):
                with self.assertRaises(smoke.SmokeFailure):
                    smoke.quiet_heartbeats(IngressResponse(200, body, delays=delay))

    def test_nonstreaming_headers_and_missing_opening_flush_fail(self):
        for status, streaming, body, extra in ((204, True, b"", []), (200, False, b"", []),
                (200, True, b"", []), (200, True, b": heartbeat\n\n", [("X-Accel-Buffering", "yes")]),
                (200, True, b": heartbeat\n\n", [("Content-Length", "13")])):
            response = IngressResponse(status, body, stream=streaming)
            response.getheaders = mock.Mock(return_value=[*response.getheaders(), *extra])
            with self.subTest(status=status, extra=extra), mock.patch.object(smoke, "ingress_get", return_value=response):
                with self.assertRaises(smoke.SmokeFailure), smoke.event_stream(8443, None, "/events", {}):
                    pass

    def test_snapshot_requires_the_same_terminal_event_state_sequence_and_cursor(self):
        terminal = {"sequence": "2", "type": "run.failed", "data": {"reason": "queue_expired"}}
        doc = {"run_id": RUN_ID, "state": "failed", "last_sequence": "2", "resume_cursor": "end", "terminal": terminal}
        smoke.check_snapshot(json.dumps(doc), RUN_ID, "end", terminal)
        for field, value in (("run_id", "another"), ("state", "queued"), ("last_sequence", "1"),
                             ("resume_cursor", "start"), ("terminal", None)):
            with self.subTest(field=field), self.assertRaises(smoke.SmokeFailure):
                smoke.check_snapshot(json.dumps({**doc, field: value}), RUN_ID, "end", terminal)

    def test_snapshot_rejects_malformed_json_and_non_objects(self):
        for body in (b"{", b"\xff", b"[]", b"null", b"false", b"1", b'"text"'):
            with self.subTest(body=body), self.assertRaisesRegex(smoke.SmokeFailure, "getRun snapshot body"):
                smoke.check_snapshot(body, RUN_ID, "start", None)

    def test_reservation_lease_and_expiry_must_match_the_one_admitted_row(self):
        harness = object.__new__(smoke.Smoke)
        good = f"{RUN_ID}|failed|12|1234|t|1"
        harness.psql = mock.Mock(return_value=good)
        self.assertEqual(harness.run_row(RUN_ID, "failed"), ("12", "1234"))
        for output in ("", good + "\n" + good, good.replace("|t|", "|f|"), good[:-1] + "0",
                       good.replace("|failed|", "|running|"), good.replace("|1234|", "||")):
            with self.subTest(output=output), self.assertRaises(smoke.SmokeFailure):
                harness.psql.return_value = output
                harness.run_row(RUN_ID, "failed")

    def test_verified_https_sni_host_and_cursor_over_chunked_transport(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_GET(self):
                seen.append((self.headers["Host"], self.headers["Last-Event-ID"]))
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for chunk in (b": heart", b"beat\n\nid:", b" next\ndata: {", b"}\n\n"):
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            def log_message(self, *_args):
                pass

        seen = []
        with tempfile.TemporaryDirectory() as directory:
            cert, key = (Path(directory) / name for name in ("cert.pem", "key.pem"))
            subprocess.run(smoke.ingress_certificate_command(cert, key), check=True, capture_output=True)
            tls = smoke.ssl.SSLContext(smoke.ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            tls.set_servername_callback(lambda sock, name, ctx: seen.append(name))
            with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.handle_request, daemon=True)
                thread.start()
                with smoke.ingress_get(server.server_port, smoke.ssl.create_default_context(cafile=str(cert)),
                                       "/events", {"Last-Event-ID": "start"}) as response:
                    self.assertEqual(smoke.sse_frame(response), "heartbeat")
                    self.assertEqual(smoke.sse_frame(response), ("next", {}))
                    self.assertIsNone(smoke.sse_frame(response))
                thread.join(5)
        self.assertEqual(seen, [smoke.INGRESS_HOST, (smoke.INGRESS_HOST, "start")])


class FreshBootstrapTest(unittest.TestCase):
    def test_query_reads_both_singleton_markers(self):
        sql = smoke.FRESH_BOOTSTRAP_SQL
        for fragment in ("metering_enforced AND metering_enforced_at IS NOT NULL", "overrides_enforced AND",
                         "overrides_enforced_at IS NOT NULL", "bootstrap_auto_pin_allowed AND volume_id IS NULL",
                         "FROM openmettle.quota_enforcement CROSS JOIN openmettle.storage_volume_control;"):
            self.assertIn(fragment, sql)

    def test_evaluate(self):
        self.assertEqual(smoke.evaluate_fresh_bootstrap("t|t\n"), {
            "metering_and_overrides_enforced": True, "artifact_volume_unpinned_auto_pin_allowed": True})
        # An upgraded database (f|f), a pinned volume (t|f), a NULL marker or a missing row all fail.
        for output in ("f|f", "t|f", "f|t", "|t", "", "t|t|t"):
            with self.subTest(output=output), self.assertRaisesRegex(smoke.SmokeFailure, "expected 't\\|t'"):
                smoke.evaluate_fresh_bootstrap(output)


class QuotaRoutesTest(unittest.TestCase):
    PROBLEM = {"type": "about:blank", "title": "t", "status": 401, "detail": "d", "code": "unauthenticated",
               "request_id": "11111111-1111-4111-8111-111111111111"}
    HEADERS = {"openmettle-api-version": smoke.V1_API_VERSION, "cache-control": "no-store",
               "content-type": "application/problem+json"}

    def responses(self, status=401, headers=None, body=None):
        body = json.dumps(self.PROBLEM).encode() if body is None else body
        return {f"{m} {p}": (status, dict(self.HEADERS if headers is None else headers), body)
                for m, p in smoke.QUOTA_ROUTES}

    def test_routes_cover_the_four_quota_operations(self):
        self.assertEqual([m for m, _ in smoke.QUOTA_ROUTES], ["GET", "GET", "PUT", "POST"])
        self.assertEqual([p.replace(smoke.QUOTA_SCOPE, "{id}") for _, p in smoke.QUOTA_ROUTES], [
            "/v1/quotas/personal", "/v1/projects/{id}/quotas", "/v1/admin/scopes/{id}/quotas/usage_tokens",
            "/v1/admin/scopes/{id}/quotas/usage_tokens/revoke"])
        self.assertRegex(smoke.QUOTA_SCOPE, smoke.UUID)

    def test_mounted_requires_a_versioned_unauthenticated_problem(self):
        self.assertEqual(smoke.evaluate_quota_routes(self.responses(), mounted=True),
                         {f"{m} {p}": 401 for m, p in smoke.QUOTA_ROUTES})
        problem = "unexpected 401 problem"
        cases = [
            ("HTTP 404, expected 401", self.responses(status=404)),
            ("missing OpenMettle-API-Version", self.responses(headers={**self.HEADERS, "cache-control": "max-age=60"})),
            ("401 body is not JSON", self.responses(body=b"unauthorized")),
            (problem, self.responses(body=json.dumps({**self.PROBLEM, "code": "forbidden"}).encode())),
            (problem, self.responses(body=json.dumps({**self.PROBLEM, "status": 403}).encode())),
            (problem, self.responses(body=b"[]")),
            (problem, self.responses(headers={**self.HEADERS, "content-type": "application/json"})),
        ]
        for message, responses in cases:
            with self.subTest(message), self.assertRaisesRegex(smoke.SmokeFailure, re.escape(message)):
                smoke.evaluate_quota_routes(responses, mounted=True)
        partial = self.responses()
        missing = f"{smoke.QUOTA_ROUTES[-1][0]} {smoke.QUOTA_ROUTES[-1][1]}"
        del partial[missing]
        with self.assertRaisesRegex(smoke.SmokeFailure, re.escape(f"{missing}: no response")):
            smoke.evaluate_quota_routes(partial, mounted=True)

    def test_unmounted_requires_404(self):
        self.assertEqual(smoke.evaluate_quota_routes(self.responses(404, {}, b""), mounted=False),
                         {f"{m} {p}": 404 for m, p in smoke.QUOTA_ROUTES})
        for status in (401, 200, 405):
            with self.subTest(status=status), self.assertRaisesRegex(smoke.SmokeFailure, "expected 404"):
                smoke.evaluate_quota_routes(self.responses(status), mounted=False)


class HttpAdmissionTest(unittest.TestCase):
    ROOT = {"conversation_id": "00000000-0000-4000-b000-000000000001",
            "branch_id": "00000000-0000-4000-b000-000000000002"}
    RUN = {"run_id": "00000000-0000-4000-c000-000000000001", "state": "queued"}

    def test_smoke_catalog_adds_prompt_bound_to_the_preset_model_only(self):
        catalog = smoke.smoke_catalog(CATALOG_FIXTURE)
        self.assertEqual(catalog["models"]["a"],
                         {"pin": _PIN_A, "output_limit": 4096, "prompt_bound": smoke.PROMPT_BOUND})
        self.assertEqual(catalog["models"]["b"], {"pin": _PIN_B})
        self.assertNotIn("prompt_bound", CATALOG_FIXTURE["models"]["a"])  # the fixture is not modified
        for broken in ({**CATALOG_FIXTURE, "presets": {}},
                       {**CATALOG_FIXTURE, "presets": {"study": {"model": "b"}}},
                       {**CATALOG_FIXTURE, "models": {}}):
            with self.subTest(broken=broken), self.assertRaises(smoke.SmokeFailure):
                smoke.smoke_catalog(broken)

    def test_run_request_appends_one_text_turn_with_the_preset(self):
        message = "00000000-0000-4000-d000-000000000001"
        self.assertEqual(smoke.run_request(self.ROOT, message), {
            **self.ROOT, "proposal": {"expected_head_message_id": None,
                                      "turn": {"mode": "append", "input_message_id": message,
                                               "parts": [{"text": "kind smoke admission"}]},
                                      "selection": {"preset": smoke.CATALOG_PRESET}}})
        with self.assertRaisesRegex(smoke.SmokeFailure, "branch_id is not a canonical UUID"):
            smoke.run_request({**self.ROOT, "branch_id": "x"}, message)

    def test_evaluate_http_admission(self):
        models = {"items": [{"model_id": "b"}, {"model_id": "a"}]}
        cancelled = {**self.RUN, "state": "cancelled"}
        self.assertEqual(smoke.evaluate_http_admission(models, self.RUN, self.RUN, cancelled),
                         {"models": ["a", "b"], "admitted": "queued", "replay": "same run", "cancelled": "cancelled"})
        other = {**self.RUN, "run_id": "00000000-0000-4000-c000-000000000002"}
        for args, message in (
            (({"items": [{"model_id": "b"}]}, self.RUN, self.RUN, cancelled), "does not list catalog model"),
            ((models, {**self.RUN, "state": "running"}, self.RUN, cancelled), "expected a queued run"),
            ((models, self.RUN, other, cancelled), "did not replay the same queued run"),
            ((models, self.RUN, self.RUN, self.RUN), "expected 'cancelled'"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(smoke.SmokeFailure, message):
                smoke.evaluate_http_admission(*args)

    def test_v1_json(self):
        headers = {"openmettle-api-version": "1.0", "cache-control": "no-store"}
        self.assertEqual(smoke.v1_json("x", (200, headers, b'{"a": 1}'), 200), {"a": 1})
        for body in (b"[]", b"not json"):
            with self.subTest(body=body), self.assertRaises(smoke.SmokeFailure):
                smoke.v1_json("x", (200, headers, body), 200)


class SessionSeedTest(unittest.TestCase):
    RAW = bytes(range(64))

    def test_credential_matches_core_framing(self):
        session_id, cookie, secret_hash = smoke.session_credential(self.RAW)
        self.assertEqual(session_id, base64.urlsafe_b64encode(self.RAW[:32]).decode().rstrip("="))
        self.assertEqual(len(cookie), 87)  # core sessions::parse requires exactly 87 bytes
        self.assertEqual(cookie.split("."), [session_id, base64.urlsafe_b64encode(self.RAW[32:]).decode().rstrip("=")])
        self.assertEqual(session_hash(cookie), (session_id, secret_hash))
        self.assertNotEqual(smoke.session_credential(bytes(64))[2], secret_hash)
        with self.assertRaises(ValueError):
            smoke.session_credential(bytes(63))

    def test_seed_stores_only_the_hash_and_configures_storage_limits(self):
        session_id, cookie, secret_hash = smoke.session_credential(self.RAW)
        login = smoke.b64url(bytes(32))
        sql = smoke.session_seed_sql(session_id, secret_hash, login)
        self.assertNotIn(cookie.split(".")[1], sql)
        self.assertIn(f"SELECT '{session_id}', decode('{secret_hash}', 'hex'), '{login}'", sql)
        self.assertIn(f"SET instance_budget_bytes = {smoke.STORAGE_LIMIT_BYTES}, "
                      f"personal_limit_bytes = {smoke.STORAGE_LIMIT_BYTES}", sql)
        # A fresh install enforces metering: admission needs the personal usage_tokens limit.
        self.assertIn("INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)\n"
                      f"    VALUES ('personal', 'usage_tokens', {smoke.PERSONAL_TOKEN_LIMIT});", sql)
        self.assertGreater(smoke.PERSONAL_TOKEN_LIMIT, 0)
        self.assertGreater(smoke.STORAGE_LIMIT_BYTES, 2 * smoke.ARTIFACT_MAX_BYTES)
        self.assertGreaterEqual(smoke.ARTIFACT_MAX_BYTES, max(map(len, smoke.ARTIFACT_PAYLOADS)))
        for table in ("login_providers", "login_provider_revisions", "users", "scopes", "user_identities",
                      "local_identity_approvals", "login_nonce_reservations", "login_transactions", "local_sessions"):
            self.assertIn(f"INSERT INTO openmettle.{table} ", sql)
        # The seeded provider is not the auth document's; validation reads only the database.
        self.assertNotIn(smoke.SESSION_IDS["provider"], json.dumps(smoke.smoke_auth_document()))

    def test_seed_refuses_values_that_could_alter_the_sql(self):
        session_id, _, secret_hash = smoke.session_credential(self.RAW)
        login = smoke.b64url(bytes(32))
        for args in ((session_id + "'", secret_hash, login), (session_id, secret_hash.upper(), login),
                     (session_id, secret_hash, "x';--"), (session_id[:-1], secret_hash, login)):
            with self.assertRaises(smoke.SmokeFailure):
                smoke.session_seed_sql(*args)


class ArtifactHttpTest(unittest.TestCase):
    PAYLOAD = smoke.ARTIFACT_PAYLOADS[1]

    def test_multipart_form_in_either_order(self):
        boundary = smoke.ARTIFACT_BOUNDARIES[0]
        content_type = f"multipart/form-data; boundary={boundary}"
        metadata_first = smoke.multipart_form(boundary, self.PAYLOAD)
        file_first = smoke.multipart_form(boundary, self.PAYLOAD, file_first=True)
        expected = {"metadata": (None, "application/json", b"{}"), "file": ("smoke.txt", "text/plain", self.PAYLOAD)}
        self.assertEqual(parse_form(content_type, metadata_first), expected)
        self.assertEqual(parse_form(content_type, file_first), expected)
        self.assertLess(metadata_first.index(b'name="metadata"'), metadata_first.index(b'name="file"'))
        self.assertLess(file_first.index(b'name="file"'), file_first.index(b'name="metadata"'))
        self.assertTrue(metadata_first.startswith(f"--{boundary}\r\n".encode()))
        self.assertTrue(metadata_first.endswith(f"\r\n--{boundary}--\r\n".encode()))
        for payload in smoke.ARTIFACT_PAYLOADS:
            for candidate in smoke.ARTIFACT_BOUNDARIES:
                self.assertNotIn(candidate.encode(), payload)

    def test_v1_headers(self):
        self.assertEqual(smoke.v1_headers("c"), {"Cookie": "__Host-openmettle-session=c",
                                                 "Origin": "https://app.example.test"})
        self.assertEqual(smoke.v1_headers("c", key="k", boundary="b", byte_range="bytes=0-9"), {
            "Cookie": "__Host-openmettle-session=c", "Origin": "https://app.example.test", "Idempotency-Key": "k",
            "Content-Type": "multipart/form-data; boundary=b", "Range": "bytes=0-9"})
        self.assertEqual(smoke.smoke_auth_document()["browser"]["origin"], smoke.AUTH_ORIGIN)

    def test_expect_v1(self):
        headers = {"openmettle-api-version": "1.0", "cache-control": "no-store"}
        self.assertEqual(smoke.expect_v1("x", (201, headers, b"{}"), 201), (headers, b"{}"))
        with self.assertRaisesRegex(smoke.SmokeFailure, r"x: HTTP 404, expected 201: b'nope'"):
            smoke.expect_v1("x", (404, headers, b"nope"), 201)
        for missing in headers:
            with self.assertRaisesRegex(smoke.SmokeFailure, "missing OpenMettle-API-Version"):
                smoke.expect_v1("x", (201, {k: v for k, v in headers.items() if k != missing}, b"{}"), 201)
        with self.assertRaises(smoke.SmokeFailure):
            smoke.expect_v1("x", (201, {**headers, "openmettle-api-version": "2.0"}, b"{}"), 201)

    def test_evaluate_artifact_revision(self):
        document = revision_document(self.PAYLOAD, 2)
        self.assertEqual(smoke.evaluate_artifact_revision(json.dumps(document).encode(), self.PAYLOAD, 2), document)
        doctored = {"state": "pending", "revision": 2, "size_bytes": len(self.PAYLOAD), "sha256": "0" * 64,
                    "display_name": "other.txt", "media_type": "application/octet-stream",
                    "scope_kind": "project", "project_id": "00000000-0000-4000-b000-000000000001",
                    "artifact_id": "not-a-uuid", "revision_id": None, "scope_id": "ABC"}
        for key, value in doctored.items():
            with self.subTest(key), self.assertRaises(smoke.SmokeFailure):
                smoke.evaluate_artifact_revision(json.dumps({**document, key: value}).encode(), self.PAYLOAD, 2)
        for body in (b"not json", b"[]"):
            with self.assertRaises(smoke.SmokeFailure):
                smoke.evaluate_artifact_revision(body, self.PAYLOAD, 2)
        with self.assertRaises(smoke.SmokeFailure):
            smoke.evaluate_artifact_revision(json.dumps(document).encode(), self.PAYLOAD, 1)

    def downloads(self):
        total = len(self.PAYLOAD)
        full = {"content-type": "text/plain", "content-length": str(total), "accept-ranges": "bytes",
                "x-content-type-options": "nosniff", "content-disposition": "attachment; filename*=UTF-8''smoke.txt"}
        partial = {**full, "content-length": "10", "content-range": f"bytes 0-9/{total}"}
        refused = {"content-type": "application/problem+json", "content-range": f"bytes */{total}"}
        problem = json.dumps({"status": 416, "code": "range_not_satisfiable"}).encode()
        return [(full, self.PAYLOAD), (partial, self.PAYLOAD[:10]), (refused, problem)]

    def test_evaluate_artifact_downloads(self):
        self.assertEqual(smoke.evaluate_artifact_downloads(self.PAYLOAD, *self.downloads()), {
            "full_bytes": len(self.PAYLOAD), "range": "bytes=0-9", "range_status": 206, "unsatisfiable_status": 416})
        cases = {
            "full body": (0, None, self.PAYLOAD[:-1], "full download"),
            "full nosniff": (0, ("x-content-type-options", None), None, "full download"),
            "full accept-ranges": (0, ("accept-ranges", "none"), None, "full download"),
            "full disposition inline": (0, ("content-disposition", "inline"), None, "full download"),
            "full content-length": (0, ("content-length", "1"), None, "full download"),
            "range slice": (1, None, self.PAYLOAD[1:11], "range download"),
            "range header": (1, ("content-range", "bytes 0-9/*"), None, "range download"),
            "range length": (1, ("content-length", "37"), None, "range download"),
            "unsatisfiable content-range": (2, ("content-range", None), None, "unsatisfiable range"),
            "unsatisfiable media type": (2, ("content-type", "application/json"), None, "unsatisfiable range"),
            "unsatisfiable code": (2, None, json.dumps({"status": 416, "code": "validation"}).encode(),
                                   "unsatisfiable range"),
            "unsatisfiable body": (2, None, b"<html>", "unsatisfiable range body is not JSON"),
        }
        for name, (index, header, body, message) in cases.items():
            with self.subTest(name):
                responses = self.downloads()
                headers, original = responses[index]
                if header:
                    headers = {k: v for k, v in headers.items() if k != header[0]}
                    if header[1] is not None:
                        headers[header[0]] = header[1]
                responses[index] = (headers, original if body is None else body)
                with self.assertRaisesRegex(smoke.SmokeFailure, message):
                    smoke.evaluate_artifact_downloads(self.PAYLOAD, *responses)

    def test_http_exchange_against_a_loopback_server(self):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append((self.path, dict(self.headers), self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(206)
                self.send_header("Content-Range", "bytes 0-1/2")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        status, headers, body = smoke.http_exchange(server.server_port, "POST", "/v1/artifacts?max_bytes=1",
                                                    {"Origin": smoke.AUTH_ORIGIN}, b"\x00\xff")
        self.assertEqual((status, headers["content-range"], body), (206, "bytes 0-1/2", b"ok"))
        self.assertEqual(seen[0][0], "/v1/artifacts?max_bytes=1")
        self.assertEqual((seen[0][1]["Origin"], seen[0][2]), (smoke.AUTH_ORIGIN, b"\x00\xff"))


class FixtureTest(unittest.TestCase):
    def setUp(self):
        self.items = smoke.fixture_manifests("postgres@sha256:" + "e" * 64, PASSWORDS, "0a1b2c3d",
                                             smoke.smoke_catalog(CATALOG_FIXTURE))["items"]

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
        self.assertEqual(smoke.DB_LOGINS, ("api", "worker", "migrate", "issuance", "gateway"))
        for role in smoke.DB_LOGINS:
            secret = self.find("Secret", smoke.SECRET[role])
            self.assertEqual(secret["metadata"]["namespace"], smoke.APP_NAMESPACE)
            url = secret["stringData"]["url"]
            self.assertRegex(url, rf"^postgres://{smoke.DB_ROLE[role]}:{PASSWORDS[role]}@[^/]+/openmettle"
                                  r"\?sslmode=disable$")
        for login in ("migrate", "issuance", "gateway"):
            holders = [i["metadata"]["name"] for i in self.items if PASSWORDS[login] in json.dumps(i)]
            self.assertEqual(sorted(holders), sorted([smoke.SECRET[login], "postgres-fixture"]), login)

    def test_provisioning_follows_core_readme(self):
        fixture = self.find("Secret", "postgres-fixture")
        self.assertEqual(fixture["metadata"]["namespace"], smoke.DB_NAMESPACE)
        sql = fixture["stringData"]["provision.sql"]
        # Five disjoint login roles before migration 1: owner, api, issuance, worker and gateway.
        self.assertEqual(sorted(re.findall(r"CREATE ROLE (\w+) ", sql)),
                         ["openmettle_api", "openmettle_gateway", "openmettle_issuance", "openmettle_owner",
                          "openmettle_worker"])
        for role in smoke.DB_LOGINS:
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

    def test_creates_synthetic_auth_configmap_and_32_byte_login_key_secret(self):
        cm = self.find("ConfigMap", smoke.AUTH_CONFIG_MAP)
        self.assertEqual(cm["metadata"]["namespace"], smoke.APP_NAMESPACE)
        doc = json.loads(cm["data"]["auth.json"])
        self.assertEqual(doc["version"], 2)
        self.assertEqual(doc["login"]["keys"]["active"]["path"], smoke.AUTH_ACTIVE_KEY_PATH)
        cursor = doc["cursor_keys"]["active"]
        self.assertEqual(cursor["path"], f"{smoke.AUTH_KEYS_DIR}/cursor.key")
        self.assertNotEqual(cursor["id"], doc["login"]["keys"]["active"]["id"])
        self.assertIn("browser", doc)
        self.assertIn("native", doc)
        # Fresh POST /v1/runs needs catalog_file, admission_limits and cursor_keys together.
        self.assertEqual(doc["catalog_file"], smoke.AUTH_CATALOG_PATH)
        self.assertEqual(doc["admission_limits"], smoke.ADMISSION_LIMITS)
        self.assertEqual(json.loads(cm["data"][smoke.AUTH_CATALOG_KEY]), smoke.smoke_catalog(CATALOG_FIXTURE))
        self.assertEqual(sorted(cm["data"]), sorted(["auth.json", smoke.AUTH_CATALOG_KEY]))
        secret = self.find("Secret", smoke.AUTH_LOGIN_KEYS_SECRET)
        self.assertEqual(secret["metadata"]["namespace"], smoke.APP_NAMESPACE)
        login, cursor = (base64.b64decode(secret["data"][key], validate=True) for key in ("active.key", "cursor.key"))
        self.assertEqual((len(login), len(cursor)), (32, 32))
        self.assertNotEqual(login, cursor)

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
    def test_core_commit_single_source_of_truth(self):
        raw = (ROOT / "CORE_COMMIT").read_text(encoding="utf-8")
        self.assertRegex(raw, r"^[0-9a-f]{40}\n$")
        self.assertEqual(raw.strip(), smoke.CORE_COMMIT)
        for workflow in ("checks.yml", "kind-smoke.yml"):
            text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            self.assertEqual(re.findall(r"CORE_COMMIT: [0-9a-f]{40}", text), [], workflow)
            self.assertIn("< CORE_COMMIT", text, workflow)
        kind_smoke = (ROOT / ".github" / "workflows" / "kind-smoke.yml").read_text(encoding="utf-8")
        self.assertEqual(kind_smoke.count("      - CORE_COMMIT\n"), 2)
        self.assertTrue((ROOT / "tests" / "fixtures" / "core" / "process-contract.json").is_file())
        self.assertIn(smoke.CORE_COMMIT, (ROOT / "tests" / "fixtures" / "core" / "README.md").read_text(encoding="utf-8"))
        self.assertIn(smoke.CORE_COMMIT, (ROOT / "UPSTREAM.md").read_text(encoding="utf-8"))

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


class TelemetryContractParityTests(unittest.TestCase):
    def test_allowed_log_fields_include_metric_export_drops_and_match_core(self):
        """Fails if ALLOWED_LOG_FIELDS drifts from core telemetry::FIELDS plus flattened metadata."""
        self.assertIn("dropped_metric_exports", smoke.ALLOWED_LOG_FIELDS)
        self.assertIn("gateway.request_id", smoke.ALLOWED_LOG_FIELDS)
        core_dir = os.environ.get("OPENMETTLE_CORE_DIR")
        if not core_dir:
            return
        contract_path = Path(core_dir) / "contracts" / "telemetry" / "v1.json"
        self.assertTrue(
            contract_path.is_file(),
            f"OPENMETTLE_CORE_DIR is set ({core_dir}) but {contract_path} does not exist",
        )
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        expected = set(contract["logs"]["allowed_fields"]) | {"timestamp", "level"}
        self.assertEqual(smoke.ALLOWED_LOG_FIELDS, expected)


class GatewayAndInferenceHelpersTest(unittest.TestCase):
    """Unit tests for ADR 0044 gateway, worker.inference, stand-in and settlement smoke helpers."""

    def test_gateway_schema_sql_and_evaluate(self):
        sql = smoke.gateway_schema_sql()
        self.assertTrue(sql.startswith("SELECT ") and sql.endswith(";"))
        self.assertIn("openmettle.gateway_dispatch(uuid,bytea)", sql)
        self.assertIn("openmettle.gateway_dispatch_scoped(uuid,bytea)", sql)
        self.assertIn(smoke.GATEWAY_SETTLE_FN, sql)
        self.assertIn("to_regclass('openmettle.gateway_bindings') IS NULL", sql)
        for priv in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            self.assertIn(f"has_table_privilege('openmettle_gateway', cl.oid, '{priv}')", sql)
        for priv in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
            self.assertIn(f"has_any_column_privilege('openmettle_gateway', cl.oid, '{priv}')", sql)
        good = "|".join("t" if expected else "f" for _, expected in smoke.GATEWAY_SCHEMA_CHECKS)
        self.assertEqual(smoke.evaluate_gateway_schema(good + "\n"), {
            "gateway_function_only": True, "superseded_tables_absent": True,
            "checks": len(smoke.GATEWAY_SCHEMA_CHECKS),
        })
        flipped = good.split("|")
        flipped[3] = "t"
        with self.assertRaisesRegex(smoke.SmokeFailure, "migration 37 gateway boundary"):
            smoke.evaluate_gateway_schema("|".join(flipped))
        with self.assertRaisesRegex(smoke.SmokeFailure, "gateway privilege query returned"):
            smoke.evaluate_gateway_schema("t|t")

    def test_smoke_inference_document_plain_and_tls(self):
        catalog = smoke.smoke_catalog(CATALOG_FIXTURE)
        plain = smoke.smoke_inference_document(catalog, tls=False)
        tls = smoke.smoke_inference_document(catalog, tls=True)
        self.assertEqual(plain["version"], 1)
        self.assertEqual(plain["catalog_file"], smoke.INFERENCE_CATALOG_PATH)
        self.assertEqual(set(plain["routes"]), set(catalog["models"]))
        self.assertEqual(set(tls["routes"]), set(catalog["models"]))
        for model in catalog["models"]:
            self.assertTrue(plain["routes"][model]["endpoint"].startswith("http://"))
            self.assertNotIn("trust", plain["routes"][model])
            self.assertEqual(plain["routes"][model]["private_cidrs"], smoke.CLUSTER_PRIVATE_CIDRS)
            self.assertTrue(tls["routes"][model]["endpoint"].startswith("https://"))
            self.assertEqual(tls["routes"][model]["trust"],
                             {"roots": "bundle", "bundle_path": smoke.INFERENCE_CA_PATH})

    @unittest.skipIf(shutil.which("openssl") is None, "openssl not on PATH")
    def test_gateway_tls_commands_produce_verifiable_ca_and_leaf_cert(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca_cert, ca_key = root / "ca.crt", root / "ca.key"
            leaf_csr, leaf_key, leaf_ext, leaf_cert = (
                root / "leaf.csr", root / "leaf.key", root / "leaf.ext", root / "leaf.crt")
            ext_body, commands = smoke.gateway_tls_commands(ca_cert, ca_key, leaf_csr, leaf_key, leaf_ext, leaf_cert)
            leaf_ext.write_text(ext_body, encoding="utf-8")
            for cmd in commands:
                subprocess.run(cmd, check=True, capture_output=True)
            verified = subprocess.run(["openssl", "verify", "-CAfile", str(ca_cert), str(leaf_cert)],
                                      check=False, capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            text = subprocess.run(["openssl", "x509", "-in", str(leaf_cert), "-noout", "-text"],
                                  check=True, capture_output=True, text=True).stdout
            self.assertIn(f"DNS:{smoke.GATEWAY_TLS_HOST}", text)
            self.assertIn("CA:FALSE", text)
            self.assertIn("TLS Web Server Authentication", text)

    def test_standin_and_inference_fixture_manifests(self):
        standin = smoke.standin_manifests("openmettle-smoke.invalid/openmettle/sglang-standin:smoke-1", "1")["items"]
        dep = next(i for i in standin if i["kind"] == "Deployment")
        pod = dep["spec"]["template"]["spec"]
        self.assertEqual(pod["securityContext"], {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                                  "seccompProfile": {"type": "RuntimeDefault"}})
        self.assertEqual(pod["containers"][0]["imagePullPolicy"], "Never")
        self.assertTrue(pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"])
        fixtures = smoke.inference_fixture_manifests("PEM", smoke.smoke_catalog(CATALOG_FIXTURE), "1")["items"]
        names = {(i["kind"], i["metadata"]["name"]) for i in fixtures}
        self.assertEqual(names, {
            ("ConfigMap", smoke.INFERENCE_PLAIN_CONFIG_MAP),
            ("ConfigMap", smoke.INFERENCE_TLS_CONFIG_MAP),
            ("ConfigMap", smoke.INFERENCE_CA_CONFIG_MAP),
            ("Ingress", smoke.GATEWAY_TLS_INGRESS),
        })

    def test_gateway_probe_plan_controls(self):
        gw_host = f"{smoke.GATEWAY_WORKLOAD}.{smoke.APP_NAMESPACE}.svc.cluster.local"
        for tls in (False, True):
            plan = smoke.gateway_probe_plan(tls=tls)
            by_name = {p["name"]: p for p in plan}
            for p in plan:
                if p["expect"] == "deny":
                    self.assertIn(p["control"], by_name)
                    self.assertEqual(by_name[p["control"]]["expect"], "connect")
        # TLS mode must verify the gateway's own ingressFrom rejects an egress-unrestricted pod
        # in DB_NAMESPACE (same namespace as smoke-traefik, different pod labels).
        tls_plan = smoke.gateway_probe_plan(tls=True)
        db_deny = [p for p in tls_plan
                   if p["namespace"] == smoke.DB_NAMESPACE and p["workload"] == "postgres"
                   and p["expect"] == "deny" and gw_host in p["command"] and "8082" in p["command"]]
        self.assertEqual(len(db_deny), 1)
        self.assertTrue(db_deny[0]["http"])

    def test_evaluate_standin_record(self):
        req_id = "00000000-0000-4000-d000-000000000001"
        good = {"headers": {"x-request-id": [req_id]}, "body": {"model": smoke.CATALOG_MODEL, "cache_salt": "f" * 64}}
        self.assertEqual(smoke.evaluate_standin_record(good, req_id),
                         {"model": smoke.CATALOG_MODEL, "authorization_stripped": True, "cache_salt_len": 64})
        canary = "CANARY-SENSITIVE-VALUE"
        for bad, msg, expect_len in (
            ({"headers": {"authorization": ["Bearer x"], "x-request-id": [req_id]}, "body": good["body"]},
             "leaked Authorization", None),
            ({"headers": {"x-request-id": ["other"]}, "body": good["body"]}, "upstream x-request-id", None),
            ({"headers": good["headers"], "body": canary}, "upstream body is not a JSON object", len(canary)),
            ({"headers": good["headers"], "body": [canary]}, "upstream body is not a JSON object", None),
            ({"headers": good["headers"], "body": {"model": canary, "cache_salt": "f" * 64}},
             "upstream body model mismatch", len(canary)),
            ({"headers": good["headers"], "body": {"model": 123, "cache_salt": "f" * 64}},
             "upstream body model mismatch", None),
            ({"headers": good["headers"], "body": {"model": smoke.CATALOG_MODEL, "cache_salt": canary}},
             "cache_salt", len(canary)),
            ({"headers": good["headers"], "body": {"model": smoke.CATALOG_MODEL, "cache_salt": None}},
             "cache_salt", None),
        ):
            with self.subTest(msg=msg, body=str(bad["body"])[:20]):
                with self.assertRaisesRegex(smoke.SmokeFailure, msg) as ctx:
                    smoke.evaluate_standin_record(bad, req_id)
                err = str(ctx.exception)
                self.assertNotIn(canary, err)
                if expect_len is not None:
                    self.assertIn(f"len={expect_len}", err)
                    self.assertIn("type=str", err)

    def test_settled_round_sql_and_evaluate(self):
        run_id = "00000000-0000-4000-c000-000000000001"
        req_id = "00000000-0000-4000-d000-000000000001"
        self.assertIn(run_id, smoke.settled_round_sql(run_id))
        with self.assertRaises(smoke.SmokeFailure):
            smoke.settled_round_sql("not-a-uuid")
        self.assertIsNone(smoke.evaluate_settled_round(""))
        good = f"{req_id}|handed_off|t|t|1|11|7|t|settled|0|18\n"
        self.assertEqual(smoke.evaluate_settled_round(good),
                         {"request_id": req_id, "prompt_tokens": 11, "completion_tokens": 7, "settled_units": 18})
        for bad in (
            f"{req_id}|reserved|t|t|1|11|7|t|settled|0|18\n",
            f"{req_id}|handed_off|f|t|1|11|7|t|settled|0|18\n",
            f"{req_id}|handed_off|t|t|1|11|7|t|held|18|0\n",
            "bad-uuid|handed_off|t|t|1|11|7|t|settled|0|18\n",
            good + good,
        ):
            with self.subTest(bad=bad[:30]), self.assertRaises(smoke.SmokeFailure):
                smoke.evaluate_settled_round(bad)


if __name__ == "__main__":
    unittest.main()
