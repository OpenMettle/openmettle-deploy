#!/usr/bin/env python3
"""Install the openmettle-core chart on an ephemeral kind cluster (V1-32 I2 smoke test).

Test harness only; not an installer. It builds core's api, worker and migrate images from a
pinned core checkout, loads them into a uniquely named kind cluster classified `dev` and
installs the chart by image digest with a synthetic PostgreSQL fixture. It then checks:
migration hook, readiness, worker scaling, an idempotent upgrade, uninstall, absence of optional
packages and Pod Security `restricted` enforcement. Every assertion reads live cluster, Helm or
database state. Core's process-contract assertions are not repeated (core tests/kubernetes).

Safety guards, tool and image pins are imported from core tests/kubernetes/qualify.py at
CORE_COMMIT; see tests/kind/README.md. Requires Python 3.10+, docker, the pinned kind and
kubectl (core install-tools.sh) and the pinned Helm (tests/chart/install-tools.sh).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openmettle-core"
# The core commit whose images are built and whose harness pins and guards are imported. It must
# equal CORE_COMMIT in .github/workflows/checks.yml and tests/fixtures/core-<sha7> (unit-tested).
CORE_COMMIT = "5cd8a9dcdd31989eb09adb425115e3d187a5d0e7"
CORE_MODULE = Path("tests") / "kubernetes" / "qualify.py"
# Everything this harness takes from core's qualify.py.
CORE_IMPORTS = (
    "KIND_VERSION", "KUBECTL_VERSION", "NODE_IMAGE", "POSTGRES_IMAGE",
    "Refusal", "QualificationFailure", "Runner", "http_get",
    "check_opt_in", "check_tools", "check_docker_context", "check_cluster_absent",
    "check_cluster_identity", "child_environment",
)
HELM_VERSION = "v4.3.0"  # tests/chart/install-tools.sh
RELEASE = "openmettle-core"
FULLNAME = RELEASE  # the release name contains the chart name (templates/_helpers.tpl)
APP_NAMESPACE = "openmettle-smoke"
DB_NAMESPACE = "openmettle-smoke-db"
RUN_LABEL = "openmettle.dev/smoke-run"
ROLES = ("api", "worker", "migrate")
WORKLOADS = ("api", "worker")
# RFC 6761 reserves .invalid: the name never resolves. Images are never pulled (pullPolicy Never);
# the node's containerd resolves the digest reference locally (see README "Image digests").
REGISTRY = "openmettle-smoke.invalid"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SECRET = {"api": "openmettle-api-database", "worker": "openmettle-worker-database",
          "migrate": "openmettle-owner-database"}
DB_ROLE = {"api": "openmettle_api", "worker": "openmettle_worker", "migrate": "openmettle_owner"}
HELM_TIMEOUT = "300s"  # >= migration.activeDeadlineSeconds below
MIGRATION_DEADLINE_SECONDS = 120
OPTIONAL_KINDS = "networkpolicies,ingresses,persistentvolumeclaims,poddisruptionbudgets,resourceclaims,horizontalpodautoscalers"
RELEASE_KINDS = "deployments,replicasets,pods,services,serviceaccounts,jobs,configmaps,secrets"
ALLOWED_RESOURCES = {"cpu", "memory", "ephemeral-storage"}
PSA_DENIAL = 'violates PodSecurity "restricted'
SUMMARY_KEYS = {"result", "classification", "core_commit", "cluster", "release", "namespace",
                "tools", "images", "checks", "error", "cleanup_errors"}


class Refusal(Exception):
    """A smoke-specific guard refused to run; nothing was created."""


class SmokeFailure(Exception):
    """Observed cluster behaviour did not match the expectation."""


# --- Pure logic (unit-tested in test_smoke.py) ---------------------------------------------

def check_core_checkout(head: str, porcelain: str) -> None:
    """Refuse unless the core checkout is exactly CORE_COMMIT with no local changes."""
    if head.strip() != CORE_COMMIT:
        raise Refusal(f"core checkout must be at {CORE_COMMIT}, found {head.strip() or 'nothing'}")
    if porcelain.strip():
        raise Refusal("core checkout has local changes; images must build from the pinned commit")


def core_checkout_state(core_dir: Path) -> tuple:
    """(HEAD, `git status --porcelain`) of the core checkout, read before any core code runs."""
    def git(*args):
        return subprocess.run(["git", "-C", str(core_dir), *args], capture_output=True, text=True,
                              timeout=60, check=False).stdout
    return git("rev-parse", "HEAD"), git("status", "--porcelain")


def load_core(core_dir: Path):
    """Import core's qualify.py from a verified checkout without writing bytecode into it."""
    path = core_dir / CORE_MODULE
    if not path.is_file():
        raise Refusal(f"{CORE_MODULE} not found in {core_dir}")
    spec = importlib.util.spec_from_file_location("openmettle_core_qualify", path)
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    missing = [name for name in CORE_IMPORTS if not hasattr(module, name)]
    if missing:
        raise Refusal(f"core qualify.py lacks {', '.join(missing)}")
    return module


def smoke_environment(env: dict, workdir: Path, helm_dir: Path | None) -> dict:
    """Drop inherited Helm settings and keep Helm's cache and config inside the run directory.

    `env` is core's child_environment(), which already strips KUBECONFIG, Docker and kind
    overrides. Helm also honours HELM_KUBECONTEXT, HELM_NAMESPACE, HELM_DRIVER and others.
    """
    result = {k: v for k, v in env.items() if not k.startswith("HELM_")}
    for name in ("CACHE", "CONFIG", "DATA"):
        result[f"HELM_{name}_HOME"] = str(workdir / "helm" / name.lower())
    if helm_dir is not None:
        result["PATH"] = f"{helm_dir}{os.pathsep}{result.get('PATH', '')}"
    return result


def check_helm_version(output: str) -> None:
    if output.strip() != HELM_VERSION:
        raise Refusal(f"Helm {HELM_VERSION} required (use tests/chart/install-tools.sh)")


def parse_ctr_digest(output: str, name: str) -> str:
    """Return the target digest of image `name` from `ctr images ls` output."""
    rows = [line.split() for line in output.splitlines()[1:]]
    matches = [fields for fields in rows if fields and fields[0] == name]
    if len(matches) != 1:
        raise SmokeFailure(f"expected one containerd image named {name}, found {len(matches)}")
    fields = matches[0]
    if len(fields) < 3 or not DIGEST.fullmatch(fields[2]):
        raise SmokeFailure(f"containerd image {name} has no sha256 target digest")
    return fields[2]


def parse_cri_image_id(output: str) -> str:
    """Return status.id from `crictl inspecti -o json`."""
    try:
        image_id = json.loads(output)["status"]["id"]
    except (ValueError, KeyError, TypeError) as exc:
        raise SmokeFailure("crictl inspecti returned no image id") from exc
    if not isinstance(image_id, str) or not DIGEST.fullmatch(image_id):
        raise SmokeFailure("crictl inspecti returned a malformed image id")
    return image_id


def parse_cri_container_image_id(output: str) -> str:
    """Return the image id of the single container in `crictl ps --id <id> --output json`.

    `crictl ps` reports the container's image id directly. Unlike `crictl inspect`, its output
    carries no container environment, so no Secret value can reach the job log.
    """
    try:
        (container,) = json.loads(output)["containers"]
    except (ValueError, KeyError, TypeError) as exc:
        raise SmokeFailure("crictl ps did not return exactly one container") from exc
    candidates = [container.get("imageId"), (container.get("image") or {}).get("image"),
                  container.get("imageRef")]
    for candidate in candidates:
        if isinstance(candidate, str) and DIGEST.fullmatch(candidate):
            return candidate
    raise SmokeFailure("crictl ps reported no image id for the container")


def tag_reference(role: str, run_id: str) -> str:
    return f"{REGISTRY}/openmettle/{role}:smoke-{run_id}"


def digest_reference(role: str, digest: str) -> str:
    if role not in ROLES or not DIGEST.fullmatch(digest):
        raise SmokeFailure(f"invalid image role or digest for {role!r}")
    return f"{REGISTRY}/openmettle/{role}@{digest}"


def smoke_values(digests: dict, worker_replicas: int) -> dict:
    """Chart values for the smoke release. Shorter migration timeouts bound a hung hook."""
    if set(digests) != set(ROLES):
        raise SmokeFailure("a digest is required for each of api, worker and migrate")
    for role in ROLES:
        digest_reference(role, digests[role])
    if worker_replicas not in (1, 2):
        raise SmokeFailure("worker replicas must be 1 or 2")
    return {
        "images": {"pullPolicy": "Never", **{
            role: {"registry": REGISTRY, "repository": f"openmettle/{role}", "digest": digests[role]}
            for role in ROLES}},
        "database": {role: {"existingSecret": SECRET[role]} for role in ROLES},
        "worker": {"replicas": worker_replicas},
        "migration": {"activeDeadlineSeconds": MIGRATION_DEADLINE_SECONDS,
                      "settings": {"connectTimeoutMs": 5000, "lockTimeoutMs": 15000,
                                   "statementTimeoutMs": 60000}},
    }


def database_url(role: str, password: str) -> str:
    host = f"postgres.{DB_NAMESPACE}.svc.cluster.local"
    return f"postgres://{DB_ROLE[role]}:{password}@{host}:5432/openmettle?sslmode=disable"


def fixture_manifests(postgres_image: str, passwords: dict, run_id: str) -> dict:
    """Namespaces, a synthetic PostgreSQL fixture and the three URL Secrets the chart reads.

    passwords holds per-run random values for admin and each role in ROLES. Provisioning follows
    core README "Schema migrations": three login roles and one database owned by the owner role.
    """
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    sql = "".join(f"CREATE ROLE {DB_ROLE[role]} LOGIN PASSWORD '{passwords[role]}';\n"
                  for role in ROLES)
    sql += "CREATE DATABASE openmettle OWNER openmettle_owner;\n"
    selector = {"app.kubernetes.io/name": "postgres"}
    items = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": APP_NAMESPACE, "labels": {
            **labels, "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "latest"}}},
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": DB_NAMESPACE, "labels": labels}},
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": "postgres-fixture", "namespace": DB_NAMESPACE, "labels": labels},
         "stringData": {"admin-password": passwords["admin"], "provision.sql": sql}},
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": "postgres", "namespace": DB_NAMESPACE, "labels": labels},
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                  "selector": {"matchLabels": selector},
                  "template": {"metadata": {"labels": selector}, "spec": {
                      "automountServiceAccountToken": False, "enableServiceLinks": False,
                      "containers": [{
                          "name": "postgres", "image": postgres_image,
                          "imagePullPolicy": "IfNotPresent",
                          "env": [{"name": "POSTGRES_USER", "value": "fixture_admin"},
                                  {"name": "POSTGRES_DB", "value": "fixture"},
                                  {"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {
                                      "name": "postgres-fixture", "key": "admin-password"}}}],
                          "ports": [{"name": "postgres", "containerPort": 5432}],
                          "readinessProbe": {"exec": {"command": [
                              "pg_isready", "-h", "127.0.0.1", "-U", "fixture_admin", "-d", "fixture"]},
                              "periodSeconds": 2, "failureThreshold": 2},
                          "volumeMounts": [
                              {"name": "data", "mountPath": "/var/lib/postgresql"},
                              {"name": "init", "mountPath": "/docker-entrypoint-initdb.d", "readOnly": True}],
                      }],
                      "volumes": [{"name": "data", "emptyDir": {}},
                                  {"name": "init", "secret": {"secretName": "postgres-fixture", "items": [
                                      {"key": "provision.sql", "path": "provision.sql"}]}}],
                  }}}},
        {"apiVersion": "v1", "kind": "Service",
         "metadata": {"name": "postgres", "namespace": DB_NAMESPACE, "labels": labels},
         "spec": {"selector": selector,
                  "ports": [{"name": "postgres", "port": 5432, "targetPort": "postgres"}]}},
    ]
    # Created by the test, not the chart: the chart only references existing Secrets.
    items += [{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
               "metadata": {"name": SECRET[role], "namespace": APP_NAMESPACE, "labels": labels},
               "stringData": {"url": database_url(role, passwords[role])}} for role in ROLES]
    return {"apiVersion": "v1", "kind": "List", "items": items}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def event_time(event: dict) -> datetime:
    value = event.get("lastTimestamp") or event.get("eventTime") or event.get("firstTimestamp")
    if not value:
        raise SmokeFailure("event has no timestamp")
    return parse_time(value)


def job_completions(events: list, job: str) -> list:
    """Earliest `Completed` time per Job uid, oldest first. Survives hook-succeeded deletion."""
    runs: dict = {}
    for event in events:
        involved = event.get("involvedObject", {})
        if (event.get("reason") == "Completed" and involved.get("kind") == "Job"
                and involved.get("name") == job and involved.get("uid")):
            when = event_time(event)
            runs[involved["uid"]] = min(when, runs.get(involved["uid"], when))
    return sorted(runs.values())


def images_reported_present(events: list, references: list) -> list:
    """References that kubelet reported as already present (pullPolicy Never, nothing pulled)."""
    messages = [e.get("message", "") for e in events if e.get("reason") == "Pulled"]
    return sorted(ref for ref in references if any(f'"{ref}"' in m for m in messages))


def object_names(items: list) -> list:
    return sorted(f"{item['kind']}/{item['metadata']['name']}" for item in items)


def expected_release_objects() -> list:
    return sorted([f"Deployment/{FULLNAME}-api", f"Deployment/{FULLNAME}-worker",
                   f"Service/{FULLNAME}-api",
                   f"ServiceAccount/{FULLNAME}-api", f"ServiceAccount/{FULLNAME}-worker"])


def unexpected_resources(pods: list) -> list:
    """Container resource names outside cpu/memory/ephemeral-storage (GPUs, devices, claims)."""
    found = set()
    for pod in pods:
        spec = pod["spec"]
        if spec.get("resourceClaims"):
            found.add("pod.resourceClaims")
        for container in spec.get("initContainers", []) + spec["containers"]:
            resources = container.get("resources", {})
            for section in ("requests", "limits"):
                found.update(set(resources.get(section, {})) - ALLOWED_RESOURCES)
            if resources.get("claims"):
                found.add("container.claims")
    return sorted(found)


def assert_no_secrets(text: str, values) -> None:
    if any(value and value in text for value in values):
        raise SmokeFailure("refusing to publish output containing a fixture credential")


def redact(text: str, values) -> str:
    for value in values:
        if value:
            text = text.replace(value, "[redacted]")
    return text


def build_summary(report: dict) -> dict:
    """The non-secret JSON published to the job summary: fixed keys, digest-only references."""
    unknown = set(report) - SUMMARY_KEYS
    if unknown:
        raise SmokeFailure(f"unexpected summary keys: {sorted(unknown)}")
    if report.get("result") not in ("passed", "failed"):
        raise SmokeFailure("summary result must be passed or failed")
    for role, image in report.get("images", {}).items():
        if role not in ROLES or set(image) != {"reference", "cri_image_id", "resolved_before_alias"}:
            raise SmokeFailure(f"unexpected image summary for {role!r}")
        if image["reference"] != digest_reference(role, image["reference"].rpartition("@")[2]):
            raise SmokeFailure(f"{role} reference is not digest-pinned")
    return {key: report[key] for key in sorted(report)}


# --- Harness ---------------------------------------------------------------------------------

def _log(message: str) -> None:
    print(f"[kind-smoke] {message}", file=sys.stderr, flush=True)


class PortForward:
    """kubectl port-forward to a loopback port; adapted from core qualify.py for a namespace."""

    def __init__(self, kubectl: list, env: dict, target: str, port: int):
        self.proc = subprocess.Popen(
            [*kubectl, "--namespace", APP_NAMESPACE, "port-forward", "--address", "127.0.0.1",
             target, f":{port}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        lines: queue.Queue = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in self.proc.stdout],
                         daemon=True).start()
        deadline = time.monotonic() + 30
        while True:
            try:
                line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                self.close()
                raise SmokeFailure(f"port-forward to {target} did not start") from None
            match = re.match(r"Forwarding from 127\.0\.0\.1:(\d+) ->", line)
            if match:
                self.port = int(match.group(1))
                return

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Smoke:
    def __init__(self, core, environ: dict, core_dir: Path, tools_dir: Path | None,
                 helm_dir: Path | None, workdir: Path):
        self.core = core
        self.core_dir = core_dir
        self.context = core.check_opt_in(environ)
        self.run_id = secrets.token_hex(4)
        # core.check_cluster_absent only accepts this name pattern.
        self.name = f"openmettle-dev-qual-{self.run_id}"
        self.node = f"{self.name}-control-plane"
        self.kubeconfig = workdir / "kubeconfig"
        self.values = workdir / "values.json"
        self.env = smoke_environment(
            core.child_environment(environ, self.kubeconfig, self.context, tools_dir), workdir, helm_dir)
        self.run = core.Runner(self.env)
        context = f"kind-{self.name}"
        self.kubectl = ["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", context]
        self.helm = ["helm", "--kubeconfig", str(self.kubeconfig), "--kube-context", context,
                     "--namespace", APP_NAMESPACE]
        self.tags = {role: tag_reference(role, self.run_id) for role in ROLES}
        self.digests: dict = {}
        self.passwords: dict = {}
        self.cluster_attempted = False
        self.built_images: list = []
        self.report: dict = {
            "result": "failed", "classification": "dev", "core_commit": CORE_COMMIT,
            "cluster": self.name, "release": RELEASE, "namespace": APP_NAMESPACE,
            "tools": {"kind": core.KIND_VERSION, "kubectl": core.KUBECTL_VERSION,
                      "helm": HELM_VERSION, "node_image": core.NODE_IMAGE,
                      "postgres_image": core.POSTGRES_IMAGE},
            "images": {}, "checks": []}

    # helpers
    def kube(self, *args, input=None, check=True, timeout=300):
        return self.run([*self.kubectl, *args], input=input, check=check, timeout=timeout)

    def kube_json(self, *args):
        return json.loads(self.kube(*args, "--output=json").stdout)

    def node_exec(self, *args, check=True):
        return self.run(["docker", "exec", self.node, *args], check=check, timeout=120)

    def helm_run(self, *args, timeout=600):
        return self.run([*self.helm, *args], timeout=timeout)

    def passed(self, check: str, **observed):
        self.report["checks"].append({"check": check, **observed})
        _log(f"PASS {check}")

    def expect(self, condition: bool, message: str):
        if not condition:
            raise SmokeFailure(message)

    def wait_for(self, description: str, predicate, timeout=120, interval=1.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(interval)
        raise SmokeFailure(f"timed out waiting for {description}")

    def pods(self, component: str, include_terminating=False) -> list:
        items = self.kube_json("--namespace", APP_NAMESPACE, "get", "pods", "--selector",
                               f"app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component={component}")["items"]
        if include_terminating:
            return items
        return [p for p in items if not p["metadata"].get("deletionTimestamp")]

    def ready_replicas(self) -> dict:
        return {c: self.kube_json("--namespace", APP_NAMESPACE, "get", "deployment",
                                  f"{FULLNAME}-{c}")["status"].get("readyReplicas", 0) for c in WORKLOADS}

    def events(self, *selectors) -> list:
        args = ["--namespace", APP_NAMESPACE, "get", "events"]
        if selectors:
            args += ["--field-selector", ",".join(selectors)]
        return self.kube_json(*args)["items"]

    # phases
    def preflight(self):
        # main() has already checked that core_dir is CORE_COMMIT with no local changes.
        self.core.check_tools(self.run)
        check_helm_version(self.run(["helm", "version", "--template", "{{ .Version }}"]).stdout)
        self.core.check_docker_context(self.run, self.context)
        self.core.check_cluster_absent(self.run, self.name)
        if self.kubeconfig.exists():
            raise Refusal("temporary kubeconfig already exists")

    def verify_identity(self):
        """Core's cluster identity guard plus this run's namespace ownership label."""
        config = json.loads(self.run(["kubectl", "--kubeconfig", str(self.kubeconfig),
                                      "config", "view", "--output=json"]).stdout)
        nodes = [n["metadata"]["name"] for n in self.kube_json("get", "nodes")["items"]]
        label = self.run(["docker", "inspect", "--format",
                          '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', self.node]).stdout.strip()
        self.core.check_cluster_identity(config, nodes, label, self.name)
        for namespace in (APP_NAMESPACE, DB_NAMESPACE):
            found = self.kube("get", "namespace", namespace, "--output=json", check=False)
            if found.returncode == 0:
                labels = json.loads(found.stdout)["metadata"].get("labels", {})
                if labels.get(RUN_LABEL) != self.run_id:
                    raise Refusal(f"namespace {namespace} was not created by this run")

    def build_images(self):
        for role in ROLES:
            _log(f"building {self.tags[role]} from core {CORE_COMMIT[:7]} (local only; never pushed)")
            self.built_images.append(self.tags[role])
            self.run(["docker", "build", "--builder", "default", "--target", role,
                      "--tag", self.tags[role], str(self.core_dir)], timeout=1800)

    def create_cluster(self):
        _log(f"creating kind cluster {self.name} (dev, temporary kubeconfig)")
        self.cluster_attempted = True
        self.run(["kind", "create", "cluster", "--name", self.name, "--image", self.core.NODE_IMAGE,
                  "--kubeconfig", str(self.kubeconfig), "--wait", "180s"], timeout=900)
        self.verify_identity()
        self.passed("isolated cluster identity", context=f"kind-{self.name}")
        for role in ROLES:
            self.run(["kind", "load", "docker-image", self.tags[role], "--name", self.name], timeout=600)

    def cri_image_id(self, reference: str, check=True):
        result = self.node_exec("crictl", "inspecti", "--output", "json", reference, check=check)
        return parse_cri_image_id(result.stdout) if result.returncode == 0 else None

    def pin_digests(self):
        """Give each loaded image a containerd name `<registry>/<repository>@<its own digest>`.

        `kind load` imports `repo:tag` and `import-<date>@sha256:...` names only, and containerd's
        CRI resolves a pod image by exact normalized name, so `repo@sha256:...` does not resolve
        by itself. The digest is read from containerd after the load, the alias is added with
        `ctr images tag` (as kind itself re-tags), then resolved through CRI like the kubelet.
        """
        listing = self.node_exec("ctr", "--namespace=k8s.io", "images", "ls").stdout
        for role in ROLES:
            digest = parse_ctr_digest(listing, self.tags[role])
            reference = digest_reference(role, digest)
            before = self.cri_image_id(reference, check=False)
            if before is None:
                self.node_exec("ctr", "--namespace=k8s.io", "images", "tag", self.tags[role], reference)
            alias = parse_ctr_digest(self.node_exec("ctr", "--namespace=k8s.io", "images", "ls").stdout,
                                     reference)
            self.expect(alias == digest, f"{role} digest name does not point at {digest}")
            resolved = self.wait_for(f"CRI to resolve {reference}",
                                     lambda r=reference: self.cri_image_id(r, check=False), timeout=30)
            self.expect(resolved == self.cri_image_id(self.tags[role]),
                        f"{role} digest reference resolves to a different image")
            self.digests[role] = digest
            self.report["images"][role] = {"reference": reference, "cri_image_id": resolved,
                                           "resolved_before_alias": before is not None}
        self.passed("images resolve by digest through CRI",
                    references=[self.report["images"][r]["reference"] for r in ROLES])

    def deploy_fixtures(self):
        self.passwords = {k: secrets.token_hex(16) for k in ("admin", *ROLES)}
        manifests = fixture_manifests(self.core.POSTGRES_IMAGE, self.passwords, self.run_id)
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(manifests))
        self.kube("--namespace", DB_NAMESPACE, "rollout", "status", "deployment/postgres",
                  "--timeout=300s", timeout=330)

    def migrations(self) -> list:
        """Applied migration history, read as the fixture superuser."""
        out = self.kube("--namespace", DB_NAMESPACE, "exec", "deployment/postgres", "--",
                        "psql", "-v", "ON_ERROR_STOP=1", "-qtA", "-U", "fixture_admin", "-d", "openmettle",
                        "-c", "SELECT version, success, encode(checksum, 'hex'), installed_on "
                              "FROM openmettle._sqlx_migrations ORDER BY version").stdout
        return [line.split("|") for line in out.splitlines() if line]

    def helm_deploy(self, command: str, worker_replicas: int):
        self.values.write_text(json.dumps(smoke_values(self.digests, worker_replicas)))
        self.verify_identity()
        self.helm_run(command, RELEASE, str(CHART), "--values", str(self.values),
                      "--wait=watcher", "--timeout", HELM_TIMEOUT)

    def observe_release(self, revision: int) -> dict:
        """Common state after each install or upgrade."""
        releases = json.loads(self.helm_run("list", "--output", "json").stdout)
        self.expect([(r["name"], r["status"], str(r["revision"])) for r in releases]
                    == [(RELEASE, "deployed", str(revision))], f"unexpected Helm release state: {releases}")
        counts = self.ready_replicas()
        pods = {c: self.pods(c) for c in WORKLOADS}
        for component, items in pods.items():
            for pod in items:
                ready = {c["type"]: c["status"] for c in pod["status"].get("conditions", [])}.get("Ready")
                self.expect(ready == "True", f"{component} pod is not Ready")
                self.expect(all(c.get("restartCount") == 0 for c in pod["status"]["containerStatuses"]),
                            f"{component} container restarted")
                container = pod["spec"]["containers"][0]
                image = self.report["images"][component]
                self.expect(container["image"] == image["reference"] and container["imagePullPolicy"] == "Never",
                            f"{component} pod does not run {image['reference']} with pullPolicy Never")
                # The kubelet's imageID is one digested name of the image (often the
                # `import-<date>@sha256:...` name `kind load` created), so ask CRI for the running
                # container's image id instead and require the image the digest reference resolved to.
                status = pod["status"]["containerStatuses"][0]
                container_id = status.get("containerID", "").removeprefix("containerd://")
                self.expect(bool(container_id), f"{component} container has no containerd id")
                running = parse_cri_container_image_id(self.node_exec(
                    "crictl", "ps", "--id", container_id, "--output", "json").stdout)
                self.expect(running == image["cri_image_id"],
                            f"{component} container runs image {running} (kubelet reports "
                            f"{status.get('imageID') or 'nothing'}), not {image['cri_image_id']} "
                            f"resolved from {image['reference']}")
        self.expect(not self.kube("--namespace", APP_NAMESPACE, "get", "job", f"{FULLNAME}-migrate",
                                  "--ignore-not-found", "--output=name").stdout.strip(),
                    "migrate Job remains after success (hook-succeeded delete policy)")
        forward = PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080)
        try:
            readyz = self.wait_for("API /readyz 200", lambda: (
                self.core.http_get(forward.port, "/readyz")[0] == 200 and 200), timeout=30)
        finally:
            forward.close()
        return {"ready_replicas": counts, "readyz": readyz,
                "pods": {c: sorted(p["metadata"]["name"] for p in pods[c]) for c in WORKLOADS},
                "generations": {c: self.kube_json("--namespace", APP_NAMESPACE, "get", "deployment",
                                                  f"{FULLNAME}-{c}")["metadata"]["generation"]
                                for c in WORKLOADS}}

    def completions(self) -> list:
        return job_completions(self.events("involvedObject.kind=Job"), f"{FULLNAME}-migrate")

    def scenario(self):
        # 1-3, 5, 8: install by digest; migrate hook; Ready; no optional package; PSA restricted.
        self.helm_deploy("install", worker_replicas=1)
        installed = self.observe_release(revision=1)
        self.expect(installed["ready_replicas"] == {"api": 1, "worker": 1},
                    f"install ready replicas: {installed['ready_replicas']}")
        runs = self.completions()
        self.expect(len(runs) == 1, f"expected one completed migrate Job after install, found {len(runs)}")
        history = self.migrations()
        self.expect(history and all(row[1] == "t" for row in history),
                    "migration history is empty or has a failed entry")
        created = {c: parse_time(self.kube_json("--namespace", APP_NAMESPACE, "get", "deployment",
                                                f"{FULLNAME}-{c}")["metadata"]["creationTimestamp"])
                   for c in WORKLOADS}
        first = runs[0].replace(microsecond=0)
        self.expect(all(first <= when for when in created.values()),
                    "migrate Job completed after the Deployments were created")
        references = [self.report["images"][r]["reference"] for r in ROLES]
        present = images_reported_present(self.events("reason=Pulled"), references)
        self.expect(present == sorted(references),
                    f"kubelet did not report every digest reference as present: {present}")
        self.passed("install by digest: migrate hook completed before Deployments; API and worker Ready",
                    migrations_applied=len(history), latest_version=int(history[-1][0]),
                    ready_replicas=installed["ready_replicas"], readyz=installed["readyz"],
                    images_present=len(present))

        # Helm deletes the succeeded hook Job; its pods are garbage-collected in the background.
        self.wait_for("migrate hook pods to be removed",
                      lambda: not self.pods("migrate", include_terminating=True), timeout=120)
        inventory = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get",
                                                "deployments,services,serviceaccounts,jobs,configmaps,secrets",
                                                "--selector", f"app.kubernetes.io/instance={RELEASE}")["items"])
        self.expect(inventory == expected_release_objects(), f"release objects: {inventory}")
        optional = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", OPTIONAL_KINDS)["items"])
        self.expect(not optional, f"optional objects present: {optional}")
        releases = json.loads(self.run([*self.helm[:5], "list", "--all-namespaces", "--all",
                                        "--output", "json"]).stdout)
        self.expect([r["name"] for r in releases] == [RELEASE], f"other Helm releases: {releases}")
        all_pods = self.kube_json("--namespace", APP_NAMESPACE, "get", "pods")["items"]
        components = sorted({p["metadata"].get("labels", {}).get("app.kubernetes.io/component", "")
                             for p in all_pods})
        self.expect(components == sorted(WORKLOADS), f"pods outside api/worker: {components}")
        extra = unexpected_resources(all_pods)
        self.expect(not extra, f"pods request optional resources: {extra}")
        self.passed("no optional package present", release_objects=inventory, helm_releases=1)

        namespace = self.kube_json("get", "namespace", APP_NAMESPACE)["metadata"]["labels"]
        self.expect(namespace.get("pod-security.kubernetes.io/enforce") == "restricted",
                    "app namespace does not enforce restricted")
        probe = {"apiVersion": "v1", "kind": "Pod",
                 "metadata": {"name": "psa-probe", "namespace": APP_NAMESPACE},
                 "spec": {"automountServiceAccountToken": False, "containers": [
                     {"name": "probe", "image": references[0], "imagePullPolicy": "Never"}]}}
        denied = self.kube("create", "--dry-run=server", "--filename", "-",
                           input=json.dumps(probe), check=False)
        self.expect(denied.returncode != 0 and PSA_DENIAL in denied.stderr,
                    "a non-compliant pod was not rejected by Pod Security admission")
        self.passed("app namespace enforces Pod Security restricted",
                    enforce="restricted", noncompliant_pod_rejected=True)

        # 4: worker to 2 through chart values while the API stays at 1. Helm 4 applies server-side
        # by default, so a kubectl scale would conflict with Helm's ownership of replicas.
        self.helm_deploy("upgrade", worker_replicas=2)
        scaled = self.observe_release(revision=2)
        self.expect(scaled["ready_replicas"] == {"api": 1, "worker": 2},
                    f"scale ready replicas: {scaled['ready_replicas']}")
        self.expect(scaled["pods"]["api"] == installed["pods"]["api"], "API pod was replaced while scaling")
        self.expect(len(self.completions()) == 2, "upgrade did not run the migrate hook")
        self.expect(self.migrations() == history, "migration history changed on a same-digest upgrade")
        self.passed("worker scales to 2 while API stays at 1", ready_replicas=scaled["ready_replicas"],
                    api_pod_unchanged=True)

        # 6: identical upgrade reruns migrate as a no-op; nothing rolls.
        self.helm_deploy("upgrade", worker_replicas=2)
        repeated = self.observe_release(revision=3)
        self.expect(len(self.completions()) == 3, "repeated upgrade did not run the migrate hook")
        self.expect(self.migrations() == history, "migration history changed on a repeated upgrade")
        self.expect(repeated["pods"] == scaled["pods"] and repeated["generations"] == scaled["generations"],
                    "identical upgrade replaced pods or changed a Deployment")
        self.passed("same-digest upgrade reruns migrate as a no-op and stays Ready",
                    migrate_runs=3, migrations_applied=len(history),
                    ready_replicas=repeated["ready_replicas"], readyz=repeated["readyz"])

        # 7: uninstall leaves no release objects.
        self.verify_identity()
        self.helm_run("uninstall", RELEASE, "--wait", "--timeout", HELM_TIMEOUT)

        def residue():
            left = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", RELEASE_KINDS, "--selector",
                                               f"app.kubernetes.io/instance={RELEASE}")["items"])
            left += object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", "secrets", "--selector",
                                                f"owner=helm,name={RELEASE}")["items"])
            left += object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", "endpointslices",
                                                "--selector", f"kubernetes.io/service-name={FULLNAME}-api")["items"])
            return left
        self.wait_for("release objects to be removed", lambda: not residue(), timeout=120)
        releases = json.loads(self.helm_run("list", "--all", "--output", "json").stdout)
        self.expect(releases == [], f"Helm still lists a release: {releases}")
        # The test, not the chart, owns the URL Secrets: uninstall must leave them alone.
        remaining = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", "secrets",
                                                "--selector", RUN_LABEL)["items"])
        self.expect(remaining == sorted(f"Secret/{SECRET[r]}" for r in ROLES),
                    f"test-owned Secrets after uninstall: {remaining}")
        self.passed("uninstall leaves no release objects", test_owned_secrets_remaining=remaining)
        self.report["result"] = "passed"

    def diagnostics(self):
        if not self.kubeconfig.exists():
            return
        for args in (["get", "pods", "--all-namespaces", "--output=wide"],
                     ["--namespace", APP_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"],
                     ["--namespace", APP_NAMESPACE, "logs", "--selector", f"app.kubernetes.io/instance={RELEASE}",
                      "--all-containers", "--prefix", "--tail=100"],
                     ["--namespace", DB_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"]):
            try:
                result = self.kube(*args, check=False, timeout=60)
            except (subprocess.TimeoutExpired, OSError):
                continue
            print(redact(result.stdout[-6000:] + result.stderr[-2000:], self.passwords.values()),
                  file=sys.stderr)

    def cleanup(self) -> list:
        commands = []
        if self.cluster_attempted:
            _log(f"deleting kind cluster {self.name}")
            commands.append((["kind", "delete", "cluster", "--name", self.name,
                              "--kubeconfig", str(self.kubeconfig)], 300))
        commands += [(["docker", "image", "rm", image], 120) for image in self.built_images]
        failures = []
        for command, timeout in commands:
            try:
                if self.run(command, check=False, timeout=timeout).returncode:
                    failures.append(f"{' '.join(command)}: failed")
            except Exception as exc:  # noqa: BLE001 - attempt every owned resource
                failures.append(f"{' '.join(command)}: {type(exc).__name__}")
        return failures


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--core-dir", type=Path, required=True,
                        help=f"openmettle-core checkout at {CORE_COMMIT}")
    parser.add_argument("--tools-dir", type=Path, help="directory from core tests/kubernetes/install-tools.sh")
    parser.add_argument("--helm-dir", type=Path, help="directory from tests/chart/install-tools.sh")
    parser.add_argument("--report", type=Path, help="write the non-secret JSON summary here")
    args = parser.parse_args(argv)
    for name in ("core_dir", "tools_dir", "helm_dir"):
        value = getattr(args, name)
        if value is not None:
            if not value.is_dir():
                parser.error(f"--{name.replace('_', '-')} {value} is not a directory")
            setattr(args, name, value.resolve())
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        # Verify the pinned, unmodified checkout before executing any of its code.
        check_core_checkout(*core_checkout_state(args.core_dir))
        core = load_core(args.core_dir)
    except (Refusal, OSError, SyntaxError, subprocess.TimeoutExpired) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    refusals = (Refusal, core.Refusal)
    failures = (SmokeFailure, core.QualificationFailure, subprocess.TimeoutExpired, *refusals)
    workdir = Path(tempfile.mkdtemp(prefix="openmettle-kind-smoke-"))
    try:
        smoke = Smoke(core, dict(os.environ), args.core_dir, args.tools_dir, args.helm_dir, workdir)
        smoke.preflight()
    except failures as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    status = 1
    try:
        smoke.build_images()
        smoke.create_cluster()
        smoke.pin_digests()
        smoke.deploy_fixtures()
        smoke.scenario()
        status = 0
    except Exception as exc:  # noqa: BLE001 - every failure is reported, diagnosed and cleaned up
        smoke.report["result"] = "failed"
        detail = str(exc) if isinstance(exc, failures) else f"{type(exc).__name__}: {exc}"
        smoke.report["error"] = redact(detail, smoke.passwords.values())
        print(f"smoke failed: {smoke.report['error']}", file=sys.stderr)
        smoke.diagnostics()
    finally:
        cleanup_failures = smoke.cleanup()
        if cleanup_failures:
            status = 1
            smoke.report["result"] = "failed"
            smoke.report["cleanup_errors"] = cleanup_failures
            _log(f"cleanup failed; temporary kubeconfig retained for recovery in {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        if args.report:
            text = json.dumps(build_summary(smoke.report), indent=2) + "\n"
            assert_no_secrets(text, smoke.passwords.values())
            args.report.write_text(text)
    return status


if __name__ == "__main__":
    sys.exit(main())
