#!/usr/bin/env python3
"""Install the openmettle-core chart on an ephemeral kind cluster (V1-32 I2/I3/I7/I10 smoke test).

Test harness only; not an installer. It builds core's api, worker and migrate images from a
pinned core checkout, loads them into a uniquely named kind cluster classified `dev` and
installs the chart by image digest with a synthetic PostgreSQL fixture. It then checks:
migration hook, readiness, worker scaling, an idempotent upgrade, an enabled-profile upgrade
(API replicas=2, PodDisruptionBudget, artifact PVC, ADR 0024 JSON/debug structured logs, and
API-only auth + /v1/* mounts), uninstall (with chart-owned PVC preservation), absence of
optional packages and unmounted 404 routes on default install, Pod Security `restricted`
enforcement and NetworkPolicy enforcement (I3). Every assertion reads
live cluster, Helm or database state. Core's process-contract assertions are not repeated
(core tests/kubernetes).

Safety guards, tool and image pins are imported from core tests/kubernetes/qualify.py at
CORE_COMMIT; see tests/kind/README.md. Requires Python 3.10+, docker, the pinned kind and
kubectl (core install-tools.sh) and the pinned Helm (tests/chart/install-tools.sh).
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import queue
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openmettle-core"
def _read_core_commit() -> str:
    pin = (ROOT / "CORE_COMMIT").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", pin):
        raise ValueError(f"CORE_COMMIT must be a 40-character lowercase hex SHA, got {pin!r}")
    return pin


# Single source of truth: root CORE_COMMIT file (also read by checks.yml and kind-smoke.yml).
CORE_COMMIT = _read_core_commit()
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
OPTIONAL_KINDS = "ingresses,persistentvolumeclaims,poddisruptionbudgets,resourceclaims,horizontalpodautoscalers"
RELEASE_KINDS = "deployments,replicasets,pods,services,serviceaccounts,jobs,configmaps,secrets,networkpolicies,poddisruptionbudgets"
INVENTORY_KINDS = "deployments,services,serviceaccounts,jobs,configmaps,secrets,networkpolicies"
API_PDB = f"{FULLNAME}-api"
ARTIFACTS_CLAIM = f"{FULLNAME}-artifacts"
ARTIFACTS_MOUNT_PATH = "/var/lib/openmettle/artifacts"
AUTH_CONFIG_MAP = "openmettle-smoke-auth-config"
AUTH_LOGIN_KEYS_SECRET = "openmettle-smoke-auth-login-keys"
AUTH_CONFIG_DIR = "/etc/openmettle/auth"
AUTH_CONFIG_PATH = f"{AUTH_CONFIG_DIR}/auth.json"
AUTH_KEYS_DIR = "/etc/openmettle/auth-keys"
AUTH_ACTIVE_KEY_PATH = f"{AUTH_KEYS_DIR}/active.key"
AUTH_CA_DIR = "/etc/openmettle/auth-ca"
AUTH_SECRET_MODE = 288  # 0440 octal
AUTH_OIDC_CIDR = "192.0.2.20/32"  # RFC 5737 TEST-NET-1 synthetic OIDC egress peer
AUTH_CHECK_BINARY = "/usr/local/bin/openmettle-api"
AUTH_CHECK_OK = "auth configuration valid (local files only)\n"
MOUNTED_AUTH_HTTP = {"/auth/session": 403, "/auth/native/session": 403, "/v1/capabilities": 401}
AUTH_ROUTE_PATHS = tuple(MOUNTED_AUTH_HTTP)
PROFILE_ROLLOUT_TIMEOUT = "180s"
LOG_LEVELS = {"ERROR", "WARN", "INFO", "DEBUG"}
# Matches core src/telemetry.rs FIELDS plus tracing-subscriber flattened JSON metadata.
ALLOWED_LOG_FIELDS = {
    "timestamp", "level", "event", "role", "signal", "request_id",
    "http.route", "http.request.method", "http.response.status_code",
    "duration_us", "error.type", "schema_version", "dropped_lines", "dropped_spans",
    "dropped_metric_exports",
}
# NetworkPolicy fixtures. The app namespace denies all traffic by default, as the owner's application
# namespaces do; the release must work under it. PEER is a second PostgreSQL server in the database
# namespace that is not a configured database peer; it is also the one configured API ingress peer.
NAMESPACE_DENY = "default-deny"
PEER = "netpol-peer"
POSTGRES_LABELS = {"app.kubernetes.io/name": "postgres"}
PEER_LABELS = {"app.kubernetes.io/name": PEER}
DNS_SELECTOR = "k8s-app=kube-dns"  # CoreDNS in kube-system (kubeadm, so kind)
DNS_METRICS_PORT = 9153  # CoreDNS `prometheus :9153` in kubeadm's Corefile; not a DNS port
PROBE_SECONDS = 5
TIMEOUT_EXIT = 124  # coreutils timeout(1)
REJECTED = re.compile(r"Connection refused|No route to host|Network is unreachable")
HTTP_OK = re.compile(r"HTTP/1\.[01] 200 ")
ALLOWED_RESOURCES = {"cpu", "memory", "ephemeral-storage"}
# Stderr kept in a failure message, as core's Runner keeps; redacted before it is truncated.
STDERR_TAIL = 2000
DIAGNOSTIC_TAIL = {"stdout": 6000, "stderr": 2000}
# Termination signals that must still run cleanup (SIGINT already raises KeyboardInterrupt).
CLEANUP_SIGNALS = (signal.SIGTERM, signal.SIGHUP)
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
    """(HEAD, `git status --porcelain --ignored`) of the core checkout, read before any core code runs.

    Ignored files count as changes because they would enter the Docker build context. Any git
    error refuses rather than reading as a clean checkout.
    """
    def git(*args):
        result = subprocess.run(["git", "-C", str(core_dir), *args], capture_output=True, text=True,
                                timeout=60, check=False)
        if result.returncode:
            raise Refusal(f"git {' '.join(args)} failed in {core_dir} (exit {result.returncode})")
        return result.stdout
    return git("rev-parse", "HEAD"), git("status", "--porcelain", "--ignored")


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


def smoke_values(digests: dict, worker_replicas: int, *, enabled_profile: bool = False) -> dict:
    """Chart values for the smoke release. Shorter migration timeouts bound a hung hook."""
    if set(digests) != set(ROLES):
        raise SmokeFailure("a digest is required for each of api, worker and migrate")
    for role in ROLES:
        digest_reference(role, digests[role])
    if worker_replicas not in (1, 2):
        raise SmokeFailure("worker replicas must be 1 or 2")
    values = {
        "images": {"pullPolicy": "Never", **{
            role: {"registry": REGISTRY, "repository": f"openmettle/{role}", "digest": digests[role]}
            for role in ROLES}},
        "database": {role: {"existingSecret": SECRET[role]} for role in ROLES},
        "worker": {"replicas": worker_replicas},
        "migration": {"activeDeadlineSeconds": MIGRATION_DEADLINE_SECONDS,
                      "settings": {"connectTimeoutMs": 5000, "lockTimeoutMs": 15000,
                                   "statementTimeoutMs": 60000}},
        # networkPolicy.enabled and the DNS peer keep the chart defaults.
        "networkPolicy": {"api": {"ingressFrom": [database_namespace_peer(PEER_LABELS)]},
                          "database": {"to": [database_namespace_peer(POSTGRES_LABELS)]}},
    }
    if enabled_profile:
        # Single-node kind cluster: local-path-provisioner binds RWO across all pods on the node.
        values["api"] = {
            "replicas": 2,
            "podDisruptionBudget": {"enabled": True, "maxUnavailable": 1},
        }
        values["telemetry"] = {"logging": {"format": "json", "level": "debug"}}
        values["storage"] = {
            "artifacts": {"enabled": True, "size": "64Mi", "accessModes": ["ReadWriteOnce"]},
        }
        values["auth"] = {
            "enabled": True,
            "configMapName": AUTH_CONFIG_MAP,
            "configKey": "auth.json",
            "loginKeysSecretName": AUTH_LOGIN_KEYS_SECRET,
        }
        values["networkPolicy"]["api"]["oidc"] = {
            "to": [{"ipBlock": {"cidr": AUTH_OIDC_CIDR}}],
            "port": 443,
        }
    return values


def smoke_auth_document() -> dict:
    """Synthetic version-2 auth document mounting browser (ADR 0025), native (ADR 0029) and /v1/* (ADR 0027)."""
    provider_id = "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f"
    return {
        "version": 2,
        "login": {
            "lifetime_seconds": 300,
            "keys": {
                "active": {"id": "smoke-active", "path": AUTH_ACTIVE_KEY_PATH},
                "decrypt_only": [],
            },
        },
        "id_token": {"max_issued_at_age_seconds": 300, "future_skew_seconds": 60},
        "provider_refresh": {
            "freshness_seconds": 3600,
            "cooldown_seconds": 60,
            "deadline_milliseconds": 5000,
            "max_providers": 2,
            "max_callers": 32,
            "max_document_gets": 3,
        },
        "session": {
            "lifetime_seconds": 28800,
            "retained_per_user": 16,
            "deadline_milliseconds": 5000,
        },
        "providers": [{
            "id": provider_id,
            "issuer": "https://issuer.example.test/realm",
            "client_id": "smoke-client",
            "revision": "r1",
            "authorization_endpoint": "https://issuer.example.test/authorize",
            "token_endpoint": "https://issuer.example.test/token",
            "discovery_url": "https://issuer.example.test/realm/.well-known/openid-configuration",
            "jwks_url": "https://issuer.example.test/jwks",
            "callback": "https://app.example.test/auth/callback",
            "destination": "web",
            "private_cidrs": [],
            "trust": {"roots": "native"},
        }],
        "browser": {
            "provider_id": provider_id,
            "origin": "https://app.example.test",
            "landing_path": "/home",
            "paths": {
                "initiation": "/auth/login",
                "session_check": "/auth/session",
                "logout": "/auth/logout",
            },
            "rates": {
                "initiation": {"burst": 20, "interval_milliseconds": 500},
                "callback": {"burst": 20, "interval_milliseconds": 500},
                "session_check": {"burst": 120, "interval_milliseconds": 100},
                "logout": {"burst": 20, "interval_milliseconds": 500},
            },
            "max_in_flight": 64,
        },
        "native": {
            "provider_id": provider_id,
            "issuer": "https://app.example.test",
            "callback": "https://app.example.test/auth/native/callback",
            "client_id": "openmettle-desktop",
            "redirect_uri": "https://app.example.test/native/complete",
            "rate": {"burst": 20, "interval_milliseconds": 500},
            "max_in_flight": 64,
        },
    }


def database_namespace_peer(labels: dict) -> dict:
    """A NetworkPolicyPeer for pods with `labels` in the database namespace."""
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": DB_NAMESPACE}},
            "podSelector": {"matchLabels": dict(labels)}}


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
    selector = POSTGRES_LABELS
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
        # Selects every pod in the app namespace, including the chart's: nothing in or out unless a
        # policy allows it. The chart's own deny-all is therefore not observable separately here.
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": NAMESPACE_DENY, "namespace": APP_NAMESPACE, "labels": labels},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
        # A PostgreSQL server that is not a configured database peer, holding no data. It reuses the
        # fixture's admin password Secret, so no new credential is created.
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": PEER, "namespace": DB_NAMESPACE, "labels": labels},
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                  "selector": {"matchLabels": PEER_LABELS},
                  "template": {"metadata": {"labels": PEER_LABELS}, "spec": {
                      "automountServiceAccountToken": False, "enableServiceLinks": False,
                      "containers": [{
                          "name": "postgres", "image": postgres_image, "imagePullPolicy": "IfNotPresent",
                          "env": [{"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {
                              "name": "postgres-fixture", "key": "admin-password"}}}],
                          "ports": [{"name": "postgres", "containerPort": 5432}],
                          "readinessProbe": {"exec": {"command": ["pg_isready", "-h", "127.0.0.1"]},
                                             "periodSeconds": 2, "failureThreshold": 2},
                          "volumeMounts": [{"name": "data", "mountPath": "/var/lib/postgresql"}],
                      }],
                      "volumes": [{"name": "data", "emptyDir": {}}],
                  }}}},
    ]
    # Created by the test, not the chart: the chart only references existing ConfigMaps and Secrets.
    items += [{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
               "metadata": {"name": SECRET[role], "namespace": APP_NAMESPACE, "labels": labels},
               "stringData": {"url": database_url(role, passwords[role])}} for role in ROLES]
    items += [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": AUTH_CONFIG_MAP, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"auth.json": json.dumps(smoke_auth_document())}},
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": AUTH_LOGIN_KEYS_SECRET, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"active.key": passwords["auth_login_key"]}},
    ]
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
    """References that kubelet reported as already present (pullPolicy Never, nothing pulled).

    A `Pulled` event also reports a real pull ("Successfully pulled image ..."); only the
    "already present" message counts.
    """
    messages = [e.get("message", "") for e in events if e.get("reason") == "Pulled"]
    return sorted(ref for ref in references
                  if any(m.startswith(f'Container image "{ref}" already present') for m in messages))


def object_names(items: list) -> list:
    return sorted(f"{item['kind']}/{item['metadata']['name']}" for item in items)


def release_network_policies() -> list:
    """The release's non-hook NetworkPolicies. The migrate policy is a hook deleted on success."""
    return sorted(f"NetworkPolicy/{FULLNAME}-{name}" for name in ("deny-all", "api", "worker"))


def expected_release_objects() -> list:
    return sorted([f"Deployment/{FULLNAME}-api", f"Deployment/{FULLNAME}-worker",
                   f"Service/{FULLNAME}-api",
                   f"ServiceAccount/{FULLNAME}-api", f"ServiceAccount/{FULLNAME}-worker",
                   *release_network_policies()])


def tcp_command(host: str, port: int) -> list:
    """Open one TCP connection from inside a container with bash's /dev/tcp, bounded by timeout(1).

    Host and port are positional arguments ($0, $1), never part of the script text.
    """
    return ["timeout", str(PROBE_SECONDS), "bash", "-c", 'exec 3<>"/dev/tcp/$0/$1"', host, str(port)]


def http_command(host: str, port: int, path: str) -> list:
    """GET `path` over one TCP connection and print the status line."""
    script = ('exec 3<>"/dev/tcp/$0/$1" && printf "GET %s HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n" '
              '"$2" "$0" >&3 && head -n 1 <&3')
    return ["timeout", str(PROBE_SECONDS), "bash", "-c", script, host, str(port), path]


def probe_plan(dns_ip: str, peer_ip: str) -> list:
    """Connections to try, each from inside a running pod (kubectl exec), with the expected result.

    Every denial has a control: the same target reached from a pod that no NetworkPolicy selects.
    A denial whose control fails is not evidence, because nothing may have been listening.
    """
    database = f"postgres.{DB_NAMESPACE}.svc.cluster.local"
    api = f"{FULLNAME}-api.{APP_NAMESPACE}.svc.cluster.local"
    readyz = http_command(api, 8080, "/readyz")

    def probe(name, namespace, workload, container, command, expect, control=None):
        return {"name": name, "namespace": namespace, "workload": workload, "container": container,
                "command": command, "expect": expect, "control": control, "http": command == readyz}
    decoy_control = "control: database namespace reaches the decoy PostgreSQL on 5432"
    metrics_control = "control: database namespace reaches CoreDNS on 9153"
    ingress_allowed = "api ingress from the configured peer: GET /readyz 200"
    plan = [
        probe(decoy_control, DB_NAMESPACE, "postgres", "postgres", tcp_command(peer_ip, 5432), "connect"),
        probe(metrics_control, DB_NAMESPACE, PEER, "postgres", tcp_command(dns_ip, DNS_METRICS_PORT), "connect"),
        probe(ingress_allowed, DB_NAMESPACE, PEER, "postgres", readyz, "connect"),
    ]
    for component in WORKLOADS:
        workload = f"{FULLNAME}-{component}"
        plan += [
            probe(f"{component} egress to the database peer by DNS name", APP_NAMESPACE, workload, component,
                  tcp_command(database, 5432), "connect"),
            probe(f"{component} egress to PostgreSQL on a non-peer pod", APP_NAMESPACE, workload, component,
                  tcp_command(peer_ip, 5432), "deny", decoy_control),
            probe(f"{component} egress to the DNS peer on a non-DNS port", APP_NAMESPACE, workload, component,
                  tcp_command(dns_ip, DNS_METRICS_PORT), "deny", metrics_control),
        ]
    plan.append(probe("api ingress from an unconfigured peer", DB_NAMESPACE, "postgres", "postgres",
                      readyz, "deny", ingress_allowed))
    return plan


def probe_outcome(returncode: int, stdout: str, stderr: str, http: bool) -> str:
    """connected, timeout or rejected (both denials), unexpected-response or inconclusive.

    A dropped connection times out; a rejecting policy engine reports refused or unreachable. Any
    other failure, such as kubectl failing to exec, is inconclusive and never counts as a denial.
    """
    if returncode == 0:
        return "connected" if not http or HTTP_OK.match(stdout) else "unexpected-response"
    if returncode == TIMEOUT_EXIT:
        return "timeout"
    if REJECTED.search(stderr):
        return "rejected"
    return "inconclusive"


def evaluate_probes(results: list) -> None:
    """Raise unless every allowed path and control connected and every other connection was denied."""
    if not results:
        raise SmokeFailure("no NetworkPolicy probes ran")
    by_name = {r["name"]: r for r in results}
    leaks = [r["name"] for r in results if r["expect"] == "deny" and r["outcome"] == "connected"]
    if leaks:
        raise SmokeFailure(
            "NetworkPolicy is not enforced in this cluster: " + "; ".join(leaks) + " connected. kind's "
            "kindnet runs kube-network-policies fail-open, so a missing or failed policy controller allows "
            "everything. Do not count this run as NetworkPolicy evidence; a pinned policy engine for the "
            "smoke cluster needs owner sign-off (tests/kind/README.md).")
    problems = []
    for r in results:
        if r["expect"] == "connect":
            if r["outcome"] != "connected":
                problems.append(f"allowed path failed: {r['name']} ({r['outcome']})")
        elif r["expect"] == "deny":
            control = by_name.get(r["control"])
            if control is None or control["expect"] != "connect":
                problems.append(f"{r['name']} has no control probe")
            elif control["outcome"] != "connected":
                problems.append(f"{r['name']}: its control did not connect, so the denial is not evidence")
            if r["outcome"] not in ("timeout", "rejected"):
                problems.append(f"{r['name']} was inconclusive ({r['outcome']})")
        else:
            problems.append(f"{r['name']} has unexpected expectation ({r['expect']})")
    if problems:
        raise SmokeFailure("; ".join(problems))


def running_pod_ip(items: list, description: str) -> str:
    """The IP of the first Running, not terminating pod by name."""
    running = sorted((p for p in items if p.get("status", {}).get("phase") == "Running"
                      and p["status"].get("podIP") and not p["metadata"].get("deletionTimestamp")),
                     key=lambda p: p["metadata"]["name"])
    if not running:
        raise SmokeFailure(f"no Running {description} pod with an IP")
    return running[0]["status"]["podIP"]


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


def evaluate_pdb(pdb: dict, *, expected_max_unavailable: int = 1, min_healthy: int = 2) -> dict | None:
    """Verify API PodDisruptionBudget spec immediately; return summary once disruptionsAllowed >= 1."""
    name = pdb.get("metadata", {}).get("name")
    if name != API_PDB:
        raise SmokeFailure(f"unexpected PodDisruptionBudget name: {name!r}")
    spec = pdb.get("spec", {})
    if spec.get("maxUnavailable") != expected_max_unavailable:
        raise SmokeFailure(f"PodDisruptionBudget maxUnavailable is {spec.get('maxUnavailable')!r}, "
                           f"expected {expected_max_unavailable}")
    if spec.get("unhealthyPodEvictionPolicy") != "AlwaysAllow":
        raise SmokeFailure(f"PodDisruptionBudget unhealthyPodEvictionPolicy is "
                           f"{spec.get('unhealthyPodEvictionPolicy')!r}, expected 'AlwaysAllow'")
    status = pdb.get("status", {})
    healthy = status.get("currentHealthy", 0)
    allowed = status.get("disruptionsAllowed", 0)
    if not isinstance(healthy, int) or not isinstance(allowed, int) or healthy < min_healthy or allowed < 1:
        return None
    return {"name": name, "max_unavailable": expected_max_unavailable,
            "current_healthy": healthy, "disruptions_allowed": allowed}


def check_artifacts_pvc(pvc: dict, pods_by_role: dict) -> dict:
    """Verify the artifact PVC is Bound with keep policy and mounted in every api and worker pod."""
    metadata = pvc.get("metadata", {})
    name = metadata.get("name")
    if name != ARTIFACTS_CLAIM:
        raise SmokeFailure(f"unexpected artifact PVC name: {name!r}")
    policy = metadata.get("annotations", {}).get("helm.sh/resource-policy")
    if policy != "keep":
        raise SmokeFailure(f"artifact PVC lacks helm.sh/resource-policy=keep annotation: {policy!r}")
    phase = pvc.get("status", {}).get("phase")
    if phase != "Bound":
        raise SmokeFailure(f"artifact PVC {name} is not Bound (phase={phase!r})")
    mounted_pods = 0
    for role in WORKLOADS:
        items = pods_by_role.get(role) or []
        if not items:
            raise SmokeFailure(f"no {role} pods found to verify artifact volume mount")
        for pod in items:
            spec = pod.get("spec", {})
            if spec.get("securityContext", {}).get("fsGroup") != 65532:
                raise SmokeFailure(f"{role} pod lacks fsGroup 65532 for artifact volume")
            volumes = spec.get("volumes") or []
            if not any(v.get("name") == "artifacts"
                       and v.get("persistentVolumeClaim", {}).get("claimName") == ARTIFACTS_CLAIM
                       for v in volumes):
                raise SmokeFailure(f"{role} pod does not attach PVC {ARTIFACTS_CLAIM}")
            containers = spec.get("containers") or []
            container = next((c for c in containers if c.get("name") == role),
                             containers[0] if containers else {})
            mounts = container.get("volumeMounts") or []
            if not any(m.get("name") == "artifacts" and m.get("mountPath") == ARTIFACTS_MOUNT_PATH
                       for m in mounts):
                raise SmokeFailure(f"{role} container does not mount artifacts at {ARTIFACTS_MOUNT_PATH}")
            mounted_pods += 1
    return {"claim": name, "phase": phase, "mount_path": ARTIFACTS_MOUNT_PATH, "mounted_pods": mounted_pods}


def check_auth_mounts(pods_by_role: dict) -> dict:
    """Verify auth ConfigMap/Secret and OPENMETTLE_API_AUTH_CONFIG mount on api only, never worker."""
    api_pods = pods_by_role.get("api") or []
    worker_pods = pods_by_role.get("worker") or []
    if not api_pods or not worker_pods:
        raise SmokeFailure("api and worker pods are required to verify auth mount isolation")
    for pod in api_pods:
        spec = pod.get("spec", {})
        if spec.get("securityContext", {}).get("fsGroup") != 65532:
            raise SmokeFailure("api pod lacks fsGroup 65532 for auth login keys")
        volumes = spec.get("volumes") or []
        if not any(v.get("name") == "auth-config"
                   and v.get("configMap", {}).get("name") == AUTH_CONFIG_MAP
                   and any(i.get("key") == "auth.json" and i.get("path") == "auth.json"
                           for i in (v.get("configMap", {}).get("items") or []))
                   for v in volumes):
            raise SmokeFailure(f"api pod does not project {AUTH_CONFIG_MAP} as auth.json")
        if not any(v.get("name") == "auth-login-keys"
                   and v.get("secret", {}).get("secretName") == AUTH_LOGIN_KEYS_SECRET
                   and v.get("secret", {}).get("defaultMode") == AUTH_SECRET_MODE
                   for v in volumes):
            raise SmokeFailure(f"api pod does not mount {AUTH_LOGIN_KEYS_SECRET} with mode 0440")
        containers = spec.get("containers") or []
        container = next((c for c in containers if c.get("name") == "api"), None)
        if container is None:
            raise SmokeFailure("api pod has no container named 'api'")
        mounts = container.get("volumeMounts") or []
        for vol_name, mount_dir in (("auth-config", AUTH_CONFIG_DIR), ("auth-login-keys", AUTH_KEYS_DIR)):
            if not any(m.get("name") == vol_name and m.get("mountPath") == mount_dir
                       and m.get("readOnly") is True for m in mounts):
                raise SmokeFailure(f"api container does not mount {vol_name} read-only at {mount_dir}")
        env = container.get("env") or []
        if not any(e.get("name") == "OPENMETTLE_API_AUTH_CONFIG" and e.get("value") == AUTH_CONFIG_PATH
                   for e in env):
            raise SmokeFailure(f"api container lacks OPENMETTLE_API_AUTH_CONFIG={AUTH_CONFIG_PATH}")
    for pod in worker_pods:
        spec = pod.get("spec", {})
        for volume in spec.get("volumes") or []:
            if str(volume.get("name", "")).startswith("auth-") \
                    or volume.get("configMap", {}).get("name") == AUTH_CONFIG_MAP \
                    or volume.get("secret", {}).get("secretName") == AUTH_LOGIN_KEYS_SECRET:
                raise SmokeFailure("worker pod must not attach auth volumes")
        for container in spec.get("containers") or []:
            for mount in container.get("volumeMounts") or []:
                if str(mount.get("name", "")).startswith("auth-") \
                        or mount.get("mountPath") in (AUTH_CONFIG_DIR, AUTH_KEYS_DIR, AUTH_CA_DIR):
                    raise SmokeFailure("worker container must not mount auth directories")
            for entry in container.get("env") or []:
                if "AUTH_CONFIG" in str(entry.get("name", "")):
                    raise SmokeFailure("worker container must not receive AUTH_CONFIG env")
    return {"api_pods": len(api_pods), "config_path": AUTH_CONFIG_PATH,
            "keys_dir": AUTH_KEYS_DIR, "secret_mode": AUTH_SECRET_MODE, "worker_isolated": True}


def evaluate_mounted_auth_http(responses: dict) -> dict:
    """Verify mounted browser (403), native (403) and /v1/capabilities (401 problem JSON body) responses."""
    for path, expected_status in MOUNTED_AUTH_HTTP.items():
        status, body = responses.get(path, (None, ""))
        if status != expected_status:
            raise SmokeFailure(f"unexpected {path} response: {status!r} {body!r}")
    if "session origin refused" not in responses["/auth/session"][1]:
        raise SmokeFailure(f"unexpected /auth/session body: {responses['/auth/session'][1]!r}")
    if "native sign-in refused" not in responses["/auth/native/session"][1]:
        raise SmokeFailure(f"unexpected /auth/native/session body: {responses['/auth/native/session'][1]!r}")
    try:
        problem = json.loads(responses["/v1/capabilities"][1])
    except ValueError as exc:
        raise SmokeFailure("/v1/capabilities 401 body is not valid JSON") from exc
    if not isinstance(problem, dict) or problem.get("status") != MOUNTED_AUTH_HTTP["/v1/capabilities"] \
            or problem.get("code") != "unauthenticated":
        raise SmokeFailure(f"unexpected /v1/capabilities problem body: {problem!r}")
    return {**MOUNTED_AUTH_HTTP, "v1_error_code": "unauthenticated"}


def parse_structured_logs(output: str, role: str) -> list:
    """Parse container stderr as ADR 0024 flattened JSON lines; fail immediately on any non-JSON line."""
    records = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except ValueError as exc:
            raise SmokeFailure(f"{role} stderr emitted non-JSON log line") from exc
        if not isinstance(record, dict):
            raise SmokeFailure(f"{role} stderr log line is not a JSON object")
        if "message" in record:
            raise SmokeFailure(f"{role} JSON log line contains forbidden ADR 0024 'message' field")
        extra = sorted(set(record) - ALLOWED_LOG_FIELDS)
        if extra:
            raise SmokeFailure(f"{role} JSON log line contains unexpected fields: {extra}")
        if not isinstance(record.get("timestamp"), str) or not record["timestamp"]:
            raise SmokeFailure(f"{role} JSON log line missing timestamp")
        if record.get("level") not in LOG_LEVELS:
            raise SmokeFailure(f"{role} JSON log line has invalid level: {record.get('level')!r}")
        if not isinstance(record.get("event"), str) or not record["event"]:
            raise SmokeFailure(f"{role} JSON log line missing event")
        records.append(record)
    return records


def evaluate_structured_logs(role: str, pod_logs: dict, *, require_debug_http: bool = False) -> dict | None:
    """Verify ADR 0024 JSON logs across all pods of `role`; return None while expected events flush."""
    if not pod_logs:
        raise SmokeFailure(f"no {role} pods to inspect for structured logs")
    total_lines = 0
    debug_http = 0
    all_started = True
    for output in pod_logs.values():
        records = parse_structured_logs(output, role)
        total_lines += len(records)
        if not any(r.get("event") == "process.started" and r.get("role") == role
                   and r.get("level") == "INFO" for r in records):
            all_started = False
        debug_http += sum(1 for r in records if r.get("event") == "http.request.completed"
                          and r.get("level") == "DEBUG")
    if not all_started:
        return None
    if require_debug_http and debug_http == 0:
        return None
    return {"pods": len(pod_logs), "lines": total_lines, "debug_http_events": debug_http}


def assert_no_secrets(text: str, values) -> None:
    if any(value and value in text for value in values):
        raise SmokeFailure("refusing to publish output containing a fixture credential")


def redact(text: str, values) -> str:
    """Replace every whole secret value. Redact before truncating: a cut can split a value."""
    for value in values:
        if value:
            text = text.replace(value, "[redacted]")
    return text


def redacted_tail(text: str, values, limit: int) -> str:
    return redact(text, values)[-limit:]


def ctr_image_names(output: str) -> set:
    """Image names from `ctr images ls` output."""
    return {line.split()[0] for line in output.splitlines()[1:] if line.split()}


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
        self.runner = core.Runner(self.env)
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
    def run(self, args, *, input=None, check=True, timeout=600):
        """core's Runner, but the exit status is checked here so that the whole stderr is redacted
        before it is truncated. core's Runner keeps only the last 2000 characters, which can split
        a fixture password so that whole-value redaction misses the remaining part."""
        result = self.runner(args, input=input, check=False, timeout=timeout)
        if check and result.returncode != 0:
            detail = redacted_tail(result.stderr.strip(), self.passwords.values(), STDERR_TAIL)
            raise self.core.QualificationFailure(
                f"{' '.join(args[:4])} ... exited {result.returncode}: {detail}")
        return result

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
            self.run(["docker", "build", "--builder", "default", "--target", role,
                      "--tag", self.tags[role], str(self.core_dir)], timeout=1800)
            # docker tags only a successful build; cleanup removes only images that exist.
            self.built_images.append(self.tags[role])

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
            # Add the name unless containerd already holds it. CRI resolving the reference first
            # does not prove the name exists, and the check below reads the name.
            if reference not in ctr_image_names(listing):
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
        self.passwords = {
            **{k: secrets.token_hex(16) for k in ("admin", *ROLES)},
            "auth_login_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        }
        manifests = fixture_manifests(self.core.POSTGRES_IMAGE, self.passwords, self.run_id)
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(manifests))
        for deployment in ("postgres", PEER):
            self.kube("--namespace", DB_NAMESPACE, "rollout", "status", f"deployment/{deployment}",
                      "--timeout=300s", timeout=330)

    def migrations(self) -> list:
        """Applied migration history, read as the fixture superuser."""
        out = self.kube("--namespace", DB_NAMESPACE, "exec", "deployment/postgres", "--",
                        "psql", "-v", "ON_ERROR_STOP=1", "-qtA", "-U", "fixture_admin", "-d", "openmettle",
                        "-c", "SELECT version, success, encode(checksum, 'hex'), installed_on "
                              "FROM openmettle._sqlx_migrations ORDER BY version").stdout
        return [line.split("|") for line in out.splitlines() if line]

    def helm_deploy(self, command: str, worker_replicas: int, *, enabled_profile: bool = False):
        self.values.write_text(json.dumps(smoke_values(self.digests, worker_replicas,
                                                       enabled_profile=enabled_profile)))
        self.verify_identity()
        self.helm_run(command, RELEASE, str(CHART), "--values", str(self.values),
                      "--wait=watcher", "--timeout", HELM_TIMEOUT)

    def probe_api_exchange(self, expected: dict) -> dict:
        forward = PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080)
        try:
            out = {}
            for path, status in expected.items():
                def fetch(p=path, code=status):
                    got, body = self.core.http_get(forward.port, p)
                    return (got, body) if got == code else None
                out[path] = self.wait_for(f"API {path} {status}", fetch, timeout=30)
            return out
        finally:
            forward.close()

    def probe_api_http(self, paths=("/readyz",), *, expected_status: int = 200) -> dict:
        exchanged = self.probe_api_exchange({path: expected_status for path in paths})
        return {path: status for path, (status, _) in exchanged.items()}

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
        readyz = self.probe_api_http(("/readyz",))["/readyz"]
        return {"ready_replicas": counts, "readyz": readyz,
                "pods": {c: sorted(p["metadata"]["name"] for p in pods[c]) for c in WORKLOADS},
                "generations": {c: self.kube_json("--namespace", APP_NAMESPACE, "get", "deployment",
                                                  f"{FULLNAME}-{c}")["metadata"]["generation"]
                                for c in WORKLOADS}}

    def network_policy(self):
        """Prove that the cluster enforces the release's NetworkPolicies, from inside running pods.

        Readiness is still read through `kubectl port-forward`, which the kubelet serves inside the
        pod's network namespace, so no policy applies to it; the probes below are the policy evidence.
        """
        policies = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", "networkpolicies")["items"])
        self.expect(policies == sorted([f"NetworkPolicy/{NAMESPACE_DENY}", *release_network_policies()]),
                    f"app namespace NetworkPolicy objects: {policies}")
        dns_ip = running_pod_ip(self.kube_json("--namespace", "kube-system", "get", "pods", "--selector",
                                               DNS_SELECTOR)["items"], "CoreDNS")
        peer_ip = running_pod_ip(self.kube_json("--namespace", DB_NAMESPACE, "get", "pods", "--selector",
                                                f"app.kubernetes.io/name={PEER}")["items"], PEER)
        results = []
        for probe in probe_plan(dns_ip, peer_ip):
            result = self.kube("--namespace", probe["namespace"], "exec", f"deployment/{probe['workload']}",
                               "--container", probe["container"], "--", *probe["command"],
                               check=False, timeout=PROBE_SECONDS + 60)
            outcome = probe_outcome(result.returncode, result.stdout, result.stderr, probe["http"])
            if outcome == "inconclusive" or outcome == "unexpected-response":
                detail = redacted_tail((result.stderr or result.stdout or "").strip(), self.passwords.values(), 200)
                _log(f"probe {probe['name']}: {outcome} (expected {probe['expect']}, rc={result.returncode}, detail={detail!r})")
            else:
                _log(f"probe {probe['name']}: {outcome} (expected {probe['expect']})")
            results.append({key: probe[key] for key in ("name", "expect", "control")} | {"outcome": outcome})
        evaluate_probes(results)
        self.passed("NetworkPolicy enforced: DNS and database egress only, API ingress from the configured peer",
                    namespace_policies=policies,
                    probes=[{"probe": r["name"], "expect": r["expect"], "outcome": r["outcome"]} for r in results])

    def completions(self) -> list:
        return job_completions(self.events("involvedObject.kind=Job"), f"{FULLNAME}-migrate")

    def enabled_profile(self, history: list):
        """Upgrade to an enabled profile and verify live PDB, PVC, auth + /v1/* mounts and JSON/debug logs."""
        self.helm_deploy("upgrade", worker_replicas=1, enabled_profile=True)
        for component in WORKLOADS:
            self.kube("--namespace", APP_NAMESPACE, "rollout", "status",
                      f"deployment/{FULLNAME}-{component}", f"--timeout={PROFILE_ROLLOUT_TIMEOUT}",
                      timeout=210)
        profile = self.observe_release(revision=4)
        self.expect(profile["ready_replicas"] == {"api": 2, "worker": 1},
                    f"enabled-profile ready replicas: {profile['ready_replicas']}")
        self.expect(len(self.completions()) == 4, "enabled-profile upgrade did not run the migrate hook")
        self.expect(self.migrations() == history, "migration history changed on enabled-profile upgrade")
        pods_by_role = {c: self.pods(c) for c in WORKLOADS}
        auth_mounts = check_auth_mounts(pods_by_role)
        for pod_name in profile["pods"]["api"]:
            checked = self.kube("--namespace", APP_NAMESPACE, "exec", pod_name, "--container", "api", "--",
                                AUTH_CHECK_BINARY, "--check-auth-config", AUTH_CONFIG_PATH, timeout=60)
            self.expect(checked.stdout == AUTH_CHECK_OK,
                        f"{pod_name} --check-auth-config unexpected output: {checked.stdout!r}")
        exchanged = self.probe_api_exchange({
            "/healthz": 200,
            "/readyz": 200,
            **MOUNTED_AUTH_HTTP,
        })
        auth_routes = evaluate_mounted_auth_http({path: exchanged[path] for path in AUTH_ROUTE_PATHS})
        pdb = self.wait_for(
            "API PodDisruptionBudget disruptionsAllowed >= 1",
            lambda: evaluate_pdb(self.kube_json("--namespace", APP_NAMESPACE,
                                                "get", "poddisruptionbudget", API_PDB)),
            timeout=60)
        pvc = check_artifacts_pvc(
            self.kube_json("--namespace", APP_NAMESPACE, "get", "persistentvolumeclaim", ARTIFACTS_CLAIM),
            pods_by_role)
        logs_summary = {}
        for role, require_debug in (("api", True), ("worker", False)):
            names = profile["pods"][role]
            logs_summary[role] = self.wait_for(
                f"{role} ADR 0024 JSON structured logs",
                lambda r=role, ns=names, dbg=require_debug: evaluate_structured_logs(
                    r,
                    {name: self.kube("--namespace", APP_NAMESPACE, "logs", name,
                                     "--container", r, timeout=60).stdout
                     for name in ns},
                    require_debug_http=dbg),
                timeout=30)
        auth_summary = {**auth_mounts, "checked_pods": len(profile["pods"]["api"]), "routes": auth_routes}
        self.passed("enabled-profile upgrade: API replicas=2, PDB, artifact PVC, auth + /v1/* mounts and JSON/debug logs",
                    ready_replicas=profile["ready_replicas"],
                    healthz=exchanged["/healthz"][0], readyz=exchanged["/readyz"][0],
                    pdb=pdb, pvc=pvc, auth=auth_summary, logs=logs_summary)

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
        inventory = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", INVENTORY_KINDS,
                                                "--selector", f"app.kubernetes.io/instance={RELEASE}")["items"])
        self.expect(inventory == expected_release_objects(), f"release objects: {inventory}")
        # Every non-hook object Helm manages, read back live (hooks are not in the manifest).
        manifest = self.helm_run("get", "manifest", RELEASE).stdout
        live = json.loads(self.kube("--namespace", APP_NAMESPACE, "get", "--filename", "-", "--output=json",
                                    input=manifest).stdout)
        managed = object_names(live["items"] if live.get("kind") == "List" else [live])
        self.expect(managed == expected_release_objects(), f"release manifest objects: {managed}")
        optional = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", OPTIONAL_KINDS)["items"])
        self.expect(not optional, f"optional objects present: {optional}")
        # Helm 4 `list` shows releases in every status by default.
        releases = json.loads(self.run([*self.helm[:5], "list", "--all-namespaces", "--output", "json"]).stdout)
        self.expect([r["name"] for r in releases] == [RELEASE], f"other Helm releases: {releases}")
        all_pods = self.kube_json("--namespace", APP_NAMESPACE, "get", "pods")["items"]
        components = sorted({p["metadata"].get("labels", {}).get("app.kubernetes.io/component", "")
                             for p in all_pods})
        self.expect(components == sorted(WORKLOADS), f"pods outside api/worker: {components}")
        extra = unexpected_resources(all_pods)
        self.expect(not extra, f"pods request optional resources: {extra}")
        unmounted_http = self.probe_api_http(AUTH_ROUTE_PATHS, expected_status=404)
        self.passed("no optional package present", release_objects=inventory, helm_releases=1,
                    unmounted_http=unmounted_http)

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

        # 9: the install above ran under the namespace's default deny, so the migrate hook had only
        # its own hook policy for egress. Now prove the policies are enforced at all.
        self.network_policy()

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

        # 10: enabled-profile upgrade on the same ephemeral cluster before uninstall.
        self.enabled_profile(history)

        # 7: uninstall leaves no non-kept release objects (chart-owned artifact PVC stays via resource-policy keep).
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
        releases = json.loads(self.helm_run("list", "--output", "json").stdout)
        self.expect(releases == [], f"Helm still lists a release: {releases}")
        # Chart-owned artifact PVC carries helm.sh/resource-policy: keep and survives uninstall.
        kept_pvcs = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", "persistentvolumeclaims",
                                                "--selector", f"app.kubernetes.io/instance={RELEASE}")["items"])
        self.expect(kept_pvcs == [f"PersistentVolumeClaim/{ARTIFACTS_CLAIM}"],
                    f"kept artifact PVC after uninstall: {kept_pvcs}")
        # The test, not the chart, owns the URL Secrets, synthetic auth fixtures and namespace default-deny.
        remaining = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get",
                                                "configmaps,secrets,networkpolicies",
                                                "--selector", RUN_LABEL)["items"])
        expected_owned = sorted([
            f"ConfigMap/{AUTH_CONFIG_MAP}",
            f"NetworkPolicy/{NAMESPACE_DENY}",
            f"Secret/{AUTH_LOGIN_KEYS_SECRET}",
            *(f"Secret/{SECRET[r]}" for r in ROLES),
        ])
        self.expect(remaining == expected_owned,
                    f"test-owned objects after uninstall: {remaining}")
        self.passed("uninstall leaves no release objects", test_owned_remaining=remaining,
                    kept_pvcs=kept_pvcs)
        self.report["result"] = "passed"

    def diagnostics(self):
        if not self.kubeconfig.exists():
            return
        for args in (["get", "pods", "--all-namespaces", "--output=wide"],
                     ["--namespace", APP_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"],
                     ["--namespace", APP_NAMESPACE, "logs", "--selector", f"app.kubernetes.io/instance={RELEASE}",
                      "--all-containers", "--prefix", "--tail=100"],
                     ["--namespace", DB_NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"],
                     ["--namespace", APP_NAMESPACE, "get", "networkpolicies", "--output=wide"],
                     ["--namespace", APP_NAMESPACE, "get", "pvc,pdb", "--output=wide"],
                     # kindnet enforces NetworkPolicy; its log shows whether the policy controller started.
                     ["--namespace", "kube-system", "logs", "--selector", "app=kindnet", "--tail=50"]):
            try:
                result = self.kube(*args, check=False, timeout=60)
            except (subprocess.TimeoutExpired, OSError):
                continue
            print(redacted_tail(result.stdout, self.passwords.values(), DIAGNOSTIC_TAIL["stdout"])
                  + redacted_tail(result.stderr, self.passwords.values(), DIAGNOSTIC_TAIL["stderr"]),
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


def install_cleanup_handlers() -> dict:
    """Turn SIGTERM and SIGHUP into KeyboardInterrupt so that main() still cleans up.

    The first signal interrupts the run; later ones are ignored so that they cannot cut cleanup
    short. SIGINT keeps Python's default, so a second Ctrl-C can still abort cleanup.
    """
    def interrupt(signum, _frame):
        for sig in CLEANUP_SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        raise KeyboardInterrupt(signal.Signals(signum).name)
    return {sig: signal.signal(sig, interrupt) for sig in CLEANUP_SIGNALS}


def restore_handlers(previous: dict) -> None:
    for sig, handler in previous.items():
        signal.signal(sig, handler)


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
    previous_handlers = install_cleanup_handlers()
    try:
        smoke.build_images()
        smoke.create_cluster()
        smoke.pin_digests()
        smoke.deploy_fixtures()
        smoke.scenario()
        status = 0
    except KeyboardInterrupt as exc:  # SIGINT, or SIGTERM/SIGHUP through the handler
        smoke.report["result"] = "failed"
        smoke.report["error"] = f"interrupted: {exc or 'SIGINT'}"
        print(f"smoke {smoke.report['error']}; cleaning up", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - every failure is reported, diagnosed and cleaned up
        smoke.report["result"] = "failed"
        detail = str(exc) if isinstance(exc, failures) else f"{type(exc).__name__}: {exc}"
        smoke.report["error"] = redact(detail, smoke.passwords.values())
        print(f"smoke failed: {smoke.report['error']}", file=sys.stderr)
        smoke.diagnostics()
    finally:
        try:
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
        finally:
            restore_handlers(previous_handlers)
    return status


if __name__ == "__main__":
    sys.exit(main())
