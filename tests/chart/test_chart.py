"""Policy tests over `helm template` output for charts/openmettle-core (V1-32 I1 render contract, I3 network
policy, I4 storage, database CA, Ingress and PodDisruptionBudget, I5 browser sign-in / OIDC, AUTHSEC-01
session issuance database credential).

These tests render the chart; they do not install it. Each test docstring names a template or
schema change that would make it fail. Requires helm (or HELM) and PyYAML (test-only).
"""
import json
import os
import re
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "openmettle-core"
VALUES = ROOT / "tests" / "chart" / "values"
CONTRACT = ROOT / "tests" / "fixtures" / "core" / "process-contract.json"
EXAMPLE = ROOT / "examples" / "values-synthetic.yaml"
WORKSTATION_EXAMPLE = ROOT / "examples" / "values-workstation-profile.yaml"
HELM = os.environ.get("HELM", "helm")
RELEASE = "openmettle"

# Values sets rendered by every policy test: overlays applied on top of minimal.yaml.
MATRIX = {
    "minimal": (),
    "all-keys": ("all-keys.yaml",),
    "migration-disabled": ("migration-disabled.yaml",),
    "network-policy-disabled": ("network-policy-disabled.yaml",),
    "storage-existing-claim": ("storage-existing-claim.yaml",),
    "ingress-network-policy-disabled": ("ingress-network-policy-disabled.yaml",),
    "auth-enabled": ("auth-enabled.yaml",),
    "auth-network-policy-disabled": ("auth-network-policy-disabled.yaml",),
    "telemetry-otlp-enabled": ("telemetry-otlp-enabled.yaml",),
    "telemetry-otlp-metrics-only": ("telemetry-otlp-metrics-only.yaml",),
    "telemetry-network-policy-disabled": ("telemetry-network-policy-disabled.yaml",),
    "gateway-and-inference-enabled": ("gateway-and-inference-enabled.yaml",),
    "gateway-tls-terminator": ("gateway-tls-terminator.yaml",),
    "gateway-network-policy-disabled": ("gateway-network-policy-disabled.yaml",),
}
PREFIX = {"api": "OPENMETTLE_API_", "worker": "OPENMETTLE_WORKER_", "migrate": "OPENMETTLE_MIGRATE_",
          "gateway": "OPENMETTLE_GATEWAY_"}
PORT = {"api": 8080, "worker": 8081, "gateway": 8082}
INFERENCE_CONFIG_DIR = "/etc/openmettle/inference"
INFERENCE_CONFIG_PATH = "/etc/openmettle/inference/inference.json"
INFERENCE_CA_DIR = "/etc/openmettle/inference-ca"
INFERENCE_VOLUMES = {"inference-config", "inference-ca"}


def role_kind(role):
    return "gateway" if role.startswith("gateway-") else role
ALLOWED_KINDS = {"Deployment", "Service", "ServiceAccount", "Job", "NetworkPolicy", "PersistentVolumeClaim", "Ingress",
                 "PodDisruptionBudget"}
ALLOWED_RESOURCES = {"cpu", "memory", "ephemeral-storage"}
IMAGE = re.compile(r"^(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
HOOK = "helm.sh/hook"
HOOK_DELETE = "helm.sh/hook-delete-policy"
SCHEMA_ERROR = "values don't meet the specifications of the schema"
DIGEST = "sha256:" + "0" * 64
DNS_PORTS = [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]
DEFAULT_DNS_PEERS = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                      "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}]
# Expected rendered env for minimal.yaml with chart defaults. These literals were copied by hand
# from core src/lib.rs and src/migrate.rs at 24808cb; this test does not read core.
ISSUANCE_URL = "OPENMETTLE_API_ISSUANCE_DATABASE_URL"
ISSUANCE_POOL = "OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS"
ISSUANCE_SECRET = "openmettle-issuance-database"
DEFAULT_ENV = {
    "api": {"BIND": "0.0.0.0:8080", "DB_MAX_CONNECTIONS": "4", "DB_TIMEOUT_MS": "2000", "SHUTDOWN_TIMEOUT_MS": "5000"},
    "worker": {"BIND": "0.0.0.0:8081", "DB_MAX_CONNECTIONS": "4", "DB_TIMEOUT_MS": "2000", "SHUTDOWN_TIMEOUT_MS": "5000"},
    "migrate": {"CONNECT_TIMEOUT_MS": "5000", "LOCK_TIMEOUT_MS": "15000", "STATEMENT_TIMEOUT_MS": "300000"},
}


def helm_template(overlays=(), set_values=(), extra=(), release=RELEASE):
    args = [HELM, "template", release, str(CHART), "-f", str(VALUES / "minimal.yaml")]
    for overlay in overlays:
        args += ["-f", str(VALUES / overlay)]
    for value in set_values:
        args += ["--set", value]
    args += list(extra)
    return subprocess.run(args, capture_output=True, text=True, timeout=120, check=False)


def render(overlays=(), set_values=(), release=RELEASE):
    result = helm_template(overlays, set_values, release=release)
    if result.returncode != 0:
        raise AssertionError(f"helm template failed: {result.stderr}")
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def component(doc):
    return doc["metadata"]["labels"]["app.kubernetes.io/component"]


def pods(docs):
    """(component, pod spec) for every workload that creates pods."""
    return [(component(d), d["spec"]["template"]["spec"]) for d in docs if d["kind"] in ("Deployment", "Job")]


def containers(pod):
    return pod.get("initContainers", []) + pod["containers"]


def pod_labels(docs):
    """(component, pod template labels) for every workload that creates pods."""
    return [(component(d), d["spec"]["template"]["metadata"]["labels"]) for d in docs if d["kind"] in ("Deployment", "Job")]


def selects(selector, labels):
    """Kubernetes label-selector semantics (matchLabels and matchExpressions)."""
    if not all(labels.get(key) == value for key, value in selector.get("matchLabels", {}).items()):
        return False
    for expression in selector.get("matchExpressions", []):
        key, operator, values = expression["key"], expression["operator"], expression.get("values", [])
        matched = {"In": key in labels and labels[key] in values, "NotIn": labels.get(key) not in values,
                   "Exists": key in labels, "DoesNotExist": key not in labels}[operator]
        if not matched:
            return False
    return True


def effective_policy(docs, labels):
    """What every NetworkPolicy selecting a pod with `labels` adds up to (policies are additive).

    Returns (isolated policy types, ingress rules, egress rules).
    """
    types, ingress, egress = set(), [], []
    for policy in (d for d in docs if d["kind"] == "NetworkPolicy"):
        spec = policy["spec"]
        if selects(spec["podSelector"], labels):
            types.update(spec.get("policyTypes", []))
            ingress += spec.get("ingress", [])
            egress += spec.get("egress", [])
    return types, ingress, egress


def find(docs, kind, name_suffix):
    matches = [d for d in docs if d["kind"] == kind and d["metadata"]["name"].endswith(name_suffix)]
    if len(matches) != 1:
        raise AssertionError(f"expected one {kind} *{name_suffix}, found {len(matches)}")
    return matches[0]


def env_map(container):
    return {e["name"]: e for e in container.get("env", [])}


class Rendered(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.renders = {name: render(overlays) for name, overlays in MATRIX.items()}

    def each_pod(self):
        for name, docs in self.renders.items():
            for role, pod in pods(docs):
                with self.subTest(values=name, component=role):
                    yield name, role, pod


class PodPolicyTest(Rendered):
    def test_pod_security_context(self):
        """Fails if any field is removed from the openmettle-core.podSecurityContext helper."""
        for _, _, pod in self.each_pod():
            context = pod["securityContext"]
            self.assertIs(context.get("runAsNonRoot"), True)
            self.assertEqual(context.get("runAsUser"), 65532)
            self.assertEqual(context.get("runAsGroup"), 65532)
            self.assertEqual(context.get("seccompProfile"), {"type": "RuntimeDefault"})
            vol_names = {v["name"] for v in pod.get("volumes", [])}
            if "artifacts" in vol_names or "auth-login-keys" in vol_names:
                self.assertEqual(context.get("fsGroup"), 65532)
            else:
                self.assertNotIn("fsGroup", context, "fsGroup is only for pods mounting artifacts or auth login keys")
            if "artifacts" in vol_names:
                self.assertEqual(context.get("fsGroupChangePolicy"), "OnRootMismatch")
            else:
                self.assertNotIn("fsGroupChangePolicy", context)

    def test_container_security_context(self):
        """Fails if the containerSecurityContext helper is dropped or loosened for any container."""
        for _, _, pod in self.each_pod():
            for container in containers(pod):
                context = container["securityContext"]
                self.assertIs(context.get("allowPrivilegeEscalation"), False)
                self.assertIs(context.get("readOnlyRootFilesystem"), True)
                self.assertFalse(context.get("privileged", False))
                self.assertEqual(context.get("capabilities"), {"drop": ["ALL"]})

    def test_no_host_access(self):
        """Fails if a template adds hostNetwork/hostPID/hostIPC, a hostPath volume or a hostPort."""
        for _, _, pod in self.each_pod():
            for field in ("hostNetwork", "hostPID", "hostIPC"):
                self.assertFalse(pod.get(field, False), field)
            for volume in pod.get("volumes", []):
                self.assertNotIn("hostPath", volume)
            for container in containers(pod):
                for port in container.get("ports", []):
                    self.assertNotIn("hostPort", port)

    def test_only_known_volumes(self):
        """Fails if a pod gains an unknown volume, auth volumes appear outside api, inference volumes appear outside worker, otlp-ca appears on migrate, or a mount lacks a matching volume."""
        for _, role, pod in self.each_pod():
            vols = {v["name"]: v for v in pod.get("volumes", [])}
            self.assertLessEqual(set(vols), {"artifacts", "db-ca", "otlp-ca"} | AUTH_VOLUMES | INFERENCE_VOLUMES)
            if role != "api":
                self.assertFalse(AUTH_VOLUMES & set(vols), f"{role} must never mount auth volumes")
            if role != "worker":
                self.assertFalse(INFERENCE_VOLUMES & set(vols), f"{role} must never mount inference volumes")
            if role_kind(role) == "gateway":
                self.assertNotIn("artifacts", vols, f"{role} must never mount artifacts")
            if role == "migrate":
                self.assertNotIn("otlp-ca", vols, "migrate must never mount otlp-ca")
            if "artifacts" in vols:
                self.assertEqual(set(vols["artifacts"]), {"name", "persistentVolumeClaim"})
            for cm_vol in ("db-ca", "auth-config", "auth-provider-ca", "otlp-ca", "inference-config", "inference-ca"):
                if cm_vol in vols:
                    self.assertEqual(set(vols[cm_vol]), {"name", "configMap"})
            if "auth-login-keys" in vols:
                self.assertEqual(set(vols["auth-login-keys"]), {"name", "secret"})
            for container in containers(pod):
                vol_mounts = container.get("volumeMounts", [])
                self.assertEqual(sorted(m["name"] for m in vol_mounts), sorted(vols))

    def test_volume_mount_paths_are_non_overlapping(self):
        """Fails if any volumeMount is nested inside another mountPath (read-only ConfigMap mounts fail nested mkdir with EROFS)."""
        for _, _, pod in self.each_pod():
            for container in containers(pod):
                paths = [m["mountPath"].rstrip("/") for m in container.get("volumeMounts", [])]
                self.assertEqual(len(paths), len(set(paths)), paths)
                for i, left in enumerate(paths):
                    for j, right in enumerate(paths):
                        if i != j:
                            self.assertFalse(right.startswith(left + "/"), f"{right} nested inside {left}")

    def test_no_token_and_no_service_links(self):
        """Fails if a pod omits automountServiceAccountToken: false or enableServiceLinks: false."""
        for _, _, pod in self.each_pod():
            self.assertIs(pod.get("automountServiceAccountToken"), False)
            self.assertIs(pod.get("enableServiceLinks"), False)

    def test_environment_is_explicit_and_prefixed(self):
        """Fails on envFrom, an env name outside the component's own prefix, or a literal DATABASE_URL."""
        for _, role, pod in self.each_pod():
            kind = role_kind(role)
            for container in containers(pod):
                self.assertNotIn("envFrom", container)
                env = container.get("env", [])
                self.assertTrue(env)
                for entry in env:
                    self.assertTrue(entry["name"].startswith(PREFIX[kind]), entry["name"])
                url = env_map(container)[PREFIX[kind] + "DATABASE_URL"]
                self.assertNotIn("value", url)
                self.assertEqual(set(url["valueFrom"]), {"secretKeyRef"})
                self.assertEqual(set(url["valueFrom"]["secretKeyRef"]), {"name", "key"})

    def test_bind_is_explicit(self):
        """Fails if BIND is removed (core would default to loopback) or set to the wrong port."""
        for _, role, pod in self.each_pod():
            if role == "migrate":
                continue
            kind = role_kind(role)
            env = env_map(pod["containers"][0])
            self.assertEqual(env[PREFIX[kind] + "BIND"].get("value"), f"0.0.0.0:{PORT[kind]}")

    def test_images_are_digest_only(self):
        """Fails if the image helper appends a tag or drops the digest."""
        for _, _, pod in self.each_pod():
            for container in containers(pod):
                image = container["image"]
                self.assertRegex(image, IMAGE)
                name = image.split("@", 1)[0]
                self.assertNotIn(":", name.split("/")[-1], "tag present")

    def test_exact_image_references(self):
        """Fails if the image helper drops or reorders the registry, repository or digest."""
        expected = {
            ("minimal", "api"): f"registry.example.test/openmettle/api@{DIGEST}",
            ("minimal", "worker"): f"registry.example.test/openmettle/worker@{DIGEST}",
            ("minimal", "migrate"): f"registry.example.test/openmettle/migrate@{DIGEST}",
            ("all-keys", "api"): f"registry.example.test:5000/openmettle/api@{DIGEST}",
        }
        for (name, role), image in expected.items():
            with self.subTest(values=name, component=role):
                pod = dict(pods(self.renders[name]))[role]
                self.assertEqual(pod["containers"][0]["image"], image)
        docs = render(set_values=["images.worker.registry="])
        worker = find(docs, "Deployment", "-worker")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(worker["image"], f"openmettle/worker@{DIGEST}")

    def test_pull_policy_follows_values(self):
        """Fails if imagePullPolicy is hard-coded instead of taken from images.pullPolicy."""
        for name, policy in (("minimal", "IfNotPresent"), ("all-keys", "Never")):
            for _, pod in pods(self.renders[name]):
                for container in containers(pod):
                    with self.subTest(values=name, container=container["name"]):
                        self.assertEqual(container["imagePullPolicy"], policy)

    def test_no_device_resources(self):
        """Fails if any resource other than cpu, memory or ephemeral-storage is requested."""
        for _, _, pod in self.each_pod():
            for container in containers(pod):
                for section in container.get("resources", {}).values():
                    self.assertLessEqual(set(section), ALLOWED_RESOURCES)
                    self.assertFalse([key for key in section if key.endswith("/gpu")])


class ReleasePolicyTest(Rendered):
    def test_only_namespaced_allowlisted_kinds(self):
        """Fails if a template adds a Secret, RBAC, Namespace, CRD, DRA object or any other kind."""
        for name, docs in self.renders.items():
            with self.subTest(values=name):
                self.assertLessEqual({d["kind"] for d in docs}, ALLOWED_KINDS)
                for doc in docs:
                    self.assertFalse(doc["apiVersion"].startswith("resource.k8s.io"))
                    self.assertNotIn("namespace", doc["metadata"])

    def test_expected_resources(self):
        """Fails if a component's Deployment, Service, ServiceAccount, Job or NetworkPolicy is dropped or duplicated."""
        names = sorted((d["kind"], d["metadata"]["name"]) for d in self.renders["minimal"])
        full = f"{RELEASE}-openmettle-core"
        self.assertEqual(names, sorted([
            ("Deployment", f"{full}-api"), ("Deployment", f"{full}-worker"), ("Service", f"{full}-api"),
            ("ServiceAccount", f"{full}-api"), ("ServiceAccount", f"{full}-worker"),
            ("ServiceAccount", f"{full}-migrate"), ("Job", f"{full}-migrate"),
            ("NetworkPolicy", f"{full}-deny-all"), ("NetworkPolicy", f"{full}-api"),
            ("NetworkPolicy", f"{full}-worker"), ("NetworkPolicy", f"{full}-migrate"),
        ]))

    def test_separate_service_accounts(self):
        """Fails if two components share a ServiceAccount or a created ServiceAccount mounts tokens."""
        for name, docs in self.renders.items():
            with self.subTest(values=name):
                accounts = {role: pod["serviceAccountName"] for role, pod in pods(docs)}
                self.assertEqual(len(set(accounts.values())), len(accounts), accounts)
                self.assertNotIn("default", accounts.values())
                for doc in docs:
                    if doc["kind"] == "ServiceAccount":
                        self.assertIs(doc.get("automountServiceAccountToken"), False)
                created = {d["metadata"]["name"] for d in docs if d["kind"] == "ServiceAccount"}
                if name == "minimal":
                    self.assertEqual(set(accounts.values()), created)

    def test_service_selects_only_api(self):
        """Fails if the Service selector also matches worker pods or targets a missing port name."""
        for name, docs in self.renders.items():
            with self.subTest(values=name):
                service = find(docs, "Service", "-api")
                selector = service["spec"]["selector"]
                for deployment in (d for d in docs if d["kind"] == "Deployment"):
                    labels = deployment["spec"]["template"]["metadata"]["labels"]
                    matches = all(labels.get(k) == v for k, v in selector.items())
                    self.assertEqual(matches, component(deployment) == "api")
                    self.assertEqual(deployment["spec"]["selector"]["matchLabels"].items() <= labels.items(), True)
                port = service["spec"]["ports"][0]
                self.assertEqual(port["targetPort"], "http")
                api = find(docs, "Deployment", "-api")["spec"]["template"]["spec"]["containers"][0]
                self.assertIn("http", [p["name"] for p in api["ports"]])
        self.assertEqual(find(self.renders["minimal"], "Service", "-api")["spec"]["ports"][0]["port"], 8080)
        self.assertEqual(find(self.renders["all-keys"], "Service", "-api")["spec"]["ports"][0]["port"], 80)

    def test_service_is_cluster_ip(self):
        """Fails if the API Service type becomes NodePort, LoadBalancer or anything but ClusterIP."""
        for name, docs in self.renders.items():
            with self.subTest(values=name):
                self.assertEqual(find(docs, "Service", "-api")["spec"]["type"], "ClusterIP")

    def test_owner_credential_only_in_migration_job(self):
        """Fails if the migrate (owner) Secret is referenced outside the Job, or a role reads another's Secret."""
        for name, docs in self.renders.items():
            with self.subTest(values=name):
                for role, pod in pods(docs):
                    kind = role_kind(role)
                    ref = env_map(pod["containers"][0])[PREFIX[kind] + "DATABASE_URL"]["valueFrom"]["secretKeyRef"]
                    expected = {"api": "openmettle-api-database", "worker": "openmettle-worker-database",
                                "migrate": "openmettle-owner-database", "gateway": "openmettle-gateway-database"}[kind]
                    self.assertEqual(ref["name"], expected)
                rendered = yaml.safe_dump_all(d for d in docs if d["kind"] != "Job")
                self.assertNotIn("openmettle-owner-database", rendered)

    def test_values_reach_the_environment(self):
        """Fails if a settings value or Secret key is not plumbed into the matching env var."""
        docs = self.renders["all-keys"]
        expected = {
            "api": {"DB_MAX_CONNECTIONS": "6", "DB_TIMEOUT_MS": "2500", "SHUTDOWN_TIMEOUT_MS": "8000",
                    "ISSUANCE_DB_MAX_CONNECTIONS": "3"},
            "worker": {"DB_MAX_CONNECTIONS": "2", "DB_TIMEOUT_MS": "1000", "SHUTDOWN_TIMEOUT_MS": "3000",
                       "SWEEP_MS": "30000", "POLL_MS": "500", "INFERENCE_CONFIG": INFERENCE_CONFIG_PATH,
                       "RUN_SLOTS": "8", "LEASE_MS": "60000", "EXECUTION_TIMEOUT_MS": "180000",
                       "EXECUTING_PER_ACTOR": "3", "EXECUTING_PER_SCOPE": "6"},
            "migrate": {"CONNECT_TIMEOUT_MS": "10000", "LOCK_TIMEOUT_MS": "30000", "STATEMENT_TIMEOUT_MS": "600000"},
            "gateway-a": {"DB_MAX_CONNECTIONS": "3", "DB_TIMEOUT_MS": "1500", "SHUTDOWN_TIMEOUT_MS": "7000",
                          "MODEL": "model-a", "UPSTREAM_URL": "http://sglang-a.inference.example.test:30000",
                          "CACHE_MODE": "per_request", "UPSTREAM_CONNECT_TIMEOUT_MS": "4000",
                          "UPSTREAM_IDLE_TIMEOUT_MS": "90000"},
        }
        keys = {"api": "api-url", "worker": "worker-url", "migrate": "owner-url", "gateway-a": "gateway-url"}
        for role, pod in pods(docs):
            kind = role_kind(role)
            env = env_map(pod["containers"][0])
            for key, value in expected[role].items():
                self.assertEqual(env[PREFIX[kind] + key]["value"], value)
            self.assertEqual(env[PREFIX[kind] + "DATABASE_URL"]["valueFrom"]["secretKeyRef"]["key"], keys[role])
        api = env_map(find(docs, "Deployment", "-api")["spec"]["template"]["spec"]["containers"][0])
        self.assertEqual(api[ISSUANCE_URL]["valueFrom"]["secretKeyRef"]["key"], "issuance-url")

    def test_default_environment(self):
        """Fails if any default env value in values.yaml changes from DEFAULT_ENV, or a variable is added or dropped."""
        for role, pod in pods(self.renders["minimal"]):
            with self.subTest(component=role):
                env = env_map(pod["containers"][0])
                url = env.pop(PREFIX[role] + "DATABASE_URL")
                self.assertEqual(set(url), {"name", "valueFrom"})
                values = {name[len(PREFIX[role]):]: entry.get("value") for name, entry in env.items()}
                self.assertEqual(values, DEFAULT_ENV[role])

    def test_readiness_timeout_covers_database_timeout(self):
        """Fails if readiness timeoutSeconds is not ceil(dbTimeoutMs / 1000) + 1."""
        cases = {("minimal", "api"): 3, ("minimal", "worker"): 3, ("all-keys", "api"): 4, ("all-keys", "worker"): 2}
        for (name, role), seconds in cases.items():
            with self.subTest(values=name, component=role):
                pod = find(self.renders[name], "Deployment", f"-{role}")["spec"]["template"]["spec"]
                self.assertEqual(pod["containers"][0]["readinessProbe"]["timeoutSeconds"], seconds)

    def test_rollout_and_scheduling_values(self):
        """Fails if replicas, strategy, grace period or scheduling values are not passed through."""
        api = find(self.renders["all-keys"], "Deployment", "-api")
        worker = find(self.renders["all-keys"], "Deployment", "-worker")
        self.assertEqual(api["spec"]["replicas"], 2)
        self.assertEqual(worker["spec"]["replicas"], 3)
        self.assertEqual(api["spec"]["strategy"], {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}})
        self.assertEqual(worker["spec"]["strategy"]["rollingUpdate"], {"maxSurge": 2, "maxUnavailable": 0})
        pod = api["spec"]["template"]["spec"]
        self.assertEqual(pod["terminationGracePeriodSeconds"], 20)
        self.assertEqual(pod["nodeSelector"], {"kubernetes.io/os": "linux"})
        self.assertEqual(pod["tolerations"][0]["key"], "example.test/dedicated")
        self.assertIn("podAntiAffinity", pod["affinity"])
        self.assertEqual(pod["imagePullSecrets"], [{"name": "example-pull-secret"}])
        self.assertEqual(api["spec"]["template"]["metadata"]["annotations"], {"example.test/note": "synthetic"})

    def test_migration_scheduling_values(self):
        """Fails if migration nodeSelector, tolerations, affinity or podAnnotations do not reach the hook pod."""
        template = find(self.renders["all-keys"], "Job", "-migrate")["spec"]["template"]
        pod = template["spec"]
        self.assertEqual(template["metadata"]["annotations"], {"example.test/note": "migrate"})
        self.assertEqual(pod["nodeSelector"], {"example.test/pool": "migrate"})
        self.assertEqual(pod["tolerations"], [{"key": "example.test/dedicated", "operator": "Exists", "effect": "NoSchedule"}])
        self.assertIn("nodeAffinity", pod["affinity"])
        minimal = find(self.renders["minimal"], "Job", "-migrate")["spec"]["template"]
        self.assertNotIn("annotations", minimal["metadata"])
        for field in ("nodeSelector", "tolerations", "affinity"):
            self.assertNotIn(field, minimal["spec"])


class MigrationHookTest(Rendered):
    def test_job_is_a_pre_install_and_pre_upgrade_hook(self):
        """Fails if the Job's hook events, delete policy or weight change."""
        for name in ("minimal", "all-keys"):
            with self.subTest(values=name):
                annotations = find(self.renders[name], "Job", "-migrate")["metadata"]["annotations"]
                self.assertEqual(annotations[HOOK], "pre-install,pre-upgrade")
                self.assertEqual(annotations[HOOK_DELETE], "before-hook-creation,hook-succeeded")
                self.assertEqual(annotations["helm.sh/hook-weight"], "0")

    def test_service_account_hook_runs_first(self):
        """Fails if the migrate ServiceAccount stops being a hook or its weight is not below the Job's."""
        for name in ("minimal", "all-keys"):
            with self.subTest(values=name):
                docs = self.renders[name]
                account = find(docs, "ServiceAccount", "-migrate")
                job = find(docs, "Job", "-migrate")
                self.assertEqual(account["metadata"]["annotations"][HOOK], job["metadata"]["annotations"][HOOK])
                self.assertLess(int(account["metadata"]["annotations"]["helm.sh/hook-weight"]),
                                int(job["metadata"]["annotations"]["helm.sh/hook-weight"]))
                self.assertEqual(job["spec"]["template"]["spec"]["serviceAccountName"], account["metadata"]["name"])

    def test_service_account_hook_delete_policy(self):
        """Fails if the migrate ServiceAccount's delete policy or weight changes."""
        for name in ("minimal", "all-keys"):
            with self.subTest(values=name):
                annotations = find(self.renders[name], "ServiceAccount", "-migrate")["metadata"]["annotations"]
                self.assertEqual(annotations[HOOK_DELETE], "before-hook-creation,hook-succeeded")
                self.assertEqual(annotations["helm.sh/hook-weight"], "-10")

    def test_no_rollback_hook_and_no_other_hooks(self):
        """Fails if any resource gains a rollback hook, or a non-migration resource becomes a hook."""
        for name, docs in self.renders.items():
            with self.subTest(values=name):
                for doc in docs:
                    hook = doc["metadata"].get("annotations", {}).get(HOOK)
                    if hook is None:
                        continue
                    self.assertNotIn("rollback", hook)
                    self.assertEqual(component(doc), "migrate")

    def test_user_annotations_cannot_replace_hook(self):
        """Fails if migration.serviceAccount.annotations can override the hook annotations."""
        docs = render(set_values=[r"migration.serviceAccount.annotations.helm\.sh/hook=post-install"])
        self.assertEqual(find(docs, "ServiceAccount", "-migrate")["metadata"]["annotations"][HOOK], "pre-install,pre-upgrade")

    def test_job_retry_and_deadline(self):
        """Fails if restartPolicy, backoffLimit, activeDeadlineSeconds or the exit-78 FailJob rule change."""
        for name, deadline in (("minimal", 900), ("all-keys", 1800)):
            with self.subTest(values=name):
                job = find(self.renders[name], "Job", "-migrate")
                spec = job["spec"]
                self.assertEqual(spec["template"]["spec"]["restartPolicy"], "Never")
                self.assertEqual(spec["backoffLimit"], 2)
                self.assertEqual(spec["activeDeadlineSeconds"], deadline)
                container = spec["template"]["spec"]["containers"][0]["name"]
                self.assertIn({"action": "FailJob", "onExitCodes": {"containerName": container, "operator": "In", "values": [78]}},
                              spec["podFailurePolicy"]["rules"])

    def test_migration_disabled(self):
        """Fails if disabling migration still renders the Job, its ServiceAccount, its NetworkPolicy or requires its inputs."""
        docs = self.renders["migration-disabled"]
        self.assertFalse([d for d in docs if component(d) == "migrate"])
        self.assertEqual({d["kind"] for d in docs}, {"Deployment", "Service", "ServiceAccount", "NetworkPolicy"})


class NetworkPolicyTest(Rendered):
    """Design §5: a chart-scoped deny-all plus DNS and database egress, and API/gateway ingress from configured peers."""

    ENABLED = ("minimal", "all-keys", "migration-disabled", "auth-enabled", "telemetry-otlp-enabled",
               "gateway-and-inference-enabled", "gateway-tls-terminator")

    def policies(self, name):
        return [d for d in self.renders[name] if d["kind"] == "NetworkPolicy"]

    def test_deny_all_selects_every_release_pod(self):
        """Fails if the deny-all is dropped, loses a policy type, gains a rule or stops selecting a release pod."""
        release = {"app.kubernetes.io/name": "openmettle-core", "app.kubernetes.io/instance": RELEASE}
        for name in self.ENABLED:
            with self.subTest(values=name):
                docs = self.renders[name]
                deny = find(docs, "NetworkPolicy", "-deny-all")
                self.assertEqual(deny["spec"], {"podSelector": {"matchLabels": release},
                                                "policyTypes": ["Ingress", "Egress"]})
                self.assertNotIn(HOOK, deny["metadata"].get("annotations", {}))
                for role, labels in pod_labels(docs):
                    self.assertTrue(selects(deny["spec"]["podSelector"], labels), role)
                # A future component of this release is denied too; another release's pods are not selected.
                selector = deny["spec"]["podSelector"]
                self.assertTrue(selects(selector, {**release, "app.kubernetes.io/component": "new"}))
                self.assertFalse(selects(selector, {**release, "app.kubernetes.io/instance": "other"}))

    def test_every_pod_is_isolated_both_ways(self):
        """Fails if any rendered pod is not selected by a policy covering both Ingress and Egress."""
        for name in self.ENABLED:
            for role, labels in pod_labels(self.renders[name]):
                with self.subTest(values=name, component=role):
                    types, _, _ = effective_policy(self.renders[name], labels)
                    self.assertEqual(types, {"Ingress", "Egress"})

    def test_egress_is_dns_and_database_only(self):
        """Fails if a component gains an unexpected egress rule, loses DNS/database egress, OIDC leaks beyond api, or OTLP leaks to migrate."""
        default_db = [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-database"}},
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "postgres"}},
        }]
        all_keys_oidc = [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-identity"}},
             "podSelector": {"matchLabels": {"app.kubernetes.io/name": "example-oidc"}}},
            {"ipBlock": {"cidr": "198.51.100.50/32"}},
        ]
        all_keys_otlp = [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-observability"}},
             "podSelector": {"matchLabels": {"app.kubernetes.io/name": "example-alloy"}}},
            {"ipBlock": {"cidr": "198.51.100.60/32"}},
        ]
        all_keys_worker_inf = [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-ingress"}},
             "podSelector": {"matchLabels": {"app.kubernetes.io/name": "example-gateway-tls"}}},
        ]
        expected = {
            "minimal": (DEFAULT_DNS_PEERS, default_db, 5432, None, None, None, {}),
            "auth-enabled": (DEFAULT_DNS_PEERS, default_db, 5432, ([{"ipBlock": {"cidr": "192.0.2.20/32"}}], 443),
                             None, None, {}),
            "telemetry-otlp-enabled": (DEFAULT_DNS_PEERS, default_db, 5432, None,
                                       ([{"ipBlock": {"cidr": "192.0.2.30/32"}}], 4318), None, {}),
            "all-keys": ([{"ipBlock": {"cidr": "192.0.2.10/32"}},
                          {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-dns"}}}],
                         [{"ipBlock": {"cidr": "198.51.100.0/24"}}, {"ipBlock": {"cidr": "2001:db8::/64"}}],
                         5433, (all_keys_oidc, 8443), (all_keys_otlp, 4319),
                         (all_keys_worker_inf, 8443),
                         {"gateway-a": ([{"ipBlock": {"cidr": "198.51.100.70/32"}}], 30000)}),
        }
        for name, (dns, database, port, api_oidc, otlp, worker_inf, gw_upstreams) in expected.items():
            roles = []
            for role, labels in pod_labels(self.renders[name]):
                roles.append(role)
                with self.subTest(values=name, component=role):
                    _, _, egress = effective_policy(self.renders[name], labels)
                    rules = [{"to": dns, "ports": DNS_PORTS},
                             {"to": database, "ports": [{"protocol": "TCP", "port": port}]}]
                    if role == "api" and api_oidc is not None:
                        oidc_peers, oidc_port = api_oidc
                        rules.append({"to": oidc_peers, "ports": [{"protocol": "TCP", "port": oidc_port}]})
                    if role != "migrate" and otlp is not None:
                        otlp_peers, otlp_port = otlp
                        rules.append({"to": otlp_peers, "ports": [{"protocol": "TCP", "port": otlp_port}]})
                    if role == "worker" and worker_inf is not None:
                        inf_peers, inf_port = worker_inf
                        rules.append({"to": inf_peers, "ports": [{"protocol": "TCP", "port": inf_port}]})
                    if role in gw_upstreams:
                        up_peers, up_port = gw_upstreams[role]
                        rules.append({"to": up_peers, "ports": [{"protocol": "TCP", "port": up_port}]})
                    self.assertEqual(egress, rules)
            self.assertEqual(sorted(roles), sorted(["api", "migrate", "worker", *gw_upstreams]))

    def test_ingress_only_to_api_from_configured_peers(self):
        """Fails if a worker or migrate pod accepts ingress, or API/gateway ingress is open, widened or on another port."""
        peers = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-ingress"}},
                  "podSelector": {"matchExpressions": [{"key": "app.kubernetes.io/name", "operator": "In",
                                                        "values": ["example-ingress-controller"]}]}},
                 {"ipBlock": {"cidr": "192.0.2.0/24", "except": ["192.0.2.128/25"]}}]
        all_keys_gw_peers = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-ingress"}},
                              "podSelector": {"matchLabels": {"app.kubernetes.io/name": "example-gateway-tls"}}}]
        tls_gw_peers = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "example-ingress"}},
                         "podSelector": {"matchLabels": {"app.kubernetes.io/name": "traefik"}}}]
        worker_peer = [{"podSelector": {"matchLabels": {
            "app.kubernetes.io/name": "openmettle-core",
            "app.kubernetes.io/instance": RELEASE,
            "app.kubernetes.io/component": "worker",
        }}}]
        for name in self.ENABLED:
            for role, labels in pod_labels(self.renders[name]):
                with self.subTest(values=name, component=role):
                    _, ingress, _ = effective_policy(self.renders[name], labels)
                    if name == "all-keys" and role == "api":
                        self.assertEqual(ingress, [{"from": peers, "ports": [{"protocol": "TCP", "port": 8080}]}])
                    elif role_kind(role) == "gateway":
                        expected_from = (all_keys_gw_peers if name == "all-keys"
                                         else tls_gw_peers if name == "gateway-tls-terminator"
                                         else worker_peer)
                        self.assertEqual(ingress, [{"from": expected_from, "ports": [{"protocol": "TCP", "port": 8082}]}])
                    else:
                        self.assertEqual(ingress, [], "ingressFrom defaults to empty: no peer may connect")

    def test_api_ingress_port_is_the_api_container_port(self):
        """Fails if the ingress port drifts from the API's container port (the Service targets that port)."""
        docs = self.renders["all-keys"]
        container = find(docs, "Deployment", "-api")["spec"]["template"]["spec"]["containers"][0]
        rule = find(docs, "NetworkPolicy", "-api")["spec"]["ingress"][0]
        self.assertEqual([p["port"] for p in rule["ports"]], [p["containerPort"] for p in container["ports"]])

    def test_no_rule_matches_every_peer_or_port(self):
        """Fails if any rendered rule has a missing or empty peer or port list, or an empty peer (each means "all")."""
        for name in self.ENABLED:
            for policy in self.policies(name):
                with self.subTest(values=name, policy=policy["metadata"]["name"]):
                    rules = [(rule, "from") for rule in policy["spec"].get("ingress", [])]
                    rules += [(rule, "to") for rule in policy["spec"].get("egress", [])]
                    for rule, key in rules:
                        self.assertTrue(rule.get(key))
                        self.assertTrue(rule.get("ports"))
                        self.assertTrue(all(rule[key]))

    def test_migrate_policy_is_a_hook_before_the_job(self):
        """Fails if the migrate egress policy is dropped, stops being a hook or does not run before the Job."""
        for name in ("minimal", "all-keys"):
            with self.subTest(values=name):
                docs = self.renders[name]
                policy = find(docs, "NetworkPolicy", "-migrate")
                job = find(docs, "Job", "-migrate")
                annotations = policy["metadata"]["annotations"]
                self.assertEqual(annotations[HOOK], job["metadata"]["annotations"][HOOK])
                self.assertEqual(annotations[HOOK_DELETE], "before-hook-creation,hook-succeeded")
                self.assertLess(int(annotations["helm.sh/hook-weight"]),
                                int(job["metadata"]["annotations"]["helm.sh/hook-weight"]))
                self.assertTrue(selects(policy["spec"]["podSelector"], job["spec"]["template"]["metadata"]["labels"]))
                # Only the migrate policy is a hook; the others are ordinary release objects.
                hooks = [p["metadata"]["name"] for p in self.policies(name) if HOOK in p["metadata"].get("annotations", {})]
                self.assertEqual(hooks, [policy["metadata"]["name"]])

    def test_component_policies_select_only_their_component(self):
        """Fails if an api, worker or migrate policy selector also matches another component's pods."""
        for name in self.ENABLED:
            docs = self.renders[name]
            for policy in self.policies(name):
                role = component(policy)
                if role == "network-policy":
                    continue
                with self.subTest(values=name, policy=role):
                    matched = sorted(r for r, labels in pod_labels(docs) if selects(policy["spec"]["podSelector"], labels))
                    self.assertEqual(matched, [role])

    def test_disabled_renders_no_policy(self):
        """Fails if networkPolicy.enabled=false still renders a NetworkPolicy or still requires database peers."""
        docs = self.renders["network-policy-disabled"]
        self.assertEqual({d["kind"] for d in docs}, {"Deployment", "Service", "ServiceAccount", "Job"})

    def test_chart_defaults(self):
        """Fails if values.yaml stops enabling policies, changes the DNS peer or ships database, API, worker or OTLP peers."""
        defaults = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))["networkPolicy"]
        self.assertEqual(defaults, {"enabled": True, "api": {"ingressFrom": [], "oidc": {"to": [], "port": 443}},
                                    "worker": {"inference": {"to": [], "port": 8082}},
                                    "dns": {"to": DEFAULT_DNS_PEERS}, "database": {"to": [], "port": 5432},
                                    "telemetry": {"otlp": {"to": [], "port": 4318}}})

    def test_names_fit_in_63_characters(self):
        """Fails if an object name can exceed 63 characters at the longest fullname (Helm caps release names at 53)."""
        names = [d["metadata"]["name"] for d in render(("all-keys.yaml",), release="r" * 53)]
        self.assertIn("r" * 52 + "-deny-all", names)
        self.assertIn("r" * 52 + "-artifacts", names)
        self.assertIn("r" * 52 + "-gateway-a", names)
        self.assertLessEqual(max(map(len, names)), 63, names)


ARTIFACTS_PATH = "/var/lib/openmettle/artifacts"
DB_CA_DIRECTORY = "/etc/openmettle/db-ca"
AUTH_CONFIG_DIR = "/etc/openmettle/auth"
AUTH_CONFIG_PATH = "/etc/openmettle/auth/auth.json"
AUTH_KEYS_DIR = "/etc/openmettle/auth-keys"
AUTH_CA_DIR = "/etc/openmettle/auth-ca"
AUTH_VOLUMES = {"auth-config", "auth-login-keys", "auth-provider-ca"}
# Reusable examples leave auth.catalogKey empty: an existing auth ConfigMap without a catalog key would
# otherwise fail the API volume mount after an upgrade. A site overlay sets it (docs/first-install.md).
EXAMPLE_AUTH_ITEMS = [{"key": "auth.json", "path": "auth.json"}]
OTLP_CA_DIR = "/etc/openmettle/otlp-ca"
OTLP_CA_PATH = "/etc/openmettle/otlp-ca/ca.crt"
I4_KINDS = {"PersistentVolumeClaim", "Ingress", "PodDisruptionBudget"}


def mounts(pod):
    return {m["name"]: m for m in pod["containers"][0].get("volumeMounts", [])}


def volumes(pod):
    return {v["name"]: v for v in pod.get("volumes", [])}


class OptionalDefaultsTest(Rendered):
    """I4, I5 and I6 features are off by default and add nothing to a default render."""

    def test_chart_defaults(self):
        """Fails if values.yaml enables or pre-fills the artifact volume, database CA, Ingress, API PDB, auth or telemetry."""
        defaults = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
        self.assertEqual(defaults["database"]["caBundle"], {"enabled": False, "configMapName": "", "key": "ca.crt"})
        self.assertEqual(defaults["database"]["issuance"], {"existingSecret": "", "key": "url"})
        self.assertEqual(defaults["api"]["settings"]["issuanceDbMaxConnections"], 2)
        self.assertNotIn("issuanceDbMaxConnections", defaults["worker"]["settings"])
        self.assertEqual(defaults["api"]["podDisruptionBudget"],
                         {"enabled": False, "minAvailable": None, "maxUnavailable": None})
        self.assertEqual(defaults["storage"], {"artifacts": {
            "enabled": False, "existingClaim": "", "size": "", "accessModes": ["ReadWriteOnce"],
            "storageClassName": None, "annotations": {}}})
        self.assertEqual(defaults["ingress"], {"enabled": False, "className": "", "annotations": {}, "hosts": [], "tls": []})
        self.assertEqual(defaults["auth"], {
            "enabled": False, "configMapName": "", "configKey": "auth.json", "catalogKey": "", "loginKeysSecretName": "",
            "providerCaBundle": {"enabled": False, "configMapName": "", "key": "ca.crt"},
        })
        self.assertEqual(defaults["telemetry"], {
            "logging": {"format": None, "level": None},
            "otlp": {
                "enabled": False,
                "tracesEndpoint": "",
                "metricsEndpoint": "",
                "privateRanges": [],
                "caBundle": {"enabled": False, "configMapName": "", "key": "ca.crt"},
            },
        })
        self.assertEqual(defaults["networkPolicy"]["telemetry"], {"otlp": {"to": [], "port": 4318}})
        self.assertEqual(defaults["networkPolicy"]["worker"], {"inference": {"to": [], "port": 8082}})
        self.assertEqual(defaults["images"]["gateway"], {"registry": "", "repository": "", "digest": ""})
        self.assertEqual(defaults["database"]["gateway"], {"existingSecret": "", "key": "url"})
        self.assertIsNone(defaults["worker"]["pollMs"])
        self.assertEqual(defaults["worker"]["inference"], {
            "enabled": False,
            "configMapName": "",
            "configKey": "inference.json",
            "catalogKey": "catalog.json",
            "settings": {
                "runSlots": 4,
                "leaseMs": 60000,
                "executionTimeoutMs": 300000,
                "executingPerActor": 2,
                "executingPerScope": 4,
            },
            "caBundle": {"enabled": False, "configMapName": "", "key": "ca.crt"},
        })
        self.assertEqual(defaults["gateways"], {})

    def test_defaults_render_no_optional_resource_volume_or_env(self):
        """Fails if a default render gains a PVC, Ingress, PDB, volume, mount, fsGroup or environment variable."""
        for name in ("minimal", "migration-disabled", "network-policy-disabled"):
            docs = self.renders[name]
            with self.subTest(values=name):
                self.assertFalse(I4_KINDS & {d["kind"] for d in docs})
                for role, pod in pods(docs):
                    self.assertNotIn("volumes", pod, role)
                    self.assertNotIn("volumeMounts", pod["containers"][0], role)
                    self.assertNotIn("fsGroup", pod["securityContext"], role)
        for role, pod in pods(self.renders["minimal"]):
            env = {e["name"][len(PREFIX[role]):] for e in pod["containers"][0]["env"]}
            self.assertEqual(env, set(DEFAULT_ENV[role]) | {"DATABASE_URL"})


class DatabaseCaTest(Rendered):
    """database.caBundle mounts one existing ConfigMap key read-only into every component."""

    def test_mounted_read_only_into_every_component(self):
        """Fails if api, worker, migrate or gateway lacks the CA volume, the mount is writable or the file name changes."""
        roles = []
        for role, pod in pods(self.renders["all-keys"]):
            roles.append(role)
            with self.subTest(component=role):
                self.assertEqual(volumes(pod)["db-ca"], {"name": "db-ca", "configMap": {
                    "name": "example-db-ca", "items": [{"key": "root-ca.pem", "path": "ca.crt"}]}})
                self.assertEqual(mounts(pod)["db-ca"], {"name": "db-ca", "mountPath": DB_CA_DIRECTORY, "readOnly": True})
        self.assertEqual(sorted(roles), ["api", "gateway-a", "migrate", "worker"])

    def test_no_environment_variable(self):
        """Fails if the CA adds an environment variable (core ADR 0002: no shared PG* defaults; use sslrootcert in the URL)."""
        enabled = dict(pods(render(set_values=["database.caBundle.enabled=true", "database.caBundle.configMapName=ca"])))
        for role, pod in pods(self.renders["minimal"]):
            with self.subTest(component=role):
                self.assertEqual(pod["containers"][0]["env"], enabled[role]["containers"][0]["env"])
                self.assertEqual(volumes(enabled[role])["db-ca"]["configMap"]["items"], [{"key": "ca.crt", "path": "ca.crt"}])

    def test_follows_migration_toggle(self):
        """Fails if the CA renders a migrate pod when migration is disabled, or is lost from api or worker."""
        docs = render(("migration-disabled.yaml",), ["database.caBundle.enabled=true", "database.caBundle.configMapName=ca"])
        self.assertEqual(sorted(role for role, pod in pods(docs) if "db-ca" in volumes(pod)), ["api", "worker"])

    def test_chart_creates_no_config_map(self):
        """Fails if the chart starts rendering the CA ConfigMap (or any ConfigMap or Secret) itself."""
        for name, docs in self.renders.items():
            with self.subTest(values=name):
                self.assertFalse({"ConfigMap", "Secret"} & {d["kind"] for d in docs})


class ArtifactStorageTest(Rendered):
    """storage.artifacts mounts one claim read-write into api and worker only."""

    def test_chart_owned_claim(self):
        """Fails if the PVC's name, access modes, class, size or keep policy change, or user annotations override keep."""
        claim = find(self.renders["all-keys"], "PersistentVolumeClaim", "-artifacts")
        self.assertEqual(claim["metadata"]["name"], f"{RELEASE}-openmettle-core-artifacts")
        self.assertEqual(claim["metadata"]["annotations"],
                         {"helm.sh/resource-policy": "keep", "example.test/role": "artifacts"})
        self.assertEqual(claim["spec"], {"accessModes": ["ReadWriteMany"], "storageClassName": "example-rwx",
                                         "resources": {"requests": {"storage": "5Gi"}}})
        self.assertNotIn(HOOK, claim["metadata"]["annotations"])
        docs = render(set_values=["storage.artifacts.enabled=true", "storage.artifacts.size=1Gi",
                                  r"storage.artifacts.annotations.helm\.sh/resource-policy=delete"])
        claim = find(docs, "PersistentVolumeClaim", "-artifacts")
        self.assertEqual(claim["metadata"]["annotations"], {"helm.sh/resource-policy": "keep"})
        self.assertEqual(claim["spec"]["accessModes"], ["ReadWriteOnce"])
        self.assertNotIn("storageClassName", claim["spec"], "null selects the cluster default class")

    def test_empty_storage_class_is_rendered(self):
        """Fails if storageClassName "" (static binding, no class) is dropped instead of rendered."""
        docs = render(set_values=["storage.artifacts.enabled=true", "storage.artifacts.size=1Gi",
                                  "storage.artifacts.storageClassName="])
        self.assertEqual(find(docs, "PersistentVolumeClaim", "-artifacts")["spec"]["storageClassName"], "")

    def test_artifacts_dir_env_follows_the_mount(self):
        """Fails if ARTIFACTS_DIR is missing or wrong where the volume mounts, set where it does not, or reaches migrate or gateway."""
        enabled = {"all-keys", "storage-existing-claim"}
        for name, docs in self.renders.items():
            for role, pod in pods(docs):
                with self.subTest(values=name, component=role):
                    kind = role_kind(role)
                    env = env_map(pod["containers"][0])
                    self.assertEqual("artifacts" in volumes(pod), name in enabled and kind in ("api", "worker"))
                    if "artifacts" in volumes(pod):
                        self.assertEqual(env[PREFIX[kind] + "ARTIFACTS_DIR"],
                                         {"name": PREFIX[kind] + "ARTIFACTS_DIR", "value": ARTIFACTS_PATH})
                    else:
                        self.assertFalse([key for key in env if "ARTIFACTS" in key])

    def test_mounted_read_write_into_api_and_worker_only(self):
        """Fails if migrate or gateway mounts artifacts, the mount is read-only or moves, or the claim name is wrong."""
        expected = {"all-keys": f"{RELEASE}-openmettle-core-artifacts", "storage-existing-claim": "example-artifacts"}
        for name, claim in expected.items():
            for role, pod in pods(self.renders[name]):
                with self.subTest(values=name, component=role):
                    if role_kind(role) not in ("api", "worker"):
                        self.assertNotIn("artifacts", volumes(pod))
                        continue
                    self.assertEqual(volumes(pod)["artifacts"], {"name": "artifacts",
                                                                  "persistentVolumeClaim": {"claimName": claim}})
                    self.assertEqual(mounts(pod)["artifacts"], {"name": "artifacts", "mountPath": ARTIFACTS_PATH})
                    self.assertIs(pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"], True)
                    self.assertEqual(pod["securityContext"]["runAsUser"], 65532)

    def test_existing_claim_renders_no_pvc(self):
        """Fails if an existingClaim still renders a chart-owned PVC."""
        self.assertNotIn("PersistentVolumeClaim", {d["kind"] for d in self.renders["storage-existing-claim"]})


class IngressTest(Rendered):
    """ingress routes HTTPS for the configured hosts to the API Service, unmodified."""

    def test_routes_every_path_to_the_api_service(self):
        """Fails if a rule rewrites or narrows the path, targets another Service or port, or drops a host or TLS entry."""
        cases = {
            "all-keys": (["openmettle.example.test"],
                         [{"secretName": "example-openmettle-tls", "hosts": ["openmettle.example.test"]}]),
            "ingress-network-policy-disabled": (
                ["openmettle.example.test", "api.openmettle.example.test"],
                [{"secretName": "example-openmettle-tls", "hosts": ["openmettle.example.test"]},
                 {"secretName": "example-openmettle-api-tls", "hosts": ["api.openmettle.example.test"]}]),
        }
        for name, (hosts, tls) in cases.items():
            with self.subTest(values=name):
                docs = self.renders[name]
                ingress = find(docs, "Ingress", "-api")
                service = find(docs, "Service", "-api")
                backend = {"service": {"name": service["metadata"]["name"], "port": {"name": "http"}}}
                self.assertEqual(ingress["apiVersion"], "networking.k8s.io/v1")
                self.assertEqual(ingress["spec"], {
                    "ingressClassName": "example-ingress", "tls": tls,
                    "rules": [{"host": host, "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": backend}]}}
                              for host in hosts]})
                self.assertIn("http", [p["name"] for p in service["spec"]["ports"]])
                self.assertNotIn(HOOK, ingress["metadata"].get("annotations", {}))
        annotations = find(self.renders["all-keys"], "Ingress", "-api")["metadata"]["annotations"]
        self.assertEqual(annotations, {"example.test/access-log": "redacted"})

    def test_every_host_is_tls_covered(self):
        """Fails if any rendered rule host lacks a TLS entry (the chart routes HTTPS only)."""
        for name, docs in self.renders.items():
            for ingress in (d for d in docs if d["kind"] == "Ingress"):
                with self.subTest(values=name):
                    covered = {h for entry in ingress["spec"]["tls"] for h in entry["hosts"]}
                    self.assertLessEqual({rule["host"] for rule in ingress["spec"]["rules"]}, covered)

    def test_network_policy_admits_only_configured_peers(self):
        """Fails if enabling the Ingress widens API ingress beyond networkPolicy.api.ingressFrom."""
        docs = self.renders["all-keys"]
        api = find(docs, "NetworkPolicy", "-api")
        self.assertEqual(len(api["spec"]["ingress"]), 1)
        self.assertEqual(api["spec"]["ingress"][0]["from"],
                         yaml.safe_load((VALUES / "all-keys.yaml").read_text(encoding="utf-8"))["networkPolicy"]["api"]["ingressFrom"])


class PodDisruptionBudgetTest(Rendered):
    """api.podDisruptionBudget protects the API only and never blocks every eviction."""

    def test_budget_selects_only_api_pods(self):
        """Fails if the PDB selector matches worker or migrate pods, drops AlwaysAllow or changes the budget."""
        docs = self.renders["all-keys"]
        pdb = find(docs, "PodDisruptionBudget", "-api")
        self.assertEqual(pdb["apiVersion"], "policy/v1")
        self.assertEqual(pdb["spec"]["maxUnavailable"], 1)
        self.assertNotIn("minAvailable", pdb["spec"])
        self.assertEqual(pdb["spec"]["unhealthyPodEvictionPolicy"], "AlwaysAllow")
        matched = sorted(role for role, labels in pod_labels(docs) if selects(pdb["spec"]["selector"], labels))
        self.assertEqual(matched, ["api"])

    def test_values_render_with_their_type(self):
        """Fails if a percentage renders as a number or an integer as a string (both change PDB semantics)."""
        base = ["api.replicas=3", "api.podDisruptionBudget.enabled=true"]
        for value, field, expected in (("50%", "minAvailable", "50%"), ("2", "minAvailable", 2),
                                       ("34%", "maxUnavailable", "34%"), ("1", "maxUnavailable", 1)):
            with self.subTest(field=field, value=value):
                pdb = find(render(set_values=base + [f"api.podDisruptionBudget.{field}={value}"]), "PodDisruptionBudget", "-api")
                self.assertEqual(pdb["spec"][field], expected)
                self.assertEqual(type(pdb["spec"][field]), type(expected))


class AuthTest(Rendered):
    """auth mounts sign-in / OIDC and /v1/* route files and env into api only, never worker or migrate (core ADRs 0025, 0027 and 0029)."""

    def test_api_mounts_config_login_keys_optional_ca_and_env(self):
        """Fails if api lacks OPENMETTLE_API_AUTH_CONFIG, read-only directory mounts, 0440 Secret mode or fsGroup 65532."""
        auth_item = {"key": "auth.json", "path": "auth.json"}
        cases = {
            "auth-enabled": ("example-auth-config", [auth_item], "example-auth-login-keys", None),
            "auth-network-policy-disabled": ("example-auth-config", [auth_item], "example-auth-login-keys", None),
            "all-keys": ("example-auth-config", [{"key": "browser-auth.json", "path": "auth.json"},
                                                 {"key": "model-catalog.json", "path": "catalog.json"}],
                         "example-auth-login-keys", ("example-oidc-ca", "idp-ca.pem")),
        }
        for name, (cm, items, secret, ca) in cases.items():
            with self.subTest(values=name):
                api = find(self.renders[name], "Deployment", "-api")["spec"]["template"]["spec"]
                container = api["containers"][0]
                env = env_map(container)
                self.assertEqual(env["OPENMETTLE_API_AUTH_CONFIG"],
                                 {"name": "OPENMETTLE_API_AUTH_CONFIG", "value": AUTH_CONFIG_PATH})
                self.assertEqual(api["securityContext"]["fsGroup"], 65532)
                self.assertEqual(volumes(api)["auth-config"], {"name": "auth-config", "configMap": {
                    "name": cm, "items": items}})
                self.assertEqual(mounts(api)["auth-config"],
                                 {"name": "auth-config", "mountPath": AUTH_CONFIG_DIR, "readOnly": True})
                self.assertEqual(volumes(api)["auth-login-keys"], {"name": "auth-login-keys", "secret": {
                    "secretName": secret, "defaultMode": 0o440}})
                self.assertEqual(mounts(api)["auth-login-keys"],
                                 {"name": "auth-login-keys", "mountPath": AUTH_KEYS_DIR, "readOnly": True})
                if ca is None:
                    self.assertNotIn("auth-provider-ca", volumes(api))
                    self.assertNotIn("auth-provider-ca", mounts(api))
                else:
                    ca_cm, ca_key = ca
                    self.assertEqual(volumes(api)["auth-provider-ca"], {"name": "auth-provider-ca", "configMap": {
                        "name": ca_cm, "items": [{"key": ca_key, "path": "ca.crt"}]}})
                    self.assertEqual(mounts(api)["auth-provider-ca"],
                                     {"name": "auth-provider-ca", "mountPath": AUTH_CA_DIR, "readOnly": True})
                for mount in container["volumeMounts"]:
                    self.assertNotIn("subPath", mount)

    def test_worker_and_migrate_never_receive_auth_env_volumes_or_secrets(self):
        """Fails if worker or migrate mounts auth config/keys/CA, sets AUTH_CONFIG or references auth object names."""
        for name in ("auth-enabled", "auth-network-policy-disabled", "all-keys"):
            docs = self.renders[name]
            with self.subTest(values=name):
                for role, pod in pods(docs):
                    if role == "api":
                        continue
                    env_names = {e["name"] for e in pod["containers"][0]["env"]}
                    self.assertFalse([e for e in env_names if "AUTH" in e], f"{role}: {env_names}")
                    self.assertFalse(AUTH_VOLUMES & set(volumes(pod)), role)
                    self.assertFalse(AUTH_VOLUMES & set(mounts(pod)), role)
                    if name != "all-keys":
                        self.assertNotIn("volumes", pod, role)
                        self.assertNotIn("volumeMounts", pod["containers"][0], role)
                        self.assertNotIn("fsGroup", pod["securityContext"], role)
                non_api_yaml = yaml.safe_dump_all(
                    d for d in docs if not (d["kind"] in ("Deployment", "NetworkPolicy") and component(d) == "api")
                )
                for ref in ("example-auth-config", "example-auth-login-keys", "example-oidc-ca", "AUTH_CONFIG",
                            ISSUANCE_SECRET, "ISSUANCE"):
                    self.assertNotIn(ref, non_api_yaml)

    def test_provider_ca_uses_default_key_ca_crt(self):
        """Fails if auth.providerCaBundle omits the default key ca.crt when enabled."""
        docs = render(("auth-enabled.yaml",), [
            "auth.providerCaBundle.enabled=true",
            "auth.providerCaBundle.configMapName=example-oidc-ca",
        ])
        api = find(docs, "Deployment", "-api")["spec"]["template"]["spec"]
        self.assertEqual(volumes(api)["auth-provider-ca"], {"name": "auth-provider-ca", "configMap": {
            "name": "example-oidc-ca", "items": [{"key": "ca.crt", "path": "ca.crt"}]}})
        self.assertEqual(mounts(api)["auth-provider-ca"],
                         {"name": "auth-provider-ca", "mountPath": AUTH_CA_DIR, "readOnly": True})
        for role, pod in pods(docs):
            if role != "api":
                self.assertNotIn("auth-provider-ca", volumes(pod), role)

    def test_catalog_key_projects_catalog_beside_auth_json_in_api_only(self):
        """Fails if auth.catalogKey is not projected as catalog.json in the auth-config volume, adds a volume,
        mount or env var, or reaches worker or migrate."""
        base = render(("auth-enabled.yaml",))
        docs = render(("auth-enabled.yaml",), ["auth.catalogKey=catalog.json"])
        api = find(docs, "Deployment", "-api")["spec"]["template"]["spec"]
        self.assertEqual(volumes(api)["auth-config"]["configMap"]["items"], [
            {"key": "auth.json", "path": "auth.json"}, {"key": "catalog.json", "path": "catalog.json"}])
        before = find(base, "Deployment", "-api")["spec"]["template"]["spec"]
        self.assertEqual(set(volumes(api)), set(volumes(before)))
        self.assertEqual(mounts(api), mounts(before))
        self.assertEqual(env_map(api["containers"][0]), env_map(before["containers"][0]))
        non_api = yaml.safe_dump_all(d for d in docs if not (d["kind"] == "Deployment" and component(d) == "api"))
        self.assertNotIn("catalog", non_api)

    def test_auth_without_catalog_key_renders_as_before(self):
        """Fails if the schema requires auth.catalogKey. `helm upgrade --reuse-values` reuses the previous
        release's computed values, which have no catalogKey; `--set auth.catalogKey=null` removes it the same way."""
        base = render(("auth-enabled.yaml",))
        docs = render(("auth-enabled.yaml",), ["auth.catalogKey=null"])
        self.assertEqual(docs, base)
        api = find(docs, "Deployment", "-api")["spec"]["template"]["spec"]
        self.assertEqual(volumes(api)["auth-config"]["configMap"]["items"], [{"key": "auth.json", "path": "auth.json"}])

    def test_auth_without_network_policy_renders_no_policies(self):
        """Fails if enabling auth while networkPolicy.enabled=false still renders a NetworkPolicy."""
        docs = self.renders["auth-network-policy-disabled"]
        self.assertNotIn("NetworkPolicy", {d["kind"] for d in docs})


class IssuanceTest(Rendered):
    """database.issuance and api.settings.issuanceDbMaxConnections reach the API container only, and only
    while auth.enabled is true (core ADR 0030: the API exits 78 on either setting without AUTH_CONFIG; the
    worker and migrator exit 78 if they receive the URL)."""

    EXPECTED = {
        "auth-enabled": ({"name": ISSUANCE_SECRET, "key": "url"}, "2"),
        "auth-network-policy-disabled": ({"name": ISSUANCE_SECRET, "key": "url"}, "2"),
        "all-keys": ({"name": ISSUANCE_SECRET, "key": "issuance-url"}, "3"),
    }

    def test_api_receives_issuance_env_exactly_with_auth(self):
        """Fails if the issuance URL or pool size is missing with auth, rendered without it, or not a Secret reference."""
        with_auth = []
        for name, docs in self.renders.items():
            for role, pod in pods(docs):
                with self.subTest(values=name, component=role):
                    env = env_map(pod["containers"][0])
                    issuance = sorted(key for key in env if "ISSUANCE" in key)
                    if role == "api" and "OPENMETTLE_API_AUTH_CONFIG" in env:
                        with_auth.append(name)
                        ref, pool = self.EXPECTED[name]
                        self.assertEqual(issuance, [ISSUANCE_URL, ISSUANCE_POOL])
                        self.assertEqual(env[ISSUANCE_URL], {"name": ISSUANCE_URL, "valueFrom": {"secretKeyRef": ref}})
                        self.assertEqual(env[ISSUANCE_POOL], {"name": ISSUANCE_POOL, "value": pool})
                    else:
                        self.assertEqual(issuance, [])
        self.assertEqual(sorted(with_auth), sorted(self.EXPECTED))

    def test_worker_and_migrate_never_reference_the_issuance_secret(self):
        """Fails if a worker, gateway or migrate pod (or any object but the API Deployment) names the issuance Secret."""
        for name in self.EXPECTED:
            docs = self.renders[name]
            with self.subTest(values=name):
                others = yaml.safe_dump_all(d for d in docs if not (d["kind"] == "Deployment" and component(d) == "api"))
                self.assertNotIn(ISSUANCE_SECRET, others)
                self.assertNotIn("ISSUANCE", others)
                expected_roles = ["api", "gateway-a", "migrate", "worker"] if name == "all-keys" else ["api", "migrate", "worker"]
                self.assertEqual(sorted(role for role, _ in pods(docs)), expected_roles)

    def test_pool_size_bounds_reach_the_api(self):
        """Fails if a valid issuanceDbMaxConnections is clamped, rejected or rendered as a number."""
        for value in (1, 64):
            with self.subTest(value=value):
                docs = render(("auth-enabled.yaml",), [f"api.settings.issuanceDbMaxConnections={value}"])
                env = env_map(find(docs, "Deployment", "-api")["spec"]["template"]["spec"]["containers"][0])
                self.assertEqual(env[ISSUANCE_POOL]["value"], str(value))

    def test_boundaries_render(self):
        """Fails if a guard rejects another key of a shared Secret or a budget equal to the issuance-inclusive peak."""
        for set_values in (["database.issuance.existingSecret=openmettle-api-database", "database.issuance.key=issuance-url"],
                           # (1 + 1) * (4 + 2) + (1 + 1) * 4 + 1 = 21
                           ["database.connectionBudget=21"]):
            for extra in ((), (SKIP,)):
                with self.subTest(values=set_values, extra=extra):
                    result = helm_template(("auth-enabled.yaml",), set_values, extra)
                    self.assertEqual(result.returncode, 0, result.stderr)
        # Without auth the issuance pool is not opened, so it is not counted.
        result = helm_template(set_values=["database.connectionBudget=17"])
        self.assertEqual(result.returncode, 0, result.stderr)


class TelemetryTest(Rendered):
    """telemetry logging (all roles, ADR 0024) and OTLP trace export (api/worker only, never migrate, ADR 0026)."""

    def test_logging_overrides_reach_all_three_roles(self):
        """Fails if telemetry.logging.{format,level} do not render for api, worker and migrate, or emit when null."""
        cases = {
            "all-keys": ("text", "debug"),
            "telemetry-network-policy-disabled": ("text", "warn"),
            "telemetry-otlp-enabled": (None, None),
            "minimal": (None, None),
        }
        for name, (fmt, level) in cases.items():
            for role, pod in pods(self.renders[name]):
                kind = role_kind(role)
                with self.subTest(values=name, component=role):
                    env = env_map(pod["containers"][0])
                    if fmt is None:
                        self.assertNotIn(PREFIX[kind] + "LOG_FORMAT", env)
                    else:
                        self.assertEqual(env[PREFIX[kind] + "LOG_FORMAT"], {"name": PREFIX[kind] + "LOG_FORMAT", "value": fmt})
                    if level is None:
                        self.assertNotIn(PREFIX[kind] + "LOG_LEVEL", env)
                    else:
                        self.assertEqual(env[PREFIX[kind] + "LOG_LEVEL"], {"name": PREFIX[kind] + "LOG_LEVEL", "value": level})
        # Independent format-only and level-only overrides, across every valid enum value.
        for fmt in ("json", "text"):
            docs = render(set_values=[f"telemetry.logging.format={fmt}"])
            for role, pod in pods(docs):
                env = env_map(pod["containers"][0])
                self.assertEqual(env[PREFIX[role] + "LOG_FORMAT"]["value"], fmt)
                self.assertNotIn(PREFIX[role] + "LOG_LEVEL", env)
        for level in ("error", "warn", "info", "debug"):
            docs = render(set_values=[f"telemetry.logging.level={level}"])
            for role, pod in pods(docs):
                env = env_map(pod["containers"][0])
                self.assertNotIn(PREFIX[role] + "LOG_FORMAT", env)
                self.assertEqual(env[PREFIX[role] + "LOG_LEVEL"]["value"], level)

    def test_otlp_env_and_optional_ca_mount_on_api_and_worker(self):
        """Fails if api/worker OTLP env vars (traces-only, metrics-only, both), privateRanges or otlp-ca mount drift."""
        cases = {
            "telemetry-otlp-enabled": (
                "https://alloy.observability.example.test:4318/v1/traces", None, None, None,
            ),
            "telemetry-otlp-metrics-only": (
                None, "https://alloy.observability.example.test:4318/v1/metrics", None, None,
            ),
            "telemetry-network-policy-disabled": (
                "https://alloy.observability.example.test:4318/v1/traces",
                None,
                "10.43.0.0/16",
                ("example-otlp-ca", "ca.crt"),
            ),
            "all-keys": (
                "https://alloy.observability.example.test:4319/v1/traces",
                "https://alloy.observability.example.test:4319/v1/metrics",
                "10.43.0.0/16,fd00:10::/64",
                ("example-otlp-ca", "collector-ca.pem"),
            ),
        }
        for name, (traces_ep, metrics_ep, ranges, ca) in cases.items():
            roles = [role for role, _ in pods(self.renders[name]) if role != "migrate"]
            for role in roles:
                kind = role_kind(role)
                with self.subTest(values=name, component=role):
                    pod = find(self.renders[name], "Deployment", f"-{role}")["spec"]["template"]["spec"]
                    container = pod["containers"][0]
                    env = env_map(container)
                    if traces_ep is None:
                        self.assertNotIn(PREFIX[kind] + "OTLP_TRACES_ENDPOINT", env)
                    else:
                        self.assertEqual(env[PREFIX[kind] + "OTLP_TRACES_ENDPOINT"],
                                         {"name": PREFIX[kind] + "OTLP_TRACES_ENDPOINT", "value": traces_ep})
                    if metrics_ep is None:
                        self.assertNotIn(PREFIX[kind] + "OTLP_METRICS_ENDPOINT", env)
                    else:
                        self.assertEqual(env[PREFIX[kind] + "OTLP_METRICS_ENDPOINT"],
                                         {"name": PREFIX[kind] + "OTLP_METRICS_ENDPOINT", "value": metrics_ep})
                    if ranges is None:
                        self.assertNotIn(PREFIX[kind] + "OTLP_PRIVATE_RANGES", env)
                    else:
                        self.assertEqual(env[PREFIX[kind] + "OTLP_PRIVATE_RANGES"],
                                         {"name": PREFIX[kind] + "OTLP_PRIVATE_RANGES", "value": ranges})
                    if ca is None:
                        self.assertNotIn(PREFIX[kind] + "OTLP_CA_FILE", env)
                        self.assertNotIn("otlp-ca", volumes(pod))
                        self.assertNotIn("otlp-ca", mounts(pod))
                    else:
                        ca_cm, ca_key = ca
                        self.assertEqual(env[PREFIX[kind] + "OTLP_CA_FILE"],
                                         {"name": PREFIX[kind] + "OTLP_CA_FILE", "value": OTLP_CA_PATH})
                        self.assertEqual(volumes(pod)["otlp-ca"], {"name": "otlp-ca", "configMap": {
                            "name": ca_cm, "items": [{"key": ca_key, "path": "ca.crt"}]}})
                        self.assertEqual(mounts(pod)["otlp-ca"],
                                         {"name": "otlp-ca", "mountPath": OTLP_CA_DIR, "readOnly": True})
                    for mount in container.get("volumeMounts", []):
                        self.assertNotIn("subPath", mount)

    def test_sibling_mount_paths_never_overlap(self):
        """Fails if any volume mount path is duplicated or nested inside another read-only mount directory."""
        for name in ("all-keys", "telemetry-network-policy-disabled", "auth-enabled"):
            for role, pod in pods(self.renders[name]):
                with self.subTest(values=name, component=role):
                    paths = [m["mountPath"].rstrip("/") for m in pod["containers"][0].get("volumeMounts", [])]
                    self.assertEqual(len(paths), len(set(paths)), paths)
                    for i, left in enumerate(paths):
                        for j, right in enumerate(paths):
                            if i != j:
                                self.assertFalse(right.startswith(left + "/"), f"{right} nested under {left}")

    def test_migrate_never_receives_otlp_env_ca_or_egress(self):
        """Fails if migrate gets any OTLP_* env var, otlp-ca mount/volume, collector URL/CA reference or OTLP egress."""
        for name in ("telemetry-otlp-enabled", "telemetry-otlp-metrics-only", "telemetry-network-policy-disabled", "all-keys"):
            docs = self.renders[name]
            with self.subTest(values=name):
                job = find(docs, "Job", "-migrate")
                pod = job["spec"]["template"]["spec"]
                env_names = {e["name"] for e in pod["containers"][0]["env"]}
                self.assertFalse([e for e in env_names if "OTLP" in e or "OTEL" in e], env_names)
                self.assertNotIn("otlp-ca", volumes(pod))
                self.assertNotIn("otlp-ca", mounts(pod))
                migrate_docs = [d for d in docs if component(d) == "migrate"]
                migrate_yaml = yaml.safe_dump_all(migrate_docs)
                for ref in ("OTLP_", "OTEL_", "otlp-ca", "example-otlp-ca", "collector-ca.pem",
                            "alloy.observability.example.test", "example-observability", "example-alloy",
                            "192.0.2.30", "198.51.100.60"):
                    self.assertNotIn(ref, migrate_yaml)

    def test_no_ambient_otel_env_vars_in_any_render(self):
        """Fails if any template emits an ambient OTEL_* variable (core ADR 0026 neutralizes them)."""
        for _, _, pod in self.each_pod():
            for container in containers(pod):
                for entry in container.get("env", []):
                    self.assertFalse(entry["name"].startswith("OTEL_"), entry["name"])

    def test_telemetry_without_network_policy_renders_no_policies(self):
        """Fails if enabling telemetry.otlp while networkPolicy.enabled=false still renders a NetworkPolicy."""
        docs = self.renders["telemetry-network-policy-disabled"]
        self.assertNotIn("NetworkPolicy", {d["kind"] for d in docs})


def _render_standalone_example(path):
    result = subprocess.run([HELM, "template", RELEASE, str(CHART), "--namespace", "openmettle", "-f", str(path)],
                            capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        raise AssertionError(f"helm template failed for {path.name}: {result.stderr}")
    docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
    values = yaml.safe_load(path.read_text(encoding="utf-8"))
    return docs, values


def _assert_synthetic_example(case, path, values):
    text = path.read_text(encoding="utf-8")
    case.assertIn("SYNTHETIC EXAMPLE", text)
    for host in values["ingress"]["hosts"] + [values["images"][r]["registry"] for r in ("api", "worker", "migrate")]:
        case.assertTrue(host == "example" or host.endswith(".example"), host)
    for key in ("tracesEndpoint", "metricsEndpoint"):
        endpoint = values["telemetry"]["otlp"][key]
        case.assertIn(".example.test:", endpoint)
    for role in ("api", "worker", "migrate"):
        case.assertEqual(values["images"][role]["digest"], DIGEST)
    for peer in (values["networkPolicy"]["database"]["to"]
                 + values["networkPolicy"]["api"]["oidc"]["to"]
                 + values["networkPolicy"]["telemetry"]["otlp"]["to"]):
        case.assertTrue(peer["ipBlock"]["cidr"].startswith("192.0.2."))
    case.assertNotIn("oidc", values)


class ExampleOverlayTest(unittest.TestCase):
    """examples/values-synthetic.yaml renders standalone and stays synthetic."""

    @classmethod
    def setUpClass(cls):
        cls.docs, cls.values = _render_standalone_example(EXAMPLE)

    def test_shows_every_i4_i5_and_i6_feature(self):
        """Fails if the example stops demonstrating I4 (PVC, Ingress, PDB, db CA), I5 (API auth & OIDC egress) or I6 (telemetry & OTLP)."""
        self.assertLessEqual(I4_KINDS, {d["kind"] for d in self.docs})
        for role, pod in pods(self.docs):
            env = env_map(pod["containers"][0])
            self.assertIn("db-ca", volumes(pod), role)
            self.assertEqual(env[PREFIX[role] + "LOG_FORMAT"]["value"], "json")
            self.assertEqual(env[PREFIX[role] + "LOG_LEVEL"]["value"], "info")
            if role == "api":
                self.assertEqual(env["OPENMETTLE_API_AUTH_CONFIG"]["value"], AUTH_CONFIG_PATH)
                self.assertEqual(env[ISSUANCE_URL]["valueFrom"]["secretKeyRef"]["name"],
                                 "example-openmettle-issuance-database")
                self.assertLessEqual(AUTH_VOLUMES, set(volumes(pod)))
                self.assertEqual(volumes(pod)["auth-config"]["configMap"]["items"], EXAMPLE_AUTH_ITEMS)
            else:
                self.assertFalse(AUTH_VOLUMES & set(volumes(pod)), role)
                self.assertNotIn("OPENMETTLE_API_AUTH_CONFIG", env)
                self.assertFalse([k for k in env if "ISSUANCE" in k], role)
            if role in ("api", "worker"):
                self.assertEqual(env[PREFIX[role] + "OTLP_TRACES_ENDPOINT"]["value"],
                                 "https://alloy.observability.example.test:4318/v1/traces")
                self.assertEqual(env[PREFIX[role] + "OTLP_METRICS_ENDPOINT"]["value"],
                                 "https://alloy.observability.example.test:4318/v1/metrics")
                self.assertEqual(env[PREFIX[role] + "OTLP_CA_FILE"]["value"], OTLP_CA_PATH)
                self.assertEqual(env[PREFIX[role] + "OTLP_PRIVATE_RANGES"]["value"], "10.43.0.0/16")
                self.assertIn("otlp-ca", volumes(pod), role)
                self.assertEqual(env[PREFIX[role] + "ARTIFACTS_DIR"]["value"], ARTIFACTS_PATH)
            else:
                self.assertNotIn("otlp-ca", volumes(pod))
                self.assertFalse([k for k in env if "OTLP" in k or "ARTIFACTS" in k])
        api_np = find(self.docs, "NetworkPolicy", "-api")["spec"]
        self.assertTrue(api_np["ingress"])
        self.assertEqual(len(api_np["egress"]), 4)
        self.assertEqual(api_np["egress"][2]["ports"], [{"protocol": "TCP", "port": 443}])
        self.assertEqual(api_np["egress"][3]["ports"], [{"protocol": "TCP", "port": 4318}])
        worker_np = find(self.docs, "NetworkPolicy", "-worker")["spec"]
        self.assertEqual(len(worker_np["egress"]), 3)
        self.assertEqual(worker_np["egress"][2]["ports"], [{"protocol": "TCP", "port": 4318}])
        self.assertEqual(len(find(self.docs, "NetworkPolicy", "-migrate")["spec"]["egress"]), 2)

    def test_values_are_synthetic(self):
        """Fails if the example names a non-reserved domain, a real digest or a non-documentation address."""
        _assert_synthetic_example(self, EXAMPLE, self.values)

    def test_traefik_annotations_stay_strings(self):
        """Fails if a Traefik annotation such as router.tls: "true" is emitted as a YAML boolean."""
        annotations = find(self.docs, "Ingress", "-api")["metadata"]["annotations"]
        self.assertEqual(annotations["traefik.ingress.kubernetes.io/router.tls"], "true")
        self.assertTrue(all(isinstance(v, str) for v in annotations.values()))


class WorkstationProfileTest(unittest.TestCase):
    """examples/values-workstation-profile.yaml renders standalone as a single-node synthetic profile."""

    @classmethod
    def setUpClass(cls):
        cls.docs, cls.values = _render_standalone_example(WORKSTATION_EXAMPLE)

    def test_single_node_workstation_boundaries_and_resources(self):
        """Fails if the workstation profile enables a 1-replica PDB, drops RWO/Ingress/auth/OTLP boundaries or omits resource bounds."""
        kinds = {d["kind"] for d in self.docs}
        self.assertIn("PersistentVolumeClaim", kinds)
        self.assertIn("Ingress", kinds)
        self.assertNotIn("PodDisruptionBudget", kinds)
        api_dep = find(self.docs, "Deployment", "-api")["spec"]
        worker_dep = find(self.docs, "Deployment", "-worker")["spec"]
        self.assertEqual(api_dep["replicas"], 1)
        self.assertEqual(worker_dep["replicas"], 1)
        for dep in (api_dep, worker_dep):
            res = dep["template"]["spec"]["containers"][0]["resources"]
            self.assertIn("requests", res)
            self.assertIn("limits", res)
        pvc = find(self.docs, "PersistentVolumeClaim", "-artifacts")["spec"]
        self.assertEqual(pvc["accessModes"], ["ReadWriteOnce"])
        for role, pod in pods(self.docs):
            env = env_map(pod["containers"][0])
            vols = set(volumes(pod))
            self.assertIn("db-ca", vols, role)
            self.assertEqual(env[PREFIX[role] + "LOG_FORMAT"]["value"], "json")
            self.assertEqual(env[PREFIX[role] + "LOG_LEVEL"]["value"], "info")
            if role == "api":
                self.assertEqual(env["OPENMETTLE_API_AUTH_CONFIG"]["value"], AUTH_CONFIG_PATH)
                self.assertEqual(env[ISSUANCE_URL]["valueFrom"]["secretKeyRef"]["name"],
                                 "workstation-openmettle-issuance-database")
                self.assertLessEqual(AUTH_VOLUMES, vols)
                self.assertEqual(volumes(pod)["auth-config"]["configMap"]["items"], EXAMPLE_AUTH_ITEMS)
            else:
                self.assertFalse(AUTH_VOLUMES & vols, role)
                self.assertNotIn("OPENMETTLE_API_AUTH_CONFIG", env)
                self.assertFalse([k for k in env if "ISSUANCE" in k], role)
            if role in ("api", "worker"):
                self.assertIn("artifacts", vols, role)
                self.assertIn("otlp-ca", vols, role)
                self.assertEqual(env[PREFIX[role] + "OTLP_TRACES_ENDPOINT"]["value"],
                                 "https://alloy.workstation.example.test:4318/v1/traces")
                self.assertEqual(env[PREFIX[role] + "OTLP_METRICS_ENDPOINT"]["value"],
                                 "https://alloy.workstation.example.test:4318/v1/metrics")
                self.assertEqual(env[PREFIX[role] + "ARTIFACTS_DIR"]["value"], ARTIFACTS_PATH)
            else:
                self.assertNotIn("artifacts", vols)
                self.assertNotIn("otlp-ca", vols)
                self.assertFalse([k for k in env if "OTLP" in k or "ARTIFACTS" in k])
        self.assertEqual(len(find(self.docs, "NetworkPolicy", "-api")["spec"]["egress"]), 4)
        self.assertEqual(len(find(self.docs, "NetworkPolicy", "-worker")["spec"]["egress"]), 3)
        self.assertEqual(len(find(self.docs, "NetworkPolicy", "-migrate")["spec"]["egress"]), 2)

    def test_values_are_synthetic(self):
        """Fails if the workstation profile leaks any non-reserved domain, real digest or non-documentation address."""
        _assert_synthetic_example(self, WORKSTATION_EXAMPLE, self.values)


# --set values for an auth-enabled render on minimal.yaml (OIDC egress peer via --set-json).
AUTH = ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys"]
ISSUANCE = f"database.issuance.existingSecret={ISSUANCE_SECRET}"
OIDC_PEER = ["--set-json", 'networkPolicy.api.oidc.to=[{"ipBlock":{"cidr":"192.0.2.20/32"}}]']
SKIP = "--skip-schema-validation"


class NegativeCaseTest(unittest.TestCase):
    """Each case must fail to render with the intended message."""

    SCHEMA = SCHEMA_ERROR
    FULL = f"{RELEASE}-openmettle-core"
    CASES = [
        # (name, --set values, extra args, expected message fragments)
        ("missing api digest", ["images.api.digest="], [], ["images.api.digest is required"]),
        ("missing worker digest", ["images.worker.digest="], [], ["images.worker.digest is required"]),
        ("missing migrate digest", ["images.migrate.digest="], [], ["images.migrate.digest is required"]),
        ("missing repository", ["images.api.repository="], [], ["images.api.repository is required"]),
        ("tag-only digest", ["images.worker.digest=latest"], [], [SCHEMA, "/images/worker/digest"]),
        ("uppercase digest", ["images.api.digest=sha256:" + "A" * 64], [], [SCHEMA, "/images/api/digest"]),
        ("tag in repository", ["images.api.repository=openmettle/api:1.0"], [], [SCHEMA, "/images/api/repository"]),
        ("tag-only digest without schema", ["images.api.digest=latest"], ["--skip-schema-validation"],
         ["images.api.digest must be sha256:<64 lowercase hex>"]),
        ("tag in repository without schema", ["images.migrate.repository=openmettle/migrate:1.0"],
         ["--skip-schema-validation"], ["images.migrate.repository must not contain a tag or digest"]),
        ("missing api Secret", ["database.api.existingSecret="], [], ["database.api.existingSecret is required"]),
        ("missing worker Secret", ["database.worker.existingSecret="], [], ["database.worker.existingSecret is required"]),
        ("missing migrate Secret", ["database.migrate.existingSecret="], [], ["database.migrate.existingSecret is required"]),
        ("unknown top-level key", ["oidc.issuer=https://idp.example.test"], [], [SCHEMA, "additional properties 'oidc' not allowed"]),
        ("unknown nested key", ["worker.settings.authFile=x"], [], [SCHEMA, "additional properties 'authFile' not allowed"]),
        ("worker has no Service", ["worker.service.port=8081"], [], [SCHEMA, "additional properties 'service' not allowed"]),
        ("GPU resource", [r"api.resources.limits.nvidia\.com/gpu=1"], [], [SCHEMA, "additional properties 'nvidia.com/gpu' not allowed"]),
        ("pool above core bound", ["api.settings.dbMaxConnections=65"], [], [SCHEMA, "/api/settings/dbMaxConnections"]),
        ("zero database timeout", ["worker.settings.dbTimeoutMs=0"], [], [SCHEMA, "/worker/settings/dbTimeoutMs"]),
        ("statement timeout above core bound", ["migration.settings.statementTimeoutMs=3600001"], [],
         [SCHEMA, "/migration/settings/statementTimeoutMs"]),
        ("api grace below shutdown", ["api.terminationGracePeriodSeconds=4"], [],
         ["api.terminationGracePeriodSeconds (4 s) must exceed api.settings.shutdownTimeoutMs (5000 ms)"]),
        ("worker grace equal to shutdown", ["worker.settings.shutdownTimeoutMs=15000"], [],
         ["worker.terminationGracePeriodSeconds (15 s) must exceed worker.settings.shutdownTimeoutMs (15000 ms)"]),
        ("connection budget exceeded", ["database.connectionBudget=16"], [],
         ["database.connectionBudget (16) is below the release's peak of 17 connections"]),
        ("connection budget counts surge", ["database.connectionBudget=20", "worker.strategy.maxSurge=2"], [],
         ["peak of 21 connections"]),
        ("rollout cannot progress", ["api.strategy.maxSurge=0"], [],
         ["api.strategy.maxSurge and api.strategy.maxUnavailable cannot both be 0"]),
        ("shared default ServiceAccount", ["worker.serviceAccount.create=false"], [],
         ["worker.serviceAccount.name is required when serviceAccount.create is false"]),
        ("migrate shared default ServiceAccount", ["migration.serviceAccount.create=false"], [],
         ["migration.serviceAccount.name is required when serviceAccount.create is false"]),
        ("api named default", ["api.serviceAccount.name=default"], [],
         ['api.serviceAccount.name must not be "default"']),
        ("existing worker account named default", ["worker.serviceAccount.create=false", "worker.serviceAccount.name=default"], [],
         ['worker.serviceAccount.name must not be "default"']),
        ("migrate named default", ["migration.serviceAccount.name=default"], [],
         ['migration.serviceAccount.name must not be "default"']),
        ("api and worker share", ["api.serviceAccount.name=shared", "worker.serviceAccount.name=shared"], [],
         ['api and worker resolve to the same ServiceAccount "shared"']),
        ("migrate takes the api account", [f"migration.serviceAccount.name={FULL}-api"], [],
         [f'api and migration resolve to the same ServiceAccount "{FULL}-api"']),
        ("migrate takes an existing worker account",
         ["worker.serviceAccount.create=false", "worker.serviceAccount.name=shared", "migration.serviceAccount.name=shared"], [],
         ['worker and migration resolve to the same ServiceAccount "shared"']),
        ("deadline equal to one attempt", ["migration.activeDeadlineSeconds=320"], [],
         ["migration.activeDeadlineSeconds (320 s) must exceed connectTimeoutMs + lockTimeoutMs + statementTimeoutMs (320000 ms)"]),
        ("deadline below a raised statement timeout", ["migration.settings.statementTimeoutMs=900000"], [],
         ["migration.activeDeadlineSeconds (900 s) must exceed", "(920000 ms)"]),
        ("no database peers", [], ["--set-json", "networkPolicy.database.to=[]"],
         ["networkPolicy.database.to must list at least one PostgreSQL peer"]),
        ("no database peers without schema", [], ["--set-json", "networkPolicy.database.to=[]", "--skip-schema-validation"],
         ["networkPolicy.database.to must list at least one PostgreSQL peer"]),
        ("no DNS peers", [], ["--set-json", "networkPolicy.dns.to=[]"],
         ["networkPolicy.dns.to must list at least one DNS peer"]),
        ("no DNS peers without schema", [], ["--set-json", "networkPolicy.dns.to=[]", "--skip-schema-validation"],
         ["networkPolicy.dns.to must list at least one DNS peer"]),
        ("empty peer", [], ["--set-json", "networkPolicy.database.to=[{}]"], [SCHEMA, "/networkPolicy/database/to/0"]),
        ("empty database peer without schema", [],
         ["--set-json", "networkPolicy.database.to=[{}]", "--skip-schema-validation"],
         ["networkPolicy.database.to[0] must be a non-empty NetworkPolicyPeer object"]),
        ("empty API ingress peer without schema", [],
         ["--set-json", "networkPolicy.api.ingressFrom=[{}]", "--skip-schema-validation"],
         ["networkPolicy.api.ingressFrom[0] must be a non-empty NetworkPolicyPeer object"]),
        ("ipBlock combined with a selector", [],
         ["--set-json", 'networkPolicy.api.ingressFrom=[{"ipBlock":{"cidr":"192.0.2.0/24"},"podSelector":{}}]'],
         [SCHEMA, "/networkPolicy/api/ingressFrom/0"]),
        ("unknown peer key", [], ["--set-json", 'networkPolicy.dns.to=[{"serviceSelector":{}}]'],
         [SCHEMA, "additional properties 'serviceSelector' not allowed"]),
        ("malformed CIDR", [], ["--set-json", 'networkPolicy.database.to=[{"ipBlock":{"cidr":"198.51.100.0"}}]'],
         [SCHEMA, "/networkPolicy/database/to/0/ipBlock/cidr"]),
        ("unknown selector operator", [], ["--set-json",
         'networkPolicy.database.to=[{"podSelector":{"matchExpressions":[{"key":"a","operator":"Matches"}]}}]'],
         [SCHEMA, "/networkPolicy/database/to/0/podSelector/matchExpressions/0/operator"]),
        ("unknown networkPolicy key", ["networkPolicy.api.ingressPorts=8081"], [],
         [SCHEMA, "additional properties 'ingressPorts' not allowed"]),
        # Database CA (I4).
        ("CA without ConfigMap", ["database.caBundle.enabled=true"], [], [SCHEMA, "/database/caBundle/configMapName"]),
        ("CA without ConfigMap without schema", ["database.caBundle.enabled=true"], ["--skip-schema-validation"],
         ["database.caBundle.configMapName is required when database.caBundle.enabled is true"]),
        ("CA key with a path", ["database.caBundle.key=../ca.crt"], [], [SCHEMA, "/database/caBundle/key"]),
        ("CA key dot-dot", ["database.caBundle.key=.."], [], [SCHEMA, "/database/caBundle/key"]),
        ("CA key dot-dot without schema",
         ["database.caBundle.enabled=true", "database.caBundle.configMapName=ca", "database.caBundle.key=.."],
         ["--skip-schema-validation"], ["database.caBundle.key must be a ConfigMap key"]),
        ("CA key with a path without schema",
         ["database.caBundle.enabled=true", "database.caBundle.configMapName=ca", "database.caBundle.key=a/b"],
         ["--skip-schema-validation"], ["database.caBundle.key must be a ConfigMap key"]),
        ("CA bad ConfigMap name", ["database.caBundle.configMapName=CA_Bundle"], [], [SCHEMA, "/database/caBundle/configMapName"]),
        ("unknown caBundle key", ["database.caBundle.mountPath=/tmp"], [], [SCHEMA, "additional properties 'mountPath' not allowed"]),
        # Artifact volume (I4).
        ("artifacts without a source", ["storage.artifacts.enabled=true"], [],
         ["storage.artifacts: set existingClaim (an existing PVC) or size (a chart-owned PVC)"]),
        ("artifacts with both sources",
         ["storage.artifacts.enabled=true", "storage.artifacts.size=1Gi", "storage.artifacts.existingClaim=claim"], [],
         ["storage.artifacts: set either existingClaim or size, not both"]),
        ("storage class with existing claim",
         ["storage.artifacts.enabled=true", "storage.artifacts.existingClaim=claim", "storage.artifacts.storageClassName=fast"], [],
         ["storage.artifacts.storageClassName applies only to the chart-owned PVC"]),
        ("annotations with existing claim",
         ["storage.artifacts.enabled=true", "storage.artifacts.existingClaim=claim", "storage.artifacts.annotations.a=b"], [],
         ["storage.artifacts.annotations apply only to the chart-owned PVC"]),
        ("ReadWriteOncePod", ["storage.artifacts.enabled=true", "storage.artifacts.size=1Gi"],
         ["--set-json", 'storage.artifacts.accessModes=["ReadWriteOncePod"]'], [SCHEMA, "/storage/artifacts/accessModes/0"]),
        ("ReadWriteOncePod without schema", ["storage.artifacts.enabled=true", "storage.artifacts.size=1Gi"],
         ["--set-json", 'storage.artifacts.accessModes=["ReadWriteOncePod"]', "--skip-schema-validation"],
         ["storage.artifacts.accessModes: ReadWriteOncePod is not accepted"]),
        ("ReadOnlyMany", [], ["--set-json", 'storage.artifacts.accessModes=["ReadOnlyMany"]'], [SCHEMA, "/storage/artifacts/accessModes/0"]),
        ("no access modes", [], ["--set-json", "storage.artifacts.accessModes=[]"], [SCHEMA, "/storage/artifacts/accessModes"]),
        ("size without unit", ["storage.artifacts.size=10"], [], [SCHEMA, "/storage/artifacts/size"]),
        ("size in GB", ["storage.artifacts.size=10GB"], [], [SCHEMA, "/storage/artifacts/size"]),
        ("zero size", ["storage.artifacts.size=0Gi"], [], [SCHEMA, "/storage/artifacts/size"]),
        ("bad claim name", ["storage.artifacts.existingClaim=Claim_1"], [], [SCHEMA, "/storage/artifacts/existingClaim"]),
        ("unknown storage key", ["storage.artifacts.mountPath=/data"], [], [SCHEMA, "additional properties 'mountPath' not allowed"]),
        # Ingress (I4).
        ("ingress without class, hosts or TLS", ["ingress.enabled=true"], [],
         [SCHEMA, "/ingress/className", "/ingress/hosts", "/ingress/tls"]),
        ("ingress without class without schema", ["ingress.enabled=true"], ["--skip-schema-validation"],
         ["ingress.className is required when ingress.enabled is true"]),
        ("ingress without hosts without schema", ["ingress.enabled=true", "ingress.className=traefik"],
         ["--skip-schema-validation"], ["ingress.hosts must list at least one hostname"]),
        ("ingress host without TLS", ["ingress.enabled=true", "ingress.className=traefik"],
         ["--set-json", 'ingress.hosts=["a.example.test","b.example.test"]',
          "--set-json", 'ingress.tls=[{"secretName":"tls","hosts":["a.example.test"]}]'],
         ['ingress host "b.example.test" has no ingress.tls entry; the chart routes HTTPS only']),
        ("ingress without TLS without schema", ["ingress.enabled=true", "ingress.className=traefik"],
         ["--set-json", 'ingress.hosts=["a.example.test"]', "--skip-schema-validation"],
         ['ingress host "a.example.test" has no ingress.tls entry']),
        ("TLS for an unrouted host", ["ingress.enabled=true", "ingress.className=traefik"],
         ["--set-json", 'ingress.hosts=["a.example.test"]',
          "--set-json", 'ingress.tls=[{"secretName":"tls","hosts":["a.example.test","c.example.test"]}]'],
         ['ingress.tls[0] lists host "c.example.test", which is not in ingress.hosts']),
        ("TLS without Secret without schema", ["ingress.enabled=true", "ingress.className=traefik"],
         ["--set-json", 'ingress.hosts=["a.example.test"]', "--set-json", 'ingress.tls=[{"hosts":["a.example.test"]}]',
          "--skip-schema-validation"], ["ingress.tls[0].secretName is required"]),
        ("TLS without hosts", [], ["--set-json", 'ingress.tls=[{"secretName":"tls","hosts":[]}]'], [SCHEMA, "/ingress/tls/0/hosts"]),
        ("ingress without controller peer", ["ingress.enabled=true", "ingress.className=traefik"],
         ["--set-json", 'ingress.hosts=["a.example.test"]',
          "--set-json", 'ingress.tls=[{"secretName":"tls","hosts":["a.example.test"]}]'],
         ["networkPolicy.api.ingressFrom must select the ingress controller pods"]),
        ("wildcard host", [], ["--set-json", 'ingress.hosts=["*.example.test"]'], [SCHEMA, "/ingress/hosts/0"]),
        ("IP address host", [], ["--set-json", 'ingress.hosts=["192.0.2.1"]'], [SCHEMA, "/ingress/hosts/0"]),
        ("single-label host", [], ["--set-json", 'ingress.hosts=["localhost"]'], [SCHEMA, "/ingress/hosts/0"]),
        ("uppercase host", [], ["--set-json", 'ingress.hosts=["Example.test"]'], [SCHEMA, "/ingress/hosts/0"]),
        ("host with port", [], ["--set-json", 'ingress.hosts=["a.example.test:443"]'], [SCHEMA, "/ingress/hosts/0"]),
        ("duplicate host", [], ["--set-json", 'ingress.hosts=["a.example.test","a.example.test"]'], [SCHEMA, "/ingress/hosts"]),
        ("ingress path setting", [], ["--set-json", 'ingress.paths=["/api"]'], [SCHEMA, "additional properties 'paths' not allowed"]),
        ("unknown TLS key", [], ["--set-json", 'ingress.tls=[{"secretName":"tls","hosts":["a.example.test"],"create":true}]'],
         [SCHEMA, "additional properties 'create' not allowed"]),
        # API PodDisruptionBudget (I4).
        ("PDB without a field", ["api.replicas=2", "api.podDisruptionBudget.enabled=true"], [],
         ["api.podDisruptionBudget: set minAvailable or maxUnavailable when enabled is true"]),
        ("PDB with both fields", ["api.replicas=2", "api.podDisruptionBudget.enabled=true",
                                  "api.podDisruptionBudget.minAvailable=1", "api.podDisruptionBudget.maxUnavailable=1"], [],
         ["api.podDisruptionBudget: set either minAvailable or maxUnavailable, not both"]),
        ("PDB on one replica", ["api.podDisruptionBudget.enabled=true", "api.podDisruptionBudget.maxUnavailable=1"], [],
         ["api.podDisruptionBudget requires api.replicas >= 2 (found 1)"]),
        ("PDB keeps every replica", ["api.replicas=2", "api.podDisruptionBudget.enabled=true",
                                     "api.podDisruptionBudget.minAvailable=2"], [],
         ["api.podDisruptionBudget.minAvailable (2) keeps all 2 API replicas"]),
        ("PDB percentage rounds up to every replica", ["api.replicas=2", "api.podDisruptionBudget.enabled=true",
                                                       "api.podDisruptionBudget.minAvailable=51%"], [],
         ["api.podDisruptionBudget.minAvailable (51%) keeps all 2 API replicas"]),
        ("PDB allows no eviction", ["api.replicas=2", "api.podDisruptionBudget.enabled=true",
                                    "api.podDisruptionBudget.maxUnavailable=0"], [],
         ["api.podDisruptionBudget.maxUnavailable (0) allows no voluntary eviction"]),
        ("PDB allows no eviction by percentage", ["api.replicas=2", "api.podDisruptionBudget.enabled=true",
                                                  "api.podDisruptionBudget.maxUnavailable=0%"], [],
         ["api.podDisruptionBudget.maxUnavailable (0%) allows no voluntary eviction"]),
        ("PDB percentage above 100", ["api.podDisruptionBudget.maxUnavailable=101%"], [],
         [SCHEMA, "/api/podDisruptionBudget/maxUnavailable"]),
        ("PDB negative", ["api.podDisruptionBudget.minAvailable=-1"], [], [SCHEMA, "/api/podDisruptionBudget/minAvailable"]),
        ("PDB fraction", ["api.podDisruptionBudget.minAvailable=0.5"], [], [SCHEMA, "/api/podDisruptionBudget/minAvailable"]),
        ("PDB malformed percentage without schema", ["api.replicas=2", "api.podDisruptionBudget.enabled=true",
                                                     "api.podDisruptionBudget.minAvailable=half"],
         ["--skip-schema-validation"], ["api.podDisruptionBudget.minAvailable must be a non-negative integer or a percentage"]),
        ("unknown PDB key", ["api.podDisruptionBudget.selector=x"], [], [SCHEMA, "additional properties 'selector' not allowed"]),
        ("worker has no PDB", ["worker.podDisruptionBudget.enabled=true"], [],
         [SCHEMA, "additional properties 'podDisruptionBudget' not allowed"]),
        # Browser sign-in / OIDC (I5).
        ("auth without ConfigMap or login keys", ["auth.enabled=true"], [],
         [SCHEMA, "/auth/configMapName", "/auth/loginKeysSecretName"]),
        ("auth without ConfigMap without schema", ["auth.enabled=true"], ["--skip-schema-validation"],
         ["auth.configMapName is required when auth.enabled is true"]),
        ("auth without login keys", ["auth.enabled=true", "auth.configMapName=auth-cm"], [],
         [SCHEMA, "/auth/loginKeysSecretName"]),
        ("auth without login keys without schema", ["auth.enabled=true", "auth.configMapName=auth-cm"],
         ["--skip-schema-validation"], ["auth.loginKeysSecretName is required when auth.enabled is true"]),
        ("auth configKey with path", ["auth.configKey=../auth.json"], [], [SCHEMA, "/auth/configKey"]),
        ("auth configKey dot-dot", ["auth.configKey=.."], [], [SCHEMA, "/auth/configKey"]),
        ("auth configKey dot without schema",
         ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys", "auth.configKey=."],
         ["--skip-schema-validation"], ["auth.configKey must be a ConfigMap key"]),
        ("auth configKey slash without schema",
         ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys", "auth.configKey=a/b"],
         ["--skip-schema-validation"], ["auth.configKey must be a ConfigMap key"]),
        ("auth bad ConfigMap name", ["auth.configMapName=Auth_Config"], [], [SCHEMA, "/auth/configMapName"]),
        ("auth bad login keys Secret name", ["auth.loginKeysSecretName=Auth_Keys"], [],
         [SCHEMA, "/auth/loginKeysSecretName"]),
        ("auth provider CA enabled while auth disabled",
         ["auth.providerCaBundle.enabled=true", "auth.providerCaBundle.configMapName=oidc-ca"], [],
         [SCHEMA, "/auth/providerCaBundle/enabled"]),
        ("auth provider CA enabled while auth disabled without schema",
         ["auth.providerCaBundle.enabled=true", "auth.providerCaBundle.configMapName=oidc-ca"],
         ["--skip-schema-validation"], ["auth.providerCaBundle.enabled cannot be true when auth.enabled is false"]),
        ("auth provider CA without ConfigMap",
         ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys",
          "auth.providerCaBundle.enabled=true"], [], [SCHEMA, "/auth/providerCaBundle/configMapName"]),
        ("auth provider CA without ConfigMap without schema",
         ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys",
          "auth.providerCaBundle.enabled=true"], ["--skip-schema-validation"],
         ["auth.providerCaBundle.configMapName is required when auth.providerCaBundle.enabled is true"]),
        ("auth provider CA key with path", ["auth.providerCaBundle.key=../ca.crt"], [],
         [SCHEMA, "/auth/providerCaBundle/key"]),
        ("auth provider CA key dot-dot", ["auth.providerCaBundle.key=.."], [],
         [SCHEMA, "/auth/providerCaBundle/key"]),
        ("auth provider CA key dot-dot without schema",
         ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys",
          "auth.providerCaBundle.enabled=true", "auth.providerCaBundle.configMapName=oidc-ca",
          "auth.providerCaBundle.key=.."], ["--skip-schema-validation"],
         ["auth.providerCaBundle.key must be a ConfigMap key"]),
        ("auth provider CA bad ConfigMap name", ["auth.providerCaBundle.configMapName=OIDC_CA"], [],
         [SCHEMA, "/auth/providerCaBundle/configMapName"]),
        ("auth enabled without OIDC egress peers", [*AUTH, ISSUANCE], [],
         ["networkPolicy.api.oidc.to must list at least one OIDC provider peer"]),
        ("auth enabled without OIDC egress peers without schema",
         ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys"],
         ["--skip-schema-validation"], ["networkPolicy.api.oidc.to must list at least one OIDC provider peer"]),
        ("OIDC egress peers while auth disabled", [],
         ["--set-json", 'networkPolicy.api.oidc.to=[{"ipBlock":{"cidr":"192.0.2.20/32"}}]'],
         ["networkPolicy.api.oidc.to must be empty when auth.enabled is false"]),
        ("OIDC egress peers while auth and networkPolicy disabled", ["networkPolicy.enabled=false"],
         ["--set-json", 'networkPolicy.api.oidc.to=[{"ipBlock":{"cidr":"192.0.2.20/32"}}]'],
         ["networkPolicy.api.oidc.to must be empty when auth.enabled is false"]),
        ("empty OIDC peer", ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys"],
         ["--set-json", "networkPolicy.api.oidc.to=[{}]"], [SCHEMA, "/networkPolicy/api/oidc/to/0"]),
        ("empty OIDC peer without schema",
         ["auth.enabled=true", "auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys"],
         ["--set-json", "networkPolicy.api.oidc.to=[{}]", "--skip-schema-validation"],
         ["networkPolicy.api.oidc.to[0] must be a non-empty NetworkPolicyPeer object"]),
        ("unknown auth key", ["auth.mountPath=/tmp"], [], [SCHEMA, "additional properties 'mountPath' not allowed"]),
        # Model catalog key (core ADR 0036).
        ("catalog key while auth disabled", ["auth.catalogKey=catalog.json"], [], [SCHEMA, "/auth/catalogKey"]),
        ("catalog key while auth disabled without schema", ["auth.catalogKey=catalog.json"], [SKIP],
         ["auth.catalogKey must be empty when auth.enabled is false"]),
        ("catalog key with path", [*AUTH, ISSUANCE, "auth.catalogKey=../catalog.json"], OIDC_PEER,
         [SCHEMA, "/auth/catalogKey"]),
        ("catalog key dot-dot", [*AUTH, ISSUANCE, "auth.catalogKey=.."], OIDC_PEER, [SCHEMA, "/auth/catalogKey"]),
        ("catalog key slash without schema", [*AUTH, ISSUANCE, "auth.catalogKey=a/b"], [*OIDC_PEER, SKIP],
         ["auth.catalogKey must be a ConfigMap key"]),
        ("catalog key equals config key", [*AUTH, ISSUANCE, "auth.catalogKey=auth.json"], OIDC_PEER,
         ["auth.catalogKey must differ from auth.configKey"]),
        # Kubernetes refuses ConfigMap keys that start with "..", not only "." and "..".
        ("catalog key with .. prefix", [*AUTH, ISSUANCE, "auth.catalogKey=..catalog"], OIDC_PEER,
         [SCHEMA, "/auth/catalogKey"]),
        ("catalog key with .. prefix without schema", [*AUTH, ISSUANCE, "auth.catalogKey=..catalog"], [*OIDC_PEER, SKIP],
         ["auth.catalogKey must be a ConfigMap key"]),
        ("config key with .. prefix", ["auth.configKey=..auth.json"], [], [SCHEMA, "/auth/configKey"]),
        ("config key with .. prefix without schema", [*AUTH, ISSUANCE, "auth.configKey=..auth.json"], [*OIDC_PEER, SKIP],
         ["auth.configKey must be a ConfigMap key"]),
        # Session issuance (AUTHSEC-01, core ADR 0030).
        ("auth without issuance Secret", AUTH, OIDC_PEER, [SCHEMA, "/database/issuance/existingSecret"]),
        ("auth without issuance Secret without schema", AUTH, [*OIDC_PEER, SKIP],
         ["database.issuance.existingSecret is required when auth.enabled is true"]),
        ("issuance Secret without auth", [ISSUANCE], [], [SCHEMA, "/database/issuance/existingSecret"]),
        ("issuance Secret without auth without schema", [ISSUANCE], [SKIP],
         ["database.issuance.existingSecret must be empty when auth.enabled is false"]),
        *[(f"issuance reuses {role}{suffix}", [*AUTH, f"database.issuance.existingSecret={secret}"], [*OIDC_PEER, *extra],
           [f'database.issuance must not reuse database.{role} (Secret "{secret}", key "url")'])
          for role, secret in (("api", "openmettle-api-database"), ("worker", "openmettle-worker-database"),
                               ("migrate", "openmettle-owner-database"))
          for suffix, extra in (("", []), (" without schema", [SKIP]))],
        ("issuance reuses a custom api key",
         [*AUTH, "database.api.key=db", "database.issuance.existingSecret=openmettle-api-database", "database.issuance.key=db"],
         OIDC_PEER, ['database.issuance must not reuse database.api (Secret "openmettle-api-database", key "db")']),
        ("issuance bad Secret name", [*AUTH, "database.issuance.existingSecret=Issuance_DB"], OIDC_PEER,
         [SCHEMA, "/database/issuance/existingSecret"]),
        ("issuance key with path", [*AUTH, ISSUANCE, "database.issuance.key=a/b"], OIDC_PEER,
         [SCHEMA, "/database/issuance/key"]),
        ("issuance key with path without schema", [*AUTH, ISSUANCE, "database.issuance.key=a/b"], [*OIDC_PEER, SKIP],
         ["database.issuance.key must be a Secret key"]),
        ("issuance empty key without schema", [*AUTH, ISSUANCE, "database.issuance.key="], [*OIDC_PEER, SKIP],
         ["database.issuance.key must be a Secret key"]),
        *[(f"issuance pool {value}{suffix}", [*AUTH, ISSUANCE, f"api.settings.issuanceDbMaxConnections={value}"],
           [*OIDC_PEER, *extra], fragments)
          for value in ("0", "65", "1.5")
          for suffix, extra, fragments in (
              ("", [], [SCHEMA_ERROR, "/api/settings/issuanceDbMaxConnections"]),
              (" without schema", [SKIP],
               [f"api.settings.issuanceDbMaxConnections ({value}) must be an integer between 1 and 64"]))],
        ("issuance pool string without schema", [*AUTH, ISSUANCE],
         [*OIDC_PEER, "--set-string", "api.settings.issuanceDbMaxConnections=2", SKIP],
         ["api.settings.issuanceDbMaxConnections (2) must be an integer between 1 and 64"]),
        ("worker has no issuance pool", ["worker.settings.issuanceDbMaxConnections=2"], [],
         [SCHEMA, "additional properties 'issuanceDbMaxConnections' not allowed"]),
        ("unknown issuance key", ["database.issuance.optional=false"], [],
         [SCHEMA, "additional properties 'optional' not allowed"]),
        ("connection budget counts the issuance pool", [*AUTH, ISSUANCE, "database.connectionBudget=20"], OIDC_PEER,
         ["database.connectionBudget (20) is below the release's peak of 21 connections"]),
        ("unknown auth providerCaBundle key", ["auth.providerCaBundle.mountPath=/tmp"], [],
         [SCHEMA, "additional properties 'mountPath' not allowed"]),
        ("unknown OIDC policy key", ["networkPolicy.api.oidc.protocol=UDP"], [],
         [SCHEMA, "additional properties 'protocol' not allowed"]),
        ("worker has no auth", ["worker.auth.enabled=true"], [],
         [SCHEMA, "additional properties 'auth' not allowed"]),
        ("telemetry invalid log format", ["telemetry.logging.format=yaml"], [],
         [SCHEMA, "/telemetry/logging/format"]),
        ("telemetry invalid log format without schema", ["telemetry.logging.format=yaml"],
         ["--skip-schema-validation"], ["telemetry.logging.format must be null"]),
        ("telemetry trace log level refused", ["telemetry.logging.level=trace"], [],
         [SCHEMA, "/telemetry/logging/level"]),
        ("telemetry trace log level refused without schema", ["telemetry.logging.level=trace"],
         ["--skip-schema-validation"], ["telemetry.logging.level must be null"]),
        ("telemetry unknown log level", ["telemetry.logging.level=verbose"], [],
         [SCHEMA, "/telemetry/logging/level"]),
        ("telemetry OTLP enabled without any endpoint", ["telemetry.otlp.enabled=true"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp"]),
        ("telemetry OTLP enabled without any endpoint without schema", ["telemetry.otlp.enabled=true"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["at least one of telemetry.otlp.tracesEndpoint or telemetry.otlp.metricsEndpoint is required"]),
        ("telemetry OTLP tracesEndpoint while disabled",
         ["telemetry.otlp.tracesEndpoint=https://alloy.observability.example.test:4318/v1/traces"], [],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP tracesEndpoint while disabled without schema",
         ["telemetry.otlp.tracesEndpoint=https://alloy.observability.example.test:4318/v1/traces"],
         ["--skip-schema-validation"], ["telemetry.otlp.tracesEndpoint must be empty when telemetry.otlp.enabled is false"]),
        ("telemetry OTLP metricsEndpoint while disabled",
         ["telemetry.otlp.metricsEndpoint=https://alloy.observability.example.test:4318/v1/metrics"], [],
         [SCHEMA, "/telemetry/otlp/metricsEndpoint"]),
        ("telemetry OTLP metricsEndpoint while disabled without schema",
         ["telemetry.otlp.metricsEndpoint=https://alloy.observability.example.test:4318/v1/metrics"],
         ["--skip-schema-validation"], ["telemetry.otlp.metricsEndpoint must be empty when telemetry.otlp.enabled is false"]),
        ("telemetry OTLP metricsEndpoint http refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=http://alloy.observability.example.test:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/metricsEndpoint"]),
        ("telemetry OTLP metricsEndpoint http refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=http://alloy.observability.example.test:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint IPv4 literal refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://127.0.0.1:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/metricsEndpoint"]),
        ("telemetry OTLP metricsEndpoint 0x-hex final host label refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://c.0x7f000001:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint default port 443 refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:443/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint port (443) must be 1-65535 and omit the default port 443"]),
        ("telemetry OTLP non-string tracesEndpoint refused without schema",
         ["telemetry.otlp.enabled=true"],
         ["--set-json", "telemetry.otlp.tracesEndpoint=123",
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a string"]),
        ("telemetry OTLP non-string metricsEndpoint refused without schema",
         ["telemetry.otlp.enabled=true"],
         ["--set-json", "telemetry.otlp.metricsEndpoint=123",
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a string"]),
        ("telemetry OTLP metricsEndpoint credentials refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://user:pass@alloy.example.test:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint query refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:4318/v1/metrics?x=1"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint fragment refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:4318/v1/metrics#frag"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint percent-encoding refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:4318/v1/%6detrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint dot-segment refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:4318/v1/../metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint uppercase host refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://Alloy.example.test:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint IPv6 literal refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://[::1]:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint numeric final label refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.123:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint port 65536 refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:65536/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint port (65536) must be 1-65535"]),
        ("telemetry OTLP metricsEndpoint host over 253 chars refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test:4318/v1/metrics"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint hostname must be at most 253 characters"]),
        ("telemetry OTLP metricsEndpoint URL over 2048 chars refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:4318/mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP metricsEndpoint missing path refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.metricsEndpoint=https://alloy.example.test:4318"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.metricsEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP http endpoint refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=http://alloy.observability.example.test:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP http endpoint refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=http://alloy.observability.example.test:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP IPv4 literal endpoint refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://127.0.0.1:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP IPv4 literal endpoint refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://127.0.0.1:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP numeric final host label refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.123/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP numeric final host label refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.123/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP numeric final host label with port refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.123:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP numeric final host label with port refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.123:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP 0x-hex final host label refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0x1f/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP 0x-hex final host label refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0x1f/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP 0x-hex final host label with port refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0x1f:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP 0x-hex final host label with port refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0x1f:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP bare 0x final host label refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0x/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP bare 0x final host label refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0x/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP 0X-hex final host label refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0X1f/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP 0X-hex final host label refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://c.0X1f/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.tracesEndpoint must be a canonical https:// URL"]),
        ("telemetry OTLP IPv6 literal endpoint refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://[::1]:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP single-label host refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://localhost:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP uppercase host refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://Alloy.example.test:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint credentials refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://user@alloy.example.test:4318/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint query refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces?x=1"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint fragment refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces#frag"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint percent-encoding refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/%74races"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint default port 443 refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:443/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint default port 443 refused without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:443/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["omit the default port 443"]),
        ("telemetry OTLP endpoint dot-segment refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/../traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint missing path slash refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/tracesEndpoint"]),
        ("telemetry OTLP endpoint port above 65535 refused",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:70000/v1/traces"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         ["must be 1-65535"]),
        ("telemetry OTLP privateRanges while disabled", [],
         ["--set-json", 'telemetry.otlp.privateRanges=["10.43.0.0/16"]'],
         [SCHEMA, "/telemetry/otlp/privateRanges"]),
        ("telemetry OTLP privateRanges while disabled without schema", [],
         ["--set-json", 'telemetry.otlp.privateRanges=["10.43.0.0/16"]', "--skip-schema-validation"],
         ["telemetry.otlp.privateRanges must be empty when telemetry.otlp.enabled is false"]),
        ("telemetry OTLP privateRanges invalid CIDR with comma",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", 'telemetry.otlp.privateRanges=["10.43.0.0/16,10.44.0.0/16"]',
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/privateRanges/0"]),
        ("telemetry OTLP privateRanges invalid CIDR without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", 'telemetry.otlp.privateRanges=["10.43.0.0/16,10.44.0.0/16"]',
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.privateRanges[0] must be a CIDR string"]),
        ("telemetry OTLP privateRanges duplicate entry",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", 'telemetry.otlp.privateRanges=["10.43.0.0/16","10.43.0.0/16"]',
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/privateRanges"]),
        ("telemetry OTLP privateRanges duplicate entry without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", 'telemetry.otlp.privateRanges=["10.43.0.0/16","10.43.0.0/16"]',
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.privateRanges contains duplicate entry"]),
        ("telemetry OTLP privateRanges exceeds 32 entries",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", "telemetry.otlp.privateRanges=" + json.dumps([f"10.{i}.0.0/16" for i in range(33)]),
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/privateRanges"]),
        ("telemetry OTLP privateRanges exceeds 32 entries without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", "telemetry.otlp.privateRanges=" + json.dumps([f"10.{i}.0.0/16" for i in range(33)]),
          "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.privateRanges accepts at most 32 CIDR entries"]),
        ("telemetry OTLP CA enabled while OTLP disabled",
         ["telemetry.otlp.caBundle.enabled=true", "telemetry.otlp.caBundle.configMapName=otlp-ca"], [],
         [SCHEMA, "/telemetry/otlp/caBundle/enabled"]),
        ("telemetry OTLP CA enabled while OTLP disabled without schema",
         ["telemetry.otlp.caBundle.enabled=true", "telemetry.otlp.caBundle.configMapName=otlp-ca"],
         ["--skip-schema-validation"], ["telemetry.otlp.caBundle.enabled cannot be true when telemetry.otlp.enabled is false"]),
        ("telemetry OTLP CA enabled without configMapName",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces",
          "telemetry.otlp.caBundle.enabled=true"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         [SCHEMA, "/telemetry/otlp/caBundle/configMapName"]),
        ("telemetry OTLP CA enabled without configMapName without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces",
          "telemetry.otlp.caBundle.enabled=true"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.caBundle.configMapName is required"]),
        ("telemetry OTLP CA key with path", ["telemetry.otlp.caBundle.key=../ca.crt"], [],
         [SCHEMA, "/telemetry/otlp/caBundle/key"]),
        ("telemetry OTLP CA key dot-dot", ["telemetry.otlp.caBundle.key=.."], [],
         [SCHEMA, "/telemetry/otlp/caBundle/key"]),
        ("telemetry OTLP CA key dot-dot without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces",
          "telemetry.otlp.caBundle.enabled=true", "telemetry.otlp.caBundle.configMapName=otlp-ca",
          "telemetry.otlp.caBundle.key=.."],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]', "--skip-schema-validation"],
         ["telemetry.otlp.caBundle.key must be a ConfigMap key"]),
        ("telemetry OTLP CA bad ConfigMap name", ["telemetry.otlp.caBundle.configMapName=OTLP_CA"], [],
         [SCHEMA, "/telemetry/otlp/caBundle/configMapName"]),
        ("telemetry OTLP enabled without collector egress peers",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"], [],
         ["networkPolicy.telemetry.otlp.to must list at least one OTLP collector peer"]),
        ("telemetry OTLP enabled without collector egress peers without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--skip-schema-validation"], ["networkPolicy.telemetry.otlp.to must list at least one OTLP collector peer"]),
        ("OTLP egress peers while OTLP disabled", [],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         ["networkPolicy.telemetry.otlp.to must be empty when telemetry.otlp.enabled is false"]),
        ("OTLP egress peers while OTLP and networkPolicy disabled", ["networkPolicy.enabled=false"],
         ["--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
         ["networkPolicy.telemetry.otlp.to must be empty when telemetry.otlp.enabled is false"]),
        ("empty OTLP peer",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", "networkPolicy.telemetry.otlp.to=[{}]"], [SCHEMA, "/networkPolicy/telemetry/otlp/to/0"]),
        ("empty OTLP peer without schema",
         ["telemetry.otlp.enabled=true", "telemetry.otlp.tracesEndpoint=https://alloy.example.test:4318/v1/traces"],
         ["--set-json", "networkPolicy.telemetry.otlp.to=[{}]", "--skip-schema-validation"],
         ["networkPolicy.telemetry.otlp.to[0] must be a non-empty NetworkPolicyPeer object"]),
        ("OTLP port 0 without schema", ["networkPolicy.telemetry.otlp.port=0"],
         ["--skip-schema-validation"], ["networkPolicy.telemetry.otlp.port (0) must be an integer between 1 and 65535"]),
        ("OTLP port 65536 without schema", ["networkPolicy.telemetry.otlp.port=65536"],
         ["--skip-schema-validation"], ["networkPolicy.telemetry.otlp.port (65536) must be an integer between 1 and 65535"]),
        ("OTLP port string without schema", [],
         ["--set-string", "networkPolicy.telemetry.otlp.port=4318", "--skip-schema-validation"],
         ["networkPolicy.telemetry.otlp.port must be an integer between 1 and 65535"]),
        ("unknown telemetry key", ["telemetry.metrics.enabled=true"], [],
         [SCHEMA, "additional properties 'metrics' not allowed"]),
        ("unknown telemetry logging key", ["telemetry.logging.target=stdout"], [],
         [SCHEMA, "additional properties 'target' not allowed"]),
        ("unknown telemetry OTLP key", ["telemetry.otlp.protocol=grpc"], [],
         [SCHEMA, "additional properties 'protocol' not allowed"]),
        ("unknown telemetry OTLP caBundle key", ["telemetry.otlp.caBundle.mountPath=/tmp"], [],
         [SCHEMA, "additional properties 'mountPath' not allowed"]),
        ("unknown networkPolicy telemetry key", ["networkPolicy.telemetry.metrics.port=9090"], [],
         [SCHEMA, "additional properties 'metrics' not allowed"]),
        ("unknown networkPolicy telemetry OTLP key", ["networkPolicy.telemetry.otlp.protocol=UDP"], [],
         [SCHEMA, "additional properties 'protocol' not allowed"]),
        ("migration has no telemetry", ["migration.telemetry.enabled=true"], [],
         [SCHEMA, "additional properties 'telemetry' not allowed"]),
        # Worker inference (core ADRs 0033, 0043 and 0044).
        ("worker inference enabled without configMapName", ["worker.inference.enabled=true"],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [SCHEMA, "/worker/inference/configMapName"]),
        ("worker inference enabled without configMapName without schema", ["worker.inference.enabled=true"],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', SKIP],
         ["worker.inference.configMapName is required when worker.inference.enabled is true"]),
        ("worker inference configMapName while disabled", ["worker.inference.configMapName=inf-cm"], [],
         [SCHEMA, "/worker/inference/configMapName"]),
        ("worker inference configMapName while disabled without schema", ["worker.inference.configMapName=inf-cm"],
         [SKIP], ["worker.inference.configMapName must be empty when worker.inference.enabled is false"]),
        ("worker inference catalogKey equals configKey",
         ["worker.inference.enabled=true", "worker.inference.configMapName=inf-cm",
          "worker.inference.catalogKey=inference.json"],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["worker.inference.catalogKey must differ from worker.inference.configKey"]),
        ("worker inference catalogKey dot-dot without schema",
         ["worker.inference.enabled=true", "worker.inference.configMapName=inf-cm",
          "worker.inference.catalogKey=.."],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', SKIP],
         ["worker.inference.catalogKey must be a ConfigMap key"]),
        ("worker inference leaseMs below 6 * dbTimeoutMs",
         ["worker.settings.dbTimeoutMs=6000", "worker.inference.enabled=true",
          "worker.inference.configMapName=inf-cm", "worker.inference.settings.leaseMs=35999"],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["worker.inference.settings.leaseMs (35999 ms) must cover six worker.settings.dbTimeoutMs (36000 ms)"]),
        ("worker inference executionTimeoutMs below 2 * leaseMs",
         ["worker.inference.enabled=true", "worker.inference.configMapName=inf-cm",
          "worker.inference.settings.leaseMs=60000", "worker.inference.settings.executionTimeoutMs=119999"],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["worker.inference.settings.executionTimeoutMs (119999 ms) must cover two worker.inference.settings.leaseMs (120000 ms)"]),
        ("worker inference caBundle enabled while inference disabled",
         ["worker.inference.caBundle.enabled=true", "worker.inference.caBundle.configMapName=inf-ca"], [],
         [SCHEMA, "/worker/inference/caBundle/enabled"]),
        ("worker inference caBundle enabled while inference disabled without schema",
         ["worker.inference.caBundle.enabled=true", "worker.inference.caBundle.configMapName=inf-ca"], [SKIP],
         ["worker.inference.caBundle.enabled cannot be true when worker.inference.enabled is false"]),
        ("worker inference caBundle without configMapName",
         ["worker.inference.enabled=true", "worker.inference.configMapName=inf-cm",
          "worker.inference.caBundle.enabled=true"],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [SCHEMA, "/worker/inference/caBundle/configMapName"]),
        ("worker inference enabled without egress peers",
         ["worker.inference.enabled=true", "worker.inference.configMapName=inf-cm"], [],
         ["networkPolicy.worker.inference.to must list at least one inference gateway or TLS-terminator peer"]),
        ("worker inference egress peers while disabled", [],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["networkPolicy.worker.inference.to must be empty when worker.inference.enabled is false"]),
        ("worker inference egress peers while inference and networkPolicy disabled", ["networkPolicy.enabled=false"],
         ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["networkPolicy.worker.inference.to must be empty when worker.inference.enabled is false"]),
        ("worker inference empty egress peer without schema",
         ["worker.inference.enabled=true", "worker.inference.configMapName=inf-cm"],
         ["--set-json", "networkPolicy.worker.inference.to=[{}]", SKIP],
         ["networkPolicy.worker.inference.to[0] must be a non-empty NetworkPolicyPeer object"]),
        # Per-model gateways (core ADR 0044).
        ("gateway image set while gateways empty", ["images.gateway.repository=openmettle/gateway"], [],
         [SCHEMA, "/images/gateway/repository"]),
        ("gateway image set while gateways empty without schema",
         ["images.gateway.registry=registry.example.test"], [SKIP],
         ["images.gateway.{registry,repository,digest} must be empty when gateways is empty"]),
        ("gateway database Secret while gateways empty",
         ["database.gateway.existingSecret=openmettle-gateway-database"], [],
         [SCHEMA, "/database/gateway/existingSecret"]),
        ("gateway database Secret while gateways empty without schema",
         ["database.gateway.existingSecret=openmettle-gateway-database"], [SKIP],
         ["database.gateway.existingSecret must be empty when gateways is empty"]),
        ("gateways non-empty without image or database Secret",
         ["gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [SCHEMA, "/images/gateway", "/database/gateway"]),
        ("gateways non-empty without image without schema",
         ["gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          "database.gateway.existingSecret=openmettle-gateway-database"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', SKIP],
         ["images.gateway.repository is required when gateways is non-empty"]),
        ("gateways non-empty without database Secret without schema",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', SKIP],
         ["database.gateway.existingSecret is required when gateways is non-empty"]),
        *[(f"gateway db reuses {role}{suffix}",
           ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
            f"database.gateway.existingSecret={secret}", "gateways.a.model=a",
            "gateways.a.upstreamUrl=http://sglang:30000"],
           ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', *extra],
           [f'database.gateway must not reuse database.{role} (Secret "{secret}", key "url")'])
          for role, secret in (("api", "openmettle-api-database"), ("worker", "openmettle-worker-database"),
                               ("migrate", "openmettle-owner-database"))
          for suffix, extra in (("", []), (" without schema", [SKIP]))],
        ("gateway db reuses issuance Secret",
         [*AUTH, ISSUANCE, "images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          f"database.gateway.existingSecret={ISSUANCE_SECRET}", "gateways.a.model=a",
          "gateways.a.upstreamUrl=http://sglang:30000"],
         [*OIDC_PEER, "--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [f'database.gateway must not reuse database.issuance (Secret "{ISSUANCE_SECRET}", key "url")']),
        ("gateway invalid map name",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.Bad_Name.model=a", "gateways.Bad_Name.upstreamUrl=http://sglang:30000"],
         ["--set-json", 'gateways.Bad_Name.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [SCHEMA, "invalid propertyName 'Bad_Name'"]),
        ("gateway invalid map name without schema",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.Bad_Name.model=a", "gateways.Bad_Name.upstreamUrl=http://sglang:30000"],
         ["--set-json", 'gateways.Bad_Name.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', SKIP],
         ["gateways.Bad_Name: name must match"]),
        ("gateway duplicate model across instances",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=dup", "gateways.a.upstreamUrl=http://sglang-a:30000",
          "gateways.b.model=dup", "gateways.b.upstreamUrl=http://sglang-b:30000"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]',
          "--set-json", 'gateways.b.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.41/32"}}]'],
         ['gateways.b.model "dup" duplicates gateways.a.model']),
        ("gateway upstreamUrl https refused",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=https://sglang:30000"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [SCHEMA, "/gateways/a/upstreamUrl"]),
        ("gateway upstreamUrl https refused without schema",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=https://sglang:30000"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', SKIP],
         ["gateways.a.upstreamUrl must use http://"]),
        *[(f"gateway upstreamUrl bad ({label}){suffix}",
           ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
            "database.gateway.existingSecret=openmettle-gateway-database",
            "gateways.a.model=a", f"gateways.a.upstreamUrl={url}"],
           ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]', *extra],
           fragments)
          for label, url in (("path", "http://sglang:30000/v1"), ("query", "http://sglang:30000/?a=1"),
                             ("fragment", "http://sglang:30000/#x"), ("userinfo", "http://u@sglang:30000"),
                             ("port 0", "http://sglang:0"), ("double slash", "http://sglang:30000//"))
          for suffix, extra, fragments in (("", [], [SCHEMA_ERROR, "/gateways/a/upstreamUrl"]),
                                           (" without schema", [SKIP], ["gateways.a.upstreamUrl must be a canonical"]))],
        ("gateway upstreamUrl port above 65535",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:70000"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["gateways.a.upstreamUrl port (70000) must be between 1 and 65535"]),
        ("gateway invalid cacheMode",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          "gateways.a.settings.cacheMode=global"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [SCHEMA, "/gateways/a/settings/cacheMode"]),
        ("gateway grace equal to shutdown",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          "gateways.a.terminationGracePeriodSeconds=5"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["gateways.a.terminationGracePeriodSeconds (5 s) must exceed gateways.a.settings.shutdownTimeoutMs (5000 ms)"]),
        ("gateway strategy both zero",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          "gateways.a.strategy.maxSurge=0", "gateways.a.strategy.maxUnavailable=0"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["gateways.a.strategy.maxSurge and gateways.a.strategy.maxUnavailable cannot both be 0"]),
        ("gateway missing upstream egress peers",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000"], [],
         ["gateways.a.networkPolicy.upstream.to must list at least one upstream peer"]),
        ("gateway empty ingressFrom peer without schema",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]',
          "--set-json", "gateways.a.networkPolicy.ingressFrom=[{}]", SKIP],
         ["gateways.a.networkPolicy.ingressFrom[0] must be a non-empty NetworkPolicyPeer object"]),
        ("gateway serviceAccount named default",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          "gateways.a.serviceAccount.name=default"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ['gateways.a.serviceAccount.name must not be "default"']),
        ("gateway serviceAccount shares worker name",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          f"gateways.a.serviceAccount.name={FULL}-worker"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         [f'worker and gateways.a resolve to the same ServiceAccount "{FULL}-worker"']),
        ("gateway serviceAccount create=false without name",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          "gateways.a.serviceAccount.create=false"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["gateways.a.serviceAccount.name is required when serviceAccount.create is false"]),
        ("connection budget counts gateway surge replicas",
         ["images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
          "database.gateway.existingSecret=openmettle-gateway-database",
          "gateways.a.model=a", "gateways.a.upstreamUrl=http://sglang:30000",
          "database.connectionBudget=24"],
         ["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
         ["database.connectionBudget (24) is below the release's peak of 25 connections", "gateways 8"]),
    ]

    def test_cases_fail_with_intended_message(self):
        """Fails if a schema constraint, `required` call or validate.yaml guard is removed or reworded."""
        for name, set_values, extra, fragments in self.CASES:
            with self.subTest(case=name):
                result = helm_template(set_values=set_values, extra=extra)
                self.assertNotEqual(result.returncode, 0, f"{name} rendered")
                for fragment in fragments:
                    self.assertIn(fragment, result.stderr)

    def test_boundaries_render(self):
        """Fails if a guard rejects the boundary value it should accept (off-by-one)."""
        for set_values in (["database.connectionBudget=17"], ["api.terminationGracePeriodSeconds=6"],
                           ["api.settings.dbMaxConnections=64"], ["api.strategy.maxSurge=0", "api.strategy.maxUnavailable=1"],
                           ["migration.activeDeadlineSeconds=321"],
                           # An unused migrate account name is not checked when migration is disabled.
                           ["migration.enabled=false", "migration.serviceAccount.name=default"]):
            with self.subTest(values=set_values):
                result = helm_template(set_values=set_values)
                self.assertEqual(result.returncode, 0, result.stderr)
        # Database peers are not required while the policies are disabled.
        result = helm_template(extra=["--set", "networkPolicy.enabled=false", "--set-json", "networkPolicy.database.to=[]"])
        self.assertEqual(result.returncode, 0, result.stderr)
        pdb = ["api.podDisruptionBudget.enabled=true"]
        for set_values in (pdb + ["api.replicas=2", "api.podDisruptionBudget.minAvailable=1"],
                           pdb + ["api.replicas=2", "api.podDisruptionBudget.minAvailable=50%"],
                           pdb + ["api.replicas=2", "api.podDisruptionBudget.minAvailable=0"],
                           pdb + ["api.replicas=2", "api.podDisruptionBudget.maxUnavailable=1%"],
                           pdb + ["api.replicas=2", "api.podDisruptionBudget.maxUnavailable=100%"],
                           # Unused values are not checked while the feature is disabled.
                           ["api.podDisruptionBudget.minAvailable=1", "api.podDisruptionBudget.maxUnavailable=1"],
                           ["storage.artifacts.existingClaim=claim", "storage.artifacts.size=1Gi"],
                           ["storage.artifacts.enabled=true", "storage.artifacts.size=1.5Gi"],
                           ["storage.artifacts.enabled=true", "storage.artifacts.size=500M"],
                           ["database.caBundle.configMapName=ca"],
                           ["ingress.className=traefik"],
                           ["auth.configMapName=auth-cm", "auth.loginKeysSecretName=auth-keys",
                            "auth.providerCaBundle.configMapName=oidc-ca"],
                           ["telemetry.otlp.caBundle.configMapName=otlp-ca"]):
            with self.subTest(values=set_values):
                result = helm_template(set_values=set_values)
                self.assertEqual(result.returncode, 0, result.stderr)
        # Canonical HTTPS OTLP endpoints (implicit 443, root path) and the 32-CIDR boundary render cleanly.
        for extra in (
            ["--set", "telemetry.otlp.enabled=true",
             "--set", "telemetry.otlp.tracesEndpoint=https://alloy.observability.example.test/v1/traces",
             "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
            ["--set", "telemetry.otlp.enabled=true",
             "--set", "telemetry.otlp.tracesEndpoint=https://alloy.observability.example.test/",
             "--set-json", "telemetry.otlp.privateRanges=" + json.dumps([f"10.{i}.0.0/16" for i in range(32)]),
             "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
            ["--set", "telemetry.otlp.enabled=true",
             "--set", "telemetry.otlp.tracesEndpoint=https://c.0x1f.example.test/v1/traces",
             "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
            ["--set", "telemetry.otlp.enabled=true",
             "--set", "telemetry.otlp.tracesEndpoint=https://c.123a/v1/traces",
             "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
            ["--set", "telemetry.otlp.enabled=true",
             "--set", "telemetry.otlp.metricsEndpoint=https://alloy.observability.example.test/v1/metrics",
             "--set-json", 'networkPolicy.telemetry.otlp.to=[{"ipBlock":{"cidr":"192.0.2.30/32"}}]'],
        ):
            with self.subTest(extra=extra):
                result = helm_template(extra=extra)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_chart_defaults_refuse_to_render(self):
        """Fails if values.yaml ever ships an image digest or Secret name."""
        result = subprocess.run([HELM, "template", RELEASE, str(CHART)], capture_output=True, text=True, timeout=120, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is required", result.stderr)


class BoundsTest(unittest.TestCase):
    """Every bounded api, worker and migration value accepts its limits and rejects one beyond."""

    # (values path, minimum, maximum or None, other values needed for the limits to render)
    MIGRATION_ROOM = ["migration.activeDeadlineSeconds=4261"]  # exceeds 60000 + 600000 + 3600000 ms
    BOUNDS = [
        *[(f"{role}.{path}", low, high, extra) for role in ("api", "worker") for path, low, high, extra in (
            ("settings.dbMaxConnections", 1, 64, []),
            ("settings.dbTimeoutMs", 1, 30000, []),
            ("settings.shutdownTimeoutMs", 1, 60000, [f"{role}.terminationGracePeriodSeconds=61"]),
            ("terminationGracePeriodSeconds", 1, None, [f"{role}.settings.shutdownTimeoutMs=1"]),
            ("replicas", 0, None, []),
            ("strategy.maxSurge", 0, None, [f"{role}.strategy.maxUnavailable=1"]),
            ("strategy.maxUnavailable", 0, None, []),
        )],
        ("api.settings.issuanceDbMaxConnections", 1, 64, []),
        ("api.service.port", 1, 65535, []),
        ("worker.sweepMs", 1000, 3600000, []),
        ("worker.pollMs", 100, 60000, []),
        ("networkPolicy.database.port", 1, 65535, []),
        ("networkPolicy.api.oidc.port", 1, 65535, []),
        ("networkPolicy.worker.inference.port", 1, 65535, []),
        ("networkPolicy.telemetry.otlp.port", 1, 65535, []),
        ("migration.settings.connectTimeoutMs", 1, 60000, MIGRATION_ROOM),
        ("migration.settings.lockTimeoutMs", 1, 600000, MIGRATION_ROOM),
        ("migration.settings.statementTimeoutMs", 1, 3600000, MIGRATION_ROOM),
        ("migration.activeDeadlineSeconds", 1, None, [f"migration.settings.{key}=1" for key in
                                                     ("connectTimeoutMs", "lockTimeoutMs", "statementTimeoutMs")]),
    ]

    def test_sweep_interval_rejects_strings_and_fractional_values(self):
        for extra in (["--set-string", "worker.sweepMs=2000"], ["--set-json", "worker.sweepMs=2000.5"]):
            with self.subTest(extra=extra):
                result = helm_template(extra=extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("/worker/sweepMs", result.stderr)

    def test_sweep_interval_rejects_invalid_values_without_schema(self):
        for value in (False, True, 2000.5, "2000", {}, [], 999, 3600001):
            with self.subTest(value=value):
                result = helm_template(extra=["--skip-schema-validation", "--set-json",
                                              f"worker.sweepMs={json.dumps(value)}"])
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stderr, r"worker\.sweepMs.*must be an integer between 1000 and 3600000")

    def test_sweep_interval_reaches_only_worker_and_null_uses_core_default(self):
        for value in ("null", "1000", "3600000"):
            docs = render(set_values=[f"worker.sweepMs={value}"])
            for role, pod in pods(docs):
                with self.subTest(value=value, role=role):
                    entries = [entry for c in containers(pod) for entry in c["env"]
                               if entry["name"].endswith("_SWEEP_MS")]
                    expected = [{"name": "OPENMETTLE_WORKER_SWEEP_MS", "value": value}]
                    self.assertEqual(entries, expected if role == "worker" and value != "null" else [])

    def test_poll_interval_reaches_only_worker_and_rejects_invalid_values(self):
        for value in ("null", "100", "60000"):
            docs = render(set_values=[f"worker.pollMs={value}"])
            for role, pod in pods(docs):
                with self.subTest(value=value, role=role):
                    entries = [entry for c in containers(pod) for entry in c["env"]
                               if entry["name"].endswith("_POLL_MS")]
                    expected = [{"name": "OPENMETTLE_WORKER_POLL_MS", "value": value}]
                    self.assertEqual(entries, expected if role == "worker" and value != "null" else [])
        for extra in (["--set-string", "worker.pollMs=500"], ["--set-json", "worker.pollMs=500.5"]):
            result = helm_template(extra=extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("/worker/pollMs", result.stderr)
        for value in (False, 500.5, "500", 99, 60001):
            result = helm_template(extra=[SKIP, "--set-json", f"worker.pollMs={json.dumps(value)}"])
            self.assertNotEqual(result.returncode, 0)
            self.assertRegex(result.stderr, r"worker\.pollMs.*must be an integer between 100 and 60000")

    def test_limits_render_and_values_beyond_fail_schema(self):
        """Fails if a schema minimum or maximum is removed, loosened or tightened."""
        for path, low, high, extra in self.BOUNDS:
            accept = [low] + ([high] if high is not None else [])
            reject = [low - 1] + ([high + 1] if high is not None else [])
            for value in accept:
                with self.subTest(path=path, value=value, expect="render"):
                    result = helm_template(set_values=extra + [f"{path}={value}"])
                    self.assertEqual(result.returncode, 0, result.stderr)
            for value in reject:
                with self.subTest(path=path, value=value, expect="schema error"):
                    result = helm_template(set_values=extra + [f"{path}={value}"])
                    self.assertNotEqual(result.returncode, 0, f"{path}={value} rendered")
                    self.assertIn(SCHEMA_ERROR, result.stderr)
                    self.assertIn("/" + path.replace(".", "/"), result.stderr)


class YamlScalarTest(unittest.TestCase):
    """Schema-valid names that YAML reads as int, bool or null must render as strings."""

    @classmethod
    def setUpClass(cls):
        cls.docs = render(("yaml-ambiguous.yaml",), release="123")

    def test_labels_are_strings(self):
        """Fails if the release name (instance label) or another label value is emitted unquoted."""
        for doc in self.docs:
            pod_labels = doc.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {})
            for labels in (doc["metadata"]["labels"], pod_labels):
                for key, value in labels.items():
                    self.assertIsInstance(value, str, f"{doc['kind']} {key}")
            self.assertEqual(doc["metadata"]["labels"]["app.kubernetes.io/instance"], "123")

    def test_names_and_keys_are_strings(self):
        """Fails if a ServiceAccount, pull Secret, Secret name, Secret key or policy peer label is emitted unquoted."""
        accounts = sorted(d["metadata"]["name"] for d in self.docs if d["kind"] == "ServiceAccount")
        self.assertEqual(accounts, ["555", "null"])
        peer = find(self.docs, "NetworkPolicy", "-worker")["spec"]["egress"][1]["to"][0]
        self.assertEqual(peer["podSelector"]["matchLabels"], {"example.test/enabled": "true", "example.test/id": "123"})
        expected = {
            "api": ("555", "456", "123"),
            "worker": ("true", "openmettle-worker-database", "false"),
            "migrate": ("null", "openmettle-owner-database", "null"),
        }
        for role, pod in pods(self.docs):
            with self.subTest(component=role):
                account, secret, key = expected[role]
                self.assertEqual(pod["serviceAccountName"], account)
                self.assertEqual(pod["imagePullSecrets"], [{"name": "true"}])
                ref = env_map(pod["containers"][0])[PREFIX[role] + "DATABASE_URL"]["valueFrom"]["secretKeyRef"]
                self.assertEqual(ref, {"name": secret, "key": key})
                self.assertIsInstance(pod["containers"][0]["imagePullPolicy"], str)
        api_pod = find(self.docs, "Deployment", "-api")["spec"]["template"]["spec"]
        self.assertEqual(env_map(api_pod["containers"][0])[ISSUANCE_URL]["valueFrom"]["secretKeyRef"],
                         {"name": "true", "key": "0x1"})
        self.assertEqual(volumes(api_pod)["auth-config"]["configMap"], {
            "name": "789", "items": [{"key": "false", "path": "auth.json"}, {"key": "1", "path": "catalog.json"}]})
        self.assertEqual(volumes(api_pod)["auth-login-keys"]["secret"], {
            "secretName": "null", "defaultMode": 0o440})
        self.assertEqual(volumes(api_pod)["auth-provider-ca"]["configMap"], {
            "name": "123", "items": [{"key": "true", "path": "ca.crt"}]})
        oidc_peer = find(self.docs, "NetworkPolicy", "-api")["spec"]["egress"][2]["to"][0]
        self.assertEqual(oidc_peer["podSelector"]["matchLabels"], {"example.test/oidc": "true", "example.test/id": "456"})
        for role, idx in (("api", 3), ("worker", 2)):
            pod = find(self.docs, "Deployment", f"-{role}")["spec"]["template"]["spec"]
            self.assertEqual(volumes(pod)["otlp-ca"]["configMap"], {
                "name": "321", "items": [{"key": "false", "path": "ca.crt"}]})
            otlp_peer = find(self.docs, "NetworkPolicy", f"-{role}")["spec"]["egress"][idx]["to"][0]
            self.assertEqual(otlp_peer["podSelector"]["matchLabels"], {"example.test/otlp": "true", "example.test/id": "789"})
            env = env_map(pod["containers"][0])
            for key in ("LOG_FORMAT", "LOG_LEVEL", "OTLP_TRACES_ENDPOINT", "OTLP_METRICS_ENDPOINT", "OTLP_CA_FILE", "OTLP_PRIVATE_RANGES"):
                self.assertIsInstance(env[PREFIX[role] + key]["value"], str)
        migrate_pod = find(self.docs, "Job", "-migrate")["spec"]["template"]["spec"]
        self.assertNotIn("otlp-ca", volumes(migrate_pod))
        for key in ("LOG_FORMAT", "LOG_LEVEL"):
            self.assertIsInstance(env_map(migrate_pod["containers"][0])[PREFIX["migrate"] + key]["value"], str)

    def test_gateway_and_inference_names_and_keys_are_strings(self):
        """Fails if ambiguous gateway/inference names, models, Secret keys or ConfigMap keys render unquoted."""
        result = helm_template(
            release="123",
            extra=[
                "--set", "images.gateway.repository=openmettle/gateway",
                "--set", f"images.gateway.digest={DIGEST}",
                "--set-string", "database.gateway.existingSecret=789",
                "--set-string", "database.gateway.key=null",
                "--set", "worker.inference.enabled=true",
                "--set-string", "worker.inference.configMapName=456",
                "--set-string", "worker.inference.configKey=true",
                "--set-string", "worker.inference.catalogKey=false",
                "--set", "worker.inference.caBundle.enabled=true",
                "--set-string", "worker.inference.caBundle.configMapName=999",
                "--set-string", "worker.inference.caBundle.key=null",
                "--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]',
                "--set-json", 'gateways={"123":{"model":"true","upstreamUrl":"http://sglang:30000","serviceAccount":{"name":"false"},"networkPolicy":{"upstream":{"to":[{"ipBlock":{"cidr":"192.0.2.41/32"}}]}}}}',
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
        worker_pod = find(docs, "Deployment", "-worker")["spec"]["template"]["spec"]
        self.assertEqual(volumes(worker_pod)["inference-config"]["configMap"], {
            "name": "456",
            "items": [{"key": "true", "path": "inference.json"}, {"key": "false", "path": "catalog.json"}],
        })
        self.assertEqual(volumes(worker_pod)["inference-ca"]["configMap"], {
            "name": "999", "items": [{"key": "null", "path": "ca.crt"}],
        })
        gw_pod = find(docs, "Deployment", "-gateway-123")["spec"]["template"]["spec"]
        self.assertEqual(gw_pod["serviceAccountName"], "false")
        gw_env = env_map(gw_pod["containers"][0])
        self.assertEqual(gw_env["OPENMETTLE_GATEWAY_MODEL"]["value"], "true")
        self.assertEqual(gw_env["OPENMETTLE_GATEWAY_DATABASE_URL"]["valueFrom"]["secretKeyRef"],
                         {"name": "789", "key": "null"})
        gw_np = find(docs, "NetworkPolicy", "-gateway-123")["spec"]
        self.assertEqual(gw_np["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/instance"], "123")


class WorkerInferenceTest(Rendered):
    """worker.inference mounts inference config, catalog and optional CA into worker only (core ADRs 0033, 0043, 0044)."""

    def test_worker_inference_env_volumes_and_isolation(self):
        """Fails if worker.inference env/volumes drift or leak onto api, gateway or migrate."""
        for name, has_ca in (("gateway-and-inference-enabled", False),
                             ("gateway-tls-terminator", True),
                             ("all-keys", True)):
            docs = self.renders[name]
            with self.subTest(values=name):
                worker = find(docs, "Deployment", "-worker")["spec"]["template"]["spec"]
                env = env_map(worker["containers"][0])
                self.assertEqual(env["OPENMETTLE_WORKER_INFERENCE_CONFIG"]["value"], INFERENCE_CONFIG_PATH)
                for key in ("RUN_SLOTS", "LEASE_MS", "EXECUTION_TIMEOUT_MS", "EXECUTING_PER_ACTOR", "EXECUTING_PER_SCOPE"):
                    self.assertIn("OPENMETTLE_WORKER_" + key, env)
                self.assertEqual(mounts(worker)["inference-config"],
                                 {"name": "inference-config", "mountPath": INFERENCE_CONFIG_DIR, "readOnly": True})
                items = volumes(worker)["inference-config"]["configMap"]["items"]
                self.assertEqual([i["path"] for i in items], ["inference.json", "catalog.json"])
                if has_ca:
                    self.assertEqual(mounts(worker)["inference-ca"],
                                     {"name": "inference-ca", "mountPath": INFERENCE_CA_DIR, "readOnly": True})
                else:
                    self.assertNotIn("inference-ca", volumes(worker))
                    self.assertNotIn("inference-ca", mounts(worker))
                # No fsGroup unless artifacts is also enabled.
                if name != "all-keys":
                    self.assertNotIn("fsGroup", worker["securityContext"])
                # Strict isolation: no inference env or volumes outside worker.
                for role, pod in pods(docs):
                    if role == "worker":
                        continue
                    other_env = env_map(pod["containers"][0])
                    self.assertFalse([k for k in other_env if any(
                        tok in k for tok in ("INFERENCE", "RUN_SLOTS", "LEASE_MS", "EXECUTION_TIMEOUT", "EXECUTING_PER"))])
                    self.assertFalse(INFERENCE_VOLUMES & set(volumes(pod)), role)

    def test_lease_and_execution_boundaries_render(self):
        """Fails if exact 6 * dbTimeoutMs or 2 * leaseMs boundaries are rejected."""
        base = ["worker.settings.dbTimeoutMs=5000", "worker.inference.enabled=true",
                "worker.inference.configMapName=inf-cm", "worker.inference.settings.leaseMs=30000",
                "worker.inference.settings.executionTimeoutMs=60000"]
        peer = ["--set-json", 'networkPolicy.worker.inference.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]']
        for extra in (peer, [*peer, SKIP]):
            result = helm_template(set_values=base, extra=extra)
            self.assertEqual(result.returncode, 0, result.stderr)


class GatewayTest(Rendered):
    """Opt-in per-model openmettle-gateway Deployments, Services, ServiceAccounts and NetworkPolicies (core ADR 0044)."""

    def test_deterministic_multi_gateway_order_and_defaults(self):
        """Fails if multiple gateways are not rendered in deterministic sortAlpha order or defaults drift."""
        docs = self.renders["gateway-and-inference-enabled"]
        gw_deployments = [d for d in docs if d["kind"] == "Deployment" and component(d).startswith("gateway-")]
        self.assertEqual([component(d) for d in gw_deployments], ["gateway-a", "gateway-b"])
        gw_services = [d for d in docs if d["kind"] == "Service" and component(d).startswith("gateway-")]
        self.assertEqual([component(d) for d in gw_services], ["gateway-a", "gateway-b"])
        # gateway-a uses chart defaults; gateway-b overrides every per-gateway setting.
        a_dep, b_dep = gw_deployments
        self.assertEqual(a_dep["spec"]["replicas"], 1)
        self.assertEqual(b_dep["spec"]["replicas"], 2)
        a_pod = a_dep["spec"]["template"]["spec"]
        a_c = a_pod["containers"][0]
        a_env = env_map(a_c)
        self.assertEqual(a_c["name"], "gateway")
        self.assertEqual(a_c["readinessProbe"]["timeoutSeconds"], 3)
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_MODEL"]["value"], "model-a")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_UPSTREAM_URL"]["value"], "http://sglang-a.inference.example.test:30000")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_CACHE_MODE"]["value"], "scoped")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_UPSTREAM_CONNECT_TIMEOUT_MS"]["value"], "5000")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_UPSTREAM_IDLE_TIMEOUT_MS"]["value"], "120000")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_DB_MAX_CONNECTIONS"]["value"], "4")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_DB_TIMEOUT_MS"]["value"], "2000")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_SHUTDOWN_TIMEOUT_MS"]["value"], "5000")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_OTLP_TRACES_ENDPOINT"]["value"],
                         "https://alloy.observability.example.test:4318/v1/traces")
        self.assertEqual(a_env["OPENMETTLE_GATEWAY_OTLP_CA_FILE"]["value"], OTLP_CA_PATH)
        self.assertEqual(set(volumes(a_pod)), {"db-ca", "otlp-ca"})
        self.assertNotIn("fsGroup", a_pod["securityContext"])
        b_c = b_dep["spec"]["template"]["spec"]["containers"][0]
        b_env = env_map(b_c)
        self.assertEqual(b_c["readinessProbe"]["timeoutSeconds"], 3)
        self.assertEqual(b_env["OPENMETTLE_GATEWAY_CACHE_MODE"]["value"], "per_request")
        self.assertEqual(b_env["OPENMETTLE_GATEWAY_UPSTREAM_CONNECT_TIMEOUT_MS"]["value"], "3000")
        self.assertEqual(b_env["OPENMETTLE_GATEWAY_UPSTREAM_IDLE_TIMEOUT_MS"]["value"], "60000")
        self.assertEqual(gw_services[0]["spec"]["type"], "ClusterIP")
        self.assertEqual(gw_services[0]["spec"]["ports"][0]["port"], 8082)
        self.assertEqual(gw_services[1]["spec"]["ports"][0]["port"], 8083)

    def test_zero_false_and_empty_list_overrides_preserved(self):
        """Fails if per-gateway default merging drops 0, false or [] overrides."""
        result = helm_template(
            set_values=[
                "images.gateway.repository=openmettle/gateway",
                f"images.gateway.digest={DIGEST}",
                "database.gateway.existingSecret=openmettle-gateway-database",
                "database.connectionBudget=21",
                "gateways.a.model=a",
                "gateways.a.upstreamUrl=http://[::1]:30000/",
                "gateways.a.replicas=0",
                "gateways.a.serviceAccount.create=false",
                "gateways.a.serviceAccount.name=preexisting-gw-sa",
            ],
            extra=[
                "--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"2001:db8::1/128"}}]',
                "--set-json", "gateways.a.networkPolicy.ingressFrom=[]",
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
        dep = find(docs, "Deployment", "-gateway-a")
        self.assertEqual(dep["spec"]["replicas"], 0)
        self.assertEqual(dep["spec"]["template"]["spec"]["serviceAccountName"], "preexisting-gw-sa")
        self.assertFalse([d for d in docs if d["kind"] == "ServiceAccount" and component(d) == "gateway-a"])
        np = find(docs, "NetworkPolicy", "-gateway-a")["spec"]
        self.assertNotIn("ingress", np, "explicit ingressFrom: [] must deny all ingress")

    def test_resource_name_63_char_limit_enforced(self):
        """Fails if <fullname>-gateway-<name> exceeding 63 characters renders instead of failing."""
        # release 'r'*53 -> fullname 'r'*52; 'r'*52 + '-gateway-ab' = 63 (OK); '-gateway-abc' = 64 (FAIL)
        ok = helm_template(
            release="r" * 53,
            set_values=[
                "images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
                "database.gateway.existingSecret=openmettle-gateway-database",
                "gateways.ab.model=a", "gateways.ab.upstreamUrl=http://sglang:30000",
            ],
            extra=["--set-json", 'gateways.ab.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
        )
        self.assertEqual(ok.returncode, 0, ok.stderr)
        bad = helm_template(
            release="r" * 53,
            set_values=[
                "images.gateway.repository=openmettle/gateway", f"images.gateway.digest={DIGEST}",
                "database.gateway.existingSecret=openmettle-gateway-database",
                "gateways.abc.model=a", "gateways.abc.upstreamUrl=http://sglang:30000",
            ],
            extra=["--set-json", 'gateways.abc.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("exceeds Kubernetes' 63-character limit", bad.stderr)

    def test_gateway_network_policy_disabled_renders_no_policies(self):
        """Fails if gateway-network-policy-disabled still renders any NetworkPolicy."""
        docs = self.renders["gateway-network-policy-disabled"]
        self.assertNotIn("NetworkPolicy", {d["kind"] for d in docs})
        self.assertEqual(find(docs, "Deployment", "-gateway-a")["spec"]["replicas"], 1)

    def test_database_gateway_same_secret_different_key_renders(self):
        """Fails if database.gateway sharing a Secret with another role under a distinct key is rejected."""
        result = helm_template(
            set_values=[
                "images.gateway.repository=openmettle/gateway",
                f"images.gateway.digest={DIGEST}",
                "database.gateway.existingSecret=openmettle-api-database",
                "database.gateway.key=gateway-url",
                "gateways.a.model=a",
                "gateways.a.upstreamUrl=http://sglang:30000",
            ],
            extra=["--set-json", 'gateways.a.networkPolicy.upstream.to=[{"ipBlock":{"cidr":"192.0.2.40/32"}}]'],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
        gw_env = env_map(find(docs, "Deployment", "-gateway-a")["spec"]["template"]["spec"]["containers"][0])
        self.assertEqual(gw_env["OPENMETTLE_GATEWAY_DATABASE_URL"]["valueFrom"]["secretKeyRef"],
                         {"name": "openmettle-api-database", "key": "gateway-url"})


class ContractDriftTest(unittest.TestCase):
    """Chart defaults against core runtime/process-contract.json at the pinned commit (tests/fixtures)."""

    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.docs = render()
        cls.gateway_docs = render(("gateway-and-inference-enabled.yaml",))

    def test_defaults_match_process_contract(self):
        """Fails if a port, probe path, request or automount default diverges from the core contract."""
        for role, docs, suffix in (("api", self.docs, "-api"),
                                   ("worker", self.docs, "-worker"),
                                   ("gateway", self.gateway_docs, "-gateway-a")):
            expected = self.contract[role]
            with self.subTest(component=role):
                pod = find(docs, "Deployment", suffix)["spec"]["template"]["spec"]
                container = pod["containers"][0]
                self.assertEqual(container["name"], expected["imageTarget"])
                self.assertEqual([p["containerPort"] for p in container["ports"]], [expected["port"]])
                self.assertEqual(container["livenessProbe"]["httpGet"]["path"], expected["livenessPath"])
                self.assertEqual(container["readinessProbe"]["httpGet"]["path"], expected["readinessPath"])
                self.assertEqual(container["resources"]["requests"], expected["requests"])
                self.assertIs(pod["automountServiceAccountToken"], expected["automountServiceAccountToken"])
                account = find(docs, "ServiceAccount", suffix)
                self.assertIs(account["automountServiceAccountToken"], expected["automountServiceAccountToken"])
                self.assertTrue(all(e["name"].startswith(expected["configurationPrefix"]) for e in container["env"]))

    def test_contract_service_account_names_are_accepted(self):
        """Fails if serviceAccount.name stops overriding the generated name (contract names are opt-in)."""
        overrides = [f"{role}.serviceAccount.name={self.contract[role]['serviceAccountName']}" for role in ("api", "worker")]
        overrides.append(f"gateways.a.serviceAccount.name={self.contract['gateway']['serviceAccountName']}")
        docs = render(("gateway-and-inference-enabled.yaml",), set_values=overrides)
        for role, suffix in (("api", "-api"), ("worker", "-worker"), ("gateway", "-gateway-a")):
            pod = find(docs, "Deployment", suffix)["spec"]["template"]["spec"]
            self.assertEqual(pod["serviceAccountName"], self.contract[role]["serviceAccountName"])

    def test_contract_has_no_unreviewed_fields(self):
        """Fails if a re-pinned contract adds fields the chart does not yet assert."""
        self.assertEqual(set(self.contract), {"status", "api", "worker", "gateway"})
        for role in ("api", "worker", "gateway"):
            self.assertEqual(set(self.contract[role]), {
                "imageTarget", "configurationPrefix", "port", "serviceAccountName",
                "automountServiceAccountToken", "requests", "livenessPath", "readinessPath",
            })


if __name__ == "__main__":
    unittest.main()
