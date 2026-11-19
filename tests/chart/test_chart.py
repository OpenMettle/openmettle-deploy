"""Policy tests over `helm template` output for charts/openmettle-core (V1-32 I1, render contract).

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
CONTRACT = ROOT / "tests" / "fixtures" / "core-5cd8a9d" / "process-contract.json"
HELM = os.environ.get("HELM", "helm")
RELEASE = "openmettle"

# Values sets rendered by every policy test: overlays applied on top of minimal.yaml.
MATRIX = {
    "minimal": (),
    "all-keys": ("all-keys.yaml",),
    "migration-disabled": ("migration-disabled.yaml",),
}
PREFIX = {"api": "OPENMETTLE_API_", "worker": "OPENMETTLE_WORKER_", "migrate": "OPENMETTLE_MIGRATE_"}
PORT = {"api": 8080, "worker": 8081}
ALLOWED_KINDS = {"Deployment", "Service", "ServiceAccount", "Job"}
ALLOWED_RESOURCES = {"cpu", "memory", "ephemeral-storage"}
IMAGE = re.compile(r"^(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
HOOK = "helm.sh/hook"
HOOK_DELETE = "helm.sh/hook-delete-policy"
SCHEMA_ERROR = "values don't meet the specifications of the schema"
DIGEST = "sha256:" + "0" * 64
# Expected rendered env for minimal.yaml with chart defaults. These literals were copied by hand
# from core src/lib.rs and src/migrate.rs at 5cd8a9d; this test does not read core.
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
            self.assertNotIn("fsGroup", context, "fsGroup is only for storage (I4)")

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

    def test_no_token_and_no_service_links(self):
        """Fails if a pod omits automountServiceAccountToken: false or enableServiceLinks: false."""
        for _, _, pod in self.each_pod():
            self.assertIs(pod.get("automountServiceAccountToken"), False)
            self.assertIs(pod.get("enableServiceLinks"), False)

    def test_environment_is_explicit_and_prefixed(self):
        """Fails on envFrom, an env name outside the component's own prefix, or a literal DATABASE_URL."""
        for _, role, pod in self.each_pod():
            for container in containers(pod):
                self.assertNotIn("envFrom", container)
                env = container.get("env", [])
                self.assertTrue(env)
                for entry in env:
                    self.assertTrue(entry["name"].startswith(PREFIX[role]), entry["name"])
                url = env_map(container)[PREFIX[role] + "DATABASE_URL"]
                self.assertNotIn("value", url)
                self.assertEqual(set(url["valueFrom"]), {"secretKeyRef"})
                self.assertEqual(set(url["valueFrom"]["secretKeyRef"]), {"name", "key"})

    def test_bind_is_explicit(self):
        """Fails if BIND is removed (core would default to loopback) or set to the wrong port."""
        for _, role, pod in self.each_pod():
            if role == "migrate":
                continue
            env = env_map(pod["containers"][0])
            self.assertEqual(env[PREFIX[role] + "BIND"].get("value"), f"0.0.0.0:{PORT[role]}")

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
        """Fails if a component's Deployment, Service, ServiceAccount or Job is dropped or duplicated."""
        names = sorted((d["kind"], d["metadata"]["name"]) for d in self.renders["minimal"])
        full = f"{RELEASE}-openmettle-core"
        self.assertEqual(names, sorted([
            ("Deployment", f"{full}-api"), ("Deployment", f"{full}-worker"), ("Service", f"{full}-api"),
            ("ServiceAccount", f"{full}-api"), ("ServiceAccount", f"{full}-worker"),
            ("ServiceAccount", f"{full}-migrate"), ("Job", f"{full}-migrate"),
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
                    ref = env_map(pod["containers"][0])[PREFIX[role] + "DATABASE_URL"]["valueFrom"]["secretKeyRef"]
                    expected = {"api": "openmettle-api-database", "worker": "openmettle-worker-database",
                                "migrate": "openmettle-owner-database"}[role]
                    self.assertEqual(ref["name"], expected)
                rendered = yaml.safe_dump_all(d for d in docs if d["kind"] != "Job")
                self.assertNotIn("openmettle-owner-database", rendered)

    def test_values_reach_the_environment(self):
        """Fails if a settings value or Secret key is not plumbed into the matching env var."""
        docs = self.renders["all-keys"]
        expected = {
            "api": {"DB_MAX_CONNECTIONS": "6", "DB_TIMEOUT_MS": "2500", "SHUTDOWN_TIMEOUT_MS": "8000"},
            "worker": {"DB_MAX_CONNECTIONS": "2", "DB_TIMEOUT_MS": "1000", "SHUTDOWN_TIMEOUT_MS": "3000"},
            "migrate": {"CONNECT_TIMEOUT_MS": "10000", "LOCK_TIMEOUT_MS": "30000", "STATEMENT_TIMEOUT_MS": "600000"},
        }
        keys = {"api": "api-url", "worker": "worker-url", "migrate": "owner-url"}
        for role, pod in pods(docs):
            env = env_map(pod["containers"][0])
            for key, value in expected[role].items():
                self.assertEqual(env[PREFIX[role] + key]["value"], value)
            self.assertEqual(env[PREFIX[role] + "DATABASE_URL"]["valueFrom"]["secretKeyRef"]["key"], keys[role])

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
        """Fails if disabling migration still renders the Job, its ServiceAccount or requires its inputs."""
        docs = self.renders["migration-disabled"]
        self.assertFalse([d for d in docs if component(d) == "migrate"])
        self.assertEqual({d["kind"] for d in docs}, {"Deployment", "Service", "ServiceAccount"})


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
        ("api.service.port", 1, 65535, []),
        ("migration.settings.connectTimeoutMs", 1, 60000, MIGRATION_ROOM),
        ("migration.settings.lockTimeoutMs", 1, 600000, MIGRATION_ROOM),
        ("migration.settings.statementTimeoutMs", 1, 3600000, MIGRATION_ROOM),
        ("migration.activeDeadlineSeconds", 1, None, [f"migration.settings.{key}=1" for key in
                                                     ("connectTimeoutMs", "lockTimeoutMs", "statementTimeoutMs")]),
    ]

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
        """Fails if a ServiceAccount, pull Secret, Secret name or Secret key is emitted unquoted."""
        accounts = sorted(d["metadata"]["name"] for d in self.docs if d["kind"] == "ServiceAccount")
        self.assertEqual(accounts, ["555", "null"])
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


class ContractDriftTest(unittest.TestCase):
    """Chart defaults against core runtime/process-contract.json at the pinned commit (tests/fixtures)."""

    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.docs = render()

    def test_defaults_match_process_contract(self):
        """Fails if a port, probe path, request or automount default diverges from the core contract."""
        for role in ("api", "worker"):
            expected = self.contract[role]
            with self.subTest(component=role):
                pod = find(self.docs, "Deployment", f"-{role}")["spec"]["template"]["spec"]
                container = pod["containers"][0]
                self.assertEqual(container["name"], expected["imageTarget"])
                self.assertEqual([p["containerPort"] for p in container["ports"]], [expected["port"]])
                self.assertEqual(container["livenessProbe"]["httpGet"]["path"], expected["livenessPath"])
                self.assertEqual(container["readinessProbe"]["httpGet"]["path"], expected["readinessPath"])
                self.assertEqual(container["resources"]["requests"], expected["requests"])
                self.assertIs(pod["automountServiceAccountToken"], expected["automountServiceAccountToken"])
                account = find(self.docs, "ServiceAccount", f"-{role}")
                self.assertIs(account["automountServiceAccountToken"], expected["automountServiceAccountToken"])
                self.assertTrue(all(e["name"].startswith(expected["configurationPrefix"]) for e in container["env"]))

    def test_contract_service_account_names_are_accepted(self):
        """Fails if serviceAccount.name stops overriding the generated name (contract names are opt-in)."""
        overrides = [f"{role}.serviceAccount.name={self.contract[role]['serviceAccountName']}" for role in ("api", "worker")]
        docs = render(set_values=overrides)
        for role in ("api", "worker"):
            pod = find(docs, "Deployment", f"-{role}")["spec"]["template"]["spec"]
            self.assertEqual(pod["serviceAccountName"], self.contract[role]["serviceAccountName"])

    def test_contract_has_no_unreviewed_fields(self):
        """Fails if a re-pinned contract adds fields the chart does not yet assert."""
        self.assertEqual(set(self.contract), {"status", "api", "worker"})
        for role in ("api", "worker"):
            self.assertEqual(set(self.contract[role]), {
                "imageTarget", "configurationPrefix", "port", "serviceAccountName",
                "automountServiceAccountToken", "requests", "livenessPath", "readinessPath",
            })


if __name__ == "__main__":
    unittest.main()
