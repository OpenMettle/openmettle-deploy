#!/usr/bin/env python3
"""Install the openmettle-core chart on an ephemeral kind cluster (V1-32 / V1-06 / V1-28 / V1-30 smoke test).

Test harness only; not an installer. It builds core's api, worker, migrate, gateway and admin images
from a pinned core checkout, loads them into a uniquely named kind cluster classified `dev` and
installs the chart by image digest with a synthetic PostgreSQL fixture. It then checks:
migration hook (through migration 45, including migrations 19/20/37 and 38–45 role boundaries and
fresh-install quota/storage markers), readiness, worker scaling, an idempotent upgrade, an
enabled-profile upgrade (API replicas=2, PodDisruptionBudget, artifact PVC, ADR 0024 JSON/debug
structured logs, API-only auth + /v1/* mounts and session issuance credential, and a live
/v1/artifacts upload, idempotent retry, revision and byte-range download round trip across both API
replicas on the PVC), queued-run SSE replay, API pod replacement and worker expiry through HTTPS
ingress, live end-to-end turn execution through `openmettle-gateway` and `worker.inference` (both
plain-HTTP in-cluster under NetworkPolicy and fronted by the Traefik TLS terminator with
`worker.inference.caBundle` and `ingressFrom` enforcement, verified against a synthetic SGLang
stand-in and settled PostgreSQL usage/quota rows), opt-in `vault` RAM-staged `0400` keys on `api`
and `worker` only plus opt-in `backup` CronJob manual capture and offline `openmettle-admin backup
verify`, uninstall (with chart-owned PVC preservation), absence of optional packages, Pod Security
`restricted` enforcement and NetworkPolicy enforcement. Every assertion reads live cluster, Helm,
HTTP or database state. Core's process-contract assertions are not repeated (core tests/kubernetes).

Safety guards, tool and image pins are imported from core tests/kubernetes/qualify.py at
CORE_COMMIT; see tests/kind/README.md. Requires Python 3.10+, docker, the pinned kind and
kubectl (core install-tools.sh) and the pinned Helm (tests/chart/install-tools.sh).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
import queue
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import closing, contextmanager
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
ROLES = ("api", "worker", "migrate", "gateway", "admin")
DEFAULT_ROLES = ("api", "worker", "migrate")
WORKLOADS = ("api", "worker")
# RFC 6761 reserves .invalid: the name never resolves. Images are never pulled (pullPolicy Never);
# the node's containerd resolves the digest reference locally (see README "Image digests").
REGISTRY = "openmettle-smoke.invalid"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SECRET = {"api": "openmettle-api-database", "worker": "openmettle-worker-database",
          "migrate": "openmettle-owner-database", "issuance": "openmettle-issuance-database",
          "gateway": "openmettle-gateway-database"}
DB_ROLE = {"api": "openmettle_api", "worker": "openmettle_worker", "migrate": "openmettle_owner",
           "issuance": "openmettle_issuance", "gateway": "openmettle_gateway"}
# Every PostgreSQL login the fixture provisions: api, worker, owner (migrate), session issuance
# (core ADR 0030, migration 18) and gateway proxy (core ADR 0044, migrations 23 and 37).
DB_LOGINS = ("api", "worker", "migrate", "issuance", "gateway")
REQUIRED_MIGRATION = 45
RUNTIME_DB_ROLES = ("openmettle_api", "openmettle_worker", "openmettle_gateway", "openmettle_issuance")
RUN_DISPATCH_LOCK = "openmettle.run_dispatch_lock"
GATEWAY_SETTLE_FN = (
    "openmettle.gateway_settle_report("
    "uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text)"
)
# Migrations 38–45 role boundaries (core ADRs 0039, 0041, 0045, 0046; verified against core src/boundaries.sql):
# - 0039: runtime_feature_gates SELECT only for api/worker; zero writes; zero access for gateway/issuance.
# - 0041/0042: restore_reconciliation_gate SELECT for worker only; restore_gate_lock_open*() EXECUTE for
#   api/worker only; zero table/column privileges on deletion_journal, deletion_journal_head and
#   retention_upgrade_baseline for all runtime roles.
# - 0043: external_connections column-scoped non-secret SELECT for api (secret/refresh columns denied);
#   table SELECT + refresh UPDATE for worker (no INSERT/DELETE); external_connection_shares SELECT for
#   api/worker (no DELETE for api, no writes for worker); zero privileges for gateway/issuance.
# - 0045: zero table/column privileges on backup_maintenance_gate, backup_runs and backup_rpo_telemetry_state
#   for all runtime roles; SECURITY DEFINER helpers backup_maintenance_{is_active,lock_open}() EXECUTE for
#   api/worker only; backup_observe_telemetry() EXECUTE for worker only; owner maintenance/capture functions
#   denied for all runtime roles.
MIGRATION_38_45_CHECKS = (
    # Migration 39: runtime_feature_gates
    ("has_table_privilege('openmettle_api', 'openmettle.runtime_feature_gates', 'SELECT')", True),
    ("has_table_privilege('openmettle_worker', 'openmettle.runtime_feature_gates', 'SELECT')", True),
    *((f"has_table_privilege('{role}', 'openmettle.runtime_feature_gates', '{priv}')", False)
      for role in ("openmettle_api", "openmettle_worker")
      for priv in ("INSERT", "UPDATE", "DELETE")),
    *((f"has_table_privilege('{role}', 'openmettle.runtime_feature_gates', '{priv}')", False)
      for role in ("openmettle_gateway", "openmettle_issuance")
      for priv in ("SELECT", "INSERT", "UPDATE", "DELETE")),
    # Migration 40: API capacity visibility & two-phase dispatch fencing (V1-18 / ADR 0042)
    ("has_table_privilege('openmettle_api', 'openmettle.capacity_profiles', 'SELECT')", True),
    ("has_any_column_privilege('openmettle_api', 'openmettle.capacity_grants', 'SELECT')", False),
    ("has_function_privilege('openmettle_api', 'openmettle.capacity_group_observations()', 'EXECUTE')", True),
    *((f"has_function_privilege('{role}', 'openmettle.capacity_group_observations()', 'EXECUTE')", False)
      for role in ("openmettle_worker", "openmettle_gateway", "openmettle_issuance")),
    ("has_function_privilege('openmettle_worker', 'openmettle.capacity_confirm_dispatch(uuid,bytea,bigint,uuid)', 'EXECUTE')", True),
    *((f"has_function_privilege('{role}', 'openmettle.capacity_confirm_dispatch(uuid,bytea,bigint,uuid)', 'EXECUTE')", False)
      for role in ("openmettle_api", "openmettle_gateway", "openmettle_issuance")),
    # Migrations 41–42: restore_reconciliation_gate & deletion journal / baseline tables
    ("has_table_privilege('openmettle_worker', 'openmettle.restore_reconciliation_gate', 'SELECT')", True),
    ("has_table_privilege('openmettle_worker', 'openmettle.restore_reconciliation_gate', 'UPDATE')", False),
    *((f"has_any_column_privilege('{role}', 'openmettle.restore_reconciliation_gate', 'SELECT')", False)
      for role in ("openmettle_api", "openmettle_gateway", "openmettle_issuance")),
    ("has_function_privilege('openmettle_api', 'openmettle.restore_gate_lock_open()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_worker', 'openmettle.restore_gate_lock_open()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_gateway', 'openmettle.restore_gate_lock_open()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_issuance', 'openmettle.restore_gate_lock_open()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_api', 'openmettle.restore_gate_lock_open_generation()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_worker', 'openmettle.restore_gate_lock_open_generation()', 'EXECUTE')", True),
    *((f"has_any_column_privilege('{role}', '{table}', '{priv}')", False)
      for table in ("openmettle.deletion_journal", "openmettle.deletion_journal_head",
                    "openmettle.retention_upgrade_baseline")
      for role in RUNTIME_DB_ROLES
      for priv in ("SELECT", "INSERT", "UPDATE")),
    *((f"has_table_privilege('{role}', '{table}', 'DELETE')", False)
      for table in ("openmettle.deletion_journal", "openmettle.deletion_journal_head",
                    "openmettle.retention_upgrade_baseline")
      for role in RUNTIME_DB_ROLES),
    # Migration 43: external_connections & external_connection_shares (V1-28 / ADR 0045)
    ("has_table_privilege('openmettle_api', 'openmettle.external_connections', 'SELECT')", False),
    ("has_column_privilege('openmettle_api', 'openmettle.external_connections', 'id', 'SELECT')", True),
    ("has_column_privilege('openmettle_api', 'openmettle.external_connections', 'state', 'SELECT')", True),
    *((f"has_column_privilege('openmettle_api', 'openmettle.external_connections', '{col}', 'SELECT')", False)
      for col in ("encryption_key_id", "access_salt", "access_nonce", "access_ciphertext",
                  "refresh_salt", "refresh_nonce", "refresh_ciphertext",
                  "refresh_claim_token", "refresh_lease_until")),
    ("has_table_privilege('openmettle_api', 'openmettle.external_connections', 'DELETE')", False),
    ("has_table_privilege('openmettle_worker', 'openmettle.external_connections', 'SELECT')", True),
    *((f"has_column_privilege('openmettle_worker', 'openmettle.external_connections', '{col}', 'UPDATE')", True)
      for col in ("refresh_salt", "refresh_nonce", "refresh_ciphertext",
                  "refresh_claim_token", "refresh_lease_until")),
    ("has_table_privilege('openmettle_worker', 'openmettle.external_connections', 'INSERT')", False),
    ("has_table_privilege('openmettle_worker', 'openmettle.external_connections', 'DELETE')", False),
    ("has_table_privilege('openmettle_api', 'openmettle.external_connection_shares', 'SELECT')", True),
    ("has_table_privilege('openmettle_api', 'openmettle.external_connection_shares', 'DELETE')", False),
    ("has_table_privilege('openmettle_worker', 'openmettle.external_connection_shares', 'SELECT')", True),
    ("has_table_privilege('openmettle_worker', 'openmettle.external_connection_shares', 'INSERT')", False),
    ("has_table_privilege('openmettle_worker', 'openmettle.external_connection_shares', 'UPDATE')", False),
    *((f"has_any_column_privilege('{role}', '{table}', '{priv}')", False)
      for table in ("openmettle.external_connections", "openmettle.external_connection_shares")
      for role in ("openmettle_gateway", "openmettle_issuance")
      for priv in ("SELECT", "INSERT", "UPDATE")),
    *((f"has_table_privilege('{role}', '{table}', 'DELETE')", False)
      for table in ("openmettle.external_connections", "openmettle.external_connection_shares")
      for role in ("openmettle_gateway", "openmettle_issuance")),
    # Migration 44: declare-lost artifact payloads (owner-only mutation, runtime read-only lost_at)
    ("has_column_privilege('openmettle_api', 'openmettle.artifact_revisions', 'lost_at', 'SELECT')", True),
    ("has_column_privilege('openmettle_worker', 'openmettle.artifact_revisions', 'lost_at', 'SELECT')", True),
    *((f"has_column_privilege('{role}', 'openmettle.artifact_revisions', 'lost_at', 'UPDATE')", False)
      for role in RUNTIME_DB_ROLES),
    *((f"has_function_privilege('{role}', 'openmettle.storage_declare_payload_lost(uuid,uuid,text,text)', 'EXECUTE')", False)
      for role in RUNTIME_DB_ROLES),
    # Migration 45: backup tables (zero runtime table/column grants) & SECURITY DEFINER functions (V1-30 / ADR 0046)
    *((f"has_any_column_privilege('{role}', '{table}', '{priv}')", False)
      for table in ("openmettle.backup_maintenance_gate", "openmettle.backup_runs",
                    "openmettle.backup_rpo_telemetry_state")
      for role in RUNTIME_DB_ROLES
      for priv in ("SELECT", "INSERT", "UPDATE")),
    *((f"has_table_privilege('{role}', '{table}', 'DELETE')", False)
      for table in ("openmettle.backup_maintenance_gate", "openmettle.backup_runs",
                    "openmettle.backup_rpo_telemetry_state")
      for role in RUNTIME_DB_ROLES),
    ("has_function_privilege('openmettle_api', 'openmettle.backup_maintenance_is_active()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_worker', 'openmettle.backup_maintenance_is_active()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_gateway', 'openmettle.backup_maintenance_is_active()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_issuance', 'openmettle.backup_maintenance_is_active()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_api', 'openmettle.backup_maintenance_lock_open()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_worker', 'openmettle.backup_maintenance_lock_open()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_gateway', 'openmettle.backup_maintenance_lock_open()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_issuance', 'openmettle.backup_maintenance_lock_open()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_worker', 'openmettle.backup_observe_telemetry()', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_api', 'openmettle.backup_observe_telemetry()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_gateway', 'openmettle.backup_observe_telemetry()', 'EXECUTE')", False),
    ("has_function_privilege('openmettle_issuance', 'openmettle.backup_observe_telemetry()', 'EXECUTE')", False),
    *((f"has_function_privilege('{role}', '{fn}', 'EXECUTE')", False)
      for fn in ("openmettle.backup_enter_maintenance(uuid,text,text)",
                 "openmettle.backup_start_capture(uuid,text,text,text,integer)")
      for role in RUNTIME_DB_ROLES),
)
# Migration 37 gateway boundaries (core ADR 0044 increment 6): openmettle_gateway has EXECUTE on
# gateway_dispatch, gateway_dispatch_scoped and gateway_settle_report, zero table privileges on
# openmettle.*, and the superseded ADR 0037 provisioning tables are gone.
GATEWAY_SCHEMA_CHECKS = (
    ("has_function_privilege('openmettle_gateway', 'openmettle.gateway_dispatch(uuid,bytea)', 'EXECUTE')", True),
    ("has_function_privilege('openmettle_gateway', 'openmettle.gateway_dispatch_scoped(uuid,bytea)', 'EXECUTE')", True),
    (f"has_function_privilege('openmettle_gateway', '{GATEWAY_SETTLE_FN}', 'EXECUTE')", True),
    ("has_table_privilege('openmettle_gateway', 'openmettle.gateway_usage_reports', 'SELECT')", False),
    ("has_table_privilege('openmettle_gateway', 'openmettle.gateway_usage_reports', 'INSERT')", False),
    ("has_table_privilege('openmettle_gateway', 'openmettle.gateway_requests', 'SELECT')", False),
    ("has_table_privilege('openmettle_gateway', 'openmettle.gateway_requests', 'INSERT')", False),
    ("has_table_privilege('openmettle_gateway', 'openmettle.gateway_requests', 'UPDATE')", False),
    ("(SELECT count(*) = 0 FROM pg_class cl JOIN pg_namespace ns ON ns.oid = cl.relnamespace"
     " WHERE ns.nspname = 'openmettle' AND cl.relkind IN ('r', 'p')"
     " AND (has_table_privilege('openmettle_gateway', cl.oid, 'SELECT')"
     " OR has_table_privilege('openmettle_gateway', cl.oid, 'INSERT')"
     " OR has_table_privilege('openmettle_gateway', cl.oid, 'UPDATE')"
     " OR has_table_privilege('openmettle_gateway', cl.oid, 'DELETE')"
     " OR has_table_privilege('openmettle_gateway', cl.oid, 'TRUNCATE')"
     " OR has_table_privilege('openmettle_gateway', cl.oid, 'REFERENCES')"
     " OR has_table_privilege('openmettle_gateway', cl.oid, 'TRIGGER')"
     " OR has_table_privilege('openmettle_gateway', cl.oid, 'MAINTAIN')"
     " OR has_any_column_privilege('openmettle_gateway', cl.oid, 'SELECT')"
     " OR has_any_column_privilege('openmettle_gateway', cl.oid, 'INSERT')"
     " OR has_any_column_privilege('openmettle_gateway', cl.oid, 'UPDATE')"
     " OR has_any_column_privilege('openmettle_gateway', cl.oid, 'REFERENCES')))", True),
    ("to_regclass('openmettle.gateway_bindings') IS NULL", True),
    ("to_regclass('openmettle.gateway_generations') IS NULL", True),
    ("to_regclass('openmettle.gateway_policy') IS NULL", True),
    ("to_regclass('openmettle.gateway_audit') IS NULL", True),
    ("to_regclass('openmettle.gateway_intents') IS NULL", True),
    ("to_regclass('openmettle.gateway_nonces') IS NULL", True),
)
# Migration 19 role boundaries, read live as the fixture superuser: each expression and its expected
# value. The worker locks the singleton dispatch row through an inert column and records claims; the
# API writes the admission decision with the run and never sees the dispatch lock.
RUN_ADMISSION_CHECKS = (
    (f"(SELECT count(*) = 1 AND bool_and(id AND NOT lock_guard) FROM {RUN_DISPATCH_LOCK})", True),
    (f"has_table_privilege('openmettle_worker', '{RUN_DISPATCH_LOCK}', 'SELECT')", True),
    (f"has_column_privilege('openmettle_worker', '{RUN_DISPATCH_LOCK}', 'lock_guard', 'UPDATE')", True),
    (f"has_table_privilege('openmettle_worker', '{RUN_DISPATCH_LOCK}', 'UPDATE')", False),
    ("has_column_privilege('openmettle_worker', 'openmettle.runs', 'claim_token', 'UPDATE')", True),
    ("has_column_privilege('openmettle_worker', 'openmettle.runs', 'claimed_at', 'UPDATE')", True),
    ("has_column_privilege('openmettle_worker', 'openmettle.runs', 'actor_approval_id', 'INSERT')", False),
    ("has_column_privilege('openmettle_api', 'openmettle.runs', 'actor_approval_id', 'INSERT')", True),
    ("has_column_privilege('openmettle_api', 'openmettle.runs', 'round_limit', 'INSERT')", True),
    ("has_column_privilege('openmettle_api', 'openmettle.runs', 'queue_expires_at', 'INSERT')", True),
    ("has_column_privilege('openmettle_api', 'openmettle.runs', 'claim_token', 'UPDATE')", False),
    # Migration 20 adds the worker lease and execution deadlines. The API may request cancellation.
    *((f"has_column_privilege('{role}', 'openmettle.runs', '{column}', 'UPDATE')",
       role == "openmettle_worker" or column == "cancel_reason")
      for role in ("openmettle_api", "openmettle_worker")
      for column in ("lease_expires_at", "execution_expires_at", "cancel_reason")),
    (f"has_any_column_privilege('openmettle_api', '{RUN_DISPATCH_LOCK}', 'SELECT')", False),
    (f"has_any_column_privilege('openmettle_api', '{RUN_DISPATCH_LOCK}', 'UPDATE')", False),
)
# Migrations 24 and 26 applied to an empty database (openmettle-migrate's bootstrap_from_zero): metering
# and override enforcement start active, and the API may pin the still-unpinned artifact store (core ADR
# 0040). An upgraded database reads f|f here until an operator activates it.
FRESH_BOOTSTRAP_SQL = (
    "SELECT metering_enforced AND metering_enforced_at IS NOT NULL AND overrides_enforced"
    " AND overrides_enforced_at IS NOT NULL, bootstrap_auto_pin_allowed AND volume_id IS NULL"
    " FROM openmettle.quota_enforcement CROSS JOIN openmettle.storage_volume_control;")
# The four /v1 quota operations (core ADR 0040, V1-17). Mounted, a request without a session is 401 before
# any path, key or body check; unmounted, every /v1 path is 404. The identifier is synthetic.
QUOTA_SCOPE = "00000000-0000-4000-8000-00000000b001"
QUOTA_ROUTES = (
    ("GET", "/v1/quotas/personal"),
    ("GET", f"/v1/projects/{QUOTA_SCOPE}/quotas"),
    ("PUT", f"/v1/admin/scopes/{QUOTA_SCOPE}/quotas/usage_tokens"),
    ("POST", f"/v1/admin/scopes/{QUOTA_SCOPE}/quotas/usage_tokens/revoke"),
)
ISSUANCE_URL_ENV = "OPENMETTLE_API_ISSUANCE_DATABASE_URL"
ISSUANCE_POOL_ENV = "OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS"
ISSUANCE_POOL = "2"  # chart default api.settings.issuanceDbMaxConnections
HELM_TIMEOUT = "300s"  # >= migration.activeDeadlineSeconds below
MIGRATION_DEADLINE_SECONDS = 120
OPTIONAL_KINDS = "ingresses,persistentvolumeclaims,poddisruptionbudgets,resourceclaims,horizontalpodautoscalers,cronjobs"
RELEASE_KINDS = "ingresses,deployments,replicasets,pods,services,serviceaccounts,jobs,cronjobs,configmaps,secrets,networkpolicies,poddisruptionbudgets"
INVENTORY_KINDS = "deployments,services,serviceaccounts,jobs,configmaps,secrets,networkpolicies"
API_PDB = f"{FULLNAME}-api"
ARTIFACTS_CLAIM = f"{FULLNAME}-artifacts"
ARTIFACTS_MOUNT_PATH = "/var/lib/openmettle/artifacts"
# Created by core's artifact_fs::Store::open at startup when ARTIFACTS_DIR is set (core ADR 0031).
ARTIFACT_SUBDIRS = ("staging", "revisions")
AUTH_CONFIG_MAP = "openmettle-smoke-auth-config"
AUTH_LOGIN_KEYS_SECRET = "openmettle-smoke-auth-login-keys"
AUTH_CONFIG_DIR = "/etc/openmettle/auth"
AUTH_CONFIG_PATH = f"{AUTH_CONFIG_DIR}/auth.json"
# The model catalog, a second key of the auth ConfigMap projected beside auth.json (auth.catalogKey).
AUTH_CATALOG_KEY = "catalog.json"
AUTH_CATALOG_PATH = f"{AUTH_CONFIG_DIR}/{AUTH_CATALOG_KEY}"
# Core's synthetic catalog fixture, read from the pinned checkout. Admission estimates the prompt from the
# selected model's prompt_bound, which the fixture omits; the bound below is the one core's own HTTP tests
# add (tests/schema/branches_http.rs and authz_http.rs). The preset `study` selects model `a`.
CORE_CATALOG_FIXTURE = "tests/fixtures/conversation-catalog-v1.json"
CATALOG_PRESET = "study"
CATALOG_MODEL = "a"
PROMPT_BOUND = {"fixed_tokens": 4, "tokens_per_turn": 4, "tokens_per_part": 2, "tokens_per_byte": 1,
                "tokens_per_attachment": 10}
# auth.json admission_limits (core README "Model catalog and run admission limits"). Check 11's fixture
# caller passes its own limits to core's store and is unaffected.
ADMISSION_LIMITS = {"live_per_actor": 4, "live_per_scope": 8, "queued_in_instance": 32,
                    "queue_timeout_seconds": 300, "round_cap": 10}
HTTP_RUN_KEYS = {"conversation": "kind-smoke-conversation", "run": "kind-smoke-http-run",
                 "cancel": "kind-smoke-http-cancel"}
AUTH_KEYS_DIR = "/etc/openmettle/auth-keys"
AUTH_ACTIVE_KEY_PATH = f"{AUTH_KEYS_DIR}/active.key"
AUTH_CA_DIR = "/etc/openmettle/auth-ca"
AUTH_SECRET_MODE = 288  # 0440 octal
AUTH_OIDC_CIDR = "192.0.2.20/32"  # RFC 5737 TEST-NET-1 synthetic OIDC egress peer
AUTH_CHECK_BINARY = "/usr/local/bin/openmettle-api"
AUTH_CHECK_OK = "auth configuration valid (local files only)\n"
MOUNTED_AUTH_HTTP = {"/auth/session": 403, "/auth/native/session": 403, "/v1/capabilities": 401}
AUTH_ROUTE_PATHS = tuple(MOUNTED_AUTH_HTTP)
INGRESS_HOST = "app.example.test"
AUTH_ORIGIN = f"https://{INGRESS_HOST}"  # the synthetic browser origin; /v1 cookie requests send it
# A synthetic browser session seeded in the fixture database as core's issuance stores it (core
# sessions.rs and tests/schema/authz_runs.rs seeded_session), so /v1 runs without an OIDC provider.
# The login provider is distinct from the auth document's: session validation reads only the database.
SESSION_COOKIE = "__Host-openmettle-session"
SESSION_DOMAIN = b"openmettle/session-secret/1\0"
SESSION_EXPIRES_MS = 4102444800000  # 2100-01-01
SESSION_ISSUER = "https://kind-smoke.example.test"
SESSION_CLIENT = "kind-smoke"
SESSION_IDS = {"provider": "00000000-0000-4000-8000-00000000a001", "user": "00000000-0000-4000-8000-00000000a002",
               "identity": "00000000-0000-4000-8000-00000000a003", "approval": "00000000-0000-4000-8000-00000000a004"}
# Uploads need configured storage limits (else 503 provisioning); max_bytes bounds each reservation.
STORAGE_LIMIT_BYTES = 1 << 20
# A fresh install enforces metering, so run admission needs a personal usage_tokens limit (core ADR 0040).
PERSONAL_TOKEN_LIMIT = 1_000_000
ARTIFACT_MAX_BYTES = 1024
ARTIFACT_FILENAME = "smoke.txt"
ARTIFACT_MEDIA_TYPE = "text/plain"
ARTIFACT_PAYLOADS = (b"openmettle-pvc-artifact-v1\n", b"openmettle-pvc-artifact-v2-0123456789")
ARTIFACT_BOUNDARIES = ("openmettle-smoke-boundary-a", "openmettle-smoke-boundary-b")
ARTIFACT_RANGE = (0, 9)
UNSATISFIABLE_RANGE = "bytes=999999-"
V1_API_VERSION = "1.0"  # every /v1 response's OpenMettle-API-Version (core ADR 0007)
INGRESS_CLASS = "smoke-traefik"
TLS_SECRET = "smoke-ingress-tls"
RUN_KEY = "kind-ingress-replay"
QUEUE_TIMEOUT_SECONDS = 120
HTTP_TIMEOUT = 30
INGRESS_READY_TIMEOUT = 4  # Let Traefik return its 3s upstream dial timeout.
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
B64_ID = re.compile(r"[A-Za-z0-9_-]{43}")
PROFILE_ROLLOUT_TIMEOUT = "180s"
LOG_LEVELS = {"ERROR", "WARN", "INFO", "DEBUG"}
# Matches core src/telemetry.rs FIELDS plus tracing-subscriber flattened JSON metadata.
ALLOWED_LOG_FIELDS = {
    "timestamp", "level", "event", "role", "signal", "request_id",
    "http.route", "http.request.method", "http.response.status_code",
    "duration_us", "error.type", "schema_version", "dropped_lines", "dropped_spans",
    "dropped_metric_exports", "target_kind", "scope_kind", "resource_kind", "threshold_pct",
    "dedupe_bucket", "gateway.step", "gateway.request_id",
}
# ADR 0044 gateway + worker.inference live smoke fixtures.
STANDIN = "sglang-standin"
STANDIN_LABELS = {"app.kubernetes.io/name": STANDIN}
STANDIN_PORT = 30000
STANDIN_EXPECTED_PROMPT_TOKENS = 11
STANDIN_EXPECTED_COMPLETION_TOKENS = 7
STANDIN_EXPECTED_SETTLED_UNITS = STANDIN_EXPECTED_PROMPT_TOKENS + STANDIN_EXPECTED_COMPLETION_TOKENS
STANDIN_EXPECTED_CONTENT = "smoke-ok"
GATEWAY_NAME = "a"
GATEWAY_COMPONENT = f"gateway-{GATEWAY_NAME}"
GATEWAY_WORKLOAD = f"{FULLNAME}-{GATEWAY_COMPONENT}"
GATEWAY_INSTALLATION = "00000000-0000-4000-8000-0000000000e1"
GATEWAY_TLS_HOST = f"{INGRESS_CLASS}.{DB_NAMESPACE}.svc.cluster.local"
GATEWAY_TLS_SECRET = "smoke-gateway-tls"
GATEWAY_TLS_INGRESS = "smoke-gateway-tls"
INFERENCE_CONFIG_DIR = "/etc/openmettle/inference"
INFERENCE_CONFIG_PATH = f"{INFERENCE_CONFIG_DIR}/inference.json"
INFERENCE_CATALOG_PATH = f"{INFERENCE_CONFIG_DIR}/{AUTH_CATALOG_KEY}"
INFERENCE_CA_DIR = "/etc/openmettle/inference-ca"
INFERENCE_CA_PATH = f"{INFERENCE_CA_DIR}/ca.crt"
INFERENCE_PLAIN_CONFIG_MAP = "openmettle-smoke-inference-plain"
INFERENCE_TLS_CONFIG_MAP = "openmettle-smoke-inference-tls"
INFERENCE_CA_CONFIG_MAP = "openmettle-smoke-inference-ca"
CLUSTER_PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
CACHE_SALT = re.compile(r"[0-9a-f]{64}")
# ADR 0045 vault + ADR 0046 backup CronJob live smoke fixtures.
VAULT_KEYS_SECRET = "openmettle-smoke-vault-keys"
VAULT_KEY_ID = "vault-k1"
VAULT_KEY_FILE = "vault-k1.key"
VAULT_KEYS_DIR = "/etc/openmettle/vault-keys"
VAULT_CONFIG_PATH = f"{VAULT_KEYS_DIR}/keyring.json"
BACKUP_KEYS_SECRET = "openmettle-smoke-backup-keys"
BACKUP_KEY_ID = "backup-k1"
BACKUP_KEY_FILE = "backup-k1.key"
BACKUP_KEYS_DIR = "/etc/openmettle/backup-keys"
BACKUP_CONFIG_PATH = f"{BACKUP_KEYS_DIR}/keyring.json"
BACKUP_DEST_CLAIM = "openmettle-smoke-backup-dest"
BACKUP_DEST_DIR = "/var/backups/openmettle"
BACKUP_DESTINATION_DOMAIN = "kind-smoke.example.test"
BACKUP_OPERATOR_ID = "00000000-0000-4000-8000-00000000b046"
BACKUP_CRONJOB = f"{FULLNAME}-backup"
BACKUP_NETWORK_POLICY = f"{FULLNAME}-backup"
BACKUP_RUN_JOB = "openmettle-smoke-backup-run"
BACKUP_VERIFY_JOB = "openmettle-smoke-backup-verify"
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


def postgres_client_image_parts(image: str) -> dict:
    """Split a digest-pinned PostgreSQL image reference into chart {registry, repository, digest} fields."""
    name, sep, digest = image.partition("@")
    if not sep or not DIGEST.fullmatch(digest):
        raise SmokeFailure(f"POSTGRES_IMAGE must be digest-pinned, got {image!r}")
    if ":" in name.rsplit("/", 1)[-1]:
        name = name.rsplit(":", 1)[0]
    if not name:
        raise SmokeFailure(f"POSTGRES_IMAGE has no repository: {image!r}")
    if "/" not in name:
        registry, repository = "docker.io", f"library/{name}"
    else:
        first, rest = name.split("/", 1)
        if "." in first or ":" in first or first == "localhost":
            registry, repository = first, rest
        else:
            registry, repository = "docker.io", name
    return {"registry": registry, "repository": repository, "digest": digest}


def find_ctr_image_for_digest(output: str, digest: str, *, preferred: str | None = None) -> str:
    """Find a containerd image name in `ctr images ls` whose target digest equals `digest`."""
    rows = [line.split() for line in output.splitlines()[1:] if line.split()]
    matches = [fields[0] for fields in rows if len(fields) >= 3 and fields[2] == digest]
    if preferred and preferred in matches:
        return preferred
    if not matches:
        raise SmokeFailure(f"no containerd image found with digest {digest}")
    return sorted(matches)[0]


def smoke_values(digests: dict, worker_replicas: int, *, enabled_profile: bool = False,
                 gateway_mode: str | None = None, vault_and_backup: bool = False,
                 postgres_client_image: dict | None = None) -> dict:
    """Chart values for the smoke release. Shorter migration timeouts bound a hung hook."""
    if set(digests) != set(ROLES):
        raise SmokeFailure("a digest is required for each of api, worker, migrate, gateway and admin")
    for role in ROLES:
        digest_reference(role, digests[role])
    if worker_replicas not in (1, 2):
        raise SmokeFailure("worker replicas must be 1 or 2")
    if gateway_mode not in (None, "plain", "tls"):
        raise SmokeFailure(f"unexpected gateway_mode: {gateway_mode!r}")
    if gateway_mode is not None and not enabled_profile:
        raise SmokeFailure("gateway_mode requires enabled_profile=True")
    if vault_and_backup and (not enabled_profile or not postgres_client_image):
        raise SmokeFailure("vault_and_backup requires enabled_profile=True and postgres_client_image")
    values = {
        "images": {"pullPolicy": "Never", **{
            role: {"registry": REGISTRY, "repository": f"openmettle/{role}", "digest": digests[role]}
            for role in DEFAULT_ROLES}},
        "database": {role: {"existingSecret": SECRET[role]} for role in DEFAULT_ROLES},
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
        values["worker"]["sweepMs"] = 1000
        values["ingress"] = {"enabled": True, "className": INGRESS_CLASS, "hosts": [INGRESS_HOST],
                             "tls": [{"secretName": TLS_SECRET, "hosts": [INGRESS_HOST]}]}
        values["networkPolicy"]["api"]["ingressFrom"] = [database_namespace_peer({"app": INGRESS_CLASS})]
        values["telemetry"] = {"logging": {"format": "json", "level": "debug"}}
        values["storage"] = {
            "artifacts": {"enabled": True, "size": "64Mi", "accessModes": ["ReadWriteOnce"]},
        }
        values["auth"] = {
            "enabled": True,
            "configMapName": AUTH_CONFIG_MAP,
            "configKey": "auth.json",
            "catalogKey": AUTH_CATALOG_KEY,
            "loginKeysSecretName": AUTH_LOGIN_KEYS_SECRET,
        }
        values["networkPolicy"]["api"]["oidc"] = {
            "to": [{"ipBlock": {"cidr": AUTH_OIDC_CIDR}}],
            "port": 443,
        }
        values["database"]["issuance"] = {"existingSecret": SECRET["issuance"]}
    if gateway_mode is not None:
        values["images"]["gateway"] = {
            "registry": REGISTRY, "repository": "openmettle/gateway", "digest": digests["gateway"],
        }
        values["database"]["gateway"] = {"existingSecret": SECRET["gateway"]}
        values["worker"]["pollMs"] = 100
        inference = {
            "enabled": True,
            "configMapName": INFERENCE_PLAIN_CONFIG_MAP if gateway_mode == "plain" else INFERENCE_TLS_CONFIG_MAP,
            "configKey": "inference.json",
            "catalogKey": AUTH_CATALOG_KEY,
            "settings": {
                "runSlots": 2,
                "leaseMs": 30000,
                "executionTimeoutMs": 60000,
                "executingPerActor": 2,
                "executingPerScope": 4,
            },
        }
        if gateway_mode == "tls":
            inference["caBundle"] = {
                "enabled": True,
                "configMapName": INFERENCE_CA_CONFIG_MAP,
                "key": "ca.crt",
            }
        values["worker"]["inference"] = inference
        gateway_peer = {"podSelector": {"matchLabels": {
            "app.kubernetes.io/name": "openmettle-core",
            "app.kubernetes.io/instance": RELEASE,
            "app.kubernetes.io/component": GATEWAY_COMPONENT,
        }}}
        traefik_peer = database_namespace_peer({"app": INGRESS_CLASS})
        values["networkPolicy"]["worker"] = {
            "inference": {"to": [gateway_peer], "port": 8082} if gateway_mode == "plain"
            else {"to": [traefik_peer], "port": 8443},
        }
        gw_np: dict = {"upstream": {"to": [database_namespace_peer(STANDIN_LABELS)], "port": STANDIN_PORT}}
        if gateway_mode == "tls":
            gw_np["ingressFrom"] = [traefik_peer]
        values["gateways"] = {
            GATEWAY_NAME: {
                "model": CATALOG_MODEL,
                "upstreamUrl": f"http://{STANDIN}.{DB_NAMESPACE}.svc.cluster.local:{STANDIN_PORT}",
                "networkPolicy": gw_np,
            },
        }
    if vault_and_backup:
        values["images"]["admin"] = {
            "registry": REGISTRY, "repository": "openmettle/admin", "digest": digests["admin"],
        }
        values["images"]["postgresClient"] = dict(postgres_client_image)
        values["database"]["backup"] = {"existingSecret": SECRET["migrate"]}
        values["vault"] = {
            "enabled": True,
            "existingSecret": VAULT_KEYS_SECRET,
            "configKey": "keyring.json",
        }
        values["backup"] = {
            "enabled": True,
            "suspend": True,
            "schedule": "0 3 * * *",
            "existingKeysSecret": BACKUP_KEYS_SECRET,
            "keysConfigKey": "keyring.json",
            "destination": {
                "existingClaim": BACKUP_DEST_CLAIM,
                "domain": BACKUP_DESTINATION_DOMAIN,
                # Single-node kind local-path-provisioner backs every PVC from the same host root device.
                "requireSeparateDevice": False,
            },
            "operatorId": BACKUP_OPERATOR_ID,
            "reason": "kind smoke coordinated backup capture",
            "drainTimeoutSecs": 60,
            "activeDeadlineSeconds": 180,
            "releaseOnSuccess": True,
        }
    return values


def smoke_inference_document(catalog: dict, *, tls: bool) -> dict:
    """ADR 0043 worker inference document covering every model of `catalog`."""
    endpoint = (
        f"https://{GATEWAY_TLS_HOST}:8443/v1/chat/completions"
        if tls
        else f"http://{GATEWAY_WORKLOAD}.{APP_NAMESPACE}.svc.cluster.local:8082/v1/chat/completions"
    )
    routes = {}
    for model, profile in catalog["models"].items():
        route: dict = {
            "endpoint": endpoint,
            "private_cidrs": list(CLUSTER_PRIVATE_CIDRS),
            "pin": dict(profile["pin"]),
            "protocol": "chat_completions",
            "stream": False,
            "images": False,
            "usage": True,
            "setup_timeout_milliseconds": 5000,
            "idle_timeout_milliseconds": 45000,
            "overall_timeout_milliseconds": 50000,
        }
        if tls:
            route["trust"] = {"roots": "bundle", "bundle_path": INFERENCE_CA_PATH}
        routes[model] = route
    return {
        "version": 1,
        "catalog_file": INFERENCE_CATALOG_PATH,
        "installation": GATEWAY_INSTALLATION,
        "routes": routes,
    }


def gateway_tls_commands(ca_cert: Path, ca_key: Path, leaf_csr: Path, leaf_key: Path,
                         leaf_ext: Path, leaf_cert: Path) -> tuple:
    """OpenSSL commands and extfile body for a CA + signed leaf server cert accepted by rustls/webpki."""
    ext_body = (
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{GATEWAY_TLS_HOST}\n"
    )
    commands = (
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=openmettle-smoke-gateway-ca",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign",
         "-keyout", str(ca_key), "-out", str(ca_cert)],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-subj", f"/CN={GATEWAY_TLS_HOST}",
         "-keyout", str(leaf_key), "-out", str(leaf_csr)],
        ["openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
         "-CAcreateserial", "-days", "1", "-extfile", str(leaf_ext), "-out", str(leaf_cert)],
    )
    return ext_body, commands


def standin_manifests(image: str, run_id: str) -> dict:
    """Synthetic recorded SGLang upstream stand-in in DB_NAMESPACE (Pod Security restricted)."""
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    return {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": STANDIN, "namespace": DB_NAMESPACE, "labels": labels},
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                  "selector": {"matchLabels": STANDIN_LABELS},
                  "template": {"metadata": {"labels": STANDIN_LABELS}, "spec": {
                      "automountServiceAccountToken": False, "enableServiceLinks": False,
                      "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                          "seccompProfile": {"type": "RuntimeDefault"}},
                      "containers": [{
                          "name": STANDIN, "image": image, "imagePullPolicy": "Never",
                          "ports": [{"name": "http", "containerPort": STANDIN_PORT}],
                          "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"},
                                             "periodSeconds": 2, "failureThreshold": 3},
                          "securityContext": {"privileged": False, "allowPrivilegeEscalation": False,
                                              "readOnlyRootFilesystem": True,
                                              "capabilities": {"drop": ["ALL"]}},
                      }],
                  }}}},
        {"apiVersion": "v1", "kind": "Service",
         "metadata": {"name": STANDIN, "namespace": DB_NAMESPACE, "labels": labels},
         "spec": {"type": "ClusterIP", "selector": STANDIN_LABELS,
                  "ports": [{"name": "http", "port": STANDIN_PORT, "targetPort": "http"}]}},
    ]}


def inference_fixture_manifests(ca_pem: str, catalog: dict, run_id: str) -> dict:
    """Test-owned inference ConfigMaps (plain & TLS), CA ConfigMap and TLS gateway Ingress."""
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    catalog_json = json.dumps(catalog)
    return {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": INFERENCE_PLAIN_CONFIG_MAP, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"inference.json": json.dumps(smoke_inference_document(catalog, tls=False)),
                  AUTH_CATALOG_KEY: catalog_json}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": INFERENCE_TLS_CONFIG_MAP, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"inference.json": json.dumps(smoke_inference_document(catalog, tls=True)),
                  AUTH_CATALOG_KEY: catalog_json}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": INFERENCE_CA_CONFIG_MAP, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"ca.crt": ca_pem}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
         "metadata": {"name": GATEWAY_TLS_INGRESS, "namespace": APP_NAMESPACE, "labels": labels},
         "spec": {"ingressClassName": INGRESS_CLASS,
                  "tls": [{"secretName": GATEWAY_TLS_SECRET, "hosts": [GATEWAY_TLS_HOST]}],
                  "rules": [{"host": GATEWAY_TLS_HOST, "http": {"paths": [{
                      "path": "/", "pathType": "Prefix",
                      "backend": {"service": {"name": GATEWAY_WORKLOAD, "port": {"name": "http"}}},
                  }]}}]}},
    ]}


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
        "cursor_keys": {"active": {"id": "smoke-cursor", "path": f"{AUTH_KEYS_DIR}/cursor.key"},
                        "verify_only": []},
        # With cursor_keys, the two members fresh POST /v1/runs admission needs (else 503 provisioning).
        "catalog_file": AUTH_CATALOG_PATH,
        "admission_limits": dict(ADMISSION_LIMITS),
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
            "origin": AUTH_ORIGIN,
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


def smoke_catalog(fixture: dict) -> dict:
    """Core's catalog fixture with PROMPT_BOUND on the model that CATALOG_PRESET selects."""
    catalog = json.loads(json.dumps(fixture))
    try:
        model = catalog["models"][catalog["presets"][CATALOG_PRESET]["model"]]
    except (KeyError, TypeError) as exc:
        raise SmokeFailure(f"core catalog fixture lacks preset {CATALOG_PRESET!r} or its model") from exc
    if catalog["presets"][CATALOG_PRESET]["model"] != CATALOG_MODEL:
        raise SmokeFailure(f"core catalog preset {CATALOG_PRESET!r} no longer selects model {CATALOG_MODEL!r}")
    model["prompt_bound"] = dict(PROMPT_BOUND)
    return catalog


def database_namespace_peer(labels: dict) -> dict:
    """A NetworkPolicyPeer for pods with `labels` in the database namespace."""
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": DB_NAMESPACE}},
            "podSelector": {"matchLabels": dict(labels)}}


def database_url(role: str, password: str) -> str:
    host = f"postgres.{DB_NAMESPACE}.svc.cluster.local"
    return f"postgres://{DB_ROLE[role]}:{password}@{host}:5432/openmettle?sslmode=disable"


def fixture_manifests(postgres_image: str, passwords: dict, run_id: str, catalog: dict) -> dict:
    """Namespaces, a synthetic PostgreSQL fixture, the five URL Secrets the chart reads and the auth
    ConfigMap (auth document and `catalog`) and key Secret.

    passwords holds per-run random values for admin and each login in DB_LOGINS. Provisioning follows
    core README "Schema migrations": five login roles (owner, api, issuance, worker, gateway),
    created before migration 1, and one database owned by the owner role.
    """
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    sql = "".join(f"CREATE ROLE {DB_ROLE[role]} LOGIN PASSWORD '{passwords[role]}';\n"
                  for role in DB_LOGINS)
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
               "stringData": {"url": database_url(role, passwords[role])}} for role in DB_LOGINS]
    items += [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": AUTH_CONFIG_MAP, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"auth.json": json.dumps(smoke_auth_document()), AUTH_CATALOG_KEY: json.dumps(catalog)}},
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": AUTH_LOGIN_KEYS_SECRET, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"active.key": passwords["auth_login_key"], "cursor.key": passwords["auth_cursor_key"]}},
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
            variable = f"OPENMETTLE_{role.upper()}_ARTIFACTS_DIR"
            if {"name": variable, "value": ARTIFACTS_MOUNT_PATH} not in (container.get("env") or []):
                raise SmokeFailure(f"{role} container lacks {variable}={ARTIFACTS_MOUNT_PATH}")
            mounted_pods += 1
    return {"claim": name, "phase": phase, "mount_path": ARTIFACTS_MOUNT_PATH, "mounted_pods": mounted_pods}


def artifact_dirs_command() -> list:
    """stat(1) core's ADR 0031 subdirectories; the debian:bookworm-slim runtime image ships coreutils."""
    return ["stat", "--format=%n|%F|%a|%u", *(f"{ARTIFACTS_MOUNT_PATH}/{d}" for d in ARTIFACT_SUBDIRS)]


def evaluate_artifact_dirs(pod: str, output: str) -> None:
    """Require the staging and revisions directories that core's artifact_fs::Store::open creates at
    startup: real directories owned by UID 65532 with permission bits 0700. A set-group-ID bit that a
    volume's fsGroup handling may add is not a permission bit and is ignored."""
    expected = [f"{ARTIFACTS_MOUNT_PATH}/{d}" for d in ARTIFACT_SUBDIRS]
    rows = [line.split("|") for line in output.splitlines()]
    if [row[0] for row in rows] != expected or any(len(row) != 4 for row in rows):
        raise SmokeFailure(f"{pod}: unexpected artifact directory listing {output!r}")
    for path, kind, mode, uid in rows:
        if kind != "directory" or not re.fullmatch(r"[0-7]{3,4}", mode) or int(mode, 8) & 0o777 != 0o700 \
                or uid != "65532":
            raise SmokeFailure(f"{pod}: {path} is {kind} mode {mode} owner {uid}, "
                               f"expected a 0700 directory owned by 65532")


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
        if not any(v.get("name") == "auth-config"
                   and {"key": AUTH_CATALOG_KEY, "path": AUTH_CATALOG_KEY} in (v.get("configMap", {}).get("items") or [])
                   for v in volumes):
            raise SmokeFailure(f"api pod does not project the model catalog as {AUTH_CATALOG_KEY}")
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
    return {"api_pods": len(api_pods), "config_path": AUTH_CONFIG_PATH, "catalog_path": AUTH_CATALOG_PATH,
            "keys_dir": AUTH_KEYS_DIR, "secret_mode": AUTH_SECRET_MODE, "worker_isolated": True}


def check_issuance_env(pods_by_role: dict, hooks: str, *, enabled: bool) -> dict:
    """Core ADR 0030: the issuance URL (a required Secret reference) and pool size reach the api
    container exactly while auth is enabled, and never a worker pod or the migrate hook Job, whose
    processes exit 78 if they receive the URL. `hooks` is the release's `helm get hooks` manifest."""
    api_pods = pods_by_role.get("api") or []
    worker_pods = pods_by_role.get("worker") or []
    if not api_pods or not worker_pods:
        raise SmokeFailure("api and worker pods are required to verify issuance credential isolation")
    for pod in api_pods:
        container = next((c for c in pod.get("spec", {}).get("containers") or [] if c.get("name") == "api"), None)
        if container is None:
            raise SmokeFailure("api pod has no container named 'api'")
        env = {e.get("name"): e for e in container.get("env") or []}
        names = sorted(name for name in env if "ISSUANCE" in str(name))
        if not enabled:
            if names:
                raise SmokeFailure(f"api container receives {names} without auth")
            continue
        if names != sorted([ISSUANCE_URL_ENV, ISSUANCE_POOL_ENV]):
            raise SmokeFailure(f"api container issuance env is {names}")
        url = env[ISSUANCE_URL_ENV]
        ref = url.get("valueFrom", {}).get("secretKeyRef", {})
        if "value" in url or (ref.get("name"), ref.get("key")) != (SECRET["issuance"], "url") \
                or ref.get("optional", False) is not False:
            raise SmokeFailure(f"api {ISSUANCE_URL_ENV} is not a required reference to "
                               f"Secret {SECRET['issuance']} key url")
        if env[ISSUANCE_POOL_ENV].get("value") != ISSUANCE_POOL:
            raise SmokeFailure(f"api {ISSUANCE_POOL_ENV} is not {ISSUANCE_POOL}")
    for pod in worker_pods:
        spec = json.dumps(pod.get("spec", {}))
        if "ISSUANCE" in spec or SECRET["issuance"] in spec:
            raise SmokeFailure("worker pod must not receive the issuance credential")
    if "OPENMETTLE_MIGRATE_DATABASE_URL" not in hooks:
        raise SmokeFailure("release hooks do not contain the migrate Job")
    if "ISSUANCE" in hooks or SECRET["issuance"] in hooks:
        raise SmokeFailure("migrate hook Job must not receive the issuance credential")
    return {"api_pods": len(api_pods), "api_issuance_env": enabled,
            "issuance_pool": ISSUANCE_POOL if enabled else None,
            "worker_isolated": True, "migrate_isolated": True}


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


def run_admission_sql() -> str:
    return "SELECT " + ", ".join(expression for expression, _ in RUN_ADMISSION_CHECKS) + ";"


def evaluate_run_admission(output: str) -> dict:
    """Compare run_admission_sql()'s one psql -tA row with RUN_ADMISSION_CHECKS."""
    observed = output.strip().split("|")
    expected = ["t" if value else "f" for _, value in RUN_ADMISSION_CHECKS]
    if len(observed) != len(expected):
        raise SmokeFailure(f"migrations 19/20 privilege query returned {output.strip()!r}")
    wrong = [f"{expression} is {got!r}, expected {want!r}"
             for (expression, _), got, want in zip(RUN_ADMISSION_CHECKS, observed, expected) if got != want]
    if wrong:
        raise SmokeFailure("migrations 19/20 role boundary: " + "; ".join(wrong))
    return {"dispatch_lock_singleton": True, "privileges_checked": len(RUN_ADMISSION_CHECKS) - 1}


def gateway_schema_sql() -> str:
    return "SELECT " + ", ".join(expression for expression, _ in GATEWAY_SCHEMA_CHECKS) + ";"


def evaluate_gateway_schema(output: str) -> dict:
    """Compare gateway_schema_sql()'s one psql -tA row with GATEWAY_SCHEMA_CHECKS (migration 37)."""
    observed = output.strip().split("|")
    expected = ["t" if value else "f" for _, value in GATEWAY_SCHEMA_CHECKS]
    if len(observed) != len(expected):
        raise SmokeFailure(f"migration 37 gateway privilege query returned {output.strip()!r}")
    wrong = [f"{expression} is {got!r}, expected {want!r}"
             for (expression, _), got, want in zip(GATEWAY_SCHEMA_CHECKS, observed, expected) if got != want]
    if wrong:
        raise SmokeFailure("migration 37 gateway boundary: " + "; ".join(wrong))
    return {"gateway_function_only": True, "superseded_tables_absent": True,
            "checks": len(GATEWAY_SCHEMA_CHECKS)}


def migration_38_45_sql() -> str:
    return "SELECT " + ", ".join(expression for expression, _ in MIGRATION_38_45_CHECKS) + ";"


def evaluate_migration_38_45(output: str) -> dict:
    """Compare migration_38_45_sql()'s one psql -tA row with MIGRATION_38_45_CHECKS (migrations 38–45)."""
    observed = output.strip().split("|")
    expected = ["t" if value else "f" for _, value in MIGRATION_38_45_CHECKS]
    if len(observed) != len(expected):
        raise SmokeFailure(f"migrations 38-45 privilege query returned {output.strip()!r}")
    wrong = [f"{expression} is {got!r}, expected {want!r}"
             for (expression, _), got, want in zip(MIGRATION_38_45_CHECKS, observed, expected) if got != want]
    if wrong:
        raise SmokeFailure("migrations 38-45 role boundary: " + "; ".join(wrong))
    return {"runtime_gates_and_restore_ok": True, "vault_column_scoped": True,
            "backup_definer_only": True, "checks": len(MIGRATION_38_45_CHECKS)}


def vault_and_backup_fixture_manifests(vault_key_b64: str, backup_key_b64: str, run_id: str) -> dict:
    """Test-owned distinct vault/backup keyring Secrets and backup destination PVC (V1-28, V1-30)."""
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    vault_keyring = json.dumps({
        "version": 1,
        "active_key_id": VAULT_KEY_ID,
        "keys": [{"id": VAULT_KEY_ID, "file": f"{VAULT_KEYS_DIR}/{VAULT_KEY_FILE}"}],
    }).encode("utf-8")
    backup_keyring = json.dumps({
        "version": 1,
        "active_key_id": BACKUP_KEY_ID,
        "keys": [{"id": BACKUP_KEY_ID, "file": f"{BACKUP_KEYS_DIR}/{BACKUP_KEY_FILE}"}],
    }).encode("utf-8")
    return {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": VAULT_KEYS_SECRET, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"keyring.json": base64.b64encode(vault_keyring).decode("ascii"),
                  VAULT_KEY_FILE: vault_key_b64}},
        {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
         "metadata": {"name": BACKUP_KEYS_SECRET, "namespace": APP_NAMESPACE, "labels": labels},
         "data": {"keyring.json": base64.b64encode(backup_keyring).decode("ascii"),
                  BACKUP_KEY_FILE: backup_key_b64}},
        {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
         "metadata": {"name": BACKUP_DEST_CLAIM, "namespace": APP_NAMESPACE, "labels": labels},
         "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}}},
    ]}


def vault_key_files_command() -> list:
    """stat(1) staged vault keyring and 32-byte key file inside api/worker pods."""
    return ["stat", "--format=%n|%F|%a|%u", VAULT_CONFIG_PATH, f"{VAULT_KEYS_DIR}/{VAULT_KEY_FILE}"]


def evaluate_vault_key_files(pod: str, output: str) -> None:
    """Require staged vault files to be mode 0400 regular files owned by UID 65532 (core ADR 0045)."""
    expected = [VAULT_CONFIG_PATH, f"{VAULT_KEYS_DIR}/{VAULT_KEY_FILE}"]
    rows = [line.split("|") for line in output.splitlines()]
    if [row[0] for row in rows] != expected or any(len(row) != 4 for row in rows):
        raise SmokeFailure(f"{pod}: unexpected vault key listing {output!r}")
    for path, kind, mode, uid in rows:
        if kind != "regular file" or not re.fullmatch(r"[0-7]{3,4}", mode) or int(mode, 8) & 0o777 != 0o400 \
                or uid != "65532":
            raise SmokeFailure(f"{pod}: {path} is {kind} mode {mode} owner {uid}, "
                               f"expected a 0400 regular file owned by 65532")


def check_vault_and_backup_spec(pods_by_role: dict, cronjob: dict, backup_np: dict,
                                *, admin_ref: str, postgres_client_ref: str) -> dict:
    """Verify live api/worker vault RAM staging, gateway isolation, backup CronJob and backup NetworkPolicy."""
    api_pods = pods_by_role.get("api") or []
    worker_pods = pods_by_role.get("worker") or []
    gateway_pods = pods_by_role.get(GATEWAY_COMPONENT) or []
    if not api_pods or not worker_pods or not gateway_pods:
        raise SmokeFailure("api, worker and gateway pods are required to verify vault and backup isolation")
    for role in WORKLOADS:
        for pod in pods_by_role[role]:
            spec = pod.get("spec", {})
            init = next((c for c in spec.get("initContainers") or [] if c.get("name") == "stage-vault-keys"), None)
            if init is None:
                raise SmokeFailure(f"{role} pod lacks stage-vault-keys initContainer")
            vols = {v.get("name"): v for v in spec.get("volumes") or []}
            if vols.get("vault-keys", {}).get("emptyDir", {}).get("medium") != "Memory":
                raise SmokeFailure(f"{role} pod vault-keys volume must be a Memory emptyDir")
            if vols.get("vault-keys-secret", {}).get("secret", {}).get("secretName") != VAULT_KEYS_SECRET:
                raise SmokeFailure(f"{role} pod does not attach vault Secret {VAULT_KEYS_SECRET}")
            container = next((c for c in spec.get("containers") or [] if c.get("name") == role), None)
            if container is None:
                raise SmokeFailure(f"{role} pod has no container named {role!r}")
            mounts = {m.get("name"): m for m in container.get("volumeMounts") or []}
            if "vault-keys-secret" in mounts:
                raise SmokeFailure(f"{role} main container must not mount raw vault-keys-secret")
            if mounts.get("vault-keys") != {"name": "vault-keys", "mountPath": VAULT_KEYS_DIR,
                                            "subPath": "keys", "readOnly": True}:
                raise SmokeFailure(f"{role} container does not mount staged vault-keys read-only with subPath keys")
            env = {e.get("name"): e.get("value") for e in container.get("env") or []}
            var = f"OPENMETTLE_{role.upper()}_VAULT_KEYS_CONFIG"
            if env.get(var) != VAULT_CONFIG_PATH:
                raise SmokeFailure(f"{role} container lacks {var}={VAULT_CONFIG_PATH}")
    for pod in gateway_pods:
        spec_text = json.dumps(pod.get("spec", {}))
        if "vault-keys" in spec_text or "VAULT_KEYS" in spec_text or VAULT_KEYS_SECRET in spec_text:
            raise SmokeFailure("gateway pod must not mount vault keys or receive VAULT_KEYS env")
    cj_spec = cronjob.get("spec", {})
    if cj_spec.get("concurrencyPolicy") != "Forbid" or cj_spec.get("suspend") is not True:
        raise SmokeFailure("backup CronJob must have concurrencyPolicy=Forbid and suspend=true")
    job_spec = cj_spec.get("jobTemplate", {}).get("spec", {})
    if job_spec.get("backoffLimit") != 0:
        raise SmokeFailure(f"backup CronJob backoffLimit is {job_spec.get('backoffLimit')!r}, expected 0")
    pod_spec = job_spec.get("template", {}).get("spec", {})
    init = next((c for c in pod_spec.get("initContainers") or [] if c.get("name") == "prepare-backup-runtime"), None)
    if init is None or init.get("image") != admin_ref or init.get("imagePullPolicy") != "Never":
        raise SmokeFailure(f"backup CronJob prepare-backup-runtime must run {admin_ref} with pullPolicy Never")
    main = next((c for c in pod_spec.get("containers") or [] if c.get("name") == "backup"), None)
    if main is None or main.get("image") != postgres_client_ref or main.get("imagePullPolicy") != "Never":
        raise SmokeFailure(f"backup CronJob main container must run {postgres_client_ref} with pullPolicy Never")
    main_env = {e.get("name"): e for e in main.get("env") or []}
    ref = main_env.get("OPENMETTLE_ADMIN_DATABASE_URL", {}).get("valueFrom", {}).get("secretKeyRef", {})
    if (ref.get("name"), ref.get("key")) != (SECRET["migrate"], "url") or ref.get("optional", False) is not False:
        raise SmokeFailure("backup container OPENMETTLE_ADMIN_DATABASE_URL does not reference owner Secret url")
    job_uid_field = (main_env.get("OPENMETTLE_BACKUP_JOB_UID", {})
                     .get("valueFrom", {}).get("fieldRef", {}).get("fieldPath"))
    if job_uid_field != "metadata.labels['batch.kubernetes.io/controller-uid']":
        raise SmokeFailure("backup container OPENMETTLE_BACKUP_JOB_UID must use batch.kubernetes.io/controller-uid")
    main_args = main.get("args") or []
    if "--destination-root" not in main_args:
        raise SmokeFailure("backup container args lack --destination-root")
    dest_root = main_args[main_args.index("--destination-root") + 1]
    if dest_root != BACKUP_DEST_DIR:
        raise SmokeFailure(f"backup container --destination-root is {dest_root!r}, expected {BACKUP_DEST_DIR!r}")
    if "--request-key" not in main_args or main_args[main_args.index("--request-key") + 1] != "cronjob-$(OPENMETTLE_BACKUP_JOB_UID)":
        raise SmokeFailure("backup container --request-key must be cronjob-$(OPENMETTLE_BACKUP_JOB_UID)")
    main_mounts = {m.get("name"): m for m in main.get("volumeMounts") or []}
    if "backup-keys-secret" in main_mounts:
        raise SmokeFailure("backup main container must not mount raw backup-keys-secret")
    if main_mounts.get("backup-keys") != {"name": "backup-keys", "mountPath": BACKUP_KEYS_DIR,
                                          "subPath": "keys", "readOnly": True}:
        raise SmokeFailure("backup container does not mount staged backup-keys read-only with subPath keys")
    if main_mounts.get("backup-destination", {}).get("mountPath") != dest_root:
        raise SmokeFailure("backup container backup-destination mountPath disagrees with --destination-root")
    if main_mounts.get("artifacts", {}).get("readOnly") is not True:
        raise SmokeFailure("backup container must mount artifacts read-only")
    np_spec = backup_np.get("spec", {})
    if np_spec.get("policyTypes") != ["Ingress", "Egress"] or np_spec.get("ingress"):
        raise SmokeFailure("backup NetworkPolicy must deny all ingress and enforce egress")
    if len(np_spec.get("egress") or []) != 2:
        raise SmokeFailure(f"backup NetworkPolicy expected 2 egress rules (DNS + DB), got {len(np_spec.get('egress') or [])}")
    return {"api_pods": len(api_pods), "worker_pods": len(worker_pods), "gateway_isolated": True,
            "cronjob": BACKUP_CRONJOB, "backup_network_policy": BACKUP_NETWORK_POLICY,
            "destination_root": dest_root}


def parse_backup_capture_log(output: str, expected_dest_dir: str = BACKUP_DEST_DIR) -> dict:
    """Parse `backup.capture_succeeded ...` printed by `openmettle-admin backup capture`."""
    line = next((ln.strip() for ln in output.splitlines() if ln.strip().startswith("backup.capture_succeeded ")), None)
    if line is None:
        raise SmokeFailure("backup Job output lacks backup.capture_succeeded line")
    fields = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
    run_id = fields.get("run_id", "")
    backup_dir = fields.get("dir", "")
    key_id = fields.get("key_id", "")
    bundle_digest = fields.get("bundle_digest", "")
    if not UUID.fullmatch(run_id):
        raise SmokeFailure(f"backup capture reported invalid run_id: {run_id!r}")
    if not backup_dir.startswith(f"{expected_dest_dir}/") or ".." in Path(backup_dir).parts:
        raise SmokeFailure(f"backup capture reported unexpected dir: {backup_dir!r}")
    if key_id != BACKUP_KEY_ID:
        raise SmokeFailure(f"backup capture used unexpected key_id {key_id!r}, expected {BACKUP_KEY_ID!r}")
    if not CACHE_SALT.fullmatch(bundle_digest):
        raise SmokeFailure(f"backup capture reported malformed bundle_digest: {bundle_digest!r}")
    if fields.get("maintenance_released") != "true":
        raise SmokeFailure(f"backup capture did not release maintenance: {fields.get('maintenance_released')!r}")
    return {"run_id": run_id, "dir": backup_dir, "key_id": key_id,
            "bundle_digest": bundle_digest, "maintenance_released": True}


def backup_run_sql(run_id: str) -> str:
    if not UUID.fullmatch(run_id):
        raise SmokeFailure(f"invalid backup run_id: {run_id!r}")
    return (
        "SELECT r.id::text, r.state, r.destination_domain, r.encryption_key_id,"
        " encode(r.bundle_digest, 'hex'), r.completed_at IS NOT NULL, r.failure_code IS NULL,"
        " g.maintenance_active, g.backup_run_id IS NULL"
        " FROM openmettle.backup_runs r"
        " CROSS JOIN openmettle.backup_maintenance_gate g"
        f" WHERE r.id = '{run_id}'::uuid;"
    )


def evaluate_backup_run_row(output: str, expected_run_id: str, expected_bundle_digest: str) -> dict:
    """Verify backup_runs recorded succeeded and backup_maintenance_gate released cleanly."""
    rows = [line for line in output.splitlines() if line]
    if len(rows) != 1:
        raise SmokeFailure(f"expected one backup_runs row for {expected_run_id}, found {len(rows)}")
    fields = rows[0].split("|")
    expected = [expected_run_id, "succeeded", BACKUP_DESTINATION_DOMAIN, BACKUP_KEY_ID,
                expected_bundle_digest, "t", "t", "f", "t"]
    if fields != expected:
        raise SmokeFailure(f"unexpected backup_runs / maintenance gate row: {fields!r}")
    return {"state": "succeeded", "destination_domain": BACKUP_DESTINATION_DOMAIN,
            "key_id": BACKUP_KEY_ID, "maintenance_active": False}


def backup_verify_job_manifest(admin_image: str, backup_dir: str, run_id: str,
                               dest_dir: str = BACKUP_DEST_DIR) -> dict:
    """Offline PodSecurity-restricted Job running `openmettle-admin backup verify` against the published dir."""
    labels = {"openmettle.dev/environment": "dev", RUN_LABEL: run_id}
    stage_script = (
        "umask 077\n"
        "stage=/run/openmettle-backup-stage/keys\n"
        "mkdir -p -- \"$stage\" && chmod 0700 \"$stage\"\n"
        "for src in /run/openmettle-backup-src/*; do\n"
        "  [ -f \"$src\" ] || continue\n"
        "  cp -L -- \"$src\" \"$stage/${src##*/}\" && chmod 0400 \"$stage/${src##*/}\"\n"
        "done\n"
    )
    container_sec = {"privileged": False, "allowPrivilegeEscalation": False,
                     "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": BACKUP_VERIFY_JOB, "namespace": APP_NAMESPACE, "labels": labels},
        "spec": {
            "backoffLimit": 0, "activeDeadlineSeconds": 120,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                        "fsGroup": 65532, "fsGroupChangePolicy": "OnRootMismatch",
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "initContainers": [{
                        "name": "stage-backup-keys", "image": admin_image, "imagePullPolicy": "Never",
                        "command": ["/bin/sh", "-eu", "-c", stage_script],
                        "securityContext": container_sec,
                        "volumeMounts": [
                            {"name": "backup-keys-secret", "mountPath": "/run/openmettle-backup-src", "readOnly": True},
                            {"name": "backup-keys", "mountPath": "/run/openmettle-backup-stage"},
                        ],
                    }],
                    "containers": [{
                        "name": "verify", "image": admin_image, "imagePullPolicy": "Never",
                        "args": ["backup", "verify", "--backup-dir", backup_dir,
                                 "--backup-keys-config", BACKUP_CONFIG_PATH],
                        "securityContext": container_sec,
                        "volumeMounts": [
                            {"name": "backup-keys", "mountPath": BACKUP_KEYS_DIR, "subPath": "keys", "readOnly": True},
                            {"name": "backup-destination", "mountPath": dest_dir, "readOnly": True},
                        ],
                    }],
                    "volumes": [
                        {"name": "backup-keys-secret", "secret": {"secretName": BACKUP_KEYS_SECRET, "defaultMode": 288}},
                        {"name": "backup-keys", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
                        {"name": "backup-destination",
                         "persistentVolumeClaim": {"claimName": BACKUP_DEST_CLAIM, "readOnly": True}},
                    ],
                },
            },
        },
    }


def parse_backup_verify_log(output: str, expected_run_id: str) -> dict:
    """Parse `backup.verified ...` printed by `openmettle-admin backup verify`."""
    line = next((ln.strip() for ln in output.splitlines() if ln.strip().startswith("backup.verified ")), None)
    if line is None:
        raise SmokeFailure("backup verify Job output lacks backup.verified line")
    fields = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
    if fields.get("run_id") != expected_run_id:
        raise SmokeFailure(f"backup verify run_id {fields.get('run_id')!r} != {expected_run_id!r}")
    try:
        schema = int(fields.get("schema", "0"))
        components = int(fields.get("components", "0"))
        artifact_revisions = int(fields.get("artifact_revisions", "-1"))
    except ValueError as exc:
        raise SmokeFailure(f"backup verify reported non-integer counts: {line!r}") from exc
    if schema < REQUIRED_MIGRATION or fields.get("key_id") != BACKUP_KEY_ID or components != 5 \
            or artifact_revisions != 2:
        raise SmokeFailure(f"unexpected backup verify summary: {line!r}")
    return {"schema": schema, "key_id": BACKUP_KEY_ID, "components": components,
            "artifact_revisions": artifact_revisions}


def gateway_probe_plan(*, tls: bool) -> list:
    """Live NetworkPolicy probes for plain-HTTP vs TLS-terminated gateway topologies."""
    gw_host = f"{GATEWAY_WORKLOAD}.{APP_NAMESPACE}.svc.cluster.local"
    gw_readyz = http_command(gw_host, 8082, "/readyz")

    def probe(name, namespace, workload, container, command, expect, control=None, is_http=False):
        return {"name": name, "namespace": namespace, "workload": workload, "container": container,
                "command": command, "expect": expect, "control": control, "http": is_http}

    if not tls:
        worker_allowed = "worker reaches plain-HTTP gateway /readyz 200"
        return [
            probe(worker_allowed, APP_NAMESPACE, f"{FULLNAME}-worker", "worker", gw_readyz, "connect", is_http=True),
            probe("api denied from plain-HTTP gateway", APP_NAMESPACE, f"{FULLNAME}-api", "api",
                  gw_readyz, "deny", worker_allowed, is_http=True),
            probe("database namespace denied from plain-HTTP gateway", DB_NAMESPACE, "postgres", "postgres",
                  gw_readyz, "deny", worker_allowed, is_http=True),
        ]
    gw_self = "control: gateway-a serves /readyz locally on 8082"
    traefik_control = "control: database namespace reaches smoke-traefik on 8443"
    return [
        probe(gw_self, APP_NAMESPACE, GATEWAY_WORKLOAD, "gateway",
              http_command("127.0.0.1", 8082, "/readyz"), "connect", is_http=True),
        probe(traefik_control, DB_NAMESPACE, "postgres", "postgres",
              tcp_command(GATEWAY_TLS_HOST, 8443), "connect"),
        probe("worker reaches TLS terminator smoke-traefik on 8443", APP_NAMESPACE, f"{FULLNAME}-worker", "worker",
              tcp_command(GATEWAY_TLS_HOST, 8443), "connect"),
        probe("database namespace denied direct connection to TLS-fronted gateway on 8082",
              DB_NAMESPACE, "postgres", "postgres", gw_readyz, "deny", gw_self, is_http=True),
        probe("worker denied direct connection to TLS-fronted gateway on 8082",
              APP_NAMESPACE, f"{FULLNAME}-worker", "worker", gw_readyz, "deny", gw_self, is_http=True),
        probe("api denied direct connection to TLS-fronted gateway on 8082",
              APP_NAMESPACE, f"{FULLNAME}-api", "api", gw_readyz, "deny", gw_self, is_http=True),
    ]


def check_inference_and_gateway_mounts(pods_by_role: dict, *, tls: bool) -> dict:
    """Verify worker.inference mounts/env and gateway-a pod isolation on live pod specs."""
    api_pods = pods_by_role.get("api") or []
    worker_pods = pods_by_role.get("worker") or []
    gateway_pods = pods_by_role.get(GATEWAY_COMPONENT) or []
    if not api_pods or not worker_pods or not gateway_pods:
        raise SmokeFailure("api, worker and gateway pods are required to verify inference and gateway mounts")
    expected_cm = INFERENCE_TLS_CONFIG_MAP if tls else INFERENCE_PLAIN_CONFIG_MAP
    for pod in worker_pods:
        spec = pod.get("spec", {})
        vols = {v.get("name"): v for v in spec.get("volumes") or []}
        cm = vols.get("inference-config", {}).get("configMap", {})
        if cm.get("name") != expected_cm or cm.get("items") != [
            {"key": "inference.json", "path": "inference.json"},
            {"key": AUTH_CATALOG_KEY, "path": AUTH_CATALOG_KEY},
        ]:
            raise SmokeFailure(f"worker pod does not project {expected_cm} as inference.json and catalog.json")
        if tls:
            ca = vols.get("inference-ca", {}).get("configMap", {})
            if ca.get("name") != INFERENCE_CA_CONFIG_MAP or ca.get("items") != [{"key": "ca.crt", "path": "ca.crt"}]:
                raise SmokeFailure(f"worker pod does not project {INFERENCE_CA_CONFIG_MAP} as ca.crt")
        elif "inference-ca" in vols:
            raise SmokeFailure("worker pod must not mount inference-ca in plain-HTTP mode")
        container = next((c for c in spec.get("containers") or [] if c.get("name") == "worker"), None)
        if container is None:
            raise SmokeFailure("worker pod has no container named 'worker'")
        mounts = {m.get("name"): m for m in container.get("volumeMounts") or []}
        if mounts.get("inference-config") != {"name": "inference-config", "mountPath": INFERENCE_CONFIG_DIR,
                                              "readOnly": True}:
            raise SmokeFailure(f"worker container does not mount inference-config read-only at {INFERENCE_CONFIG_DIR}")
        if tls and mounts.get("inference-ca") != {"name": "inference-ca", "mountPath": INFERENCE_CA_DIR,
                                                  "readOnly": True}:
            raise SmokeFailure(f"worker container does not mount inference-ca read-only at {INFERENCE_CA_DIR}")
        env = {e.get("name"): e.get("value") for e in container.get("env") or []}
        expected_env = {
            "OPENMETTLE_WORKER_POLL_MS": "100",
            "OPENMETTLE_WORKER_INFERENCE_CONFIG": INFERENCE_CONFIG_PATH,
            "OPENMETTLE_WORKER_RUN_SLOTS": "2",
            "OPENMETTLE_WORKER_LEASE_MS": "30000",
            "OPENMETTLE_WORKER_EXECUTION_TIMEOUT_MS": "60000",
            "OPENMETTLE_WORKER_EXECUTING_PER_ACTOR": "2",
            "OPENMETTLE_WORKER_EXECUTING_PER_SCOPE": "4",
        }
        for key, value in expected_env.items():
            if env.get(key) != value:
                raise SmokeFailure(f"worker container lacks {key}={value}")
    for pod in gateway_pods:
        spec = pod.get("spec", {})
        if "fsGroup" in (spec.get("securityContext") or {}):
            raise SmokeFailure("gateway pod must not set fsGroup")
        if spec.get("volumes"):
            raise SmokeFailure(f"gateway pod mounted unexpected volumes: {[v.get('name') for v in spec['volumes']]}")
        container = next((c for c in spec.get("containers") or [] if c.get("name") == "gateway"), None)
        if container is None:
            raise SmokeFailure("gateway pod has no container named 'gateway'")
        env = {e.get("name"): e for e in container.get("env") or []}
        ref = env.get("OPENMETTLE_GATEWAY_DATABASE_URL", {}).get("valueFrom", {}).get("secretKeyRef", {})
        if (ref.get("name"), ref.get("key")) != (SECRET["gateway"], "url") or ref.get("optional", False) is not False:
            raise SmokeFailure(f"gateway DATABASE_URL is not a required reference to Secret {SECRET['gateway']} key url")
        if env.get("OPENMETTLE_GATEWAY_MODEL", {}).get("value") != CATALOG_MODEL:
            raise SmokeFailure(f"gateway container lacks OPENMETTLE_GATEWAY_MODEL={CATALOG_MODEL}")
        if env.get("OPENMETTLE_GATEWAY_CACHE_MODE", {}).get("value") != "scoped":
            raise SmokeFailure("gateway container lacks OPENMETTLE_GATEWAY_CACHE_MODE=scoped")
        for key in env:
            if not str(key).startswith("OPENMETTLE_GATEWAY_"):
                raise SmokeFailure(f"gateway container received non-gateway env {key}")
    for pod in api_pods:
        spec_text = json.dumps(pod.get("spec", {}))
        if "INFERENCE_CONFIG" in spec_text or "RUN_SLOTS" in spec_text or "inference-config" in spec_text:
            raise SmokeFailure("api pod must not receive worker inference config or settings")
    return {"mode": "tls" if tls else "plain", "worker_pods": len(worker_pods),
            "gateway_pods": len(gateway_pods), "ca_mounted": tls}


def evaluate_standin_record(record: dict, expected_request_id: str) -> dict:
    """Verify the stand-in observed stripped Authorization, matching x-request-id and 64-hex cache_salt."""
    headers = record.get("headers") or {}
    body = record.get("body")
    if "authorization" in headers:
        raise SmokeFailure("openmettle-gateway leaked Authorization header to upstream")
    req_ids = headers.get("x-request-id")
    if req_ids != [expected_request_id]:
        count = len(req_ids) if isinstance(req_ids, list) else 0
        raise SmokeFailure(f"upstream x-request-id mismatch (type={type(req_ids).__name__}, count={count})")
    if not isinstance(body, dict):
        detail = f"type={type(body).__name__}, len={len(body)}" if isinstance(body, str) else f"type={type(body).__name__}"
        raise SmokeFailure(f"upstream body is not a JSON object ({detail})")
    model = body.get("model")
    if model != CATALOG_MODEL:
        detail = f"type={type(model).__name__}, len={len(model)}" if isinstance(model, str) else f"type={type(model).__name__}"
        raise SmokeFailure(f"upstream body model mismatch ({detail})")
    salt = body.get("cache_salt")
    if not isinstance(salt, str) or not CACHE_SALT.fullmatch(salt):
        detail = f"type={type(salt).__name__}, len={len(salt)}" if isinstance(salt, str) else f"type={type(salt).__name__}"
        raise SmokeFailure(f"upstream body missing 64-char lowercase hex cache_salt ({detail})")
    return {"model": CATALOG_MODEL, "authorization_stripped": True, "cache_salt_len": len(salt)}


def settled_round_sql(run_id: str) -> str:
    if not UUID.fullmatch(run_id):
        raise SmokeFailure(f"invalid run_id for settlement check: {run_id!r}")
    return (
        "SELECT q.id::text, q.state, q.dispatched_at IS NOT NULL,"
        " r.final, r.revision, r.prompt_tokens, r.completion_tokens, r.incomplete IS NULL,"
        " qr.state, qr.held_units, qr.settled_units"
        " FROM openmettle.gateway_requests q"
        " JOIN openmettle.gateway_usage_reports r ON r.request_id = q.id"
        " JOIN openmettle.quota_reservations qr"
        "   ON qr.gateway_request_id = q.id AND qr.resource_kind = 'usage_tokens'"
        f" WHERE q.run_id = '{run_id}'::uuid;"
    )


def evaluate_settled_round(output: str) -> dict | None:
    """Return settlement summary once gateway usage report & quota settlement are committed, else None."""
    rows = [line for line in output.splitlines() if line]
    if not rows:
        return None
    if len(rows) != 1:
        raise SmokeFailure(f"expected one settled gateway request row, found {len(rows)}")
    fields = rows[0].split("|")
    if len(fields) != 11 or not UUID.fullmatch(fields[0]):
        raise SmokeFailure(f"malformed gateway settlement row: {rows[0]!r}")
    expected_tail = [
        "handed_off", "t", "t", "1",
        str(STANDIN_EXPECTED_PROMPT_TOKENS), str(STANDIN_EXPECTED_COMPLETION_TOKENS), "t",
        "settled", "0", str(STANDIN_EXPECTED_SETTLED_UNITS),
    ]
    if fields[1:] != expected_tail:
        raise SmokeFailure(f"unexpected gateway settlement row: {fields[1:]} != {expected_tail}")
    return {
        "request_id": fields[0],
        "prompt_tokens": STANDIN_EXPECTED_PROMPT_TOKENS,
        "completion_tokens": STANDIN_EXPECTED_COMPLETION_TOKENS,
        "settled_units": STANDIN_EXPECTED_SETTLED_UNITS,
    }


def evaluate_fresh_bootstrap(output: str) -> dict:
    """FRESH_BOOTSTRAP_SQL's one psql -tA row: both markers must be true."""
    if output.strip() != "t|t":
        raise SmokeFailure(f"fresh-install quota and artifact-volume markers are {output.strip()!r}, "
                           "expected 't|t'")
    return {"metering_and_overrides_enforced": True, "artifact_volume_unpinned_auto_pin_allowed": True}


def evaluate_quota_routes(responses: dict, *, mounted: bool) -> dict:
    """Each QUOTA_ROUTES (status, headers, body) for a request without a session. Mounted: a versioned,
    uncacheable 401 `unauthenticated` problem. Unmounted: 404."""
    statuses = {}
    for method, path in QUOTA_ROUTES:
        name = f"{method} {path}"
        if name not in responses:
            raise SmokeFailure(f"{name}: no response")
        status, headers, body = responses[name]
        if not mounted:
            if status != 404:
                raise SmokeFailure(f"unmounted {name}: HTTP {status}, expected 404")
        else:
            expect_v1(name, responses[name], 401)
            try:
                problem = json.loads(body)
            except ValueError as exc:
                raise SmokeFailure(f"{name}: 401 body is not JSON") from exc
            if not str(headers.get("content-type", "")).startswith("application/problem+json") \
                    or not isinstance(problem, dict) or problem.get("status") != 401 \
                    or problem.get("code") != "unauthenticated":
                raise SmokeFailure(f"{name}: unexpected 401 problem {problem!r}")
        statuses[name] = status
    return statuses


def v1_json(name: str, response: tuple, status: int) -> dict:
    """The JSON object of a versioned /v1 response with `status`."""
    _, body = expect_v1(name, response, status)
    try:
        document = json.loads(body)
    except ValueError as exc:
        raise SmokeFailure(f"{name}: body is not JSON") from exc
    if not isinstance(document, dict):
        raise SmokeFailure(f"{name}: body is not a JSON object")
    return document


def run_request(root: dict, input_message_id: str) -> dict:
    """POST /v1/runs body: one text turn appended to the new root branch, selecting CATALOG_PRESET
    (core contract RunCreateRequest with the AppendProposal example's shape)."""
    for field in ("conversation_id", "branch_id"):
        if not UUID.fullmatch(str(root.get(field, ""))):
            raise SmokeFailure(f"POST /v1/conversations: {field} is not a canonical UUID")
    return {"conversation_id": root["conversation_id"], "branch_id": root["branch_id"],
            "proposal": {"expected_head_message_id": None,
                         "turn": {"mode": "append", "input_message_id": input_message_id,
                                  "parts": [{"text": "kind smoke admission"}]},
                         "selection": {"preset": CATALOG_PRESET}}}


def evaluate_http_admission(models: dict, created: dict, replay: dict, cancelled: dict) -> dict:
    """GET /v1/models lists the mounted catalog; POST /v1/runs admits a queued run, an exact retry replays
    it and cancel makes it terminal (core ADRs 0032 and 0036)."""
    listed = sorted(str(item.get("model_id")) for item in models.get("items") or [] if isinstance(item, dict))
    if CATALOG_MODEL not in listed:
        raise SmokeFailure(f"GET /v1/models does not list catalog model {CATALOG_MODEL!r}: {listed}")
    run_id = created.get("run_id")
    if not UUID.fullmatch(str(run_id)) or created.get("state") != "queued":
        raise SmokeFailure(f"POST /v1/runs: expected a queued run, got state {created.get('state')!r}")
    if replay.get("run_id") != run_id or replay.get("state") != "queued":
        raise SmokeFailure("POST /v1/runs: the exact retry did not replay the same queued run")
    if cancelled.get("run_id") != run_id or cancelled.get("state") != "cancelled":
        raise SmokeFailure(f"POST /v1/runs/{{run_id}}/cancel: state {cancelled.get('state')!r}, expected 'cancelled'")
    return {"models": listed, "admitted": "queued", "replay": "same run", "cancelled": "cancelled"}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def session_credential(raw: bytes) -> tuple:
    """(session id, cookie value, secret hash hex) from 64 random bytes, as core sessions.rs
    create_with: the hash is SHA-256 over the domain and the length-framed id and secret."""
    if len(raw) != 64:
        raise ValueError("a session credential needs 64 random bytes")
    session_id, secret = b64url(raw[:32]), raw[32:]
    framed = SESSION_DOMAIN + b"".join(len(field).to_bytes(8, "big") + field
                                       for field in (session_id.encode("ascii"), secret))
    return session_id, f"{session_id}.{b64url(secret)}", hashlib.sha256(framed).hexdigest()


def session_seed_sql(session_id: str, secret_hash: str, login_id: str) -> str:
    """One personal-scope user with an active approval and a browser session stored as issuance
    stores it, plus storage limits and a personal usage_tokens limit. Only the hash reaches the
    database, never the secret."""
    if not (B64_ID.fullmatch(session_id) and B64_ID.fullmatch(login_id)
            and re.fullmatch(r"[0-9a-f]{64}", secret_hash)):
        raise SmokeFailure("malformed synthetic session values")
    ids, expires = SESSION_IDS, SESSION_EXPIRES_MS
    by = "'kind-smoke', 'synthetic smoke fixture'"
    return f"""\
INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason)
    VALUES ('{ids['provider']}', '{SESSION_ISSUER}', '{SESSION_CLIENT}', {by});
INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ('{ids['provider']}', 'r1');
INSERT INTO openmettle.users (id) VALUES ('{ids['user']}');
INSERT INTO openmettle.scopes (kind, personal_user_id) VALUES ('personal', '{ids['user']}');
INSERT INTO openmettle.user_identities (id, user_id, issuer, subject)
    VALUES ('{ids['identity']}', '{ids['user']}', '{SESSION_ISSUER}', 'kind-smoke-user');
INSERT INTO openmettle.local_identity_approvals (id, provider_id, identity_id, active, expires_ms, changed_by, change_reason)
    VALUES ('{ids['approval']}', '{ids['provider']}', '{ids['identity']}', true, {expires}, {by});
INSERT INTO openmettle.login_nonce_reservations (key_id, nonce)
    VALUES ('kind-smoke', substring(sha256(convert_to('{login_id}', 'UTF8')) FROM 1 FOR 12));
INSERT INTO openmettle.login_transactions (id, binding, expires_ms, state_hash, nonce_hash, caller_hash,
        key_id, nonce, ciphertext, consumed, session_issued)
    SELECT '{login_id}', decode('01', 'hex'), {expires}, sha256(convert_to('{login_id}:state', 'UTF8')),
           sha256(convert_to('{login_id}:nonce', 'UTF8')), sha256(convert_to('{login_id}:caller', 'UTF8')),
           key_id, nonce, NULL, true, true
      FROM openmettle.login_nonce_reservations WHERE key_id = 'kind-smoke';
INSERT INTO openmettle.local_sessions (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id,
        issued_client, issued_epoch, issued_revision, provider_generation, approval_generation,
        user_generation, created_ms, expires_ms)
    SELECT '{session_id}', decode('{secret_hash}', 'hex'), '{login_id}', '{ids['provider']}', '{ids['identity']}',
           '{ids['approval']}', '{ids['user']}', '{SESSION_CLIENT}', max(epoch), 1, 0, 0, 0, 1, {expires}
      FROM openmettle.login_provider_revisions WHERE provider_id = '{ids['provider']}';
UPDATE openmettle.storage_instance
    SET instance_budget_bytes = {STORAGE_LIMIT_BYTES}, personal_limit_bytes = {STORAGE_LIMIT_BYTES};
INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
    VALUES ('personal', 'usage_tokens', {PERSONAL_TOKEN_LIMIT});
"""


def multipart_form(boundary: str, payload: bytes, *, file_first: bool = False) -> bytes:
    """An artifact upload body: an empty `metadata` object and one `file` part, in either order."""
    metadata = b'Content-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n{}'
    file = (f'Content-Disposition: form-data; name="file"; filename="{ARTIFACT_FILENAME}"\r\n'
            f"Content-Type: {ARTIFACT_MEDIA_TYPE}\r\n\r\n").encode("ascii") + payload
    delimiter = f"--{boundary}".encode("ascii")
    parts = (file, metadata) if file_first else (metadata, file)
    return b"".join(delimiter + b"\r\n" + part + b"\r\n" for part in parts) + delimiter + b"--\r\n"


def v1_headers(cookie: str, *, key: str | None = None, boundary: str | None = None,
               byte_range: str | None = None) -> dict:
    """Browser cookie channel: the session cookie and the configured Origin (core ADRs 0007, 0019)."""
    headers = {"Cookie": f"{SESSION_COOKIE}={cookie}", "Origin": AUTH_ORIGIN}
    if key is not None:
        headers["Idempotency-Key"] = key
    if boundary is not None:
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    if byte_range is not None:
        headers["Range"] = byte_range
    return headers


def http_exchange(port: int, method: str, path: str, headers: dict, body: bytes = b"") -> tuple:
    """One HTTP/1.1 request to the loopback port-forward: (status, lowercase headers, body bytes)."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        connection.close()


def expect_v1(name: str, response: tuple, status: int) -> tuple:
    """(headers, body) of a /v1 response with `status`; every one is versioned and uncacheable."""
    got, headers, body = response
    if got != status:
        raise SmokeFailure(f"{name}: HTTP {got}, expected {status}: {body[:300]!r}")
    if headers.get("openmettle-api-version") != V1_API_VERSION or headers.get("cache-control") != "no-store":
        raise SmokeFailure(f"{name}: missing OpenMettle-API-Version {V1_API_VERSION} or Cache-Control no-store")
    return headers, body


def ingress_certificate_command(cert, key):
    return ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", f"/CN={INGRESS_HOST}", "-addext", f"subjectAltName=DNS:{INGRESS_HOST}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
            "-keyout", str(key), "-out", str(cert)]


@contextmanager
def ingress_get(port, context, path, headers, *, timeout=HTTP_TIMEOUT, host=INGRESS_HOST):
    """Dial only the controller's loopback tunnel. SNI, host validation and Host use `host`."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as tcp:
        with context.wrap_socket(tcp, server_hostname=host) as tls:
            with closing(http.client.HTTPConnection(host, timeout=timeout)) as conn:
                conn.sock = tls
                conn.request("GET", path, headers={"Host": host, **headers})
                with conn.getresponse() as response:
                    yield response


def sse_frame(response):
    """Read one ADR 0034 block across HTTP chunks, including its terminating blank line."""
    first = response.readline(518)
    if not first:
        return None
    if first == b": heartbeat\n" and response.readline(2) == b"\n":
        return "heartbeat"
    if not re.fullmatch(rb"id: [A-Za-z0-9_-]{1,512}\n", first):
        raise SmokeFailure("missing SSE cursor or unexpected comment")
    data = response.readline(131080)
    if not data.startswith(b"data: ") or not data.endswith(b"\n") or response.readline(2) != b"\n":
        raise SmokeFailure("invalid or incomplete SSE data frame")
    try:
        item = json.loads(data[6:])
    except ValueError as exc:
        raise SmokeFailure("malformed SSE JSON") from exc
    if not isinstance(item, dict):
        raise SmokeFailure("expected a run event object")
    return first[4:-1].decode("ascii"), item


def expect_event(response, run_id, sequence, kind, data, *, deadline):
    while time.monotonic() < deadline:
        frame = sse_frame(response)
        if frame == "heartbeat":
            continue
        if frame is None:
            raise SmokeFailure("SSE ended before the expected event")
        _, event = frame
        if type(event.get("type_version")) is not int or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", str(event.get("occurred_at"))):
            raise SmokeFailure("invalid event version or occurrence timestamp")
        if (event.get("run_id"), event.get("sequence"), event.get("type"), event.get("type_version"),
                event.get("data")) != (run_id, str(sequence), kind, 1, data):
            raise SmokeFailure(f"expected {kind} at sequence {sequence} on the admitted run")
        if time.monotonic() >= deadline:
            break
        return frame
    raise SmokeFailure(f"timed out waiting for {kind}")


def ingress_headers(operation, response, status):
    # Check status before reading: an unexpected 200 can have an unbounded stream body.
    received = {k.lower(): v for k, v in response.getheaders()}
    expect_v1(operation, (response.status, received, b""), status)
    return received


@contextmanager
def event_stream(port, context, path, headers):
    with ingress_get(port, context, path, headers) as response:
        received = ingress_headers("streamRunEvents", response, 200)
        if (received.get("content-type") != "text/event-stream" or received.get("x-accel-buffering") != "no"
                or "content-length" in received or sse_frame(response) != "heartbeat"):
            raise SmokeFailure("stream missing SSE headers or opening heartbeat")
        yield response


def quiet_heartbeats(response):
    """Two periodic comments after the opening comment. A buffered burst cannot satisfy the intervals."""
    started = previous = time.monotonic()
    for _ in range(2):
        if sse_frame(response) != "heartbeat":
            raise SmokeFailure("resumed stream replayed data or ended during the quiet interval")
        now = time.monotonic()
        if not 8 <= now - previous <= 25:
            raise SmokeFailure("periodic SSE heartbeat arrived in a burst or too late")
        previous = now
    return round(previous - started, 2)


def check_snapshot(body, run_id, cursor, terminal):
    try:
        snapshot = json.loads(body)
    except ValueError as exc:
        raise SmokeFailure("getRun snapshot body is not JSON") from exc
    if not isinstance(snapshot, dict):
        raise SmokeFailure("getRun snapshot body is not a JSON object")
    if (snapshot.get("run_id"), snapshot.get("state"), snapshot.get("last_sequence"),
        snapshot.get("resume_cursor"), snapshot.get("terminal")) != (
            run_id, "failed" if terminal else "queued", "2" if terminal else "1", cursor, terminal):
        raise SmokeFailure("getRun snapshot disagrees with the stream")


def evaluate_artifact_revision(body: bytes, payload: bytes, revision: int) -> dict:
    """An active revision `revision` of `payload` in the caller's personal scope."""
    try:
        document = json.loads(body)
    except ValueError as exc:
        raise SmokeFailure("artifact revision body is not JSON") from exc
    if not isinstance(document, dict):
        raise SmokeFailure("artifact revision body is not a JSON object")
    expected = {"revision": str(revision), "state": "active", "scope_kind": "personal", "project_id": None,
                "media_type": ARTIFACT_MEDIA_TYPE, "display_name": ARTIFACT_FILENAME,
                "size_bytes": str(len(payload)), "sha256": hashlib.sha256(payload).hexdigest()}
    observed = {key: document.get(key) for key in expected}
    if observed != expected:
        raise SmokeFailure(f"artifact revision {revision}: {observed}, expected {expected}")
    if not all(isinstance(document.get(key), str) and UUID.fullmatch(document[key])
               for key in ("artifact_id", "revision_id", "scope_id")):
        raise SmokeFailure(f"artifact revision {revision} lacks canonical artifact, revision or scope ids")
    return document


def evaluate_artifact_downloads(payload: bytes, full: tuple, partial: tuple, unsatisfiable: tuple) -> dict:
    """The (headers, body) of a full download, a single byte range and an unsatisfiable range."""
    total = len(payload)
    headers, body = full
    expected = {"content-type": ARTIFACT_MEDIA_TYPE, "content-length": str(total), "accept-ranges": "bytes",
                "x-content-type-options": "nosniff", "content-range": None,
                "content-disposition": f"attachment; filename*=UTF-8''{ARTIFACT_FILENAME}"}
    observed = {key: headers.get(key) for key in expected}
    if body != payload or observed != expected:
        raise SmokeFailure(f"full download: {len(body)} bytes matching={body == payload}, headers {observed}")
    first, last = ARTIFACT_RANGE
    headers, body = partial
    if body != payload[first:last + 1] or headers.get("content-range") != f"bytes {first}-{last}/{total}" \
            or headers.get("content-length") != str(last - first + 1):
        raise SmokeFailure(f"range download: {body!r} Content-Range {headers.get('content-range')!r} "
                           f"Content-Length {headers.get('content-length')!r}")
    headers, body = unsatisfiable
    try:
        problem = json.loads(body)
    except ValueError as exc:
        raise SmokeFailure("unsatisfiable range body is not JSON") from exc
    if not str(headers.get("content-type", "")).startswith("application/problem+json") \
            or not isinstance(problem, dict) or problem.get("status") != 416 \
            or problem.get("code") != "range_not_satisfiable" \
            or headers.get("content-range") != f"bytes */{total}":
        raise SmokeFailure(f"unsatisfiable range: {problem!r} Content-Range {headers.get('content-range')!r}")
    return {"full_bytes": total, "range": f"bytes={first}-{last}", "range_status": 206,
            "unsatisfiable_status": 416}


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

    def __init__(self, kubectl: list, env: dict, target: str, port: int, namespace: str = APP_NAMESPACE):
        self.proc = subprocess.Popen(
            [*kubectl, "--namespace", namespace, "port-forward", "--address", "127.0.0.1",
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
        self.catalog: dict = {}
        self.standin_image = f"{REGISTRY}/openmettle/{STANDIN}:smoke-{self.run_id}"
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
            **{k: secrets.token_hex(16) for k in ("admin", *DB_LOGINS)},
            "auth_cursor_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "auth_login_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        }
        catalog = smoke_catalog(json.loads((self.core_dir / CORE_CATALOG_FIXTURE).read_text(encoding="utf-8")))
        self.catalog = catalog
        manifests = fixture_manifests(self.core.POSTGRES_IMAGE, self.passwords, self.run_id, catalog)
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(manifests))
        for deployment in ("postgres", PEER):
            self.kube("--namespace", DB_NAMESPACE, "rollout", "status", f"deployment/{deployment}",
                      "--timeout=300s", timeout=330)

    def psql(self, sql: str) -> str:
        """Run `sql` from stdin in one transaction on the openmettle database as the fixture superuser."""
        return self.kube("--namespace", DB_NAMESPACE, "exec", "--stdin", "deployment/postgres", "--",
                         "psql", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-qtA",
                         "-U", "fixture_admin", "-d", "openmettle", input=sql).stdout

    def migrations(self) -> list:
        """Applied migration history, read as the fixture superuser."""
        out = self.psql("SELECT version, success, encode(checksum, 'hex'), installed_on "
                        "FROM openmettle._sqlx_migrations ORDER BY version;")
        return [line.split("|") for line in out.splitlines() if line]

    def helm_deploy(self, command: str, worker_replicas: int, *, enabled_profile: bool = False,
                    gateway_mode: str | None = None, vault_and_backup: bool = False,
                    postgres_client_image: dict | None = None):
        self.values.write_text(json.dumps(smoke_values(self.digests, worker_replicas,
                                                       enabled_profile=enabled_profile,
                                                       gateway_mode=gateway_mode,
                                                       vault_and_backup=vault_and_backup,
                                                       postgres_client_image=postgres_client_image)))
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

    def run_probe_plan(self, plan: list) -> list:
        results = []
        for probe in plan:
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
        return results

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
        results = self.run_probe_plan(probe_plan(dns_ip, peer_ip))
        self.passed("NetworkPolicy enforced: DNS and database egress only, API ingress from the configured peer",
                    namespace_policies=policies,
                    probes=[{"probe": r["name"], "expect": r["expect"], "outcome": r["outcome"]} for r in results])

    def completions(self) -> list:
        return job_completions(self.events("involvedObject.kind=Job"), f"{FULLNAME}-migrate")

    def quota_route_responses(self) -> dict:
        """Each QUOTA_ROUTES request without a cookie, Origin or Authorization, through the API Service."""
        forward = PortForward(self.kubectl, self.env, f"service/{FULLNAME}-api", 8080)
        try:
            return {f"{method} {path}": http_exchange(forward.port, method, path, {})
                    for method, path in QUOTA_ROUTES}
        finally:
            forward.close()

    def seed_session(self) -> str:
        """Seed a synthetic browser session; return its cookie value, which is redacted from then on."""
        session_id, cookie, secret_hash = session_credential(secrets.token_bytes(64))
        self.passwords["session"] = cookie
        self.psql(session_seed_sql(session_id, secret_hash, b64url(secrets.token_bytes(32))))
        return cookie

    def artifact_round_trip(self, api_pods: list, cookie: str) -> dict:
        """Core ADR 0031 /v1/artifacts on the live PVC. Writes alternate between the two API replicas
        and every read goes to the replica that did not write that revision, so the bytes cross pods."""
        forwards = []
        try:
            for name in api_pods:
                forwards.append(PortForward(self.kubectl, self.env, f"pod/{name}", 8080))
            first, second = (forward.port for forward in forwards)

            def send(port, method, path, status, *, key=None, boundary=None, body=b"", byte_range=None):
                headers = v1_headers(cookie, key=key, boundary=boundary, byte_range=byte_range)
                return expect_v1(f"{method} {path.partition('?')[0]}",
                                 http_exchange(port, method, path, headers, body), status)
            v1, v2 = ARTIFACT_PAYLOADS
            boundary_a, boundary_b = ARTIFACT_BOUNDARIES
            query = f"?max_bytes={ARTIFACT_MAX_BYTES}"
            _, body = send(first, "POST", f"/v1/artifacts{query}", 201, key="kind-smoke-create",
                           boundary=boundary_a, body=multipart_form(boundary_a, v1))
            created = evaluate_artifact_revision(body, v1, 1)
            # The exact retry, with another boundary and the file part first, replays revision 1.
            _, body = send(second, "POST", f"/v1/artifacts{query}", 201, key="kind-smoke-create",
                           boundary=boundary_b, body=multipart_form(boundary_b, v1, file_first=True))
            self.expect(evaluate_artifact_revision(body, v1, 1) == created,
                        "idempotent artifact upload retry did not return the same artifact and revision")
            revisions = f"/v1/artifacts/{created['artifact_id']}/revisions"
            _, body = send(first, "POST", f"{revisions}{query}", 201, key="kind-smoke-revision",
                           boundary=boundary_a, body=multipart_form(boundary_a, v2))
            latest = evaluate_artifact_revision(body, v2, 2)
            self.expect(latest["artifact_id"] == created["artifact_id"]
                        and latest["revision_id"] != created["revision_id"],
                        "revision 2 did not append a new revision to the same artifact")
            path = f"{revisions}/{latest['revision_id']}"
            _, body = send(second, "GET", path, 200)
            self.expect(evaluate_artifact_revision(body, v2, 2) == latest,
                        "revision 2 metadata differs from its upload response")
            first_byte, last_byte = ARTIFACT_RANGE
            downloads = evaluate_artifact_downloads(
                v2,
                send(second, "GET", f"{path}/content", 200),
                send(second, "GET", f"{path}/content", 206, byte_range=f"bytes={first_byte}-{last_byte}"),
                send(second, "GET", f"{path}/content", 416, byte_range=UNSATISFIABLE_RANGE))
        finally:
            for forward in forwards:
                forward.close()
        return {"session": "synthetic browser session (cookie channel)", "api_pods": len(forwards),
                "revisions": 2, "idempotent_retry": "same revision from the other replica",
                "downloads": downloads}

    def http_run_admission(self, api_pod: str, cookie: str) -> dict:
        """Admit, replay and cancel one run through POST /v1/runs with the mounted catalog."""
        forward = PortForward(self.kubectl, self.env, f"pod/{api_pod}", 8080)
        try:
            def send(method, path, status, *, key=None, document=None):
                headers = v1_headers(cookie, key=key)
                body = b""
                if document is not None:
                    headers["Content-Type"] = "application/json"
                    body = json.dumps(document).encode()
                return v1_json(f"{method} {path}", http_exchange(forward.port, method, path, headers, body), status)
            models = send("GET", "/v1/models", 200)
            root = send("POST", "/v1/conversations", 201, key=HTTP_RUN_KEYS["conversation"], document={})
            request = run_request(root, str(uuid.uuid4()))
            created = send("POST", "/v1/runs", 201, key=HTTP_RUN_KEYS["run"], document=request)
            replay = send("POST", "/v1/runs", 200, key=HTTP_RUN_KEYS["run"], document=request)
            cancelled = send("POST", f"/v1/runs/{created.get('run_id')}/cancel", 200, key=HTTP_RUN_KEYS["cancel"])
        finally:
            forward.close()
        return evaluate_http_admission(models, created, replay, cancelled)

    def prepare_ingress(self):
        cert, key = self.kubeconfig.parent / "ingress.crt", self.kubeconfig.parent / "ingress.key"
        self.run(ingress_certificate_command(cert, key))
        self.verify_identity()
        self.kube("--namespace", APP_NAMESPACE, "create", "secret", "tls", TLS_SECRET,
                  f"--cert={cert}", f"--key={key}")
        self.verify_identity()
        self.kube("apply", "-f", str(ROOT / "tests/kind/ingress.yaml"))
        self.kube("--namespace", DB_NAMESPACE, "rollout", "status", f"deployment/{INGRESS_CLASS}",
                  "--timeout=180s")
        return cert

    def admit_queued_run(self):
        # Build one test executable against the exact core lockfile using its cached build stage.
        # Only this executable is exported. The chart images and core checkout are unmodified.
        export = self.kubeconfig.parent / "admission"
        recipe = (self.core_dir / "Dockerfile").read_text() + """
FROM build AS admission-build
COPY --from=fixture /admit.rs /source/src/bin/kind-admit.rs
RUN cargo build --release --locked --offline --bin kind-admit
FROM scratch AS admission-export
COPY --from=admission-build /source/target/release/kind-admit /kind-admit
"""
        self.run(["docker", "build", "--builder", "default", "--file", "-", "--target", "admission-export",
                  "--build-context", f"fixture={ROOT / 'tests/kind'}", "--output", f"type=local,dest={export}",
                  str(self.core_dir)], input=recipe, timeout=600)
        pods = self.kube_json("--namespace", DB_NAMESPACE, "get", "pods", "--selector",
                              "app.kubernetes.io/name=postgres")["items"]
        (postgres,) = [pod["metadata"]["name"] for pod in pods if not pod["metadata"].get("deletionTimestamp")]
        self.verify_identity()
        self.kube("--namespace", DB_NAMESPACE, "cp", str(export / "kind-admit"), f"{postgres}:/tmp/kind-admit")
        self.verify_identity()
        result = self.kube("--namespace", DB_NAMESPACE, "exec", "--stdin", postgres, "--", "/tmp/kind-admit",
                           SESSION_IDS["user"], SESSION_IDS["approval"], RUN_KEY, str(QUEUE_TIMEOUT_SECONDS),
                           input=f"postgres://openmettle_api:{self.passwords['api']}@127.0.0.1/openmettle?sslmode=disable\n")
        run_id = result.stdout.strip()
        self.expect(UUID.fullmatch(run_id), "core admission and idempotent replay did not return a run ID")
        return run_id

    def run_row(self, run_id, state):
        # ADR 0032: the keyed row *is* the slot reservation. Two matching rows produce two lines.
        # Read the deadline on the database clock and count the terminal append by its durable key.
        sql = f"""SELECT id::text, state, xmin::text, extract(epoch FROM queue_expires_at),
            claim_token IS NULL AND claimed_at IS NULL AND lease_expires_at IS NULL AND execution_expires_at IS NULL,
            (SELECT count(*) FROM openmettle.run_events e WHERE e.run_id = r.id AND e.append_key = 'run-terminal'
                 AND e.format = 'openmettle.run-expired' AND clock_timestamp() >= r.queue_expires_at)
            FROM openmettle.runs r WHERE actor_user_id = '{SESSION_IDS["user"]}' AND idempotency_key = '{RUN_KEY}'"""
        rows = self.psql(sql).splitlines()
        self.expect(len(rows) == 1, "expected exactly one reservation for the admission key")
        fields = rows[0].split("|")
        self.expect(len(fields) == 6 and fields[:2] == [run_id, state] and fields[2].isdigit() and fields[3]
                    and fields[4:] == ["t", "1" if state == "failed" else "0"],
                    "unexpected run state, lease, queue deadline or expiry event")
        return fields[2], fields[3]

    def replace_apis(self, ready):
        old = {p["metadata"]["uid"] for p in self.pods("api", include_terminating=True)}
        self.expect(len(old) == 2 and self.ready_replicas()["api"] == 2, "expected two Ready API replicas")
        self.verify_identity()
        self.kube("--namespace", APP_NAMESPACE, "rollout", "restart", f"deployment/{FULLNAME}-api")

        def ready_during_restart():
            # Traefik's EndpointSlice watch and kindnet's policy rules converge independently.
            deadline = time.monotonic() + 5
            while (remaining := deadline - time.monotonic()) > 0:
                if ready(timeout=min(INGRESS_READY_TIMEOUT, remaining)):
                    return time.monotonic() <= deadline
                time.sleep(0.25)
            return False

        def replaced():
            self.expect(ready_during_restart(), "HTTPS ingress lost the API during its rolling restart")
            pods = self.pods("api", include_terminating=True)
            return (len(pods) == 2 and old.isdisjoint(p["metadata"]["uid"] for p in pods)
                    and self.ready_replicas()["api"] == 2)
        self.wait_for("two Ready replacement APIs and both original pods gone", replaced, timeout=180)

    def ingress_replay(self, cookie, cert):
        context = ssl.create_default_context(cafile=str(cert))
        headers = v1_headers(cookie)
        with closing(PortForward(self.kubectl, self.env, f"deployment/{INGRESS_CLASS}", 8443,
                                 namespace=DB_NAMESPACE)) as forward:
            port = forward.port

            def ready(timeout=INGRESS_READY_TIMEOUT):
                try:
                    with ingress_get(port, context, "/readyz", {}, timeout=timeout) as response:
                        return response.status == 200
                except (OSError, http.client.HTTPException):
                    return False
            self.wait_for("chart host with verified TLS and ready API backend", ready)
            run_id = self.admit_queued_run()
            deadline = time.monotonic() + QUEUE_TIMEOUT_SECONDS + 20
            path = f"/v1/runs/{run_id}"
            events = path + "/events"

            def snapshot(cursor, terminal=None):
                with ingress_get(port, context, path, headers) as response:
                    received = ingress_headers("getRun", response, 200)
                    self.expect(received.get("content-type") == "application/json", "getRun returned non-JSON")
                    check_snapshot(response.read(65536), run_id, cursor, terminal)

            row = self.run_row(run_id, "queued")
            with event_stream(port, context, events, headers) as stream:
                created = expect_event(stream, run_id, 1, "run.created", {}, deadline=deadline)
            snapshot(created[0])
            resume = {**headers, "Last-Event-ID": created[0]}
            with event_stream(port, context, events, resume) as stream:
                seconds = quiet_heartbeats(stream)
                self.expect(self.run_row(run_id, "queued") == row, "SSE traffic changed the queued run")
            self.replace_apis(ready)
            self.wait_for("HTTPS ingress ready on replacement APIs", ready)
            with event_stream(port, context, events, resume) as stream:
                self.expect(self.run_row(run_id, "queued") == row, "pod replacement changed the queued run")
                expired = expect_event(stream, run_id, 2, "run.failed", {"reason": "queue_expired"}, deadline=deadline)
                self.expect(sse_frame(stream) is None, "stream continued after the terminal event")
            self.expect(expired[0] != created[0], "terminal event reused the creation cursor")
            snapshot(*expired)
            self.expect(self.run_row(run_id, "failed")[1] == row[1], "queue deadline changed during replay")
            with event_stream(port, context, events, headers) as stream:
                for expected in (created, expired):
                    item = expected[1]
                    actual = expect_event(stream, run_id, item["sequence"], item["type"], item["data"], deadline=deadline)
                    self.expect(actual == expected, "replay changed an event or its cursor")
                self.expect(sse_frame(stream) is None, "duplicate event after terminal replay")
            with ingress_get(port, context, events, {**headers, "Last-Event-ID": expired[0]}) as response:
                ingress_headers("resume past terminal", response, 204)
                self.expect(not response.read(1), "resume past terminal returned a body")
        return {"api_replicas_replaced": 2, "quiet_seconds": seconds, "periodic_heartbeats": 2,
                "reservations": 1, "sequences": [1, 2], "terminal": "queue_expired", "past_terminal_http": 204}

    def enabled_profile(self, history: list):
        """Upgrade to an enabled profile and verify live PDB, PVC and ARTIFACTS_DIR store, auth + /v1/* mounts,
        a /v1/artifacts round trip across both API replicas and JSON/debug logs."""
        cert = self.prepare_ingress()
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
        issuance = check_issuance_env(pods_by_role, self.helm_run("get", "hooks", RELEASE).stdout, enabled=True)
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
        quota_routes = evaluate_quota_routes(self.quota_route_responses(), mounted=True)
        pdb = self.wait_for(
            "API PodDisruptionBudget disruptionsAllowed >= 1",
            lambda: evaluate_pdb(self.kube_json("--namespace", APP_NAMESPACE,
                                                "get", "poddisruptionbudget", API_PDB)),
            timeout=60)
        pvc = check_artifacts_pvc(
            self.kube_json("--namespace", APP_NAMESPACE, "get", "persistentvolumeclaim", ARTIFACTS_CLAIM),
            pods_by_role)
        for role in WORKLOADS:
            for pod_name in profile["pods"][role]:
                listed = self.kube("--namespace", APP_NAMESPACE, "exec", pod_name, "--container", role, "--",
                                   *artifact_dirs_command(), timeout=60)
                evaluate_artifact_dirs(pod_name, listed.stdout)
        pvc["store_subdirectories"] = list(ARTIFACT_SUBDIRS)
        cookie = self.seed_session()
        artifacts = self.artifact_round_trip(profile["pods"]["api"], cookie)
        # Cancelled before check 11, so its fixture admission still finds no live run for the actor.
        http_admission = self.http_run_admission(profile["pods"]["api"][0], cookie)
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
        self.passed("enabled-profile upgrade: API replicas=2, PDB, artifact PVC and ARTIFACTS_DIR store, auth + /v1/* mounts, "
                    "unauthenticated /v1 quota routes 401, API-only issuance credential, /v1/artifacts upload, "
                    "retry, revision and byte ranges on the PVC, catalog-backed POST /v1/runs admission, "
                    "and JSON/debug logs",
                    ready_replicas=profile["ready_replicas"],
                    healthz=exchanged["/healthz"][0], readyz=exchanged["/readyz"][0],
                    pdb=pdb, pvc=pvc, auth=auth_summary, quota_routes=quota_routes, issuance=issuance,
                    artifacts=artifacts, run_admission_http=http_admission,
                    logs=logs_summary)
        self.passed("HTTPS ingress queued run replay and worker expiry",
                    **self.ingress_replay(cookie, cert))
        self.gateway_end_to_end(history, cookie)
        self.vault_and_backup(history)

    def pin_postgres_client_image(self) -> tuple:
        """Ensure the already-pulled PostgreSQL 18 fixture image resolves under its tagless digest name."""
        parts = postgres_client_image_parts(self.core.POSTGRES_IMAGE)
        reference = f"{parts['registry']}/{parts['repository']}@{parts['digest']}"
        listing = self.node_exec("ctr", "--namespace=k8s.io", "images", "ls").stdout
        if reference not in ctr_image_names(listing):
            source = find_ctr_image_for_digest(listing, parts["digest"], preferred=self.core.POSTGRES_IMAGE)
            self.node_exec("ctr", "--namespace=k8s.io", "images", "tag", source, reference)
        self.wait_for(f"CRI to resolve {reference}",
                      lambda r=reference: self.cri_image_id(r, check=False), timeout=30)
        return parts, reference

    def vault_and_backup(self, history: list):
        """Exercise opt-in vault 0400 RAM staging on api/worker and backup CronJob capture + verify (rev 7)."""
        pg_client_parts, pg_client_ref = self.pin_postgres_client_image()
        vault_key_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        backup_key_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        self.passwords["vault_key"] = vault_key_b64
        self.passwords["backup_key"] = backup_key_b64
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(
            vault_and_backup_fixture_manifests(vault_key_b64, backup_key_b64, self.run_id)))
        self.helm_deploy("upgrade", worker_replicas=1, enabled_profile=True, gateway_mode="tls",
                         vault_and_backup=True, postgres_client_image=pg_client_parts)
        for deployment in (f"{FULLNAME}-api", f"{FULLNAME}-worker", GATEWAY_WORKLOAD):
            self.kube("--namespace", APP_NAMESPACE, "rollout", "status", f"deployment/{deployment}",
                      f"--timeout={PROFILE_ROLLOUT_TIMEOUT}", timeout=210)
        profile = self.observe_release(revision=7)
        self.expect(len(self.completions()) == 7, "vault/backup upgrade did not run the migrate hook")
        self.expect(self.migrations() == history, "migration history changed on vault/backup upgrade")
        gw_pods = self.observe_gateway_pod()
        pods_by_role = {**{c: self.pods(c) for c in WORKLOADS}, GATEWAY_COMPONENT: gw_pods}
        cronjob = self.kube_json("--namespace", APP_NAMESPACE, "get", "cronjob", BACKUP_CRONJOB)
        backup_np = self.kube_json("--namespace", APP_NAMESPACE, "get", "networkpolicy", BACKUP_NETWORK_POLICY)
        spec_summary = check_vault_and_backup_spec(
            pods_by_role, cronjob, backup_np,
            admin_ref=self.report["images"]["admin"]["reference"],
            postgres_client_ref=pg_client_ref,
        )
        for role in WORKLOADS:
            for pod_name in profile["pods"][role]:
                listed = self.kube("--namespace", APP_NAMESPACE, "exec", pod_name, "--container", role, "--",
                                   *vault_key_files_command(), timeout=60)
                evaluate_vault_key_files(pod_name, listed.stdout)
        self.verify_identity()
        self.kube("--namespace", APP_NAMESPACE, "create", "job", BACKUP_RUN_JOB, f"--from=cronjob/{BACKUP_CRONJOB}")
        self.kube("--namespace", APP_NAMESPACE, "wait", "--for=condition=complete",
                  f"job/{BACKUP_RUN_JOB}", "--timeout=180s", timeout=210)
        capture_logs = self.kube("--namespace", APP_NAMESPACE, "logs", f"job/{BACKUP_RUN_JOB}",
                                 "--container", "backup", timeout=60).stdout
        dest_root = spec_summary["destination_root"]
        capture = parse_backup_capture_log(capture_logs, dest_root)
        backup_row = evaluate_backup_run_row(
            self.psql(backup_run_sql(capture["run_id"])), capture["run_id"], capture["bundle_digest"])
        admin_ref = self.report["images"]["admin"]["reference"]
        present = images_reported_present(self.events("reason=Pulled"), [admin_ref, pg_client_ref])
        self.expect(present == sorted([admin_ref, pg_client_ref]),
                    f"kubelet did not report backup digest references as present: {present}")
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(
            backup_verify_job_manifest(admin_ref, capture["dir"], self.run_id, dest_root)))
        self.kube("--namespace", APP_NAMESPACE, "wait", "--for=condition=complete",
                  f"job/{BACKUP_VERIFY_JOB}", "--timeout=120s", timeout=150)
        verify_logs = self.kube("--namespace", APP_NAMESPACE, "logs", f"job/{BACKUP_VERIFY_JOB}",
                                "--container", "verify", timeout=60).stdout
        verified = parse_backup_verify_log(verify_logs, capture["run_id"])
        self.verify_identity()
        self.kube("--namespace", APP_NAMESPACE, "delete", "job", BACKUP_RUN_JOB, BACKUP_VERIFY_JOB,
                  "--wait=true", timeout=120)
        self.passed("opt-in vault RAM-staged 0400 keys and backup CronJob capture + offline verify",
                    spec=spec_summary,
                    vault_staged_pods=sum(len(profile["pods"][r]) for r in WORKLOADS),
                    backup_run=backup_row,
                    verified=verified)

    def prepare_gateway_fixtures(self):
        """Build & deploy the synthetic SGLang stand-in and apply plain/TLS inference fixtures."""
        _log(f"building {self.standin_image} from cached core build stage (local only; never pushed)")
        recipe = (self.core_dir / "Dockerfile").read_text() + """
FROM build AS standin-build
COPY --from=fixture /standin.rs /source/src/bin/kind-standin.rs
RUN cargo build --release --locked --offline --bin kind-standin
FROM runtime AS standin-runtime
COPY --from=standin-build /source/target/release/kind-standin /usr/local/bin/kind-standin
EXPOSE 30000
ENTRYPOINT ["/usr/local/bin/kind-standin"]
"""
        self.run(["docker", "build", "--builder", "default", "--file", "-", "--target", "standin-runtime",
                  "--build-context", f"fixture={ROOT / 'tests/kind'}", "--tag", self.standin_image,
                  str(self.core_dir)], input=recipe, timeout=600)
        self.built_images.append(self.standin_image)
        self.run(["kind", "load", "docker-image", self.standin_image, "--name", self.name], timeout=300)
        work = self.kubeconfig.parent
        ca_cert, ca_key = work / "gw-ca.crt", work / "gw-ca.key"
        leaf_csr, leaf_key, leaf_ext, leaf_cert = (
            work / "gw-leaf.csr", work / "gw-leaf.key", work / "gw-leaf.ext", work / "gw-leaf.crt")
        ext_body, commands = gateway_tls_commands(ca_cert, ca_key, leaf_csr, leaf_key, leaf_ext, leaf_cert)
        leaf_ext.write_text(ext_body, encoding="utf-8")
        for command in commands:
            self.run(command)
        ca_pem = ca_cert.read_text(encoding="utf-8")
        self.verify_identity()
        self.kube("apply", "--filename", "-", input=json.dumps(standin_manifests(self.standin_image, self.run_id)))
        self.kube("--namespace", DB_NAMESPACE, "rollout", "status", f"deployment/{STANDIN}",
                  "--timeout=180s", timeout=210)
        self.verify_identity()
        self.kube("--namespace", APP_NAMESPACE, "create", "secret", "tls", GATEWAY_TLS_SECRET,
                  f"--cert={leaf_cert}", f"--key={leaf_key}")
        self.verify_identity()
        self.kube("apply", "--filename", "-",
                  input=json.dumps(inference_fixture_manifests(ca_pem, self.catalog, self.run_id)))
        return ca_cert

    def observe_gateway_pod(self) -> list:
        """Verify gateway-a pod runs the digest-pinned gateway image cleanly under CRI and passes /readyz."""
        gw_pods = self.pods(GATEWAY_COMPONENT)
        self.expect(len(gw_pods) == 1, f"expected one {GATEWAY_COMPONENT} pod, found {len(gw_pods)}")
        pod = gw_pods[0]
        ready = {c["type"]: c["status"] for c in pod["status"].get("conditions", [])}.get("Ready")
        self.expect(ready == "True", f"{GATEWAY_COMPONENT} pod is not Ready")
        self.expect(all(c.get("restartCount") == 0 for c in pod["status"]["containerStatuses"]),
                    f"{GATEWAY_COMPONENT} container restarted")
        container = pod["spec"]["containers"][0]
        image = self.report["images"]["gateway"]
        self.expect(container["image"] == image["reference"] and container["imagePullPolicy"] == "Never",
                    f"{GATEWAY_COMPONENT} pod does not run {image['reference']} with pullPolicy Never")
        status = pod["status"]["containerStatuses"][0]
        container_id = status.get("containerID", "").removeprefix("containerd://")
        self.expect(bool(container_id), f"{GATEWAY_COMPONENT} container has no containerd id")
        running = parse_cri_container_image_id(self.node_exec(
            "crictl", "ps", "--id", container_id, "--output", "json").stdout)
        self.expect(running == image["cri_image_id"],
                    f"{GATEWAY_COMPONENT} container runs image {running}, not {image['cri_image_id']}")
        present = images_reported_present(self.events("reason=Pulled"), [image["reference"]])
        self.expect(present == [image["reference"]],
                    f"kubelet did not report gateway digest reference as present: {present}")
        forward = PortForward(self.kubectl, self.env, f"service/{GATEWAY_WORKLOAD}", 8082)
        try:
            self.wait_for(f"{GATEWAY_COMPONENT} /readyz 200",
                          lambda: self.core.http_get(forward.port, "/readyz")[0] == 200, timeout=30)
        finally:
            forward.close()
        return gw_pods

    def execute_turn_through_gateway(self, api_pod: str, cookie: str, *, mode: str,
                                     expected_records: int) -> dict:
        """Admit a run, wait for worker -> gateway -> stand-in execution, and verify settlement + cache_salt."""
        forward = PortForward(self.kubectl, self.env, f"pod/{api_pod}", 8080)
        try:
            def send(method, path, status, *, key=None, document=None):
                headers = v1_headers(cookie, key=key)
                body = b""
                if document is not None:
                    headers["Content-Type"] = "application/json"
                    body = json.dumps(document).encode()
                return v1_json(f"{method} {path}", http_exchange(forward.port, method, path, headers, body), status)

            root = send("POST", "/v1/conversations", 201, key=f"kind-smoke-gw-conv-{mode}", document={})
            request = run_request(root, str(uuid.uuid4()))
            created = send("POST", "/v1/runs", 201, key=f"kind-smoke-gw-run-{mode}", document=request)
            run_id = created.get("run_id")
            self.expect(bool(UUID.fullmatch(str(run_id))), f"gateway {mode}: POST /v1/runs returned invalid run_id")

            def succeeded():
                snap = send("GET", f"/v1/runs/{run_id}", 200)
                state = snap.get("state")
                if state in ("failed", "cancelled"):
                    raise SmokeFailure(f"gateway {mode}: run reached unexpected terminal state {state!r}: {snap!r}")
                return snap if state == "succeeded" else None

            self.wait_for(f"gateway {mode} run to succeed", succeeded, timeout=60, interval=0.5)
            messages = send(
                "GET", f"/v1/conversations/{root['conversation_id']}/branches/{root['branch_id']}/messages", 200)
            items = messages.get("items") or []
            assistant = next((m for m in items if m.get("role") == "assistant"), None)
            self.expect(
                assistant is not None
                and (assistant.get("parts") or [{}])[0].get("text") == STANDIN_EXPECTED_CONTENT
                and assistant.get("input_count") == str(STANDIN_EXPECTED_PROMPT_TOKENS)
                and assistant.get("output_count") == str(STANDIN_EXPECTED_COMPLETION_TOKENS),
                f"gateway {mode}: unexpected assistant message {assistant!r}",
            )
        finally:
            forward.close()
        settled = self.wait_for(
            f"gateway {mode} usage report and quota settlement",
            lambda: evaluate_settled_round(self.psql(settled_round_sql(run_id))),
            timeout=30, interval=0.5,
        )
        standin_fwd = PortForward(self.kubectl, self.env, f"service/{STANDIN}", STANDIN_PORT,
                                  namespace=DB_NAMESPACE)
        try:
            status, _, raw = http_exchange(standin_fwd.port, "GET", "/_recorded", {})
            self.expect(status == 200, f"stand-in GET /_recorded returned HTTP {status}")
            records = json.loads(raw)
        finally:
            standin_fwd.close()
        self.expect(isinstance(records, list) and len(records) == expected_records,
                    f"gateway {mode}: expected {expected_records} recorded upstream call(s), found {len(records)}")
        upstream = evaluate_standin_record(records[-1], settled["request_id"])
        return {"run_state": "succeeded", "assistant_content": STANDIN_EXPECTED_CONTENT,
                "settlement": {k: v for k, v in settled.items() if k != "request_id"},
                "upstream": upstream}

    def gateway_end_to_end(self, history: list, cookie: str):
        """Exercise both plain-HTTP and external TLS-terminated gateway + worker.inference topologies."""
        gw_ca_cert = self.prepare_gateway_fixtures()
        for step, (mode, revision, expected_records) in enumerate(
                (("plain", 5, 1), ("tls", 6, 2)), start=1):
            tls = mode == "tls"
            self.helm_deploy("upgrade", worker_replicas=1, enabled_profile=True, gateway_mode=mode)
            for deployment in (f"{FULLNAME}-worker", GATEWAY_WORKLOAD):
                self.kube("--namespace", APP_NAMESPACE, "rollout", "status", f"deployment/{deployment}",
                          f"--timeout={PROFILE_ROLLOUT_TIMEOUT}", timeout=210)
            profile = self.observe_release(revision=revision)
            self.expect(len(self.completions()) == revision,
                        f"gateway {mode} upgrade did not run the migrate hook")
            self.expect(self.migrations() == history,
                        f"migration history changed on gateway {mode} upgrade")
            gw_pods = self.observe_gateway_pod()
            pods_by_role = {**{c: self.pods(c) for c in WORKLOADS}, GATEWAY_COMPONENT: gw_pods}
            mounts_summary = check_inference_and_gateway_mounts(pods_by_role, tls=tls)
            gw_logs = self.wait_for(
                f"gateway ({mode}) ADR 0024 JSON structured logs",
                lambda gp=gw_pods: evaluate_structured_logs(
                    "gateway",
                    {p["metadata"]["name"]: self.kube("--namespace", APP_NAMESPACE, "logs", p["metadata"]["name"],
                                                      "--container", "gateway", timeout=60).stdout
                     for p in gp}),
                timeout=30,
            )
            probes = self.run_probe_plan(gateway_probe_plan(tls=tls))
            if tls:
                gw_context = ssl.create_default_context(cafile=str(gw_ca_cert))
                with closing(PortForward(self.kubectl, self.env, f"deployment/{INGRESS_CLASS}", 8443,
                                         namespace=DB_NAMESPACE)) as forward:
                    def tls_ready():
                        try:
                            with ingress_get(forward.port, gw_context, "/readyz", {},
                                             timeout=INGRESS_READY_TIMEOUT, host=GATEWAY_TLS_HOST) as response:
                                return response.status == 200
                        except (OSError, http.client.HTTPException):
                            return False
                    self.wait_for("Traefik TLS terminator ready for gateway-a backend", tls_ready, timeout=60)
            turn = self.execute_turn_through_gateway(
                profile["pods"]["api"][0], cookie, mode=mode, expected_records=expected_records)
            self.passed(
                f"gateway + worker.inference end-to-end ({mode} topology, step {step}/2)",
                mounts=mounts_summary,
                gateway_logs=gw_logs,
                probes=[{"probe": r["name"], "expect": r["expect"], "outcome": r["outcome"]} for r in probes],
                turn=turn,
            )

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
        self.expect(int(history[-1][0]) >= REQUIRED_MIGRATION,
                    f"migration history ends at version {history[-1][0]}, before migration {REQUIRED_MIGRATION}")
        run_admission = evaluate_run_admission(self.psql(run_admission_sql()))
        gateway_schema = evaluate_gateway_schema(self.psql(gateway_schema_sql()))
        migration_38_45 = evaluate_migration_38_45(self.psql(migration_38_45_sql()))
        fresh_bootstrap = evaluate_fresh_bootstrap(self.psql(FRESH_BOOTSTRAP_SQL))
        created = {c: parse_time(self.kube_json("--namespace", APP_NAMESPACE, "get", "deployment",
                                                f"{FULLNAME}-{c}")["metadata"]["creationTimestamp"])
                   for c in WORKLOADS}
        first = runs[0].replace(microsecond=0)
        self.expect(all(first <= when for when in created.values()),
                    "migrate Job completed after the Deployments were created")
        references = [self.report["images"][r]["reference"] for r in DEFAULT_ROLES]
        present = images_reported_present(self.events("reason=Pulled"), references)
        self.expect(present == sorted(references),
                    f"kubelet did not report every digest reference as present: {present}")
        self.passed("install by digest: migrate hook completed before Deployments; API and worker Ready; "
                    "migrations 19/20/37 and 38-45 role boundaries; fresh-install quota and artifact-volume markers",
                    migrations_applied=len(history), latest_version=int(history[-1][0]),
                    run_admission=run_admission, gateway_schema=gateway_schema,
                    migration_38_45=migration_38_45, fresh_bootstrap=fresh_bootstrap,
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
        unmounted_quota = evaluate_quota_routes(self.quota_route_responses(), mounted=False)
        issuance = check_issuance_env({c: self.pods(c) for c in WORKLOADS},
                                      self.helm_run("get", "hooks", RELEASE).stdout, enabled=False)
        self.passed("no optional package present", release_objects=inventory, helm_releases=1,
                    unmounted_http=unmounted_http, unmounted_quota_routes=unmounted_quota, issuance=issuance)

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
            left += object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", "endpointslices",
                                                "--selector", f"kubernetes.io/service-name={GATEWAY_WORKLOAD}")["items"])
            return left
        self.wait_for("release objects to be removed", lambda: not residue(), timeout=120)
        releases = json.loads(self.helm_run("list", "--output", "json").stdout)
        self.expect(releases == [], f"Helm still lists a release: {releases}")
        # Chart-owned artifact PVC carries helm.sh/resource-policy: keep and survives uninstall.
        kept_pvcs = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get", "persistentvolumeclaims",
                                                "--selector", f"app.kubernetes.io/instance={RELEASE}")["items"])
        self.expect(kept_pvcs == [f"PersistentVolumeClaim/{ARTIFACTS_CLAIM}"],
                    f"kept artifact PVC after uninstall: {kept_pvcs}")
        # The test, not the chart, owns the five URL Secrets (including issuance and gateway),
        # synthetic auth/inference/vault/backup fixtures, backup destination PVC and namespace default-deny.
        remaining = object_names(self.kube_json("--namespace", APP_NAMESPACE, "get",
                                                "configmaps,secrets,networkpolicies,persistentvolumeclaims",
                                                "--selector", RUN_LABEL)["items"])
        expected_owned = sorted([
            f"ConfigMap/{AUTH_CONFIG_MAP}",
            f"ConfigMap/{INFERENCE_PLAIN_CONFIG_MAP}",
            f"ConfigMap/{INFERENCE_TLS_CONFIG_MAP}",
            f"ConfigMap/{INFERENCE_CA_CONFIG_MAP}",
            f"NetworkPolicy/{NAMESPACE_DENY}",
            f"PersistentVolumeClaim/{BACKUP_DEST_CLAIM}",
            f"Secret/{AUTH_LOGIN_KEYS_SECRET}",
            f"Secret/{BACKUP_KEYS_SECRET}",
            f"Secret/{VAULT_KEYS_SECRET}",
            *(f"Secret/{SECRET[r]}" for r in DB_LOGINS),
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
                     ["--namespace", APP_NAMESPACE, "get", "pvc,pdb,cronjobs,jobs", "--output=wide"],
                     ["--namespace", DB_NAMESPACE, "logs", "--selector", f"app={INGRESS_CLASS}", "--tail=50"],
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
