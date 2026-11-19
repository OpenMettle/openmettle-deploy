#!/usr/bin/env bash
# Lint and render the core chart for each synthetic values set, then validate the output with
# kubeconform against pinned Kubernetes schemas. Uses helm and kubeconform from PATH, or HELM and
# KUBECONFORM. Negative cases and policy assertions live in the Python unit tests.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
chart="$root/charts/openmettle-core"
values="$root/tests/chart/values"
helm="${HELM:-helm}"
kubeconform="${KUBECONFORM:-kubeconform}"

# Kubernetes version: the kind node pinned by openmettle-core tests/kubernetes/qualify.py.
# Schemas: yannh/kubernetes-json-schema (Apache-2.0) pinned to master as of 2026-11-19.
KUBERNETES_VERSION=1.37.0
SCHEMA_COMMIT=11639286f15b208b6c7f1f93bc2c1a70f42cfbcb
schema_location="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/$SCHEMA_COMMIT/{{ .NormalizedKubernetesVersion }}-standalone{{ .StrictSuffix }}/{{ .ResourceKind }}{{ .KindSuffix }}.json"

# Each entry is a space-separated list of overlays applied on top of minimal.yaml.
matrix=(
  ""
  "all-keys.yaml"
  "migration-disabled.yaml"
)

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

"$helm" version --short
"$kubeconform" -v
for entry in "${matrix[@]}"; do
  args=(-f "$values/minimal.yaml")
  for overlay in $entry; do
    args+=(-f "$values/$overlay")
  done
  name=${entry:-minimal}
  echo "== $name"
  "$helm" lint --strict "$chart" "${args[@]}"
  "$helm" template openmettle "$chart" "${args[@]}" > "$out/rendered.yaml"
  "$kubeconform" -strict -summary -kubernetes-version "$KUBERNETES_VERSION" \
    -schema-location "$schema_location" "$out/rendered.yaml"
done
