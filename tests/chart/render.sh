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

# The Helm version the tests were written against (tests/chart/install-tools.sh).
HELM_VERSION=v4.3.0

# Each entry is a release name followed by overlays applied on top of minimal.yaml.
matrix=(
  "openmettle"
  "openmettle all-keys.yaml"
  "openmettle migration-disabled.yaml"
  "123 yaml-ambiguous.yaml"
)

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

helm_version=$("$helm" version --template '{{ .Version }}')
if [ "$helm_version" != "$HELM_VERSION" ]; then
  echo "Expected Helm $HELM_VERSION, found $helm_version." >&2
  exit 1
fi
echo "Helm $helm_version"
"$kubeconform" -v
for entry in "${matrix[@]}"; do
  read -r -a fields <<< "$entry"
  release=${fields[0]}
  args=(-f "$values/minimal.yaml")
  for overlay in "${fields[@]:1}"; do
    args+=(-f "$values/$overlay")
  done
  echo "== $entry"
  "$helm" lint --strict "$chart" "${args[@]}"
  "$helm" template "$release" "$chart" "${args[@]}" > "$out/rendered.yaml"
  "$kubeconform" -strict -summary -kubernetes-version "$KUBERNETES_VERSION" \
    -schema-location "$schema_location" "$out/rendered.yaml"
done
