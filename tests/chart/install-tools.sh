#!/usr/bin/env bash
# Download pinned Helm and kubeconform into a new, empty directory and verify their SHA-256 digests.
# linux/amd64 only (the hosted CI runner). Installs nothing globally; never run as root.
# Modelled on openmettle-core tests/kubernetes/install-tools.sh. Origins and licences: UPSTREAM.md.
set -euo pipefail

# Digests resolved 2026-11-19 from the projects' published checksum files and cross-checked
# against the downloaded archives:
#   https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz.sha256sum
#   https://github.com/yannh/kubeconform/releases/download/v0.8.0/CHECKSUMS
HELM_VERSION=v4.3.0
HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
KUBECONFORM_VERSION=v0.8.0
KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883

dest="${1:?usage: install-tools.sh NEW_EMPTY_DIRECTORY}"
if [ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]; then
  echo "Pinned digests are recorded for linux/amd64 only." >&2
  exit 2
fi
if [ "$(id -u)" = 0 ]; then
  echo "Refusing to run as root." >&2
  exit 2
fi
if [ -e "$dest" ] && [ -n "$(ls -A -- "$dest")" ]; then
  echo "Refusing to write into non-empty $dest." >&2
  exit 2
fi
mkdir -p "$dest"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Verify the archive digest before extracting exactly one named member.
fetch() {
  local name="$1" url="$2" sha="$3" member="$4"
  curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 \
    --output "$work/$name.tar.gz" "$url"
  echo "$sha  $work/$name.tar.gz" | sha256sum --check --strict --quiet -
  mkdir "$work/$name"
  tar -xzf "$work/$name.tar.gz" -C "$work/$name" --no-same-owner "$member"
  install -m 0755 "$work/$name/$member" "$dest/$name"
}

fetch helm "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_SHA256" linux-amd64/helm
fetch kubeconform \
  "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-linux-amd64.tar.gz" \
  "$KUBECONFORM_SHA256" kubeconform
"$dest/helm" version
"$dest/kubeconform" -v
