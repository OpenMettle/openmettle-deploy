{{/*
Names are truncated to 52 characters so that "<fullname>-migrate" stays within 63.
*/}}
{{- define "openmettle-core.name" -}}
{{- .Chart.Name | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "openmettle-core.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
CronJob names are limited to 52 DNS characters so the CronJob controller can append a 10-digit
timestamp ("-<ts>") within Kubernetes' 63-character Job name limit.
*/}}
{{- define "openmettle-core.backupCronJobName" -}}
{{- $fullname := include "openmettle-core.fullname" . -}}
{{- $candidate := printf "%s-backup" $fullname -}}
{{- if le (len $candidate) 52 -}}
{{- $candidate -}}
{{- else -}}
{{- $hash := substr 0 8 (sha256sum (printf "%s/%s" .Release.Name .Chart.Name)) -}}
{{- printf "%s-%s-backup" ($fullname | trunc 36 | trimSuffix "-") $hash -}}
{{- end -}}
{{- end -}}

{{/*
POSIX /bin/sh snippet staging a Secret volume into 0400 regular files inside a 0700 subdirectory of
a RAM-backed emptyDir, rejecting dot-prefixed Secret entries and verifying that the keyring JSON
manifest and every 32-byte key file it references under mountDir exist.
Arguments: dict "label" "vault|backup" "srcDir" <path> "stageDir" <path> "mountDir" <path> "configKey" <key>
*/}}
{{- define "openmettle-core.stageKeyringScript" -}}
stage={{ .stageDir | quote }}
src_dir={{ .srcDir | quote }}
mount_dir={{ .mountDir | quote }}
cfg_key={{ .configKey | quote }}
if [ -d "$stage" ]; then
  chmod -R u+w "$stage"
  rm -rf -- "$stage"
fi
mkdir -p -- "$stage"
chmod 0700 "$stage"
for hidden in "$src_dir"/.*; do
  base="${hidden##*/}"
  case "$base" in
    .|..|..data|..[0-9]*) continue ;;
  esac
  if [ -e "$hidden" ] || [ -L "$hidden" ]; then
    echo "dot-prefixed {{ .label }} Secret entry is not allowed: $base" >&2
    exit 78
  fi
done
for src in "$src_dir"/*; do
  [ -f "$src" ] || continue
  dst="$stage/${src##*/}"
  cp -L -- "$src" "$dst"
  chmod 0400 "$dst"
done
[ -f "$stage/$cfg_key" ] || { echo "missing {{ .label }} keyring config: $cfg_key" >&2; exit 78; }
refs_list="${stage%/*}/.refs"
tr '\n\r\t{}' '   \n\n' < "$stage/$cfg_key" | sed -n 's/.*"file"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' > "$refs_list"
[ -s "$refs_list" ] || { rm -f -- "$refs_list"; echo "invalid {{ .label }} keyring config: missing referenced key files" >&2; exit 78; }
while IFS= read -r rel_path; do
  case "$rel_path" in
    "$mount_dir/"*) rel="${rel_path#"$mount_dir/"}" ;;
    *) rm -f -- "$refs_list"; echo "{{ .label }} key file outside $mount_dir: $rel_path" >&2; exit 78 ;;
  esac
  case "$rel" in
    ""|*/*|.*) rm -f -- "$refs_list"; echo "invalid {{ .label }} key file name: $rel" >&2; exit 78 ;;
  esac
  [ "$rel" != "$cfg_key" ] || { rm -f -- "$refs_list"; echo "{{ .label }} key file must differ from keyring config: $rel" >&2; exit 78; }
  [ -f "$stage/$rel" ] || { rm -f -- "$refs_list"; echo "missing referenced {{ .label }} key file: $rel" >&2; exit 78; }
  [ "$(wc -c < "$stage/$rel")" -eq 32 ] || { rm -f -- "$refs_list"; echo "{{ .label }} key file must be 32 bytes: $rel" >&2; exit 78; }
done < "$refs_list"
rm -f -- "$refs_list"
{{- end -}}

{{/* Labels on every pod of this release, whatever its component. Argument: the root context. */}}
{{- define "openmettle-core.releaseSelectorLabels" -}}
app.kubernetes.io/name: {{ include "openmettle-core.name" . }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{/* Arguments: dict "root" $ "component" "api|worker|migrate" */}}
{{- define "openmettle-core.selectorLabels" -}}
{{ include "openmettle-core.releaseSelectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "openmettle-core.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "openmettle-core.selectorLabels" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service | quote }}
app.kubernetes.io/part-of: openmettle
{{- end -}}

{{/* Arguments: dict "root" $ "component" "api|worker|migrate|gateway-<name>" "serviceAccount" <values> ["field" <values path>] */}}
{{- define "openmettle-core.serviceAccountName" -}}
{{- $field := default (ternary "migration" .component (eq .component "migrate")) .field -}}
{{- include "openmettle-core.validate.bool" (dict "field" (printf "%s.serviceAccount.create" $field) "value" .serviceAccount.create) -}}
{{- if .serviceAccount.create -}}
{{- default (printf "%s-%s" (include "openmettle-core.fullname" .root) .component) .serviceAccount.name -}}
{{- else -}}
{{- required (printf "%s.serviceAccount.name is required when serviceAccount.create is false; components never share the default ServiceAccount" $field) .serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Digest-only image reference. Arguments: dict "name" "api|worker|migrate" "image" <values>.
The schema enforces the same pattern; this guard also holds under --skip-schema-validation.
*/}}
{{- define "openmettle-core.image" -}}
{{- $repository := required (printf "images.%s.repository is required" .name) .image.repository -}}
{{- $digest := required (printf "images.%s.digest is required (sha256:<64 lowercase hex>); tags are not accepted" .name) .image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail (printf "images.%s.digest must be sha256:<64 lowercase hex>; tags are not accepted" .name) -}}
{{- end -}}
{{- if or (contains ":" $repository) (contains "@" $repository) -}}
{{- fail (printf "images.%s.repository must not contain a tag or digest" .name) -}}
{{- end -}}
{{- if .image.registry -}}
{{- printf "%s/%s@%s" .image.registry $repository $digest -}}
{{- else -}}
{{- printf "%s@%s" $repository $digest -}}
{{- end -}}
{{- end -}}

{{/* Arguments: dict "name" "api|worker|migrate" "ref" <database values> */}}
{{- define "openmettle-core.databaseUrlEnv" -}}
valueFrom:
  secretKeyRef:
    name: {{ required (printf "database.%s.existingSecret is required (an existing Secret holding the PostgreSQL URL)" .name) .ref.existingSecret | quote }}
    key: {{ required (printf "database.%s.key is required" .name) .ref.key | quote }}
{{- end -}}

{{/*
Matches the core images (USER 65532:65532) and the restricted Pod Security Standard.
Arguments: dict "storage" <bool> "auth" <bool>. fsGroup is set on pods that mount the artifact
volume (so a freshly provisioned volume is writable by the non-root user) or the API login keys
Secret (so mode 0440 key files are readable by GID 65532 without world-read permission).
fsGroupChangePolicy applies only to persistent volumes.
*/}}
{{- define "openmettle-core.podSecurityContext" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  {{- if or .storage .auth (default false .vault) }}
  fsGroup: 65532
  {{- end }}
  {{- if .storage }}
  fsGroupChangePolicy: OnRootMismatch
  {{- end }}
  seccompProfile:
    type: RuntimeDefault
{{- end -}}

{{/*
Fixed in-pod paths. The database URL's sslrootcert must name the CA file exactly. Auth and OTLP CA
paths are non-overlapping sibling directories under /etc/openmettle so read-only ConfigMap mounts
never block nested mountpoints under containerd/runc.
*/}}
{{- define "openmettle-core.artifactsMountPath" -}}/var/lib/openmettle/artifacts{{- end -}}
{{- define "openmettle-core.databaseCaDirectory" -}}/etc/openmettle/db-ca{{- end -}}
{{- define "openmettle-core.authConfigDirectory" -}}/etc/openmettle/auth{{- end -}}
{{- define "openmettle-core.authConfigPath" -}}/etc/openmettle/auth/auth.json{{- end -}}
{{- define "openmettle-core.authLoginKeysDirectory" -}}/etc/openmettle/auth-keys{{- end -}}
{{- define "openmettle-core.authProviderCaDirectory" -}}/etc/openmettle/auth-ca{{- end -}}
{{- define "openmettle-core.otlpCaDirectory" -}}/etc/openmettle/otlp-ca{{- end -}}
{{- define "openmettle-core.otlpCaPath" -}}/etc/openmettle/otlp-ca/ca.crt{{- end -}}
{{- define "openmettle-core.inferenceConfigDirectory" -}}/etc/openmettle/inference{{- end -}}
{{- define "openmettle-core.inferenceConfigPath" -}}/etc/openmettle/inference/inference.json{{- end -}}
{{- define "openmettle-core.inferenceCaDirectory" -}}/etc/openmettle/inference-ca{{- end -}}
{{- define "openmettle-core.mcpCaDirectory" -}}/etc/openmettle/mcp-ca{{- end -}}
{{- define "openmettle-core.vaultKeysDirectory" -}}/etc/openmettle/vault-keys{{- end -}}
{{- define "openmettle-core.backupKeysDirectory" -}}/etc/openmettle/backup-keys{{- end -}}
{{- define "openmettle-core.backupDestinationDirectory" -}}/var/backups/openmettle{{- end -}}
{{- define "openmettle-core.backupNeo4jDirectory" -}}/var/backups/openmettle-neo4j{{- end -}}
{{- define "openmettle-core.backupChromaDirectory" -}}/var/backups/openmettle-chroma{{- end -}}
{{- define "openmettle-core.backupConfigDirectory" -}}/etc/openmettle/backup-config{{- end -}}

{{/*
Resolve one gateways.<name> entry against per-gateway defaults without Sprig mergeOverwrite quirks
on 0, false, "" or []. Mutates .out with the resolved dict.
Arguments: dict "name" <string> "raw" <map> "out" <dict>
*/}}
{{- define "openmettle-core.resolveGateway" -}}
{{- $name := .name -}}
{{- $raw := .raw -}}
{{- $out := .out -}}
{{- if not (kindIs "map" $raw) -}}
{{- fail (printf "gateways.%s must be a mapping" $name) -}}
{{- end -}}
{{- $requests := dict "cpu" "100m" "memory" "64Mi" -}}
{{- $resources := dict "requests" $requests -}}
{{- if hasKey $raw "resources" -}}
{{- $rawRes := index $raw "resources" -}}
{{- if not (kindIs "map" $rawRes) -}}
{{- fail (printf "gateways.%s.resources must be a mapping" $name) -}}
{{- end -}}
{{- if hasKey $rawRes "requests" -}}
{{- $rawReq := index $rawRes "requests" -}}
{{- if not (kindIs "map" $rawReq) -}}
{{- fail (printf "gateways.%s.resources.requests must be a mapping" $name) -}}
{{- end -}}
{{- range $k, $v := $rawReq -}}
{{- $_ := set $requests $k $v -}}
{{- end -}}
{{- end -}}
{{- if hasKey $rawRes "limits" -}}
{{- $rawLim := index $rawRes "limits" -}}
{{- if not (kindIs "map" $rawLim) -}}
{{- fail (printf "gateways.%s.resources.limits must be a mapping" $name) -}}
{{- end -}}
{{- $limits := dict -}}
{{- range $k, $v := $rawLim -}}
{{- $_ := set $limits $k $v -}}
{{- end -}}
{{- $_ := set $resources "limits" $limits -}}
{{- end -}}
{{- end -}}
{{- $sa := dict "create" true "name" "" "annotations" (dict) -}}
{{- if hasKey $raw "serviceAccount" -}}
{{- $rawSa := index $raw "serviceAccount" -}}
{{- if not (kindIs "map" $rawSa) -}}
{{- fail (printf "gateways.%s.serviceAccount must be a mapping" $name) -}}
{{- end -}}
{{- range $k, $v := $rawSa -}}
{{- $_ := set $sa $k $v -}}
{{- end -}}
{{- end -}}
{{- include "openmettle-core.validate.bool" (dict "field" (printf "gateways.%s.serviceAccount.create" $name) "value" $sa.create) -}}
{{- $settings := dict "cacheMode" "scoped" "upstreamConnectTimeoutMs" 5000 "upstreamIdleTimeoutMs" 120000 "dbMaxConnections" 4 "dbTimeoutMs" 2000 "shutdownTimeoutMs" 5000 -}}
{{- if hasKey $raw "settings" -}}
{{- $rawSet := index $raw "settings" -}}
{{- if not (kindIs "map" $rawSet) -}}
{{- fail (printf "gateways.%s.settings must be a mapping" $name) -}}
{{- end -}}
{{- range $k, $v := $rawSet -}}
{{- $_ := set $settings $k $v -}}
{{- end -}}
{{- end -}}
{{- $strategy := dict "maxSurge" 1 "maxUnavailable" 0 -}}
{{- if hasKey $raw "strategy" -}}
{{- $rawStrat := index $raw "strategy" -}}
{{- if not (kindIs "map" $rawStrat) -}}
{{- fail (printf "gateways.%s.strategy must be a mapping" $name) -}}
{{- end -}}
{{- range $k, $v := $rawStrat -}}
{{- $_ := set $strategy $k $v -}}
{{- end -}}
{{- end -}}
{{- $service := dict "port" 8082 -}}
{{- if hasKey $raw "service" -}}
{{- $rawSvc := index $raw "service" -}}
{{- if not (kindIs "map" $rawSvc) -}}
{{- fail (printf "gateways.%s.service must be a mapping" $name) -}}
{{- end -}}
{{- range $k, $v := $rawSvc -}}
{{- $_ := set $service $k $v -}}
{{- end -}}
{{- end -}}
{{- $upstream := dict "to" (list) "port" 30000 -}}
{{- $np := dict "upstream" $upstream -}}
{{- if hasKey $raw "networkPolicy" -}}
{{- $rawNp := index $raw "networkPolicy" -}}
{{- if not (kindIs "map" $rawNp) -}}
{{- fail (printf "gateways.%s.networkPolicy must be a mapping" $name) -}}
{{- end -}}
{{- if hasKey $rawNp "ingressFrom" -}}
{{- $_ := set $np "ingressFrom" (index $rawNp "ingressFrom") -}}
{{- end -}}
{{- if hasKey $rawNp "upstream" -}}
{{- $rawUp := index $rawNp "upstream" -}}
{{- if not (kindIs "map" $rawUp) -}}
{{- fail (printf "gateways.%s.networkPolicy.upstream must be a mapping" $name) -}}
{{- end -}}
{{- range $k, $v := $rawUp -}}
{{- $_ := set $upstream $k $v -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $_ := set $out "model" (ternary (index $raw "model") "" (hasKey $raw "model")) -}}
{{- $_ := set $out "upstreamUrl" (ternary (index $raw "upstreamUrl") "" (hasKey $raw "upstreamUrl")) -}}
{{- $_ := set $out "replicas" (ternary (index $raw "replicas") 1 (hasKey $raw "replicas")) -}}
{{- $_ := set $out "resources" $resources -}}
{{- $_ := set $out "serviceAccount" $sa -}}
{{- $_ := set $out "settings" $settings -}}
{{- $_ := set $out "terminationGracePeriodSeconds" (ternary (index $raw "terminationGracePeriodSeconds") 15 (hasKey $raw "terminationGracePeriodSeconds")) -}}
{{- $_ := set $out "strategy" $strategy -}}
{{- $_ := set $out "service" $service -}}
{{- $_ := set $out "networkPolicy" $np -}}
{{- $_ := set $out "podAnnotations" (ternary (index $raw "podAnnotations") (dict) (hasKey $raw "podAnnotations")) -}}
{{- $_ := set $out "nodeSelector" (ternary (index $raw "nodeSelector") (dict) (hasKey $raw "nodeSelector")) -}}
{{- $_ := set $out "tolerations" (ternary (index $raw "tolerations") (list) (hasKey $raw "tolerations")) -}}
{{- $_ := set $out "affinity" (ternary (index $raw "affinity") (dict) (hasKey $raw "affinity")) -}}
{{- end -}}

{{/* Arguments: the root context. Name of the claim the artifact volume mounts. */}}
{{- define "openmettle-core.artifactsClaimName" -}}
{{- default (printf "%s-artifacts" (include "openmettle-core.fullname" .)) .Values.storage.artifacts.existingClaim -}}
{{- end -}}

{{/*
Volumes and mounts for one pod. Arguments: dict "root" $ "artifacts" <bool> "auth" <bool> "otlp"
<bool> ["inference" <bool>]. The database CA is mounted into every component (api, worker, migrate,
gateway) when enabled; the artifact volume only where "artifacts" is true (api and worker); auth
config, login keys and optional provider CA only where "auth" is true (api only); worker inference
config, model catalog and optional TLS terminator CA only where "inference" is true (worker only);
optional OTLP CA bundle only where "otlp" is true (api, worker and gateway, never migrate). Each
helper renders nothing when no volume applies.
*/}}
{{- define "openmettle-core.volumes" -}}
{{- include "openmettle-core.validate.booleans" .root -}}
{{- $ca := .root.Values.database.caBundle -}}
{{- $auth := .root.Values.auth -}}
{{- $otlp := .root.Values.telemetry.otlp -}}
{{- $inference := default dict .root.Values.worker.inference -}}
{{- $mcp := default dict .root.Values.worker.mcp -}}
{{- $vault := default dict .root.Values.vault -}}
{{- $mountAuth := and .auth $auth.enabled -}}
{{- $mountProviderCa := and $mountAuth $auth.providerCaBundle.enabled -}}
{{- $mountOtlpCa := and .otlp $otlp.enabled $otlp.caBundle.enabled -}}
{{- $mountInference := and (default false .inference) (default false (get $inference "enabled")) -}}
{{- $mountInferenceCa := and $mountInference (default false (get (default dict (get $inference "caBundle")) "enabled")) -}}
{{- $mountMcp := and (default false .mcp) (default false (get $mcp "enabled")) -}}
{{- $mountMcpCa := and $mountMcp (default false (get (default dict (get $mcp "caBundle")) "enabled")) -}}
{{- $mountVault := and (default false .vault) (default false (get $vault "enabled")) -}}
{{- if or $ca.enabled .artifacts $mountAuth $mountOtlpCa $mountInference $mountMcpCa $mountVault }}
volumes:
  {{- if .artifacts }}
  - name: artifacts
    persistentVolumeClaim:
      claimName: {{ include "openmettle-core.artifactsClaimName" .root | quote }}
  {{- end }}
  {{- if $ca.enabled }}
  {{- include "openmettle-core.caBundleVolume" (dict "name" "db-ca" "path" "database.caBundle" "bundle" $ca) | nindent 2 }}
  {{- end }}
  {{- if $mountAuth }}
  - name: auth-config
    configMap:
      name: {{ required "auth.configMapName is required when auth.enabled is true" $auth.configMapName | quote }}
      items:
        - key: {{ $auth.configKey | quote }}
          path: auth.json
        {{- if $auth.catalogKey }}
        {{- /* Named by catalog_file in auth.json (core ADR 0036); read once at API startup. */}}
        - key: {{ $auth.catalogKey | quote }}
          path: catalog.json
        {{- end }}
  - name: auth-login-keys
    secret:
      secretName: {{ required "auth.loginKeysSecretName is required when auth.enabled is true" $auth.loginKeysSecretName | quote }}
      # 0440 octal: readable by root and pod fsGroup 65532 only, never world-readable.
      defaultMode: 288
  {{- end }}
  {{- if $mountProviderCa }}
  {{- include "openmettle-core.caBundleVolume" (dict "name" "auth-provider-ca" "path" "auth.providerCaBundle" "bundle" $auth.providerCaBundle) | nindent 2 }}
  {{- end }}
  {{- if $mountOtlpCa }}
  {{- include "openmettle-core.caBundleVolume" (dict "name" "otlp-ca" "path" "telemetry.otlp.caBundle" "bundle" $otlp.caBundle) | nindent 2 }}
  {{- end }}
  {{- if $mountInference }}
  - name: inference-config
    configMap:
      name: {{ required "worker.inference.configMapName is required when worker.inference.enabled is true" $inference.configMapName | quote }}
      items:
        - key: {{ $inference.configKey | quote }}
          path: inference.json
        - key: {{ $inference.catalogKey | quote }}
          path: catalog.json
  {{- end }}
  {{- if $mountInferenceCa }}
  {{- include "openmettle-core.caBundleVolume" (dict "name" "inference-ca" "path" "worker.inference.caBundle" "bundle" $inference.caBundle) | nindent 2 }}
  {{- end }}
  {{- if $mountMcpCa }}
  {{- include "openmettle-core.caBundleVolume" (dict "name" "mcp-ca" "path" "worker.mcp.caBundle" "bundle" $mcp.caBundle) | nindent 2 }}
  {{- end }}
  {{- if $mountVault }}
  - name: vault-keys-secret
    secret:
      secretName: {{ required "vault.existingSecret is required when vault.enabled is true" $vault.existingSecret | quote }}
      # 0440 octal: readable by root and pod fsGroup 65532 only; staged to 0400 by stage-vault-keys.
      defaultMode: 288
  - name: vault-keys
    emptyDir:
      medium: Memory
      sizeLimit: 1Mi
  {{- end }}
{{- end }}
{{- end -}}

{{- define "openmettle-core.caBundleVolume" -}}
- name: {{ .name }}
  configMap:
    name: {{ required (printf "%s.configMapName is required when %s.enabled is true" .path .path) .bundle.configMapName | quote }}
    items:
      - key: {{ .bundle.key | quote }}
        path: ca.crt
{{- end -}}

{{- define "openmettle-core.volumeMounts" -}}
{{- $ca := .root.Values.database.caBundle -}}
{{- $auth := .root.Values.auth -}}
{{- $otlp := .root.Values.telemetry.otlp -}}
{{- $inference := default dict .root.Values.worker.inference -}}
{{- $mcp := default dict .root.Values.worker.mcp -}}
{{- $vault := default dict .root.Values.vault -}}
{{- $mountAuth := and .auth $auth.enabled -}}
{{- $mountProviderCa := and $mountAuth $auth.providerCaBundle.enabled -}}
{{- $mountOtlpCa := and .otlp $otlp.enabled $otlp.caBundle.enabled -}}
{{- $mountInference := and (default false .inference) (default false (get $inference "enabled")) -}}
{{- $mountInferenceCa := and $mountInference (default false (get (default dict (get $inference "caBundle")) "enabled")) -}}
{{- $mountMcp := and (default false .mcp) (default false (get $mcp "enabled")) -}}
{{- $mountMcpCa := and $mountMcp (default false (get (default dict (get $mcp "caBundle")) "enabled")) -}}
{{- $mountVault := and (default false .vault) (default false (get $vault "enabled")) -}}
{{- if or $ca.enabled .artifacts $mountAuth $mountOtlpCa $mountInference $mountMcpCa $mountVault }}
volumeMounts:
  {{- if .artifacts }}
  - name: artifacts
    mountPath: {{ include "openmettle-core.artifactsMountPath" . | quote }}
  {{- end }}
  {{- if $ca.enabled }}
  - name: db-ca
    mountPath: {{ include "openmettle-core.databaseCaDirectory" . | quote }}
    readOnly: true
  {{- end }}
  {{- if $mountAuth }}
  - name: auth-config
    mountPath: {{ include "openmettle-core.authConfigDirectory" . | quote }}
    readOnly: true
  - name: auth-login-keys
    mountPath: {{ include "openmettle-core.authLoginKeysDirectory" . | quote }}
    readOnly: true
  {{- end }}
  {{- if $mountProviderCa }}
  - name: auth-provider-ca
    mountPath: {{ include "openmettle-core.authProviderCaDirectory" . | quote }}
    readOnly: true
  {{- end }}
  {{- if $mountOtlpCa }}
  - name: otlp-ca
    mountPath: {{ include "openmettle-core.otlpCaDirectory" . | quote }}
    readOnly: true
  {{- end }}
  {{- if $mountInference }}
  - name: inference-config
    mountPath: {{ include "openmettle-core.inferenceConfigDirectory" . | quote }}
    readOnly: true
  {{- end }}
  {{- if $mountInferenceCa }}
  - name: inference-ca
    mountPath: {{ include "openmettle-core.inferenceCaDirectory" . | quote }}
    readOnly: true
  {{- end }}
  {{- if $mountMcpCa }}
  - name: mcp-ca
    mountPath: {{ include "openmettle-core.mcpCaDirectory" . | quote }}
    readOnly: true
  {{- end }}
  {{- if $mountVault }}
  - name: vault-keys
    mountPath: {{ include "openmettle-core.vaultKeysDirectory" . | quote }}
    subPath: keys
    readOnly: true
  {{- end }}
{{- end }}
{{- end -}}

{{- define "openmettle-core.containerSecurityContext" -}}
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
{{- end -}}

{{/*
Validate every boolean flag before any template branches on it (guards --skip-schema-validation
regardless of Helm's template rendering order). Argument: the root context.
*/}}
{{- define "openmettle-core.validate.booleans" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "migration.enabled" "value" .Values.migration.enabled) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "networkPolicy.enabled" "value" .Values.networkPolicy.enabled) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "storage.artifacts.enabled" "value" .Values.storage.artifacts.enabled) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "ingress.enabled" "value" .Values.ingress.enabled) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "api.podDisruptionBudget.enabled" "value" .Values.api.podDisruptionBudget.enabled) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "auth.enabled" "value" .Values.auth.enabled) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "telemetry.otlp.enabled" "value" .Values.telemetry.otlp.enabled) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "api.serviceAccount.create" "value" .Values.api.serviceAccount.create) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "worker.serviceAccount.create" "value" .Values.worker.serviceAccount.create) -}}
{{- include "openmettle-core.validate.bool" (dict "field" "migration.serviceAccount.create" "value" .Values.migration.serviceAccount.create) -}}
{{- if not (kindIs "map" .Values.database.caBundle) -}}
{{- fail "database.caBundle must be a mapping" -}}
{{- end -}}
{{- if hasKey .Values.database.caBundle "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "database.caBundle.enabled" "value" (index .Values.database.caBundle "enabled")) -}}
{{- end -}}
{{- if not (kindIs "map" .Values.auth.providerCaBundle) -}}
{{- fail "auth.providerCaBundle must be a mapping" -}}
{{- end -}}
{{- if hasKey .Values.auth.providerCaBundle "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "auth.providerCaBundle.enabled" "value" (index .Values.auth.providerCaBundle "enabled")) -}}
{{- end -}}
{{- if not (kindIs "map" .Values.telemetry.otlp.caBundle) -}}
{{- fail "telemetry.otlp.caBundle must be a mapping" -}}
{{- end -}}
{{- if hasKey .Values.telemetry.otlp.caBundle "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "telemetry.otlp.caBundle.enabled" "value" (index .Values.telemetry.otlp.caBundle "enabled")) -}}
{{- end -}}
{{- $inference := default dict .Values.worker.inference -}}
{{- if not (kindIs "map" $inference) -}}
{{- fail "worker.inference must be a mapping" -}}
{{- end -}}
{{- if hasKey $inference "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "worker.inference.enabled" "value" (index $inference "enabled")) -}}
{{- end -}}
{{- $infCa := default dict (get $inference "caBundle") -}}
{{- if not (kindIs "map" $infCa) -}}
{{- fail "worker.inference.caBundle must be a mapping" -}}
{{- end -}}
{{- if hasKey $infCa "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "worker.inference.caBundle.enabled" "value" (index $infCa "enabled")) -}}
{{- end -}}
{{- $mcp := default dict .Values.worker.mcp -}}
{{- if not (kindIs "map" $mcp) -}}
{{- fail "worker.mcp must be a mapping" -}}
{{- end -}}
{{- if hasKey $mcp "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "worker.mcp.enabled" "value" (index $mcp "enabled")) -}}
{{- end -}}
{{- $mcpCa := default dict (get $mcp "caBundle") -}}
{{- if not (kindIs "map" $mcpCa) -}}
{{- fail "worker.mcp.caBundle must be a mapping" -}}
{{- end -}}
{{- if hasKey $mcpCa "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "worker.mcp.caBundle.enabled" "value" (index $mcpCa "enabled")) -}}
{{- end -}}
{{- $vault := default dict .Values.vault -}}
{{- if not (kindIs "map" $vault) -}}
{{- fail "vault must be a mapping" -}}
{{- end -}}
{{- if hasKey $vault "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "vault.enabled" "value" (index $vault "enabled")) -}}
{{- end -}}
{{- $backup := default dict .Values.backup -}}
{{- if not (kindIs "map" $backup) -}}
{{- fail "backup must be a mapping" -}}
{{- end -}}
{{- if hasKey $backup "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "backup.enabled" "value" (index $backup "enabled")) -}}
{{- end -}}
{{- if hasKey $backup "suspend" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "backup.suspend" "value" (index $backup "suspend")) -}}
{{- end -}}
{{- if hasKey $backup "releaseOnSuccess" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "backup.releaseOnSuccess" "value" (index $backup "releaseOnSuccess")) -}}
{{- end -}}
{{- $backupDest := default dict (get $backup "destination") -}}
{{- if not (kindIs "map" $backupDest) -}}
{{- fail "backup.destination must be a mapping" -}}
{{- end -}}
{{- if hasKey $backupDest "requireSeparateDevice" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "backup.destination.requireSeparateDevice" "value" (index $backupDest "requireSeparateDevice")) -}}
{{- end -}}
{{- $backupRet := default dict (get $backup "retention") -}}
{{- if not (kindIs "map" $backupRet) -}}
{{- fail "backup.retention must be a mapping" -}}
{{- end -}}
{{- if hasKey $backupRet "prune" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "backup.retention.prune" "value" (index $backupRet "prune")) -}}
{{- end -}}
{{- $backupCb := default dict (get $backup "configBundle") -}}
{{- if not (kindIs "map" $backupCb) -}}
{{- fail "backup.configBundle must be a mapping" -}}
{{- end -}}
{{- if hasKey $backupCb "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "backup.configBundle.enabled" "value" (index $backupCb "enabled")) -}}
{{- end -}}
{{- $backupSa := default dict (get $backup "serviceAccount") -}}
{{- if not (kindIs "map" $backupSa) -}}
{{- fail "backup.serviceAccount must be a mapping" -}}
{{- end -}}
{{- if hasKey $backupSa "create" -}}
{{- include "openmettle-core.validate.bool" (dict "field" "backup.serviceAccount.create" "value" (index $backupSa "create")) -}}
{{- end -}}
{{- end -}}

{{/* Render-time guards that do not depend on schema validation. */}}
{{- define "openmettle-core.validate" -}}
{{- include "openmettle-core.validate.booleans" . -}}
{{- if not (kindIs "invalid" .Values.worker.sweepMs) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "worker.sweepMs" "value" .Values.worker.sweepMs "min" 1000 "max" 3600000) -}}
{{- end -}}
{{- if not (kindIs "invalid" .Values.worker.pollMs) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "worker.pollMs" "value" .Values.worker.pollMs "min" 100 "max" 60000) -}}
{{- end -}}
{{- range $component := list "api" "worker" -}}
{{- $values := index $.Values $component -}}
{{- $grace := int64 $values.terminationGracePeriodSeconds -}}
{{- $shutdown := int64 $values.settings.shutdownTimeoutMs -}}
{{- if le (mul $grace 1000) $shutdown -}}
{{- fail (printf "%s.terminationGracePeriodSeconds (%d s) must exceed %s.settings.shutdownTimeoutMs (%d ms)" $component $grace $component $shutdown) -}}
{{- end -}}
{{- if and (eq (int64 $values.strategy.maxSurge) 0) (eq (int64 $values.strategy.maxUnavailable) 0) -}}
{{- fail (printf "%s.strategy.maxSurge and %s.strategy.maxUnavailable cannot both be 0" $component $component) -}}
{{- end -}}
{{- end -}}
{{- /*
Resolve and validate optional per-model openmettle-gateway instances (core ADR 0044) before
ServiceAccount uniqueness and connection-budget checks so gateways participate in both.
*/ -}}
{{- $rawGateways := default dict .Values.gateways -}}
{{- if not (kindIs "map" $rawGateways) -}}
{{- fail "gateways must be a mapping of gateway name to configuration" -}}
{{- end -}}
{{- $gwNames := keys $rawGateways | sortAlpha -}}
{{- $resolvedGateways := dict -}}
{{- $fullname := include "openmettle-core.fullname" . -}}
{{- $seenModels := dict -}}
{{- $gwImage := default dict .Values.images.gateway -}}
{{- $gwDb := default dict .Values.database.gateway -}}
{{- if gt (len $gwNames) 0 -}}
{{- if not (get $gwImage "repository") -}}
{{- fail "images.gateway.repository is required when gateways is non-empty" -}}
{{- end -}}
{{- if not (get $gwImage "digest") -}}
{{- fail "images.gateway.digest is required when gateways is non-empty (sha256:<64 lowercase hex>; tags are not accepted)" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" (toString (get $gwImage "digest"))) -}}
{{- fail "images.gateway.digest must be sha256:<64 lowercase hex>; tags are not accepted" -}}
{{- end -}}
{{- if or (contains ":" (toString (get $gwImage "repository"))) (contains "@" (toString (get $gwImage "repository"))) -}}
{{- fail "images.gateway.repository must not contain a tag or digest" -}}
{{- end -}}
{{- $gwSecret := toString (default "" (get $gwDb "existingSecret")) -}}
{{- $gwKey := toString (default "" (get $gwDb "key")) -}}
{{- if not $gwSecret -}}
{{- fail "database.gateway.existingSecret is required when gateways is non-empty (an existing Secret holding the openmettle_gateway PostgreSQL URL; core ADR 0044)" -}}
{{- end -}}
{{- if not (regexMatch "^[-._a-zA-Z0-9]+$" $gwKey) -}}
{{- fail "database.gateway.key must be a Secret key: letters, digits, '-', '_' or '.'" -}}
{{- end -}}
{{- $dbRoles := list "api" "worker" "migrate" -}}
{{- if .Values.auth.enabled -}}
{{- $dbRoles = append $dbRoles "issuance" -}}
{{- end -}}
{{- if default false (get (default dict .Values.backup) "enabled") -}}
{{- $dbRoles = append $dbRoles "backup" -}}
{{- end -}}
{{- range $role := $dbRoles -}}
{{- $ref := index $.Values.database $role -}}
{{- if and (eq $gwSecret (toString $ref.existingSecret)) (eq $gwKey (toString $ref.key)) -}}
{{- fail (printf "database.gateway must not reuse database.%s (Secret %q, key %q); openmettle-gateway needs its own openmettle_gateway login (core ADR 0044)" $role (toString $ref.existingSecret) (toString $ref.key)) -}}
{{- end -}}
{{- end -}}
{{- range $name := $gwNames -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]{0,30}[a-z0-9])?$" $name) -}}
{{- fail (printf "gateways.%s: name must match ^[a-z0-9]([-a-z0-9]{0,30}[a-z0-9])?$" $name) -}}
{{- end -}}
{{- $resourceName := printf "%s-gateway-%s" $fullname $name -}}
{{- if gt (len $resourceName) 63 -}}
{{- fail (printf "gateways.%s: rendered resource name %q (%d chars) exceeds Kubernetes' 63-character limit" $name $resourceName (len $resourceName)) -}}
{{- end -}}
{{- $g := dict -}}
{{- include "openmettle-core.resolveGateway" (dict "name" $name "raw" (index $rawGateways $name) "out" $g) -}}
{{- $_ := set $resolvedGateways $name $g -}}
{{- if or (not (kindIs "string" $g.model)) (eq (len $g.model) 0) (gt (len $g.model) 128) -}}
{{- fail (printf "gateways.%s.model must be a non-empty string of at most 128 bytes" $name) -}}
{{- end -}}
{{- if hasKey $seenModels $g.model -}}
{{- fail (printf "gateways.%s.model %q duplicates gateways.%s.model; each gateway instance must serve one distinct model" $name $g.model (get $seenModels $g.model)) -}}
{{- end -}}
{{- $_ := set $seenModels $g.model $name -}}
{{- include "openmettle-core.validate.gatewayUpstreamUrl" (dict "field" (printf "gateways.%s.upstreamUrl" $name) "url" $g.upstreamUrl) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.replicas" $name) "value" $g.replicas "min" 0 "max" 1000000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.terminationGracePeriodSeconds" $name) "value" $g.terminationGracePeriodSeconds "min" 1 "max" 1000000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.strategy.maxSurge" $name) "value" $g.strategy.maxSurge "min" 0 "max" 1000000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.strategy.maxUnavailable" $name) "value" $g.strategy.maxUnavailable "min" 0 "max" 1000000) -}}
{{- if and (eq (int64 $g.strategy.maxSurge) 0) (eq (int64 $g.strategy.maxUnavailable) 0) -}}
{{- fail (printf "gateways.%s.strategy.maxSurge and gateways.%s.strategy.maxUnavailable cannot both be 0" $name $name) -}}
{{- end -}}
{{- if or (not (kindIs "string" $g.settings.cacheMode)) (not (has $g.settings.cacheMode (list "scoped" "per_request"))) -}}
{{- fail (printf "gateways.%s.settings.cacheMode must be \"scoped\" or \"per_request\"" $name) -}}
{{- end -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.settings.upstreamConnectTimeoutMs" $name) "value" $g.settings.upstreamConnectTimeoutMs "min" 1 "max" 30000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.settings.upstreamIdleTimeoutMs" $name) "value" $g.settings.upstreamIdleTimeoutMs "min" 1 "max" 3600000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.settings.dbMaxConnections" $name) "value" $g.settings.dbMaxConnections "min" 1 "max" 64) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.settings.dbTimeoutMs" $name) "value" $g.settings.dbTimeoutMs "min" 1 "max" 30000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.settings.shutdownTimeoutMs" $name) "value" $g.settings.shutdownTimeoutMs "min" 1 "max" 60000) -}}
{{- if le (mul (int64 $g.terminationGracePeriodSeconds) 1000) (int64 $g.settings.shutdownTimeoutMs) -}}
{{- fail (printf "gateways.%s.terminationGracePeriodSeconds (%d s) must exceed gateways.%s.settings.shutdownTimeoutMs (%d ms)" $name (int64 $g.terminationGracePeriodSeconds) $name (int64 $g.settings.shutdownTimeoutMs)) -}}
{{- end -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.service.port" $name) "value" $g.service.port "min" 1 "max" 65535) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "gateways.%s.networkPolicy.upstream.port" $name) "value" $g.networkPolicy.upstream.port "min" 1 "max" 65535) -}}
{{- if not (kindIs "invalid" $g.networkPolicy.ingressFrom) -}}
{{- if not (kindIs "slice" $g.networkPolicy.ingressFrom) -}}
{{- fail (printf "gateways.%s.networkPolicy.ingressFrom must be null or a list of NetworkPolicyPeer objects" $name) -}}
{{- end -}}
{{- range $i, $peer := $g.networkPolicy.ingressFrom -}}
{{- if or (not (kindIs "map" $peer)) (eq (len $peer) 0) -}}
{{- fail (printf "gateways.%s.networkPolicy.ingressFrom[%d] must be a non-empty NetworkPolicyPeer object" $name $i) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $.Values.networkPolicy.enabled -}}
{{- if not $g.networkPolicy.upstream.to -}}
{{- fail (printf "gateways.%s.networkPolicy.upstream.to must list at least one upstream peer when networkPolicy.enabled is true (an empty list would allow egress to every destination)" $name) -}}
{{- end -}}
{{- range $i, $peer := $g.networkPolicy.upstream.to -}}
{{- if or (not (kindIs "map" $peer)) (eq (len $peer) 0) -}}
{{- fail (printf "gateways.%s.networkPolicy.upstream.to[%d] must be a non-empty NetworkPolicyPeer object" $name $i) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- else -}}
{{- if or (get $gwImage "registry") (get $gwImage "repository") (get $gwImage "digest") -}}
{{- fail "images.gateway.{registry,repository,digest} must be empty when gateways is empty" -}}
{{- end -}}
{{- if get $gwDb "existingSecret" -}}
{{- fail "database.gateway.existingSecret must be empty when gateways is empty; the gateway URL is mounted only when gateways is non-empty (core ADR 0044)" -}}
{{- end -}}
{{- end -}}
{{- /*
Each component runs as its own ServiceAccount. A shared name would also let the migrate hook's
delete policy remove another component's ServiceAccount on every install or upgrade.
*/ -}}
{{- $accounts := dict -}}
{{- $components := list (list "api" "api" .Values.api.serviceAccount) (list "worker" "worker" .Values.worker.serviceAccount) -}}
{{- if .Values.migration.enabled -}}
{{- $components = append $components (list "migrate" "migration" .Values.migration.serviceAccount) -}}
{{- end -}}
{{- range $name := $gwNames -}}
{{- $g := index $resolvedGateways $name -}}
{{- $components = append $components (list (printf "gateway-%s" $name) (printf "gateways.%s" $name) $g.serviceAccount) -}}
{{- end -}}
{{- $backupCfg := default dict .Values.backup -}}
{{- if default false (get $backupCfg "enabled") -}}
{{- $backupSa := default (dict "create" true "name" "" "annotations" (dict)) (get $backupCfg "serviceAccount") -}}
{{- $components = append $components (list "backup" "backup" $backupSa) -}}
{{- end -}}
{{- range $entry := $components -}}
{{- $key := index $entry 1 -}}
{{- $name := include "openmettle-core.serviceAccountName" (dict "root" $ "component" (index $entry 0) "field" $key "serviceAccount" (index $entry 2)) -}}
{{- if eq $name "default" -}}
{{- fail (printf "%s.serviceAccount.name must not be \"default\"; each component needs its own ServiceAccount" $key) -}}
{{- end -}}
{{- if hasKey $accounts $name -}}
{{- fail (printf "%s and %s resolve to the same ServiceAccount %q; each component needs its own" (get $accounts $name) $key $name) -}}
{{- end -}}
{{- $_ := set $accounts $name $key -}}
{{- end -}}
{{- /*
One migration attempt opens a connection (connect timeout), waits for the advisory and table
locks (lock timeout) and runs statements (statement timeout). The Job deadline must leave room
for at least one attempt whose longest statement reaches the statement timeout; otherwise the
deadline, not the configured timeout, ends long migrations. This is a lower bound only.
*/ -}}
{{- if .Values.migration.enabled -}}
{{- $timeouts := .Values.migration.settings -}}
{{- $attempt := add (int64 $timeouts.connectTimeoutMs) (int64 $timeouts.lockTimeoutMs) (int64 $timeouts.statementTimeoutMs) -}}
{{- $deadline := int64 .Values.migration.activeDeadlineSeconds -}}
{{- if le (mul $deadline 1000) $attempt -}}
{{- fail (printf "migration.activeDeadlineSeconds (%d s) must exceed connectTimeoutMs + lockTimeoutMs + statementTimeoutMs (%d ms)" $deadline (int64 $attempt)) -}}
{{- end -}}
{{- end -}}
{{- /*
An egress rule with an empty `to` list matches every destination, so the DNS and database peer
lists must not be empty while the NetworkPolicies are rendered.
*/ -}}
{{- if .Values.networkPolicy.enabled -}}
{{- if not .Values.networkPolicy.database.to -}}
{{- fail "networkPolicy.database.to must list at least one PostgreSQL peer when networkPolicy.enabled is true (an empty list would allow egress to every destination on the database port)" -}}
{{- end -}}
{{- if not .Values.networkPolicy.dns.to -}}
{{- fail "networkPolicy.dns.to must list at least one DNS peer when networkPolicy.enabled is true (an empty list would allow egress to every destination on port 53)" -}}
{{- end -}}
{{- $npWorker := default dict .Values.networkPolicy.worker -}}
{{- $npInference := default (dict "to" (list) "port" 8082) (get $npWorker "inference") -}}
{{- $npMcp := default (dict "to" (list) "ports" (list 443)) (get $npWorker "mcp") -}}
{{- range $entry := list (dict "path" "networkPolicy.database.to" "peers" .Values.networkPolicy.database.to) (dict "path" "networkPolicy.dns.to" "peers" .Values.networkPolicy.dns.to) (dict "path" "networkPolicy.api.ingressFrom" "peers" .Values.networkPolicy.api.ingressFrom) (dict "path" "networkPolicy.api.oidc.to" "peers" .Values.networkPolicy.api.oidc.to) (dict "path" "networkPolicy.worker.inference.to" "peers" $npInference.to) (dict "path" "networkPolicy.worker.mcp.to" "peers" $npMcp.to) (dict "path" "networkPolicy.telemetry.otlp.to" "peers" .Values.networkPolicy.telemetry.otlp.to) -}}
{{- range $i, $peer := $entry.peers -}}
{{- if or (not (kindIs "map" $peer)) (eq (len $peer) 0) -}}
{{- fail (printf "%s[%d] must be a non-empty NetworkPolicyPeer object" $entry.path $i) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- /*
Database CA bundle. The key selects one ConfigMap entry; it is mounted under the fixed file name
ca.crt, so the key never becomes a path. The checks repeat the schema for --skip-schema-validation.
*/ -}}
{{- include "openmettle-core.validate.caBundle" (dict "path" "database.caBundle" "bundle" .Values.database.caBundle) -}}
{{- /*
Artifact volume: exactly one source. The chart-owned settings would be silently ignored for an
existing claim, so they are rejected there.
*/ -}}
{{- $artifacts := .Values.storage.artifacts -}}
{{- if $artifacts.enabled -}}
{{- if and $artifacts.existingClaim $artifacts.size -}}
{{- fail "storage.artifacts: set either existingClaim or size, not both" -}}
{{- end -}}
{{- if not (or $artifacts.existingClaim $artifacts.size) -}}
{{- fail "storage.artifacts: set existingClaim (an existing PVC) or size (a chart-owned PVC) when storage.artifacts.enabled is true" -}}
{{- end -}}
{{- if $artifacts.existingClaim -}}
{{- if not (kindIs "invalid" $artifacts.storageClassName) -}}
{{- fail "storage.artifacts.storageClassName applies only to the chart-owned PVC; leave it null with existingClaim" -}}
{{- end -}}
{{- if $artifacts.annotations -}}
{{- fail "storage.artifacts.annotations apply only to the chart-owned PVC; leave them empty with existingClaim" -}}
{{- end -}}
{{- else -}}
{{- if not $artifacts.accessModes -}}
{{- fail "storage.artifacts.accessModes must list at least one access mode" -}}
{{- end -}}
{{- range $artifacts.accessModes -}}
{{- if not (has . (list "ReadWriteOnce" "ReadWriteMany")) -}}
{{- fail (printf "storage.artifacts.accessModes: %v is not accepted; api and worker both mount the claim read-write (ReadWriteOnce or ReadWriteMany)" .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- /*
Ingress: HTTPS only, every routed host covered by a TLS entry, and, under the chart's
NetworkPolicies, an explicit ingress-controller peer (otherwise the controller could not reach the
API and the Ingress would be dead).
*/ -}}
{{- $ingress := .Values.ingress -}}
{{- if $ingress.enabled -}}
{{- if not $ingress.className -}}
{{- fail "ingress.className is required when ingress.enabled is true; the access-log redaction it relies on is controller-specific" -}}
{{- end -}}
{{- if not $ingress.hosts -}}
{{- fail "ingress.hosts must list at least one hostname when ingress.enabled is true" -}}
{{- end -}}
{{- $covered := list -}}
{{- range $i, $entry := $ingress.tls -}}
{{- if not $entry.secretName -}}
{{- fail (printf "ingress.tls[%d].secretName is required (an existing TLS Secret)" $i) -}}
{{- end -}}
{{- range $entry.hosts -}}
{{- if not (has . $ingress.hosts) -}}
{{- fail (printf "ingress.tls[%d] lists host %q, which is not in ingress.hosts" $i .) -}}
{{- end -}}
{{- $covered = append $covered . -}}
{{- end -}}
{{- end -}}
{{- range $ingress.hosts -}}
{{- if not (has . $covered) -}}
{{- fail (printf "ingress host %q has no ingress.tls entry; the chart routes HTTPS only" .) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.api.ingressFrom) -}}
{{- fail "networkPolicy.api.ingressFrom must select the ingress controller pods when ingress.enabled and networkPolicy.enabled are true" -}}
{{- end -}}
{{- end -}}
{{- /*
API PodDisruptionBudget. Kubernetes rounds percentages up for both fields. The budget must allow
at least one voluntary eviction, or it blocks node drains.
*/ -}}
{{- $pdb := .Values.api.podDisruptionBudget -}}
{{- if $pdb.enabled -}}
{{- $min := $pdb.minAvailable -}}
{{- $max := $pdb.maxUnavailable -}}
{{- $hasMin := not (kindIs "invalid" $min) -}}
{{- $hasMax := not (kindIs "invalid" $max) -}}
{{- if and $hasMin $hasMax -}}
{{- fail "api.podDisruptionBudget: set either minAvailable or maxUnavailable, not both" -}}
{{- end -}}
{{- if not (or $hasMin $hasMax) -}}
{{- fail "api.podDisruptionBudget: set minAvailable or maxUnavailable when enabled is true" -}}
{{- end -}}
{{- $replicas := int64 .Values.api.replicas -}}
{{- if lt $replicas 2 -}}
{{- fail (printf "api.podDisruptionBudget requires api.replicas >= 2 (found %d); a budget on one replica would block node drains" $replicas) -}}
{{- end -}}
{{- $field := ternary "minAvailable" "maxUnavailable" $hasMin -}}
{{- $value := ternary $min $max $hasMin -}}
{{- $count := 0 -}}
{{- if kindIs "string" $value -}}
{{- if not (regexMatch "^(100|[1-9]?[0-9])%$" $value) -}}
{{- fail (printf "api.podDisruptionBudget.%s must be a non-negative integer or a percentage from 0%% to 100%%" $field) -}}
{{- end -}}
{{- $count = div (add (mul (atoi (trimSuffix "%" $value)) $replicas) 99) 100 -}}
{{- else -}}
{{- $count = int64 $value -}}
{{- if lt $count 0 -}}
{{- fail (printf "api.podDisruptionBudget.%s must not be negative" $field) -}}
{{- end -}}
{{- end -}}
{{- if and $hasMin (ge (int64 $count) $replicas) -}}
{{- fail (printf "api.podDisruptionBudget.minAvailable (%v) keeps all %d API replicas and would block every voluntary eviction" $value $replicas) -}}
{{- end -}}
{{- if and $hasMax (lt (int64 $count) 1) -}}
{{- fail (printf "api.podDisruptionBudget.maxUnavailable (%v) allows no voluntary eviction and would block node drains" $value) -}}
{{- end -}}
{{- end -}}
{{- /*
Peak while a rollout surges. Terminating pods keep their pools open for up to their grace period
and are not counted; see the chart README. With auth, each API pod also opens its issuance pool.
*/ -}}
{{- with .Values.database.connectionBudget -}}
{{- $apiPool := $.Values.api.settings.dbMaxConnections -}}
{{- if $.Values.auth.enabled -}}
{{- $apiPool = add $apiPool $.Values.api.settings.issuanceDbMaxConnections -}}
{{- end -}}
{{- $api := mul (add $.Values.api.replicas $.Values.api.strategy.maxSurge) $apiPool -}}
{{- $worker := mul (add $.Values.worker.replicas $.Values.worker.strategy.maxSurge) $.Values.worker.settings.dbMaxConnections -}}
{{- $gateways := 0 -}}
{{- range $name := $gwNames -}}
{{- $g := index $resolvedGateways $name -}}
{{- $gateways = add $gateways (mul (add $g.replicas $g.strategy.maxSurge) $g.settings.dbMaxConnections) -}}
{{- end -}}
{{- $backupConns := ternary 3 0 (default false (get (default dict $.Values.backup) "enabled")) -}}
{{- $total := add $api $worker $gateways 1 $backupConns -}}
{{- if gt (int64 $total) (int64 .) -}}
{{- fail (printf "database.connectionBudget (%d) is below the release's peak of %d connections: api %d + worker %d + gateways %d (replicas plus maxSurge, times dbMaxConnections, plus api.settings.issuanceDbMaxConnections while auth.enabled) + 1 migrator + %d backup" (int64 .) (int64 $total) (int64 $api) (int64 $worker) (int64 $gateways) (int64 $backupConns)) -}}
{{- end -}}
{{- end -}}
{{- /*
Worker turn execution against openmettle-gateway (core ADRs 0033, 0043 and 0044). Mounted into the
worker pod only; never into api, gateway or migrate pods.
*/ -}}
{{- $npWorkerAll := default dict .Values.networkPolicy.worker -}}
{{- $npInferenceAll := default (dict "to" (list) "port" 8082) (get $npWorkerAll "inference") -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "networkPolicy.worker.inference.port" "value" $npInferenceAll.port "min" 1 "max" 65535) -}}
{{- $inference := default dict .Values.worker.inference -}}
{{- $infEnabled := default false (get $inference "enabled") -}}
{{- $infCa := default dict (get $inference "caBundle") -}}
{{- $infCaEnabled := default false (get $infCa "enabled") -}}
{{- if $infEnabled -}}
{{- if not (get $inference "configMapName") -}}
{{- fail "worker.inference.configMapName is required when worker.inference.enabled is true (an existing ConfigMap holding inference.json and catalog.json)" -}}
{{- end -}}
{{- include "openmettle-core.validate.configMapKey" (dict "field" "worker.inference.configKey" "key" $inference.configKey) -}}
{{- include "openmettle-core.validate.configMapKey" (dict "field" "worker.inference.catalogKey" "key" $inference.catalogKey) -}}
{{- if eq (toString $inference.catalogKey) (toString $inference.configKey) -}}
{{- fail "worker.inference.catalogKey must differ from worker.inference.configKey; the model catalog is a separate file named by catalog_file in inference.json" -}}
{{- end -}}
{{- $infSettings := default dict (get $inference "settings") -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "worker.inference.settings.runSlots" "value" $infSettings.runSlots "min" 1 "max" 256) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "worker.inference.settings.leaseMs" "value" $infSettings.leaseMs "min" 30000 "max" 600000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "worker.inference.settings.executionTimeoutMs" "value" $infSettings.executionTimeoutMs "min" 60000 "max" 86400000) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "worker.inference.settings.executingPerActor" "value" $infSettings.executingPerActor "min" 1 "max" 1024) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "worker.inference.settings.executingPerScope" "value" $infSettings.executingPerScope "min" 1 "max" 1024) -}}
{{- $minLease := mul 6 (int64 .Values.worker.settings.dbTimeoutMs) -}}
{{- if lt (int64 $infSettings.leaseMs) $minLease -}}
{{- fail (printf "worker.inference.settings.leaseMs (%d ms) must cover six worker.settings.dbTimeoutMs (%d ms)" (int64 $infSettings.leaseMs) (int64 $minLease)) -}}
{{- end -}}
{{- $minExec := mul 2 (int64 $infSettings.leaseMs) -}}
{{- if lt (int64 $infSettings.executionTimeoutMs) $minExec -}}
{{- fail (printf "worker.inference.settings.executionTimeoutMs (%d ms) must cover two worker.inference.settings.leaseMs (%d ms)" (int64 $infSettings.executionTimeoutMs) (int64 $minExec)) -}}
{{- end -}}
{{- include "openmettle-core.validate.caBundle" (dict "path" "worker.inference.caBundle" "bundle" $infCa) -}}
{{- if and .Values.networkPolicy.enabled (not $npInferenceAll.to) -}}
{{- fail "networkPolicy.worker.inference.to must list at least one inference gateway or TLS-terminator peer when worker.inference.enabled and networkPolicy.enabled are true (an empty list would block inference or allow egress to every destination)" -}}
{{- end -}}
{{- else -}}
{{- if get $inference "configMapName" -}}
{{- fail "worker.inference.configMapName must be empty when worker.inference.enabled is false" -}}
{{- end -}}
{{- if $infCaEnabled -}}
{{- fail "worker.inference.caBundle.enabled cannot be true when worker.inference.enabled is false" -}}
{{- end -}}
{{- if $npInferenceAll.to -}}
{{- fail "networkPolicy.worker.inference.to must be empty when worker.inference.enabled is false; remove inference egress peers or enable worker.inference" -}}
{{- end -}}
{{- end -}}
{{- /*
Worker external MCP and OAuth refresh egress/CA (core V1-14, ADR 0045). External MCP connections
live inside inference.json, so worker.mcp.enabled requires worker.inference.enabled.
*/ -}}
{{- $npMcpAll := default (dict "to" (list) "ports" (list 443)) (get $npWorkerAll "mcp") -}}
{{- if not (kindIs "map" $npMcpAll) -}}
{{- fail "networkPolicy.worker.mcp must be a mapping" -}}
{{- end -}}
{{- $npMcpPorts := list 443 -}}
{{- if hasKey $npMcpAll "ports" -}}
{{- $npMcpPorts = index $npMcpAll "ports" -}}
{{- end -}}
{{- if or (not (kindIs "slice" $npMcpPorts)) (eq (len $npMcpPorts) 0) (gt (len $npMcpPorts) 16) -}}
{{- fail "networkPolicy.worker.mcp.ports must list between 1 and 16 TCP ports (1-65535)" -}}
{{- end -}}
{{- $seenMcpPorts := dict -}}
{{- range $i, $port := $npMcpPorts -}}
{{- include "openmettle-core.validate.intRange" (dict "field" (printf "networkPolicy.worker.mcp.ports[%d]" $i) "value" $port "min" 1 "max" 65535) -}}
{{- $portKey := printf "%d" (int64 $port) -}}
{{- if hasKey $seenMcpPorts $portKey -}}
{{- fail (printf "networkPolicy.worker.mcp.ports contains duplicate port %d" (int64 $port)) -}}
{{- end -}}
{{- $_ := set $seenMcpPorts $portKey true -}}
{{- end -}}
{{- $mcp := default dict .Values.worker.mcp -}}
{{- $mcpEnabled := default false (get $mcp "enabled") -}}
{{- $mcpCa := default dict (get $mcp "caBundle") -}}
{{- $mcpCaEnabled := default false (get $mcpCa "enabled") -}}
{{- if $mcpEnabled -}}
{{- if not $infEnabled -}}
{{- fail "worker.mcp.enabled requires worker.inference.enabled (external_mcp connections and refresh_routes live in inference.json)" -}}
{{- end -}}
{{- include "openmettle-core.validate.caBundle" (dict "path" "worker.mcp.caBundle" "bundle" $mcpCa) -}}
{{- if and .Values.networkPolicy.enabled (not (get $npMcpAll "to")) -}}
{{- fail "networkPolicy.worker.mcp.to must list at least one external MCP or OAuth refresh peer when worker.mcp.enabled and networkPolicy.enabled are true (an empty list would block egress or allow egress to every destination)" -}}
{{- end -}}
{{- else -}}
{{- if $mcpCaEnabled -}}
{{- fail "worker.mcp.caBundle.enabled cannot be true when worker.mcp.enabled is false" -}}
{{- end -}}
{{- if get $npMcpAll "to" -}}
{{- fail "networkPolicy.worker.mcp.to must be empty when worker.mcp.enabled is false; remove MCP egress peers or enable worker.mcp" -}}
{{- end -}}
{{- end -}}
{{- /*
Sign-in / OIDC and /v1/* application routes (core ADRs 0025, 0027 and 0029). Mounted into the API pod only; never into worker or
migrate pods. The checks repeat the schema for --skip-schema-validation and enforce cross-field
provider CA, NetworkPolicy egress and session issuance credential (core ADR 0030) guards.
*/ -}}
{{- $auth := .Values.auth -}}
{{- if $auth.enabled -}}
{{- if not $auth.configMapName -}}
{{- fail "auth.configMapName is required when auth.enabled is true (an existing ConfigMap holding the version-2 auth settings document)" -}}
{{- end -}}
{{- include "openmettle-core.validate.configMapKey" (dict "field" "auth.configKey" "key" $auth.configKey) -}}
{{- if $auth.catalogKey -}}
{{- include "openmettle-core.validate.configMapKey" (dict "field" "auth.catalogKey" "key" $auth.catalogKey) -}}
{{- if eq (toString $auth.catalogKey) (toString $auth.configKey) -}}
{{- fail "auth.catalogKey must differ from auth.configKey; the model catalog is a separate file named by catalog_file in auth.json" -}}
{{- end -}}
{{- end -}}
{{- if not $auth.loginKeysSecretName -}}
{{- fail "auth.loginKeysSecretName is required when auth.enabled is true (an existing Secret holding raw 32-byte login key files)" -}}
{{- end -}}
{{- range $dbRole := list "api" "worker" "migrate" "issuance" "gateway" "backup" -}}
{{- $dbSec := toString (default "" (get (default dict (index $.Values.database $dbRole)) "existingSecret")) -}}
{{- if and $dbSec (eq (toString $auth.loginKeysSecretName) $dbSec) -}}
{{- fail (printf "auth.loginKeysSecretName (%q) must differ from database.%s.existingSecret; never mount a database URL Secret wholesale into the API login-keys directory" (toString $auth.loginKeysSecretName) $dbRole) -}}
{{- end -}}
{{- end -}}
{{- include "openmettle-core.validate.caBundle" (dict "path" "auth.providerCaBundle" "bundle" $auth.providerCaBundle) -}}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.api.oidc.to) -}}
{{- fail "networkPolicy.api.oidc.to must list at least one OIDC provider peer when auth.enabled and networkPolicy.enabled are true (an empty list would block sign-in or allow egress to every destination)" -}}
{{- end -}}
{{- /*
Session issuance (core ADR 0030): sign-in requires a second, API-only database credential for a
login role of openmettle_issuance. Reusing another component's Secret key would hand the API the
same login role twice (core exits 78) or mount a role's credential where it does not belong.
*/ -}}
{{- $issuance := .Values.database.issuance -}}
{{- if not $issuance.existingSecret -}}
{{- fail "database.issuance.existingSecret is required when auth.enabled is true (an existing Secret holding the openmettle_issuance PostgreSQL URL; core ADR 0030)" -}}
{{- end -}}
{{- if not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $issuance.key)) -}}
{{- fail "database.issuance.key must be a Secret key: letters, digits, '-', '_' or '.'" -}}
{{- end -}}
{{- $issuanceDbRoles := list "api" "worker" "migrate" -}}
{{- if default false (get (default dict .Values.backup) "enabled") -}}
{{- $issuanceDbRoles = append $issuanceDbRoles "backup" -}}
{{- end -}}
{{- range $role := $issuanceDbRoles -}}
{{- $ref := index $.Values.database $role -}}
{{- if and (eq (toString $issuance.existingSecret) (toString $ref.existingSecret)) (eq (toString $issuance.key) (toString $ref.key)) -}}
{{- fail (printf "database.issuance must not reuse database.%s (Secret %q, key %q); session issuance needs its own openmettle_issuance login (core ADR 0030)" $role (toString $ref.existingSecret) (toString $ref.key)) -}}
{{- end -}}
{{- end -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "api.settings.issuanceDbMaxConnections" "value" .Values.api.settings.issuanceDbMaxConnections "min" 1 "max" 64 "includeValueOnTypeError" true) -}}
{{- else -}}
{{- if .Values.database.issuance.existingSecret -}}
{{- fail "database.issuance.existingSecret must be empty when auth.enabled is false; the issuance URL is mounted only with sign-in (core ADR 0030)" -}}
{{- end -}}
{{- if $auth.catalogKey -}}
{{- fail "auth.catalogKey must be empty when auth.enabled is false; the model catalog is mounted only with sign-in" -}}
{{- end -}}
{{- if $auth.providerCaBundle.enabled -}}
{{- fail "auth.providerCaBundle.enabled cannot be true when auth.enabled is false" -}}
{{- end -}}
{{- if .Values.networkPolicy.api.oidc.to -}}
{{- fail "networkPolicy.api.oidc.to must be empty when auth.enabled is false; remove OIDC egress peers or enable auth" -}}
{{- end -}}
{{- end -}}
{{- /*
Telemetry logging (core ADR 0024) and OTLP trace export (core ADR 0026). Logging overrides apply to
api, worker and migrate; OTLP settings, CA bundle mount and NetworkPolicy egress apply to api and
worker only (never migrate). The checks repeat the schema for --skip-schema-validation and enforce
cross-field CA, CIDR, port and NetworkPolicy guards.
*/ -}}
{{- $logging := .Values.telemetry.logging -}}
{{- if not (kindIs "invalid" $logging.format) -}}
{{- if or (not (kindIs "string" $logging.format)) (not (has $logging.format (list "json" "text"))) -}}
{{- fail "telemetry.logging.format must be null, \"json\" or \"text\"" -}}
{{- end -}}
{{- end -}}
{{- if not (kindIs "invalid" $logging.level) -}}
{{- if or (not (kindIs "string" $logging.level)) (not (has $logging.level (list "error" "warn" "info" "debug"))) -}}
{{- fail "telemetry.logging.level must be null, \"error\", \"warn\", \"info\" or \"debug\" (\"trace\" is refused by core ADR 0024)" -}}
{{- end -}}
{{- end -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "networkPolicy.telemetry.otlp.port" "value" .Values.networkPolicy.telemetry.otlp.port "min" 1 "max" 65535) -}}
{{- $otlp := .Values.telemetry.otlp -}}
{{- if not (kindIs "string" $otlp.tracesEndpoint) -}}
{{- fail "telemetry.otlp.tracesEndpoint must be a string" -}}
{{- end -}}
{{- if not (kindIs "string" $otlp.metricsEndpoint) -}}
{{- fail "telemetry.otlp.metricsEndpoint must be a string" -}}
{{- end -}}
{{- if $otlp.enabled -}}
{{- if and (not $otlp.tracesEndpoint) (not $otlp.metricsEndpoint) -}}
{{- fail "at least one of telemetry.otlp.tracesEndpoint or telemetry.otlp.metricsEndpoint is required when telemetry.otlp.enabled is true (a canonical https:// URL with a DNS host)" -}}
{{- end -}}
{{- if $otlp.tracesEndpoint -}}
{{- include "openmettle-core.validate.otlpEndpoint" (dict "field" "telemetry.otlp.tracesEndpoint" "endpoint" $otlp.tracesEndpoint) -}}
{{- end -}}
{{- if $otlp.metricsEndpoint -}}
{{- include "openmettle-core.validate.otlpEndpoint" (dict "field" "telemetry.otlp.metricsEndpoint" "endpoint" $otlp.metricsEndpoint) -}}
{{- end -}}
{{- if $otlp.privateRanges -}}
{{- if not (kindIs "slice" $otlp.privateRanges) -}}
{{- fail "telemetry.otlp.privateRanges must be a list of CIDR strings" -}}
{{- end -}}
{{- if gt (len $otlp.privateRanges) 32 -}}
{{- fail (printf "telemetry.otlp.privateRanges accepts at most 32 CIDR entries (found %d)" (len $otlp.privateRanges)) -}}
{{- end -}}
{{- $seenRanges := dict -}}
{{- $cidrPattern := "^([0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2}|[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/[0-9]{1,3})$" -}}
{{- range $i, $cidr := $otlp.privateRanges -}}
{{- if or (not (kindIs "string" $cidr)) (not (regexMatch $cidrPattern $cidr)) -}}
{{- fail (printf "telemetry.otlp.privateRanges[%d] must be a CIDR string (<ip>/<prefix> with no commas or whitespace)" $i) -}}
{{- end -}}
{{- if hasKey $seenRanges $cidr -}}
{{- fail (printf "telemetry.otlp.privateRanges contains duplicate entry %q" $cidr) -}}
{{- end -}}
{{- $_ := set $seenRanges $cidr true -}}
{{- end -}}
{{- end -}}
{{- include "openmettle-core.validate.caBundle" (dict "path" "telemetry.otlp.caBundle" "bundle" $otlp.caBundle) -}}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.telemetry.otlp.to) -}}
{{- fail "networkPolicy.telemetry.otlp.to must list at least one OTLP collector peer when telemetry.otlp.enabled and networkPolicy.enabled are true (an empty list would block OTLP export or allow egress to every destination)" -}}
{{- end -}}
{{- else -}}
{{- if $otlp.tracesEndpoint -}}
{{- fail "telemetry.otlp.tracesEndpoint must be empty when telemetry.otlp.enabled is false; clear tracesEndpoint or enable telemetry.otlp" -}}
{{- end -}}
{{- if $otlp.metricsEndpoint -}}
{{- fail "telemetry.otlp.metricsEndpoint must be empty when telemetry.otlp.enabled is false; clear metricsEndpoint or enable telemetry.otlp" -}}
{{- end -}}
{{- if $otlp.privateRanges -}}
{{- fail "telemetry.otlp.privateRanges must be empty when telemetry.otlp.enabled is false; clear privateRanges or enable telemetry.otlp" -}}
{{- end -}}
{{- if $otlp.caBundle.enabled -}}
{{- fail "telemetry.otlp.caBundle.enabled cannot be true when telemetry.otlp.enabled is false" -}}
{{- end -}}
{{- if .Values.networkPolicy.telemetry.otlp.to -}}
{{- fail "networkPolicy.telemetry.otlp.to must be empty when telemetry.otlp.enabled is false; remove OTLP egress peers or enable telemetry.otlp" -}}
{{- end -}}
{{- end -}}
{{- /*
Credential vault keyring (core ADR 0045, V1-28). Mounted into api and worker only via
stage-vault-keys (never gateway, migrate or backup).
*/ -}}
{{- $vault := default dict .Values.vault -}}
{{- $vaultEnabled := default false (get $vault "enabled") -}}
{{- $vaultSecret := toString (default "" (get $vault "existingSecret")) -}}
{{- $vaultConfigKey := toString (default "keyring.json" (get $vault "configKey")) -}}
{{- if $vaultEnabled -}}
{{- if not $vaultSecret -}}
{{- fail "vault.existingSecret is required when vault.enabled is true (an existing Secret holding the vault keyring and 32-byte key files)" -}}
{{- end -}}
{{- include "openmettle-core.validate.nonDotKey" (dict "field" "vault.configKey" "key" $vaultConfigKey) -}}
{{- if and .Values.auth.enabled (eq $vaultSecret (toString .Values.auth.loginKeysSecretName)) -}}
{{- fail (printf "vault.existingSecret (%q) must differ from auth.loginKeysSecretName; keep vault master keys in a dedicated Secret (core ADR 0045)" $vaultSecret) -}}
{{- end -}}
{{- range $dbRole := list "api" "worker" "migrate" "issuance" "gateway" "backup" -}}
{{- $dbSec := toString (default "" (get (default dict (index $.Values.database $dbRole)) "existingSecret")) -}}
{{- if and $dbSec (eq $vaultSecret $dbSec) -}}
{{- fail (printf "vault.existingSecret (%q) must differ from database.%s.existingSecret; never stage a database URL Secret into api/worker pods" $vaultSecret $dbRole) -}}
{{- end -}}
{{- end -}}
{{- else -}}
{{- if $vaultSecret -}}
{{- fail "vault.existingSecret must be empty when vault.enabled is false" -}}
{{- end -}}
{{- end -}}
{{- /*
Coordinated maintenance-window backup CronJob (core ADR 0046, V1-30).
*/ -}}
{{- $backup := default dict .Values.backup -}}
{{- $backupEnabled := default false (get $backup "enabled") -}}
{{- $adminImage := default dict .Values.images.admin -}}
{{- $pgClientImage := default dict .Values.images.postgresClient -}}
{{- $backupDb := default dict .Values.database.backup -}}
{{- $backupSecret := toString (default "" (get $backup "existingKeysSecret")) -}}
{{- $backupKeysKey := toString (default "keyring.json" (get $backup "keysConfigKey")) -}}
{{- $backupDest := default dict (get $backup "destination") -}}
{{- $backupGraphiti := default dict (get $backup "graphiti") -}}
{{- $backupChroma := default dict (get $backup "chroma") -}}
{{- $backupCb := default dict (get $backup "configBundle") -}}
{{- if $backupEnabled -}}
{{- range $imgEntry := list (dict "name" "admin" "image" $adminImage) (dict "name" "postgresClient" "image" $pgClientImage) -}}
{{- if not (get $imgEntry.image "repository") -}}
{{- fail (printf "images.%s.repository is required when backup.enabled is true" $imgEntry.name) -}}
{{- end -}}
{{- if not (get $imgEntry.image "digest") -}}
{{- fail (printf "images.%s.digest is required when backup.enabled is true (sha256:<64 lowercase hex>; tags are not accepted)" $imgEntry.name) -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" (toString (get $imgEntry.image "digest"))) -}}
{{- fail (printf "images.%s.digest must be sha256:<64 lowercase hex>; tags are not accepted" $imgEntry.name) -}}
{{- end -}}
{{- if or (contains ":" (toString (get $imgEntry.image "repository"))) (contains "@" (toString (get $imgEntry.image "repository"))) -}}
{{- fail (printf "images.%s.repository must not contain a tag or digest" $imgEntry.name) -}}
{{- end -}}
{{- end -}}
{{- $backupDbSecret := toString (default "" (get $backupDb "existingSecret")) -}}
{{- $backupDbKey := toString (default "" (get $backupDb "key")) -}}
{{- if not $backupDbSecret -}}
{{- fail "database.backup.existingSecret is required when backup.enabled is true (an existing Secret holding the openmettle_owner PostgreSQL URL; core ADR 0046)" -}}
{{- end -}}
{{- if not (regexMatch "^[-._a-zA-Z0-9]+$" $backupDbKey) -}}
{{- fail "database.backup.key must be a Secret key: letters, digits, '-', '_' or '.'" -}}
{{- end -}}
{{- $nonOwnerRoles := list "api" "worker" -}}
{{- if .Values.auth.enabled -}}
{{- $nonOwnerRoles = append $nonOwnerRoles "issuance" -}}
{{- end -}}
{{- if gt (len $gwNames) 0 -}}
{{- $nonOwnerRoles = append $nonOwnerRoles "gateway" -}}
{{- end -}}
{{- range $role := $nonOwnerRoles -}}
{{- $ref := index $.Values.database $role -}}
{{- if and (eq $backupDbSecret (toString $ref.existingSecret)) (eq $backupDbKey (toString $ref.key)) -}}
{{- fail (printf "database.backup must not reuse database.%s (Secret %q, key %q); backup capture requires an openmettle_owner login (core ADR 0046)" $role (toString $ref.existingSecret) (toString $ref.key)) -}}
{{- end -}}
{{- end -}}
{{- if or (not (kindIs "string" $backup.schedule)) (eq (len $backup.schedule) 0) (gt (len $backup.schedule) 128) (regexMatch "[\\x00-\\x1f\\x7f]" $backup.schedule) -}}
{{- fail "backup.schedule must be a non-empty cron expression of at most 128 characters without control characters" -}}
{{- end -}}
{{- if not (kindIs "invalid" $backup.timeZone) -}}
{{- if or (not (kindIs "string" $backup.timeZone)) (not (regexMatch "^[A-Za-z0-9_./+-]{1,64}$" $backup.timeZone)) -}}
{{- fail "backup.timeZone must be null or a valid IANA time zone name (1-64 characters)" -}}
{{- end -}}
{{- end -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.startingDeadlineSeconds" "value" $backup.startingDeadlineSeconds "min" 1 "max" 86400) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.activeDeadlineSeconds" "value" $backup.activeDeadlineSeconds "min" 60 "max" 86400) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.successfulJobsHistoryLimit" "value" $backup.successfulJobsHistoryLimit "min" 0 "max" 100) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.failedJobsHistoryLimit" "value" $backup.failedJobsHistoryLimit "min" 0 "max" 100) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.drainTimeoutSecs" "value" $backup.drainTimeoutSecs "min" 1 "max" 86400) -}}
{{- if le (int64 $backup.activeDeadlineSeconds) (int64 $backup.drainTimeoutSecs) -}}
{{- fail (printf "backup.activeDeadlineSeconds (%d s) must exceed backup.drainTimeoutSecs (%d s)" (int64 $backup.activeDeadlineSeconds) (int64 $backup.drainTimeoutSecs)) -}}
{{- end -}}
{{- if not $backupSecret -}}
{{- fail "backup.existingKeysSecret is required when backup.enabled is true (an existing Secret holding the backup keyring and 32-byte key files)" -}}
{{- end -}}
{{- include "openmettle-core.validate.nonDotKey" (dict "field" "backup.keysConfigKey" "key" $backupKeysKey) -}}
{{- if and $vaultEnabled (eq $backupSecret $vaultSecret) -}}
{{- fail (printf "backup.existingKeysSecret (%q) must differ from vault.existingSecret; backup and vault master keys require separate custody (core ADR 0046)" $backupSecret) -}}
{{- end -}}
{{- if and .Values.auth.enabled (eq $backupSecret (toString .Values.auth.loginKeysSecretName)) -}}
{{- fail (printf "backup.existingKeysSecret (%q) must differ from auth.loginKeysSecretName; keep backup master keys in a dedicated Secret (core ADR 0046)" $backupSecret) -}}
{{- end -}}
{{- range $dbRole := list "api" "worker" "migrate" "issuance" "gateway" "backup" -}}
{{- $dbSec := toString (default "" (get (default dict (index $.Values.database $dbRole)) "existingSecret")) -}}
{{- if and $dbSec (eq $backupSecret $dbSec) -}}
{{- fail (printf "backup.existingKeysSecret (%q) must differ from database.%s.existingSecret; keep backup master keys in a dedicated Secret (core ADR 0046)" $backupSecret $dbRole) -}}
{{- end -}}
{{- end -}}
{{- $destClaim := toString (default "" (get $backupDest "existingClaim")) -}}
{{- $destSubPath := toString (default "" (get $backupDest "subPath")) -}}
{{- $destDomain := toString (default "" (get $backupDest "domain")) -}}
{{- if not $destClaim -}}
{{- fail "backup.destination.existingClaim is required when backup.enabled is true (an existing off-host PVC)" -}}
{{- end -}}
{{- $artifactsClaim := include "openmettle-core.artifactsClaimName" . -}}
{{- if and .Values.storage.artifacts.enabled (eq $destClaim $artifactsClaim) -}}
{{- fail (printf "backup.destination.existingClaim (%q) must differ from the resolved storage.artifacts claim (%q); backups must write to an isolated destination PVC (core ADR 0046)" $destClaim $artifactsClaim) -}}
{{- end -}}
{{- if $destSubPath -}}
{{- include "openmettle-core.validate.relativePath" (dict "field" "backup.destination.subPath" "path" $destSubPath) -}}
{{- end -}}
{{- if or (not (kindIs "string" (get $backupDest "domain"))) (not (regexMatch "^[A-Za-z0-9._:/-]{1,128}$" $destDomain)) -}}
{{- fail "backup.destination.domain is required when backup.enabled is true (1-128 ASCII characters matching ^[A-Za-z0-9._:/-]+$)" -}}
{{- end -}}
{{- $opId := toString (default "" (get $backup "operatorId")) -}}
{{- if not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" $opId) -}}
{{- fail "backup.operatorId is required when backup.enabled is true and must be a canonical lowercase UUID" -}}
{{- end -}}
{{- $reason := get $backup "reason" -}}
{{- if or (not (kindIs "string" $reason)) (eq (len $reason) 0) (gt (len $reason) 512) (ne (trim $reason) $reason) (regexMatch "[\\x00-\\x1f\\x7f]" $reason) -}}
{{- fail "backup.reason must be a trimmed non-empty string of at most 512 bytes without control characters" -}}
{{- end -}}
{{- $ret := default dict (get $backup "retention") -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.retention.daily" "value" $ret.daily "min" 1 "max" 3650) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.retention.weekly" "value" $ret.weekly "min" 1 "max" 520) -}}
{{- include "openmettle-core.validate.intRange" (dict "field" "backup.retention.monthly" "value" $ret.monthly "min" 1 "max" 120) -}}
{{- $gMode := toString (default "not-provisioned" (get $backupGraphiti "mode")) -}}
{{- $gClaim := toString (default "" (get $backupGraphiti "existingClaim")) -}}
{{- $gDump := toString (default "" (get $backupGraphiti "dumpPath")) -}}
{{- if eq $gMode "not-provisioned" -}}
{{- if or $gClaim $gDump -}}
{{- fail "backup.graphiti.existingClaim and dumpPath must be empty when backup.graphiti.mode is \"not-provisioned\"" -}}
{{- end -}}
{{- else if eq $gMode "offline-dump" -}}
{{- if not $gClaim -}}
{{- fail "backup.graphiti.existingClaim is required when backup.graphiti.mode is \"offline-dump\"" -}}
{{- end -}}
{{- if eq $gClaim $destClaim -}}
{{- fail "backup.graphiti.existingClaim must differ from backup.destination.existingClaim" -}}
{{- end -}}
{{- if and .Values.storage.artifacts.enabled (eq $gClaim $artifactsClaim) -}}
{{- fail "backup.graphiti.existingClaim must differ from the storage.artifacts claim" -}}
{{- end -}}
{{- include "openmettle-core.validate.relativePath" (dict "field" "backup.graphiti.dumpPath" "path" $gDump) -}}
{{- else -}}
{{- fail "backup.graphiti.mode must be \"not-provisioned\" or \"offline-dump\"" -}}
{{- end -}}
{{- $cMode := toString (default "not-provisioned" (get $backupChroma "mode")) -}}
{{- $cClaim := toString (default "" (get $backupChroma "existingClaim")) -}}
{{- $cArchive := toString (default "" (get $backupChroma "archivePath")) -}}
{{- $cQual := toString (default "" (get $backupChroma "qualificationRef")) -}}
{{- if eq $cMode "not-provisioned" -}}
{{- if or $cClaim $cArchive $cQual -}}
{{- fail "backup.chroma.existingClaim, archivePath and qualificationRef must be empty when backup.chroma.mode is \"not-provisioned\"" -}}
{{- end -}}
{{- else if eq $cMode "archive" -}}
{{- if $cQual -}}
{{- fail "backup.chroma.qualificationRef must be empty when backup.chroma.mode is \"archive\"" -}}
{{- end -}}
{{- if not $cClaim -}}
{{- fail "backup.chroma.existingClaim is required when backup.chroma.mode is \"archive\"" -}}
{{- end -}}
{{- if eq $cClaim $destClaim -}}
{{- fail "backup.chroma.existingClaim must differ from backup.destination.existingClaim" -}}
{{- end -}}
{{- if and .Values.storage.artifacts.enabled (eq $cClaim $artifactsClaim) -}}
{{- fail "backup.chroma.existingClaim must differ from the storage.artifacts claim" -}}
{{- end -}}
{{- include "openmettle-core.validate.relativePath" (dict "field" "backup.chroma.archivePath" "path" $cArchive) -}}
{{- else if eq $cMode "qualified-rebuild" -}}
{{- if or $cClaim $cArchive -}}
{{- fail "backup.chroma.existingClaim and archivePath must be empty when backup.chroma.mode is \"qualified-rebuild\"" -}}
{{- end -}}
{{- if or (eq (len $cQual) 0) (gt (len $cQual) 256) (ne (trim $cQual) $cQual) (not (regexMatch "^[\\x20-\\x7e]+$" $cQual)) -}}
{{- fail "backup.chroma.qualificationRef is required when backup.chroma.mode is \"qualified-rebuild\" (1-256 trimmed printable ASCII characters)" -}}
{{- end -}}
{{- else -}}
{{- fail "backup.chroma.mode must be \"not-provisioned\", \"archive\" or \"qualified-rebuild\"" -}}
{{- end -}}
{{- $cbEnabled := default false (get $backupCb "enabled") -}}
{{- $cbCm := toString (default "" (get $backupCb "configMapName")) -}}
{{- $cbFiles := default (list) (get $backupCb "files") -}}
{{- if $cbEnabled -}}
{{- if not $cbCm -}}
{{- fail "backup.configBundle.configMapName is required when backup.configBundle.enabled is true" -}}
{{- end -}}
{{- if or (not (kindIs "slice" $cbFiles)) (eq (len $cbFiles) 0) (gt (len $cbFiles) 32) -}}
{{- fail "backup.configBundle.files must list between 1 and 32 entries when backup.configBundle.enabled is true" -}}
{{- end -}}
{{- $seenCbNames := dict -}}
{{- range $i, $entry := $cbFiles -}}
{{- if not (kindIs "map" $entry) -}}
{{- fail (printf "backup.configBundle.files[%d] must be a mapping with name and key" $i) -}}
{{- end -}}
{{- $fname := toString (default "" (get $entry "name")) -}}
{{- if or (not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" $fname)) (eq (lower $fname) "vault-key-inventory.json") -}}
{{- fail (printf "backup.configBundle.files[%d].name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ and must not be vault-key-inventory.json" $i) -}}
{{- end -}}
{{- $lowerName := lower $fname -}}
{{- if hasKey $seenCbNames $lowerName -}}
{{- fail (printf "backup.configBundle.files contains duplicate case-insensitive name %q" $fname) -}}
{{- end -}}
{{- $_ := set $seenCbNames $lowerName true -}}
{{- include "openmettle-core.validate.configMapKey" (dict "field" (printf "backup.configBundle.files[%d].key" $i) "key" (get $entry "key")) -}}
{{- end -}}
{{- else -}}
{{- if $cbCm -}}
{{- fail "backup.configBundle.configMapName must be empty when backup.configBundle.enabled is false" -}}
{{- end -}}
{{- if $cbFiles -}}
{{- fail "backup.configBundle.files must be empty when backup.configBundle.enabled is false" -}}
{{- end -}}
{{- end -}}
{{- else -}}
{{- if or (get $adminImage "registry") (get $adminImage "repository") (get $adminImage "digest") -}}
{{- fail "images.admin.{registry,repository,digest} must be empty when backup.enabled is false" -}}
{{- end -}}
{{- if or (get $pgClientImage "registry") (get $pgClientImage "repository") (get $pgClientImage "digest") -}}
{{- fail "images.postgresClient.{registry,repository,digest} must be empty when backup.enabled is false" -}}
{{- end -}}
{{- if get $backupDb "existingSecret" -}}
{{- fail "database.backup.existingSecret must be empty when backup.enabled is false; the backup owner URL is mounted only when backup.enabled is true (core ADR 0046)" -}}
{{- end -}}
{{- if $backupSecret -}}
{{- fail "backup.existingKeysSecret must be empty when backup.enabled is false" -}}
{{- end -}}
{{- if or (get $backupDest "existingClaim") (get $backupDest "subPath") (get $backupDest "domain") -}}
{{- fail "backup.destination.{existingClaim,subPath,domain} must be empty when backup.enabled is false" -}}
{{- end -}}
{{- if get $backup "operatorId" -}}
{{- fail "backup.operatorId must be empty when backup.enabled is false" -}}
{{- end -}}
{{- if or (ne (toString (default "not-provisioned" (get $backupGraphiti "mode"))) "not-provisioned") (get $backupGraphiti "existingClaim") (get $backupGraphiti "dumpPath") -}}
{{- fail "backup.graphiti must stay not-provisioned with empty paths when backup.enabled is false" -}}
{{- end -}}
{{- if or (ne (toString (default "not-provisioned" (get $backupChroma "mode"))) "not-provisioned") (get $backupChroma "existingClaim") (get $backupChroma "archivePath") (get $backupChroma "qualificationRef") -}}
{{- fail "backup.chroma must stay not-provisioned with empty paths when backup.enabled is false" -}}
{{- end -}}
{{- if or (default false (get $backupCb "enabled")) (get $backupCb "configMapName") (get $backupCb "files") -}}
{{- fail "backup.configBundle must stay disabled and empty when backup.enabled is false" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Arguments: dict "field" <path> "key" <value> */}}
{{- define "openmettle-core.validate.nonDotKey" -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$" (toString .key)) -}}
{{- fail (printf "%s must start with an ASCII letter or digit and use only letters, digits, '-', '_' or '.'" .field) -}}
{{- end -}}
{{- end -}}

{{/* Arguments: dict "field" <path> "path" <value> */}}
{{- define "openmettle-core.validate.relativePath" -}}
{{- $p := toString .path -}}
{{- if or (eq (len $p) 0) (gt (len $p) 256) (not (regexMatch "^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$" $p)) -}}
{{- fail (printf "%s must be a non-empty relative path without leading slash, whitespace or traversal" .field) -}}
{{- end -}}
{{- range $seg := splitList "/" $p -}}
{{- if or (eq $seg ".") (eq $seg "..") -}}
{{- fail (printf "%s must not contain '.' or '..' path segments" $.field) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Arguments: dict "field" <path> "value" <val> */}}
{{- define "openmettle-core.validate.bool" -}}
{{- if not (kindIs "bool" .value) -}}
{{- fail (printf "%s must be a boolean (true or false)" .field) -}}
{{- end -}}
{{- end -}}

{{/* Arguments: dict "field" <path> "key" <value> */}}
{{- define "openmettle-core.validate.configMapKey" -}}
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]+$" (toString .key))) (eq (toString .key) ".") (hasPrefix ".." (toString .key)) -}}
{{- fail (printf "%s must be a ConfigMap key: letters, digits, '-', '_' or '.', not '.' and not starting with '..'" .field) -}}
{{- end -}}
{{- end -}}

{{/* Arguments: dict "path" <prefix> "bundle" <map> */}}
{{- define "openmettle-core.validate.caBundle" -}}
{{- if not (kindIs "map" .bundle) -}}
{{- fail (printf "%s must be a mapping" .path) -}}
{{- end -}}
{{- $enabled := false -}}
{{- if hasKey .bundle "enabled" -}}
{{- $enabled = index .bundle "enabled" -}}
{{- include "openmettle-core.validate.bool" (dict "field" (printf "%s.enabled" .path) "value" $enabled) -}}
{{- end -}}
{{- if $enabled -}}
{{- if not .bundle.configMapName -}}
{{- fail (printf "%s.configMapName is required when %s.enabled is true (an existing ConfigMap holding the PEM CA bundle)" .path .path) -}}
{{- end -}}
{{- include "openmettle-core.validate.configMapKey" (dict "field" (printf "%s.key" .path) "key" .bundle.key) -}}
{{- end -}}
{{- end -}}

{{/* Arguments: dict "field" <path> "value" <val> "min" <int> "max" <int> ["includeValueOnTypeError" <bool>] */}}
{{- define "openmettle-core.validate.intRange" -}}
{{- if not (or (kindIs "int" .value) (kindIs "int64" .value) (kindIs "float64" .value)) -}}
{{- fail (printf "%s%s must be an integer between %d and %d" .field (ternary (printf " (%v)" .value) "" (default false .includeValueOnTypeError)) (int64 .min) (int64 .max)) -}}
{{- end -}}
{{- if or (ne (float64 (int64 .value)) (float64 .value)) (lt (int64 .value) (int64 .min)) (gt (int64 .value) (int64 .max)) -}}
{{- fail (printf "%s (%v) must be an integer between %d and %d" .field .value (int64 .min) (int64 .max)) -}}
{{- end -}}
{{- end -}}

{{/*
Validate one non-empty OTLP collector HTTPS endpoint URL (core ADRs 0010, 0026 and 0028).
Arguments: dict "field" "telemetry.otlp.<name>" "endpoint" <string>
*/}}
{{- define "openmettle-core.validate.otlpEndpoint" -}}
{{- $field := .field -}}
{{- $endpoint := .endpoint -}}
{{- $endpointPattern := "^https://([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\\.)+[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(:[1-9][0-9]{0,4})?/[-A-Za-z0-9._~!$&'()*+,;=:/]*$" -}}
{{- if or (gt (len $endpoint) 2048) (not (regexMatch $endpointPattern $endpoint)) (regexMatch "^https://[0-9.]+(:|/)" $endpoint) (regexMatch "^https://[^/:]+\\.([0-9]+|0[xX][0-9a-fA-F]*)(:|/)" $endpoint) (regexMatch "/\\.\\.?(/|$)" $endpoint) -}}
{{- fail (printf "%s must be a canonical https:// URL with a lowercase DNS host (no http://, IP literal, numeric/hex final host label, credentials, query, fragment, percent-encoding or dot-segments)" $field) -}}
{{- end -}}
{{- $authority := index (splitList "/" (trimPrefix "https://" $endpoint)) 0 -}}
{{- $authorityParts := splitList ":" $authority -}}
{{- $endpointHost := index $authorityParts 0 -}}
{{- if gt (len $endpointHost) 253 -}}
{{- fail (printf "%s hostname must be at most 253 characters" $field) -}}
{{- end -}}
{{- if gt (len $authorityParts) 1 -}}
{{- $endpointPort := int64 (atoi (index $authorityParts 1)) -}}
{{- if or (lt $endpointPort 1) (gt $endpointPort 65535) (eq $endpointPort 443) -}}
{{- fail (printf "%s port (%d) must be 1-65535 and omit the default port 443" $field $endpointPort) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate one gateway upstream origin URL (core src/gateway_proxy.rs origin()).
Arguments: dict "field" "gateways.<name>.upstreamUrl" "url" <string>
*/}}
{{- define "openmettle-core.validate.gatewayUpstreamUrl" -}}
{{- $field := .field -}}
{{- $url := .url -}}
{{- if or (not (kindIs "string" $url)) (eq (len $url) 0) -}}
{{- fail (printf "%s is required (canonical http://host[:port] origin)" $field) -}}
{{- end -}}
{{- if not (hasPrefix "http://" $url) -}}
{{- fail (printf "%s must use http:// (canonical http://host[:port] origin)" $field) -}}
{{- end -}}
{{- $pattern := "^http://(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\\.?)|(\\[[0-9a-fA-F:.]+\\]))(:[1-9][0-9]{0,4})?/?$" -}}
{{- if or (gt (len $url) 2048) (not (regexMatch $pattern $url)) -}}
{{- fail (printf "%s must be a canonical http://host[:port] origin with at most a / path (no https://, userinfo, non-root path, query or fragment)" $field) -}}
{{- end -}}
{{- $authority := trimSuffix "/" (trimPrefix "http://" $url) -}}
{{- $portStr := "" -}}
{{- if hasPrefix "[" $authority -}}
{{- $parts := splitList "]" (trimPrefix "[" $authority) -}}
{{- $ipv6 := index $parts 0 -}}
{{- $afterBracket := index $parts 1 -}}
{{- $halves := splitList "::" $ipv6 -}}
{{- if or (not (contains ":" $ipv6)) (gt (len $halves) 2) -}}
{{- fail (printf "%s must be a canonical http://host[:port] origin with a valid RFC 4291 IPv6 literal" $field) -}}
{{- end -}}
{{- $compressed := eq (len $halves) 2 -}}
{{- $left := ternary (splitList ":" (index $halves 0)) (list) (ne (index $halves 0) "") -}}
{{- $right := list -}}
{{- if $compressed -}}
{{- $right = ternary (splitList ":" (index $halves 1)) (list) (ne (index $halves 1) "") -}}
{{- end -}}
{{- $v4Pattern := "^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$" -}}
{{- $groups := 0 -}}
{{- range $i, $seg := $left -}}
{{- $isLastOverall := and (not $compressed) (eq $i (sub (len $left) 1)) -}}
{{- if and $isLastOverall (regexMatch $v4Pattern $seg) -}}
{{- $groups = add $groups 2 -}}
{{- else if regexMatch "^[0-9a-fA-F]{1,4}$" $seg -}}
{{- $groups = add $groups 1 -}}
{{- else -}}
{{- fail (printf "%s must be a canonical http://host[:port] origin with a valid RFC 4291 IPv6 literal" $field) -}}
{{- end -}}
{{- end -}}
{{- range $i, $seg := $right -}}
{{- $isLastOverall := eq $i (sub (len $right) 1) -}}
{{- if and $isLastOverall (regexMatch $v4Pattern $seg) -}}
{{- $groups = add $groups 2 -}}
{{- else if regexMatch "^[0-9a-fA-F]{1,4}$" $seg -}}
{{- $groups = add $groups 1 -}}
{{- else -}}
{{- fail (printf "%s must be a canonical http://host[:port] origin with a valid RFC 4291 IPv6 literal" $field) -}}
{{- end -}}
{{- end -}}
{{- if or (and (not $compressed) (ne (int64 $groups) 8)) (and $compressed (gt (int64 $groups) 7)) -}}
{{- fail (printf "%s must be a canonical http://host[:port] origin with a valid RFC 4291 IPv6 literal" $field) -}}
{{- end -}}
{{- if hasPrefix ":" $afterBracket -}}
{{- $portStr = trimPrefix ":" $afterBracket -}}
{{- end -}}
{{- else if contains ":" $authority -}}
{{- $portStr = index (splitList ":" $authority) 1 -}}
{{- end -}}
{{- if $portStr -}}
{{- $port := int64 (atoi $portStr) -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "%s port (%d) must be between 1 and 65535" $field $port) -}}
{{- end -}}
{{- end -}}
{{- end -}}
