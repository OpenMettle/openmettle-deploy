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

{{/* Arguments: dict "root" $ "component" "api|worker|migrate" "serviceAccount" <values> */}}
{{- define "openmettle-core.serviceAccountName" -}}
{{- if .serviceAccount.create -}}
{{- default (printf "%s-%s" (include "openmettle-core.fullname" .root) .component) .serviceAccount.name -}}
{{- else -}}
{{- required (printf "%s.serviceAccount.name is required when serviceAccount.create is false; components never share the default ServiceAccount" (ternary "migration" .component (eq .component "migrate"))) .serviceAccount.name -}}
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
  {{- if or .storage .auth }}
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

{{/* Arguments: the root context. Name of the claim the artifact volume mounts. */}}
{{- define "openmettle-core.artifactsClaimName" -}}
{{- default (printf "%s-artifacts" (include "openmettle-core.fullname" .)) .Values.storage.artifacts.existingClaim -}}
{{- end -}}

{{/*
Volumes and mounts for one pod. Arguments: dict "root" $ "artifacts" <bool> "auth" <bool> "otlp"
<bool>. The database CA is mounted into every component (api, worker, migrate) when enabled; the
artifact volume only where "artifacts" is true (api and worker); auth config, login keys and
optional provider CA only where "auth" is true (api only); optional OTLP CA bundle only where
"otlp" is true (api and worker, never migrate). Each helper renders nothing when no volume applies.
*/}}
{{- define "openmettle-core.volumes" -}}
{{- $ca := .root.Values.database.caBundle -}}
{{- $auth := .root.Values.auth -}}
{{- $otlp := .root.Values.telemetry.otlp -}}
{{- $mountAuth := and .auth $auth.enabled -}}
{{- $mountProviderCa := and $mountAuth $auth.providerCaBundle.enabled -}}
{{- $mountOtlpCa := and .otlp $otlp.enabled $otlp.caBundle.enabled -}}
{{- if or $ca.enabled .artifacts $mountAuth $mountOtlpCa }}
volumes:
  {{- if .artifacts }}
  - name: artifacts
    persistentVolumeClaim:
      claimName: {{ include "openmettle-core.artifactsClaimName" .root | quote }}
  {{- end }}
  {{- if $ca.enabled }}
  - name: db-ca
    configMap:
      name: {{ required "database.caBundle.configMapName is required when database.caBundle.enabled is true" $ca.configMapName | quote }}
      items:
        - key: {{ $ca.key | quote }}
          path: ca.crt
  {{- end }}
  {{- if $mountAuth }}
  - name: auth-config
    configMap:
      name: {{ required "auth.configMapName is required when auth.enabled is true" $auth.configMapName | quote }}
      items:
        - key: {{ $auth.configKey | quote }}
          path: auth.json
  - name: auth-login-keys
    secret:
      secretName: {{ required "auth.loginKeysSecretName is required when auth.enabled is true" $auth.loginKeysSecretName | quote }}
      # 0440 octal: readable by root and pod fsGroup 65532 only, never world-readable.
      defaultMode: 288
  {{- end }}
  {{- if $mountProviderCa }}
  - name: auth-provider-ca
    configMap:
      name: {{ required "auth.providerCaBundle.configMapName is required when auth.providerCaBundle.enabled is true" $auth.providerCaBundle.configMapName | quote }}
      items:
        - key: {{ $auth.providerCaBundle.key | quote }}
          path: ca.crt
  {{- end }}
  {{- if $mountOtlpCa }}
  - name: otlp-ca
    configMap:
      name: {{ required "telemetry.otlp.caBundle.configMapName is required when telemetry.otlp.caBundle.enabled is true" $otlp.caBundle.configMapName | quote }}
      items:
        - key: {{ $otlp.caBundle.key | quote }}
          path: ca.crt
  {{- end }}
{{- end }}
{{- end -}}

{{- define "openmettle-core.volumeMounts" -}}
{{- $ca := .root.Values.database.caBundle -}}
{{- $auth := .root.Values.auth -}}
{{- $otlp := .root.Values.telemetry.otlp -}}
{{- $mountAuth := and .auth $auth.enabled -}}
{{- $mountProviderCa := and $mountAuth $auth.providerCaBundle.enabled -}}
{{- $mountOtlpCa := and .otlp $otlp.enabled $otlp.caBundle.enabled -}}
{{- if or $ca.enabled .artifacts $mountAuth $mountOtlpCa }}
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

{{/* Render-time guards that do not depend on schema validation. */}}
{{- define "openmettle-core.validate" -}}
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
Each component runs as its own ServiceAccount. A shared name would also let the migrate hook's
delete policy remove another component's ServiceAccount on every install or upgrade.
*/ -}}
{{- $accounts := dict -}}
{{- $components := list (list "api" "api" .Values.api.serviceAccount) (list "worker" "worker" .Values.worker.serviceAccount) -}}
{{- if .Values.migration.enabled -}}
{{- $components = append $components (list "migrate" "migration" .Values.migration.serviceAccount) -}}
{{- end -}}
{{- range $entry := $components -}}
{{- $key := index $entry 1 -}}
{{- $name := include "openmettle-core.serviceAccountName" (dict "root" $ "component" (index $entry 0) "serviceAccount" (index $entry 2)) -}}
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
{{- range $entry := list (dict "path" "networkPolicy.database.to" "peers" .Values.networkPolicy.database.to) (dict "path" "networkPolicy.dns.to" "peers" .Values.networkPolicy.dns.to) (dict "path" "networkPolicy.api.ingressFrom" "peers" .Values.networkPolicy.api.ingressFrom) (dict "path" "networkPolicy.api.oidc.to" "peers" .Values.networkPolicy.api.oidc.to) (dict "path" "networkPolicy.telemetry.otlp.to" "peers" .Values.networkPolicy.telemetry.otlp.to) -}}
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
{{- $ca := .Values.database.caBundle -}}
{{- if $ca.enabled -}}
{{- if not $ca.configMapName -}}
{{- fail "database.caBundle.configMapName is required when database.caBundle.enabled is true (an existing ConfigMap holding the PEM CA bundle)" -}}
{{- end -}}
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $ca.key))) (has (toString $ca.key) (list "." "..")) -}}
{{- fail "database.caBundle.key must be a ConfigMap key: letters, digits, '-', '_' or '.', and not '.' or '..'" -}}
{{- end -}}
{{- end -}}
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
{{- $total := add $api $worker 1 -}}
{{- if gt (int64 $total) (int64 .) -}}
{{- fail (printf "database.connectionBudget (%d) is below the release's peak of %d connections: api %d + worker %d (replicas plus maxSurge, times dbMaxConnections, plus api.settings.issuanceDbMaxConnections while auth.enabled) + 1 migrator" (int64 .) (int64 $total) (int64 $api) (int64 $worker)) -}}
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
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $auth.configKey))) (has (toString $auth.configKey) (list "." "..")) -}}
{{- fail "auth.configKey must be a ConfigMap key: letters, digits, '-', '_' or '.', and not '.' or '..'" -}}
{{- end -}}
{{- if not $auth.loginKeysSecretName -}}
{{- fail "auth.loginKeysSecretName is required when auth.enabled is true (an existing Secret holding raw 32-byte login key files)" -}}
{{- end -}}
{{- if $auth.providerCaBundle.enabled -}}
{{- if not $auth.providerCaBundle.configMapName -}}
{{- fail "auth.providerCaBundle.configMapName is required when auth.providerCaBundle.enabled is true (an existing ConfigMap holding the PEM CA bundle)" -}}
{{- end -}}
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $auth.providerCaBundle.key))) (has (toString $auth.providerCaBundle.key) (list "." "..")) -}}
{{- fail "auth.providerCaBundle.key must be a ConfigMap key: letters, digits, '-', '_' or '.', and not '.' or '..'" -}}
{{- end -}}
{{- end -}}
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
{{- range $role := list "api" "worker" "migrate" -}}
{{- $ref := index $.Values.database $role -}}
{{- if and (eq (toString $issuance.existingSecret) (toString $ref.existingSecret)) (eq (toString $issuance.key) (toString $ref.key)) -}}
{{- fail (printf "database.issuance must not reuse database.%s (Secret %q, key %q); session issuance needs its own openmettle_issuance login (core ADR 0030)" $role (toString $ref.existingSecret) (toString $ref.key)) -}}
{{- end -}}
{{- end -}}
{{- $issuanceConnections := .Values.api.settings.issuanceDbMaxConnections -}}
{{- if or (not (or (kindIs "int" $issuanceConnections) (kindIs "int64" $issuanceConnections) (kindIs "float64" $issuanceConnections))) (ne (float64 (int64 $issuanceConnections)) (float64 $issuanceConnections)) (lt (int64 $issuanceConnections) 1) (gt (int64 $issuanceConnections) 64) -}}
{{- fail (printf "api.settings.issuanceDbMaxConnections (%v) must be an integer between 1 and 64" $issuanceConnections) -}}
{{- end -}}
{{- else -}}
{{- if .Values.database.issuance.existingSecret -}}
{{- fail "database.issuance.existingSecret must be empty when auth.enabled is false; the issuance URL is mounted only with sign-in (core ADR 0030)" -}}
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
{{- $otlpPort := .Values.networkPolicy.telemetry.otlp.port -}}
{{- if not (or (kindIs "int" $otlpPort) (kindIs "int64" $otlpPort) (kindIs "float64" $otlpPort)) -}}
{{- fail "networkPolicy.telemetry.otlp.port must be an integer between 1 and 65535" -}}
{{- end -}}
{{- if or (ne (float64 (int64 $otlpPort)) (float64 $otlpPort)) (lt (int64 $otlpPort) 1) (gt (int64 $otlpPort) 65535) -}}
{{- fail (printf "networkPolicy.telemetry.otlp.port (%v) must be an integer between 1 and 65535" $otlpPort) -}}
{{- end -}}
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
{{- if $otlp.caBundle.enabled -}}
{{- if not $otlp.caBundle.configMapName -}}
{{- fail "telemetry.otlp.caBundle.configMapName is required when telemetry.otlp.caBundle.enabled is true (an existing ConfigMap holding the PEM CA bundle)" -}}
{{- end -}}
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]+$" (toString $otlp.caBundle.key))) (has (toString $otlp.caBundle.key) (list "." "..")) -}}
{{- fail "telemetry.otlp.caBundle.key must be a ConfigMap key: letters, digits, '-', '_' or '.', and not '.' or '..'" -}}
{{- end -}}
{{- end -}}
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
