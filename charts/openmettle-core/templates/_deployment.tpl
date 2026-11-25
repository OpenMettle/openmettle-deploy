{{/*
API, worker and per-model gateway Deployments share one shape (core runtime/process-contract.json).
Arguments: dict "root" $ "component" "api|worker|gateway-<name>" "port" <container port>
           ["role" "api|worker|gateway"] ["values" <resolved map>] ["field" <values path>]
           ["sweepMs" ...] ["pollMs" ...]
*/}}
{{- define "openmettle-core.deployment" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- $role := default $component .role -}}
{{- $values := default (index $root.Values $component) .values -}}
{{- $settings := $values.settings -}}
{{- $prefix := printf "OPENMETTLE_%s_" (upper $role) -}}
{{- $context := dict "root" $root "component" $component -}}
{{- $artifacts := and (ne $role "gateway") $root.Values.storage.artifacts.enabled -}}
{{- $auth := and (eq $role "api") $root.Values.auth.enabled -}}
{{- $inference := and (eq $role "worker") (default false (get (default dict $root.Values.worker.inference) "enabled")) -}}
{{- $logging := $root.Values.telemetry.logging -}}
{{- $otlp := $root.Values.telemetry.otlp -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "openmettle-core.fullname" $root }}-{{ $component }}
  labels:
    {{- include "openmettle-core.labels" $context | nindent 4 }}
spec:
  replicas: {{ int64 $values.replicas }}
  revisionHistoryLimit: 3
  selector:
    matchLabels:
      {{- include "openmettle-core.selectorLabels" $context | nindent 6 }}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: {{ int64 $values.strategy.maxSurge }}
      maxUnavailable: {{ int64 $values.strategy.maxUnavailable }}
  template:
    metadata:
      labels:
        {{- include "openmettle-core.labels" $context | nindent 8 }}
      {{- with $values.podAnnotations }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    spec:
      serviceAccountName: {{ include "openmettle-core.serviceAccountName" (merge (dict "serviceAccount" $values.serviceAccount "field" (default $component .field)) $context) | quote }}
      automountServiceAccountToken: false
      enableServiceLinks: false
      terminationGracePeriodSeconds: {{ int64 $values.terminationGracePeriodSeconds }}
      {{- $volumes := dict "root" $root "artifacts" $artifacts "auth" $auth "otlp" $otlp.enabled "inference" $inference }}
      {{- include "openmettle-core.podSecurityContext" (dict "storage" $artifacts "auth" $auth) | nindent 6 }}
      {{- with $root.Values.images.pullSecrets }}
      imagePullSecrets:
        {{- range . }}
        - name: {{ . | quote }}
        {{- end }}
      {{- end }}
      containers:
        - name: {{ $role }}
          image: {{ include "openmettle-core.image" (dict "name" $role "image" (index $root.Values.images $role)) | quote }}
          imagePullPolicy: {{ $root.Values.images.pullPolicy | quote }}
          ports:
            - name: http
              containerPort: {{ .port }}
              protocol: TCP
          env:
            - name: {{ $prefix }}BIND
              value: {{ printf "0.0.0.0:%d" (int .port) | quote }}
            - name: {{ $prefix }}DATABASE_URL
              {{- include "openmettle-core.databaseUrlEnv" (dict "name" $role "ref" (index $root.Values.database $role)) | nindent 14 }}
            - name: {{ $prefix }}DB_MAX_CONNECTIONS
              value: {{ int64 $settings.dbMaxConnections | quote }}
            - name: {{ $prefix }}DB_TIMEOUT_MS
              value: {{ int64 $settings.dbTimeoutMs | quote }}
            - name: {{ $prefix }}SHUTDOWN_TIMEOUT_MS
              value: {{ int64 $settings.shutdownTimeoutMs | quote }}
            {{- if eq $role "gateway" }}
            - name: OPENMETTLE_GATEWAY_MODEL
              value: {{ $values.model | quote }}
            - name: OPENMETTLE_GATEWAY_UPSTREAM_URL
              value: {{ $values.upstreamUrl | quote }}
            - name: OPENMETTLE_GATEWAY_CACHE_MODE
              value: {{ $settings.cacheMode | quote }}
            - name: OPENMETTLE_GATEWAY_UPSTREAM_CONNECT_TIMEOUT_MS
              value: {{ int64 $settings.upstreamConnectTimeoutMs | quote }}
            - name: OPENMETTLE_GATEWAY_UPSTREAM_IDLE_TIMEOUT_MS
              value: {{ int64 $settings.upstreamIdleTimeoutMs | quote }}
            {{- end }}
            {{- if not (kindIs "invalid" .sweepMs) }}
            - name: OPENMETTLE_WORKER_SWEEP_MS
              value: {{ int64 .sweepMs | quote }}
            {{- end }}
            {{- if not (kindIs "invalid" .pollMs) }}
            - name: OPENMETTLE_WORKER_POLL_MS
              value: {{ int64 .pollMs | quote }}
            {{- end }}
            {{- if $inference }}
            {{- $infSettings := $root.Values.worker.inference.settings }}
            - name: OPENMETTLE_WORKER_INFERENCE_CONFIG
              value: {{ include "openmettle-core.inferenceConfigPath" $root | quote }}
            - name: OPENMETTLE_WORKER_RUN_SLOTS
              value: {{ int64 $infSettings.runSlots | quote }}
            - name: OPENMETTLE_WORKER_LEASE_MS
              value: {{ int64 $infSettings.leaseMs | quote }}
            - name: OPENMETTLE_WORKER_EXECUTION_TIMEOUT_MS
              value: {{ int64 $infSettings.executionTimeoutMs | quote }}
            - name: OPENMETTLE_WORKER_EXECUTING_PER_ACTOR
              value: {{ int64 $infSettings.executingPerActor | quote }}
            - name: OPENMETTLE_WORKER_EXECUTING_PER_SCOPE
              value: {{ int64 $infSettings.executingPerScope | quote }}
            {{- end }}
            {{- if not (kindIs "invalid" $logging.format) }}
            - name: {{ $prefix }}LOG_FORMAT
              value: {{ $logging.format | quote }}
            {{- end }}
            {{- if not (kindIs "invalid" $logging.level) }}
            - name: {{ $prefix }}LOG_LEVEL
              value: {{ $logging.level | quote }}
            {{- end }}
            {{- if $otlp.enabled }}
            {{- if $otlp.tracesEndpoint }}
            - name: {{ $prefix }}OTLP_TRACES_ENDPOINT
              value: {{ $otlp.tracesEndpoint | quote }}
            {{- end }}
            {{- if $otlp.metricsEndpoint }}
            - name: {{ $prefix }}OTLP_METRICS_ENDPOINT
              value: {{ $otlp.metricsEndpoint | quote }}
            {{- end }}
            {{- if $otlp.caBundle.enabled }}
            - name: {{ $prefix }}OTLP_CA_FILE
              value: {{ include "openmettle-core.otlpCaPath" $root | quote }}
            {{- end }}
            {{- if $otlp.privateRanges }}
            - name: {{ $prefix }}OTLP_PRIVATE_RANGES
              value: {{ join "," $otlp.privateRanges | quote }}
            {{- end }}
            {{- end }}
            {{- if $artifacts }}
            - name: {{ $prefix }}ARTIFACTS_DIR
              value: {{ include "openmettle-core.artifactsMountPath" $root | quote }}
            {{- end }}
            {{- if $auth }}
            - name: OPENMETTLE_API_AUTH_CONFIG
              value: {{ include "openmettle-core.authConfigPath" $root | quote }}
            {{- /* core ADR 0030: the issuance pool, API only and only with sign-in. */}}
            - name: OPENMETTLE_API_ISSUANCE_DATABASE_URL
              {{- include "openmettle-core.databaseUrlEnv" (dict "name" "issuance" "ref" $root.Values.database.issuance) | nindent 14 }}
            - name: OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS
              value: {{ int64 $settings.issuanceDbMaxConnections | quote }}
            {{- end }}
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            periodSeconds: 10
            timeoutSeconds: 1
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
            periodSeconds: 10
            # /readyz waits up to the database timeout before answering.
            timeoutSeconds: {{ add (div (add (int64 $settings.dbTimeoutMs) 999) 1000) 1 }}
            failureThreshold: 3
          {{- with $values.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- include "openmettle-core.containerSecurityContext" $root | nindent 10 }}
          {{- with include "openmettle-core.volumeMounts" $volumes | trim }}
          {{- . | nindent 10 }}
          {{- end }}
      {{- with include "openmettle-core.volumes" $volumes | trim }}
      {{- . | nindent 6 }}
      {{- end }}
      {{- with $values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end -}}
