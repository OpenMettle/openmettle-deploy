{{/*
API and worker Deployments share one shape (core runtime/process-contract.json).
Arguments: dict "root" $ "component" "api|worker" "port" <container port>
*/}}
{{- define "openmettle-core.deployment" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- $values := index $root.Values $component -}}
{{- $settings := $values.settings -}}
{{- $prefix := printf "OPENMETTLE_%s_" (upper $component) -}}
{{- $context := dict "root" $root "component" $component -}}
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
      serviceAccountName: {{ include "openmettle-core.serviceAccountName" (merge (dict "serviceAccount" $values.serviceAccount) $context) }}
      automountServiceAccountToken: false
      enableServiceLinks: false
      terminationGracePeriodSeconds: {{ int64 $values.terminationGracePeriodSeconds }}
      {{- include "openmettle-core.podSecurityContext" $root | nindent 6 }}
      {{- with $root.Values.images.pullSecrets }}
      imagePullSecrets:
        {{- range . }}
        - name: {{ . }}
        {{- end }}
      {{- end }}
      containers:
        - name: {{ $component }}
          image: {{ include "openmettle-core.image" (dict "name" $component "image" (index $root.Values.images $component)) | quote }}
          imagePullPolicy: {{ $root.Values.images.pullPolicy }}
          ports:
            - name: http
              containerPort: {{ .port }}
              protocol: TCP
          env:
            - name: {{ $prefix }}BIND
              value: {{ printf "0.0.0.0:%d" (int .port) | quote }}
            - name: {{ $prefix }}DATABASE_URL
              {{- include "openmettle-core.databaseUrlEnv" (dict "name" $component "ref" (index $root.Values.database $component)) | nindent 14 }}
            - name: {{ $prefix }}DB_MAX_CONNECTIONS
              value: {{ int64 $settings.dbMaxConnections | quote }}
            - name: {{ $prefix }}DB_TIMEOUT_MS
              value: {{ int64 $settings.dbTimeoutMs | quote }}
            - name: {{ $prefix }}SHUTDOWN_TIMEOUT_MS
              value: {{ int64 $settings.shutdownTimeoutMs | quote }}
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
