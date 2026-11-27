{{/*
Per-component NetworkPolicy. Every component may reach DNS and the database only; the API may
also accept connections on its container port from networkPolicy.api.ingressFrom and, when
auth.enabled is true, reach OIDC provider peers in networkPolicy.api.oidc; api, worker and gateway
pods (never migrate or backup) may also reach OTLP collector peers in networkPolicy.telemetry.otlp
when telemetry.otlp.enabled is true; worker (when worker.inference.enabled or worker.mcp.enabled)
and per-model gateways may also carry explicit TCP extraEgress rules (each with `port` or `ports`).
Arguments: dict "root" $ "component" "api|worker|migrate|backup|gateway-<name>" "ingressFrom" <peers>
"port" <container port> "oidc" <bool> "otlp" <bool> "extraEgress" <list of {to, port|ports}>
"annotations" <map>. An empty ingressFrom renders no ingress rule, which denies all ingress.
*/}}
{{- define "openmettle-core.networkPolicy" -}}
{{- $root := .root -}}
{{- $values := $root.Values.networkPolicy -}}
{{- $context := dict "root" $root "component" .component -}}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "openmettle-core.fullname" $root }}-{{ .component }}
  labels:
    {{- include "openmettle-core.labels" $context | nindent 4 }}
  {{- with .annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  podSelector:
    matchLabels:
      {{- include "openmettle-core.selectorLabels" $context | nindent 6 }}
  policyTypes:
    - Ingress
    - Egress
  {{- if .ingressFrom }}
  ingress:
    - from:
        {{- toYaml .ingressFrom | nindent 8 }}
      ports:
        - protocol: TCP
          port: {{ .port }}
  {{- end }}
  egress:
    - to:
        {{- toYaml $values.dns.to | nindent 8 }}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        {{- toYaml $values.database.to | nindent 8 }}
      ports:
        - protocol: TCP
          port: {{ int64 $values.database.port }}
    {{- if .oidc }}
    - to:
        {{- toYaml $values.api.oidc.to | nindent 8 }}
      ports:
        - protocol: TCP
          port: {{ int64 $values.api.oidc.port }}
    {{- end }}
    {{- if .otlp }}
    - to:
        {{- toYaml $values.telemetry.otlp.to | nindent 8 }}
      ports:
        - protocol: TCP
          port: {{ int64 $values.telemetry.otlp.port }}
    {{- end }}
    {{- range .extraEgress }}
    - to:
        {{- toYaml .to | nindent 8 }}
      ports:
        {{- if hasKey . "ports" }}
        {{- range .ports }}
        - protocol: TCP
          port: {{ int64 . }}
        {{- end }}
        {{- else }}
        - protocol: TCP
          port: {{ int64 .port }}
        {{- end }}
    {{- end }}
{{- end -}}
