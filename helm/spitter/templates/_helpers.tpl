{{/*
Expand the name of the chart.
*/}}
{{- define "spitter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "spitter.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "spitter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "spitter.labels" -}}
helm.sh/chart: {{ include "spitter.chart" . }}
{{ include "spitter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "spitter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spitter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "spitter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "spitter.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Container image reference; a digest takes precedence over the tag.
*/}}
{{- define "spitter.image" -}}
{{- $repo := .Values.image.repository }}
{{- with .Values.image.registry }}
{{- $repo = printf "%s/%s" . $repo }}
{{- end }}
{{- if .Values.image.digest }}
{{- printf "%s@%s" $repo .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" $repo (default .Chart.AppVersion .Values.image.tag | toString) }}
{{- end }}
{{- end }}

{{/*
Name of the chart-generated config ConfigMap/Secret.
*/}}
{{- define "spitter.configName" -}}
{{- printf "%s-config" (include "spitter.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Non-empty when the chart generates the spitter config file (no existingConfig given).
*/}}
{{- define "spitter.generateConfig" -}}
{{- with .Values.spitter.existingConfig }}
{{- if not (or .configMap .secret) }}true{{ end }}
{{- end }}
{{- end }}

{{/*
Non-empty when an additional routers ConfigMap/Secret is mounted.
*/}}
{{- define "spitter.hasAdditionalRouters" -}}
{{- with .Values.spitter.additionalRouters }}
{{- if or .configMap .secret }}true{{ end }}
{{- end }}
{{- end }}

{{/*
Generated spitter config file.  Leaving listen.host empty binds all interfaces, including IPv6.
*/}}
{{- define "spitter.configFile" -}}
{{- $s := .Values.spitter }}
{{- $cfg := dict
  "listen" (dict "port" ($s.port | int))
  "alertmanagerURL" (required "spitter.alertmanagerURL is required unless spitter.existingConfig is set" $s.alertmanagerURL)
  "prometheusURL" (required "spitter.prometheusURL is required unless spitter.existingConfig is set" $s.prometheusURL)
  "metrics" (dict "path" $s.metricsPath)
}}
{{- with $s.routers }}
{{- $_ := set $cfg "routers" . }}
{{- end }}
{{- toYaml $cfg }}
{{- end }}

{{/*
Reject contradictory settings early instead of producing a crash-looping pod.
*/}}
{{- define "spitter.validate" -}}
{{- $s := .Values.spitter }}
{{- if and $s.existingConfig.configMap $s.existingConfig.secret }}
{{- fail "spitter.existingConfig: set configMap or secret, not both" }}
{{- end }}
{{- if and $s.additionalRouters.configMap $s.additionalRouters.secret }}
{{- fail "spitter.additionalRouters: set configMap or secret, not both" }}
{{- end }}
{{- if and (include "spitter.generateConfig" .) (not $s.routers) (not (include "spitter.hasAdditionalRouters" .)) }}
{{- fail "spitter needs at least one router: set spitter.routers, spitter.additionalRouters or spitter.existingConfig" }}
{{- end }}
{{- if and .Values.httpRoute.enabled (not .Values.httpRoute.parentRefs) }}
{{- fail "httpRoute.parentRefs must list at least one Gateway when httpRoute.enabled is true" }}
{{- end }}
{{- end }}
