{{/*
Expand the name of the chart.
*/}}
{{- define "iamd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "iamd.fullname" -}}
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
{{- define "iamd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "iamd.labels" -}}
helm.sh/chart: {{ include "iamd.chart" . }}
{{ include "iamd.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "iamd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iamd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "iamd.postgresql.fullname" -}}
{{- printf "%s-%s" .Release.Name "postgresql" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "iamd.jwtKey" -}}
{{- if .Values.secrets.jwtKey }}
{{- .Values.secrets.jwtKey }}
{{- else }}
{{- randAlphaNum 32 | b64enc }}
{{- end }}
{{- end }}

{{- define "iamd.rootPassword" -}}
{{- if .Values.secrets.rootPassword }}
{{- .Values.secrets.rootPassword }}
{{- else }}
{{- randAlphaNum 16 }}
{{- end }}
{{- end }}

{{- define "iamd.checkRandomSecrets" }}
{{- if .Release.IsUpgrade }}
  {{- if not .Values.secrets.jwtKey }}
    {{- printf "You must provide the current JWT key when upgrading!" | fail }}
  {{- end }}
  {{- if not .Values.secrets.rootPassword }}
    {{- printf "You must provide the current root password when upgrading!" | fail }}
  {{- end }}
{{- end }}
{{- end }}
