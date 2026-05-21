{{/*
Standard Helm naming/labeling helpers.

These follow the patterns from `helm create` so anyone familiar with
generic Helm charts can read this without surprises.
*/}}

{{- define "postman-insights-webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "postman-insights-webhook.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "postman-insights-webhook.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "postman-insights-webhook.labels" -}}
helm.sh/chart: {{ include "postman-insights-webhook.chart" . }}
{{ include "postman-insights-webhook.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "postman-insights-webhook.selectorLabels" -}}
app.kubernetes.io/name: {{ include "postman-insights-webhook.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "postman-insights-webhook.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "postman-insights-webhook.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the image reference for the webhook + init containers.
*/}}
{{- define "postman-insights-webhook.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "postman-insights-webhook.initImage" -}}
{{- if .Values.mutation.initImage -}}
{{- .Values.mutation.initImage -}}
{{- else -}}
{{- include "postman-insights-webhook.image" . -}}
{{- end -}}
{{- end -}}
