{{- define "apexguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "apexguard.fullname" -}}
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

{{- define "apexguard.labels" -}}
helm.sh/chart: {{ include "apexguard.name" . }}
{{ include "apexguard.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "apexguard.selectorLabels" -}}
app.kubernetes.io/part-of: apexguard
{{- end }}

{{- define "apexguard.image" -}}
{{- printf "%s:%s" (index . 0) (index . 1) }}
{{- end }}
