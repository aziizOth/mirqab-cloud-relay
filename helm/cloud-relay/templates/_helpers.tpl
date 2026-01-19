{{/*
Expand the name of the chart.
*/}}
{{- define "cloud-relay.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "cloud-relay.fullname" -}}
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
{{- define "cloud-relay.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cloud-relay.labels" -}}
helm.sh/chart: {{ include "cloud-relay.chart" . }}
{{ include "cloud-relay.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cloud-relay.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cloud-relay.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "cloud-relay.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cloud-relay.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "cloud-relay.databaseUrl" -}}
{{- if .Values.database.external }}
postgresql://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)
{{- else }}
postgresql://cloudrelay:cloudrelay@{{ include "cloud-relay.fullname" . }}-postgresql:5432/cloudrelay
{{- end }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "cloud-relay.redisUrl" -}}
{{- if .Values.redis.enabled }}
redis://{{ include "cloud-relay.fullname" . }}-redis-master:6379
{{- else }}
redis://$(REDIS_HOST):$(REDIS_PORT)
{{- end }}
{{- end }}
