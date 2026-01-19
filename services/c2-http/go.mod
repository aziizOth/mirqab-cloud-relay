module github.com/mirqab/cloud-relay/services/c2-http

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/google/uuid v1.5.0
	github.com/prometheus/client_golang v1.18.0
	github.com/redis/go-redis/v9 v9.4.0
	github.com/rs/zerolog v1.31.0
	github.com/spf13/viper v1.18.2
	go.opentelemetry.io/otel v1.21.0
	go.opentelemetry.io/otel/exporters/prometheus v0.44.0
	go.opentelemetry.io/otel/sdk v1.21.0
	go.opentelemetry.io/otel/trace v1.21.0
)
