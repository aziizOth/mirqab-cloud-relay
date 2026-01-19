# Mirqab Cloud Relay - C2 HTTP Simulator
# Multi-stage build for minimal production image

# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always 2>/dev/null || echo 'dev')" \
    -o /c2-http ./main.go

# Runtime stage - using distroless for security
FROM gcr.io/distroless/static:nonroot

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /c2-http /c2-http

# Run as non-root
USER 65534:65534

# Expose ports
EXPOSE 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/c2-http", "-health"]

ENTRYPOINT ["/c2-http"]
