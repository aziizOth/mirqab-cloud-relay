# Mirqab Cloud Relay - Payload Server
# Multi-stage build for minimal secure container

# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

# Copy source
COPY . .

# Initialize module if needed
RUN go mod init payload-server 2>/dev/null || true
RUN go mod tidy

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static'" \
    -o /payload-server main.go

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

# Copy binary
COPY --from=builder /payload-server /payload-server

# Copy CA certificates for TLS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Expose ports
EXPOSE 8080 9092

# Run as non-root
USER nonroot:nonroot

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/payload-server", "-health-check"] || exit 1

ENTRYPOINT ["/payload-server"]
