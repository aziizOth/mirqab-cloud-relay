# Mirqab Cloud Relay - Kubernetes Operator
# Multi-stage build for minimal production image

# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /workspace

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o operator \
    ./cmd/main.go

# Runtime stage - distroless for security
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy binary
COPY --from=builder /workspace/operator .

# Run as non-root
USER 65534:65534

ENTRYPOINT ["/operator"]
