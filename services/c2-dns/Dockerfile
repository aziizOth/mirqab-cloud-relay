# Mirqab Cloud Relay - C2 DNS Simulator
# Multi-stage build for minimal production image

FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /c2-dns ./main.go

# Runtime stage
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /c2-dns /c2-dns

USER 65534:65534

# DNS ports
EXPOSE 53/udp 53/tcp 9091

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/c2-dns", "-health"]

ENTRYPOINT ["/c2-dns"]
