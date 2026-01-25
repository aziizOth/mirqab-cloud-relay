# Sliver C2 Server for Mirqab Cloud Relay
# Generates real C2 implants for security validation testing

FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git make mingw-w64-gcc

# Clone and build Sliver
WORKDIR /build
RUN git clone --depth 1 https://github.com/BishopFox/sliver.git
WORKDIR /build/sliver
RUN make linux

# Runtime image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    mingw-w64-gcc \
    curl \
    bash

# Create sliver user
RUN adduser -D -h /home/sliver sliver

# Copy built binary
COPY --from=builder /build/sliver/sliver-server /usr/local/bin/sliver-server
RUN chmod +x /usr/local/bin/sliver-server

# Create directories
RUN mkdir -p /home/sliver/.sliver /home/sliver/payloads && \
    chown -R sliver:sliver /home/sliver

USER sliver
WORKDIR /home/sliver

# Expose ports
# 31337 - gRPC (operator API)
# 443   - HTTPS implant listener
# 8888  - HTTP implant listener
# 53    - DNS implant listener
EXPOSE 31337 443 8888 53/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:31337/health || exit 1

# Start Sliver server in daemon mode
ENTRYPOINT ["sliver-server"]
CMD ["daemon"]
