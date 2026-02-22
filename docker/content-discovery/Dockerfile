# bbai-content-discovery: Content discovery tools
# Tools: Feroxbuster, GoSpider, Hakrawler, HTTPx

FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Install Feroxbuster
RUN wget -qO /tmp/feroxbuster.zip \
    https://github.com/epi052/feroxbuster/releases/download/nightly/aarch64-linux-feroxbuster.zip && \
    unzip /tmp/feroxbuster.zip -d /tmp && \
    mv /tmp/feroxbuster /usr/local/bin/feroxbuster && \
    chmod +x /usr/local/bin/feroxbuster

# Install GoSpider
RUN go install -v github.com/jaeles-project/gospider@latest

# Install Hakrawler
RUN go install -v github.com/hakluke/hakrawler@latest

# Install HTTPx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binaries from builder
COPY --from=builder /usr/local/bin/feroxbuster /usr/local/bin/
COPY --from=builder /go/bin/gospider /usr/local/bin/
COPY --from=builder /go/bin/hakrawler /usr/local/bin/
COPY --from=builder /go/bin/httpx /usr/local/bin/

# Create non-root user
RUN adduser -D -u 1000 scanner

# Create workspace
RUN mkdir -p /workspace && chown scanner:scanner /workspace

WORKDIR /workspace
USER scanner

# Default command
ENTRYPOINT ["/bin/sh"]
