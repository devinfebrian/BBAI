# bbai-secrets: Secret scanning tools
# Tools: TruffleHog, Gitleaks, JSubfinder

FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Install TruffleHog
RUN go install -v github.com/trufflesecurity/trufflehog/v3@latest

# Install Gitleaks
RUN go install -v github.com/zricethezav/gitleaks/v8@latest

# Install JSubfinder
RUN go install -v github.com/ThreatUnk/jsubfinder@latest

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates git

# Copy binaries from builder
COPY --from=builder /go/bin/trufflehog /usr/local/bin/
COPY --from=builder /go/bin/gitleaks /usr/local/bin/
COPY --from=builder /go/bin/jsubfinder /usr/local/bin/

# Create non-root user
RUN adduser -D -u 1000 scanner

# Create workspace
RUN mkdir -p /workspace && chown scanner:scanner /workspace

WORKDIR /workspace
USER scanner

# Default command
ENTRYPOINT ["/bin/sh"]
