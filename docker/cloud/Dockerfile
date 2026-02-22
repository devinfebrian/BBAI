# bbai-cloud: Cloud security tools
# Tools: CloudEnum, S3Scanner, ScoutURL

FROM python:3.12-alpine AS python-builder

# Install Python tools
RUN pip install --user cloudenum s3scanner

FROM golang:1.22-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Install ScoutURL (if available via go)
# Note: ScoutURL may need to be installed differently

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates python3 py3-pip

# Copy Python tools
COPY --from=python-builder /root/.local/bin/cloudenum /usr/local/bin/
COPY --from=python-builder /root/.local/bin/s3scanner /usr/local/bin/

# Install ScoutURL via pip
RUN pip3 install --break-system-packages scout-url || \
    pip3 install scout-url || \
    echo "ScoutURL installation skipped"

# Create non-root user
RUN adduser -D -u 1000 scanner

# Create workspace
RUN mkdir -p /workspace && chown scanner:scanner /workspace

WORKDIR /workspace
USER scanner

# Default command
ENTRYPOINT ["/bin/sh"]
