# bbai-js-analysis: JavaScript analysis tools
# Tools: LinkFinder, Semgrep, JS-Beautify

FROM python:3.12-alpine AS python-builder

# Install Python tools
RUN pip install --user jsbeautifier

FROM golang:1.22-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Install LinkFinder dependencies
RUN go install -v github.com/tomnomnom/waybackurls@latest

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates python3 py3-pip git nodejs npm

# Install Semgrep
RUN pip3 install --break-system-packages semgrep || pip3 install semgrep

# Copy LinkFinder
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder && \
    cd /opt/linkfinder && \
    pip3 install --break-system-packages -r requirements.txt || \
    pip3 install -r requirements.txt

# Copy binaries from builders
COPY --from=go-builder /go/bin/waybackurls /usr/local/bin/
COPY --from=python-builder /root/.local/bin/js-beautify /usr/local/bin/

# Create non-root user
RUN adduser -D -u 1000 scanner

# Create workspace
RUN mkdir -p /workspace && chown scanner:scanner /workspace

WORKDIR /workspace
USER scanner

# Default command
ENTRYPOINT ["/bin/sh"]
