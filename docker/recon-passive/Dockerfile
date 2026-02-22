# bbai-recon-passive: Passive reconnaissance tools
# Tools: Amass, Subfinder, Assetfinder, GAU, Waybackurls

FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Install Amass
RUN go install -v github.com/owasp-amass/amass/v4/...@latest

# Install Subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Assetfinder
RUN go install -v github.com/tomnomnom/assetfinder@latest

# Install GAU
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest

# Install Waybackurls
RUN go install -v github.com/tomnomnom/waybackurls@latest

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates bind-tools libpcap

# Copy binaries from builder
COPY --from=builder /go/bin/amass /usr/local/bin/
COPY --from=builder /go/bin/subfinder /usr/local/bin/
COPY --from=builder /go/bin/assetfinder /usr/local/bin/
COPY --from=builder /go/bin/gau /usr/local/bin/
COPY --from=builder /go/bin/waybackurls /usr/local/bin/

# Create non-root user
RUN adduser -D -u 1000 scanner

# Create workspace
RUN mkdir -p /workspace && chown scanner:scanner /workspace

WORKDIR /workspace
USER scanner

# Default command
ENTRYPOINT ["/bin/sh"]
