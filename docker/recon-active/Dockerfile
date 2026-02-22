# bbai-recon-active: Active reconnaissance tools
# Tools: Katana, Naabu, DNSx, RustScan, FFUF

FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base libpcap-dev

# Install Katana
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install Naabu
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install DNSx
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Install RustScan (using pre-built binary for now due to Rust compile time)
RUN wget -qO /tmp/rustscan.tar.gz \
    https://github.com/RustScan/RustScan/releases/download/2.2.3/rustscan-2.2.3-x86_64-unknown-linux-musl.tar.gz && \
    tar -xzf /tmp/rustscan.tar.gz -C /tmp && \
    mv /tmp/rustscan-2.2.3-x86_64-unknown-linux-musl/rustscan /tmp/rustscan && \
    chmod +x /tmp/rustscan

# Install FFUF
RUN go install -v github.com/ffuf/ffuf/v2@latest

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates bind-tools libpcap nmap nmap-scripts

# Copy binaries from builder
COPY --from=builder /go/bin/katana /usr/local/bin/
COPY --from=builder /go/bin/naabu /usr/local/bin/
COPY --from=builder /go/bin/dnsx /usr/local/bin/
COPY --from=builder /tmp/rustscan /usr/local/bin/
COPY --from=builder /go/bin/ffuf /usr/local/bin/

# Create non-root user
RUN adduser -D -u 1000 scanner

# Create workspace
RUN mkdir -p /workspace && chown scanner:scanner /workspace

WORKDIR /workspace
USER scanner

# Default command
ENTRYPOINT ["/bin/sh"]
