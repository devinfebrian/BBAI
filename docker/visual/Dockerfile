# bbai-visual: Visual/screenshot tools
# Tools: GoWitness, Chromium

FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Install GoWitness
RUN go install -v github.com/sensepost/gowitness@latest

# Final stage
FROM alpine:3.19

# Install Chromium and dependencies
RUN apk add --no-cache \
    ca-certificates \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ttf-freefont \
    libstdc++

# Copy GoWitness binary
COPY --from=builder /go/bin/gowitness /usr/local/bin/

# Create non-root user
RUN adduser -D -u 1000 scanner

# Create workspace
RUN mkdir -p /workspace/screenshots && chown -R scanner:scanner /workspace

# Set Chrome path for GoWitness
ENV CHROME_BIN=/usr/bin/chromium-browser
ENV CHROME_PATH=/usr/lib/chromium/

WORKDIR /workspace
USER scanner

# Default command
ENTRYPOINT ["/bin/sh"]
