# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o agentguard ./cmd/agentguard

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates \
    && addgroup -S agentguard \
    && adduser -S -G agentguard -u 10001 agentguard \
    && mkdir -p /var/lib/agentguard \
    && chown -R agentguard:agentguard /var/lib/agentguard

COPY --from=builder /app/agentguard /usr/local/bin/agentguard
COPY configs/default.yaml /etc/agentguard/default.yaml

# Run as non-root. /var/lib/agentguard is the default writable location for
# the audit log; mount a volume here in production so the log survives
# container restarts.
USER agentguard:agentguard
WORKDIR /var/lib/agentguard

EXPOSE 8080
ENTRYPOINT ["agentguard"]
CMD ["serve", "--policy", "/etc/agentguard/default.yaml", "--dashboard", "--audit-log", "/var/lib/agentguard/audit.jsonl"]
