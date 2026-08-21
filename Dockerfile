# Build stage
# Must stay >= the `toolchain` directive in go.mod (go1.26.7), which carries the
# stdlib fixes govulncheck gates on — see that file for the advisory list. A
# builder older than the toolchain directive still works (Go downloads the
# pinned toolchain) but silently adds a download to every image build, so keep
# these two in step.
FROM golang:1.26.7-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o agentguard ./cmd/agentguard

# Runtime stage
FROM alpine:3.22

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

# GOMEMLIMIT is deliberately NOT hardcoded: the right value is the container's
# memory limit, which is only known at run time. Without it the Go runtime is
# unaware of the cgroup ceiling and can be OOM-killed under GC pressure rather
# than collecting harder. Set it to ~90% of the container limit, e.g.
#   docker run -m 512m -e GOMEMLIMIT=460MiB ...
# or in Kubernetes via a resourceFieldRef on limits.memory.

EXPOSE 8080

# Liveness for orchestrators. /health is unauthenticated by design and the
# server binds 127.0.0.1 unless --api-key is set, so the probe runs from inside
# the container against loopback. NOTE: this reports "process is serving", not
# "state hydration succeeded" — a boot where hydration failed still answers 200
# (audit B9). Use it for restarts, not as an enforcement-readiness signal.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["agentguard"]
CMD ["serve", "--policy", "/etc/agentguard/default.yaml", "--dashboard", "--audit-log", "/var/lib/agentguard/audit.jsonl"]
