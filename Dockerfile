# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o agentguard ./cmd/agentguard

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates
COPY --from=builder /app/agentguard /usr/local/bin/agentguard
COPY configs/default.yaml /etc/agentguard/default.yaml

EXPOSE 8080
ENTRYPOINT ["agentguard"]
CMD ["serve", "--policy", "/etc/agentguard/default.yaml", "--dashboard"]
