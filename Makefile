.PHONY: build test lint run clean docker validate help

# Binary name
BINARY=agentguard
VERSION=0.3.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"

## build: Compile the binary
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/agentguard

## test: Run all tests with race detection
test:
	go test -v -race -coverprofile=coverage.out ./...

## lint: Run linter
lint:
	golangci-lint run ./...

## run: Build and start with default policy + dashboard
run: build
	./$(BINARY) serve --policy configs/default.yaml --dashboard --watch

## validate: Validate all policy files
validate: build
	@for f in configs/*.yaml configs/examples/*.yaml; do \
		echo "Validating $$f..."; \
		./$(BINARY) validate --policy $$f || exit 1; \
	done
	@echo "All policies valid."

## docker: Build Docker image
docker:
	docker build -t $(BINARY):$(VERSION) -t $(BINARY):latest .

## docker-run: Run in Docker
docker-run: docker
	docker run -d -p 8080:8080 --name agentguard $(BINARY):latest

## clean: Remove build artifacts
clean:
	rm -f $(BINARY) coverage.out
	rm -rf dist/

## install-python-sdk: Install the Python SDK in development mode
install-python-sdk:
	cd plugins/python && pip install -e ".[all]"

## install-ts-sdk: Build the TypeScript SDK
install-ts-sdk:
	cd plugins/typescript && npm install && npm run build

## help: Show this help
help:
	@echo "AgentGuard — The firewall for AI agents\n"
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
