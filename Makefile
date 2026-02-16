.PHONY: all build build-client build-server clean release test

VERSION := 0.1.5
LDFLAGS := -ldflags "-X ssrok/internal/constants.Version=$(VERSION) -s -w"

all: build

build: build-client build-server

build-client:
	@echo "Building ssrok client..."
	go build $(LDFLAGS) -o ssrok ./cmd/client

build-server:
	@echo "Building ssrok server..."
	go build $(LDFLAGS) -o ssrok-server ./cmd/server

# Production builds
build-prod: build-client-prod build-server-prod
	@echo "Production builds complete."

build-client-prod:
	@echo "Building production client..."
	@if [ -f .env.prod ]; then \
		export $$(cat .env.prod | grep -v '^#' | xargs) && \
		echo "Embedding Server URL: $$SSROK_SERVER" && \
		go build -ldflags "-X 'ssrok/internal/constants.DefaultServerURL=$$SSROK_SERVER' -s -w" -o ssrok-prod ./cmd/client; \
	else \
		echo "Error: .env.prod file not found"; \
		exit 1; \
	fi

build-server-prod:
	@echo "Building production server..."
	go build $(LDFLAGS) -o ssrok-server-prod ./cmd/server

release:
	@echo "Building release binaries..."
	mkdir -p dist

	# macOS ARM64
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/ssrok-darwin-arm64 ./cmd/client

	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/ssrok-darwin-amd64 ./cmd/client

	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/ssrok-linux-arm64 ./cmd/client

	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/ssrok-linux-amd64 ./cmd/client

	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/ssrok-windows-amd64.exe ./cmd/client

	# Server binaries
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/ssrok-server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/ssrok-server-darwin-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/ssrok-server-linux-amd64 ./cmd/server

	@echo "Release binaries built in dist/"
	@echo "Generate SHA256 checksums:"
	@cd dist && shasum -a 256 * > checksums.txt

clean:
	rm -f ssrok ssrok-server
	rm -rf dist/

test:
	go test -v ./...

install: build
	@echo "Installing ssrok..."
	cp ssrok /usr/local/bin/
	cp ssrok-server /usr/local/bin/
	@echo "Installed successfully"

# Scripts
# Generate TLS certificates for local HTTPS development
gen-certs:
	@chmod +x scripts/generate-certs.sh
	@./scripts/generate-certs.sh

# Run the server in development mode (defaults to localhost:8080)
# Use SSROK_CONFIG_FILE=.env.prod to test production config (note: script default ports may take precedence)
dev-server:
	@chmod +x scripts/run-server.sh
	@./scripts/run-server.sh

# Build the client using production settings defined in .env.prod
build-script:
	@chmod +x scripts/build-client.sh
	@./scripts/build-client.sh
