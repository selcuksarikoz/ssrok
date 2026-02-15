.PHONY: all build build-client build-server clean release test

VERSION ?= 1.0.0
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -s -w"

all: build

build: build-client build-server

build-client:
	@echo "Building ssrok client..."
	go build $(LDFLAGS) -o ssrok ./cmd/client

build-server:
	@echo "Building ssrok server..."
	go build $(LDFLAGS) -o ssrok-server ./cmd/server

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
