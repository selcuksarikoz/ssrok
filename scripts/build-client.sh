#!/bin/bash

set -e

echo "Building ssrok client..."

# Detect OS and ARCH
GOOS=${GOOS:-$(go env GOOS)}
GOARCH=${GOARCH:-$(go env GOARCH)}

OUTPUT="ssrok"
if [ "$GOOS" = "windows" ]; then
    OUTPUT="ssrok.exe"
fi

echo "Building for $GOOS/$GOARCH..."

GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "$OUTPUT" ./cmd/client

echo "✅ Build complete: $OUTPUT"
