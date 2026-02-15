#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION=$(grep "^VERSION :=" "$PROJECT_DIR/Makefile" | sed 's/.*= *//')

echo "Building ssrok client..."

GOOS=${GOOS:-$(go env GOOS)}
GOARCH=${GOARCH:-$(go env GOARCH)}

OUTPUT="ssrok"
if [ "$GOOS" = "windows" ]; then
    OUTPUT="ssrok.exe"
fi

echo "Building for $GOOS/$GOARCH..."

GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-X ssrok/internal/constants.Version=$VERSION -s -w" -o "$OUTPUT" ./cmd/client

echo "✅ Build complete: $OUTPUT"
