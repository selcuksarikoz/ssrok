#!/bin/bash

set -e

echo "Running ssrok server..."

# Set default environment variables
export PORT=${PORT:-8080}
export SSROK_HOST=${SSROK_HOST:-"http://localhost:8080"}

echo "PORT: $PORT"
echo "SSROK_HOST: $SSROK_HOST"
echo ""
echo "To use HTTPS, set SSROK_HOST explicitly:"
echo "  SSROK_HOST=https://yourdomain.com go run ./cmd/server"
echo ""

go run ./cmd/server
