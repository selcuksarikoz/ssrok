#!/bin/bash

set -e

echo "Running ssrok server..."

# Set default environment variables
export PORT=${PORT:-80}
export SSROK_SERVER=${SSROK_SERVER:-"http://localhost"}

echo "PORT: $PORT"
echo "SSROK_SERVER: $SSROK_SERVER"
echo ""
echo "To use HTTPS, set SSROK_SERVER explicitly:"
echo "  SSROK_SERVER=https://yourdomain.com go run ./cmd/server"
echo ""

go run ./cmd/server
