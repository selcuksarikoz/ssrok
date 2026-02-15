#!/bin/bash
# Generate self-signed certificates for local HTTPS testing

cd "$(dirname "$0")/../certs"

# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate signing request
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=ssrok/OU=Development/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Clean up CSR
rm server.csr

echo "✅ Self-signed certificates generated in certs/"
echo "   - server.crt (certificate)"
echo "   - server.key (private key)"
