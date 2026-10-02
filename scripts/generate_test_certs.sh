#!/bin/bash
set -e
mkdir -p proxy/certs
echo "Generating self-signed test certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout proxy/certs/server.key \
    -out proxy/certs/server.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
echo "Test certificates generated at proxy/certs/"
