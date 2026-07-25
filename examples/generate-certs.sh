#!/bin/sh
# Generate self-signed certificates for TLS examples.
# Usage: cd examples && sh generate-certs.sh

set -e
mkdir -p certs

# CA certificate (used as trust anchor for mTLS and client verification)
openssl req -x509 -newkey rsa:2048 -keyout certs/ca.key \
    -out certs/ca.crt -days 365 -nodes -subj '/CN=synclaire-ca' \
    -addext 'basicConstraints=critical,CA:TRUE' 2>/dev/null

# Server certificate signed by CA (CN=localhost, SAN=localhost,127.0.0.1)
openssl req -newkey rsa:2048 -keyout certs/server.key \
    -out certs/server.csr -nodes -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>/dev/null
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out certs/server.crt -days 365 \
    -copy_extensions copyall 2>/dev/null
rm -f certs/server.csr certs/ca.srl

# Client certificate signed by CA (for mTLS examples)
openssl req -newkey rsa:2048 -keyout certs/client.key \
    -out certs/client.csr -nodes -subj '/CN=client' 2>/dev/null
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -out certs/client.crt -days 365 2>/dev/null
rm -f certs/client.csr certs/ca.srl

echo "Generated certs/{ca,server,client}.{crt,key}"
