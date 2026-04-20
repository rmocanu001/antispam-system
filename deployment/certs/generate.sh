#!/bin/sh
set -e

CERTS_DIR=/certs

if [ -f "$CERTS_DIR/server.crt" ] && [ -f "$CERTS_DIR/server.key" ]; then
    echo "Certificates already exist, skipping generation."
    exit 0
fi

echo "Generating IGSU CA and wildcard certificate for *.igsu.local ..."

# CA key + self-signed cert
openssl genrsa -out "$CERTS_DIR/ca.key" 4096

openssl req -new -x509 -days 3650 \
    -key "$CERTS_DIR/ca.key" \
    -out "$CERTS_DIR/ca.crt" \
    -subj "/C=RO/ST=Ilfov/L=Bucuresti/O=Inspectoratul General pentru Situatii de Urgenta/OU=IT/CN=IGSU Root CA"

# Wildcard server key + CSR
openssl genrsa -out "$CERTS_DIR/server.key" 2048

openssl req -new \
    -key "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.csr" \
    -subj "/C=RO/ST=Ilfov/L=Bucuresti/O=IGSU/OU=IT/CN=*.igsu.local"

# SAN extensions
cat > /tmp/v3ext.cnf << 'EOF'
[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = *.igsu.local
DNS.2 = igsu.local
DNS.3 = localhost
DNS.4 = postfix
DNS.5 = dovecot
DNS.6 = roundcube
DNS.7 = account-admin
IP.1  = 127.0.0.1
EOF

openssl x509 -req -days 3650 \
    -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/server.crt" \
    -extensions v3_req \
    -extfile /tmp/v3ext.cnf

chmod 640 "$CERTS_DIR/server.key" "$CERTS_DIR/ca.key"
chmod 644 "$CERTS_DIR/server.crt" "$CERTS_DIR/ca.crt"

echo "Done."
openssl x509 -in "$CERTS_DIR/server.crt" -noout -text \
    | grep -A6 "Subject Alternative Name"
