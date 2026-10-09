#!/usr/bin/env bash
# Regenerates the TLS fixtures used by test/client_certificate_test.dart.
# Requires OpenSSL 3. Output files are committed; rerun only when they expire.
set -euo pipefail
cd "$(dirname "$0")"

PASS=test1234
PBE_OPTS=(-keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256)

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 3650 -subj "/CN=Vikunja Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 3650 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth")
openssl pkcs12 -export -in server.pem -inkey server.key -certfile ca.pem \
  -out server.p12 -passout "pass:$PASS" "${PBE_OPTS[@]}"

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=vikunja-test-client"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 3650 \
  -extfile <(printf "extendedKeyUsage=clientAuth")
openssl pkcs12 -export -in client.pem -inkey client.key -certfile ca.pem \
  -out client.p12 -passout "pass:$PASS" "${PBE_OPTS[@]}"

# A certificate-only PKCS#12 (no private key) for the negative test.
openssl pkcs12 -export -nokeys -in client.pem -out client-nokey.p12 \
  -passout "pass:$PASS" "${PBE_OPTS[@]}"

rm -f ca.key ca.srl server.key server.csr server.pem client.key client.csr client.pem
