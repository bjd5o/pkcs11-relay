#!/bin/sh
# Writes App/Resources/proto.p12: a throwaway EC P-256 key with a self-signed certificate (email in
# the subjectAltName, so Mail can offer it for S/MIME signing), password `ctk-proto`. Git-ignored.
#   ./make-test-identity.sh [email]
set -eu
cd "$(dirname "$0")"
EMAIL=${1:-ctk-proto@example.invalid}
OUT=App/Resources
mkdir -p "$OUT"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$T/key.pem"
openssl req -new -x509 -key "$T/key.pem" -out "$T/cert.pem" -days 90 -subj "/CN=CTK proto/emailAddress=$EMAIL" \
  -addext "subjectAltName=email:$EMAIL" \
  -addext "keyUsage=critical,digitalSignature,keyAgreement" \
  -addext "extendedKeyUsage=emailProtection,clientAuth"
# Legacy PBE so SecPKCS12Import on older systems reads it too.
openssl pkcs12 -export -inkey "$T/key.pem" -in "$T/cert.pem" -out "$OUT/proto.p12" -passout pass:ctk-proto \
  -name "CTK proto" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
echo "wrote $OUT/proto.p12 for $EMAIL"
