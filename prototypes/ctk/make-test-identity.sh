#!/bin/sh
# Writes to App/Resources (git-ignored):
#   proto.p12       a throwaway EC P-256 leaf key with its certificate (email in the subjectAltName,
#                   so Mail can offer it for S/MIME), password `ctk-proto`. Not a CA.
#   proto-root.cer  the public certificate of the throwaway root that issued it. The root's private
#                   key exists only while this script runs and is never written outside its temp dir.
#   ./make-test-identity.sh [email]
# Only proto-root.cer may ever be trusted on a device, and only for this test. Never install
# proto.p12 there: it holds the leaf key, and Mail would use that copy instead of the token.
set -eu
cd "$(dirname "$0")"
EMAIL=${1:-ctk-proto@example.invalid}
OUT=${OUT:-App/Resources}
mkdir -p "$OUT"
T=$(mktemp -d)
trap 'rm -rf "${T:?}"' EXIT
cat > "$T/ext.cnf" <<CNF
[req]
distinguished_name = dn
[dn]
[root]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyAgreement
extendedKeyUsage = emailProtection,clientAuth
subjectAltName = email:$EMAIL
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$T/root.key"
openssl req -new -x509 -key "$T/root.key" -out "$T/root.pem" -days 30 -sha256 -config "$T/ext.cnf" -extensions root \
  -subj "/CN=CTK proto test root (throwaway)"
openssl ecparam -name prime256v1 -genkey -noout -out "$T/key.pem"
openssl req -new -key "$T/key.pem" -out "$T/leaf.csr" -config "$T/ext.cnf" -subj "/CN=CTK proto/emailAddress=$EMAIL"
openssl x509 -req -in "$T/leaf.csr" -CA "$T/root.pem" -CAkey "$T/root.key" -set_serial "0x$(openssl rand -hex 8)" \
  -days 30 -sha256 -extfile "$T/ext.cnf" -extensions leaf -out "$T/cert.pem" 2>/dev/null
rm -f "$T/root.key"
openssl verify -CAfile "$T/root.pem" "$T/cert.pem" >/dev/null
# Legacy PBE so SecPKCS12Import on older systems reads it too.
openssl pkcs12 -export -inkey "$T/key.pem" -in "$T/cert.pem" -certfile "$T/root.pem" -out "$OUT/proto.p12" \
  -passout pass:ctk-proto -name "CTK proto" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
openssl x509 -in "$T/root.pem" -outform der -out "$OUT/proto-root.cer"
echo "wrote $OUT/proto.p12 and $OUT/proto-root.cer for $EMAIL"
