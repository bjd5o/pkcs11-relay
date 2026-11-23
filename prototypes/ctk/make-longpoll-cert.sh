#!/bin/sh
# Certificate for longpoll-server.py: a throwaway root (key deleted before this script ends) and a
# server key for one address, in .longpoll (git-ignored). App/Resources/longpoll-root.der is the
# root's public certificate, which the prototype trusts for this check only (never the system).
#   ./make-longpoll-cert.sh 10.0.0.170
set -eu
cd "$(dirname "$0")"
ADDR=${1:?address}
umask 077
mkdir -p .longpoll App/Resources
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
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:$ADDR
authorityKeyIdentifier = keyid
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$T/root.key"
openssl req -new -x509 -key "$T/root.key" -out "$T/root.pem" -days 14 -sha256 -config "$T/ext.cnf" -extensions root -subj "/CN=CTK proto long-poll root (throwaway)"
openssl ecparam -name prime256v1 -genkey -noout -out .longpoll/server.key
openssl req -new -key .longpoll/server.key -out "$T/s.csr" -config "$T/ext.cnf" -subj "/CN=ctk-proto long-poll"
openssl x509 -req -in "$T/s.csr" -CA "$T/root.pem" -CAkey "$T/root.key" -set_serial "0x$(openssl rand -hex 8)" -days 14 -sha256 -extfile "$T/ext.cnf" -extensions leaf -out .longpoll/server.pem 2>/dev/null
rm -f "$T/root.key"
openssl verify -CAfile "$T/root.pem" .longpoll/server.pem >/dev/null
openssl x509 -in "$T/root.pem" -outform der -out App/Resources/longpoll-root.der
chmod 644 App/Resources/longpoll-root.der
cp "$T/root.pem" .longpoll/root.pem
echo "wrote .longpoll and App/Resources/longpoll-root.der for $ADDR"
