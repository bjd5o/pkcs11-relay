#!/bin/sh
# Milestone 3 gate, run by the client container: third-party PKCS#11 callers against the
# provider, through the relay and the fixture approvers (A approves, B denies, C is stale).
# Every signature is verified by OpenSSL against the public key read through the provider.
set -u
MOD=/usr/lib/pkcs11/librelay_pkcs11.so
export RELAY_PKCS11_CONFIG=/fixtures/provider.toml
W=$(mktemp -d)
FAILS=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILS=$((FAILS + 1)); }
check() { name=$1; shift; if "$@" >"$W/out" 2>&1; then pass "$name"; else fail "$name"; sed 's/^/      /' "$W/out"; fi; }
p11() { pkcs11-tool --module "$MOD" "$@"; }
# CKA_ID of each fixture key (the manifest's id): pkcs11-tool selects keys for --sign,
# --decrypt and --read-object by --id, not by --label.
id_of() { case $1 in openbao-unseal) echo 01;; sign-ec) echo 02;; sign-rsa) echo 03;; auth-ec) echo 04;; auth-rsa) echo 05;; esac; }
# expect_rv NAME 'CKR_NAME|0xHEX' command...: the command must fail and print that return code
# (by name, or by value for codes this pkcs11-tool cannot name, such as CKR_FUNCTION_REJECTED).
expect_rv() {
  name=$1; rv=$2; shift 2
  if "$@" >"$W/out" 2>&1; then fail "$name (succeeded)"; cat "$W/out"; return; fi
  if grep -qE "$rv" "$W/out"; then pass "$name"; else fail "$name"; sed 's/^/      /' "$W/out"; fi
}

# --- Pairing: the first run registers and logs the code; approver A approves it. ---
i=0
until p11 --token-label softcard-a -O 2>/dev/null | grep -q "label: *sign-ec"; do
  i=$((i + 1)); [ $i -gt 60 ] && { fail "pairing and discovery"; exit 1; }
  sleep 1
done
pass "pairing approved; keys discovered"

# --- Listing: exactly the trusted keys, manifest labels and IDs, no attest key. ---
p11 -L >"$W/slots" 2>&1
check "pkcs11-tool -L lists one slot per manifest token" sh -c "grep -c 'token label *: softcard-' $W/slots | grep -qx 3"
p11 --token-label softcard-a -O >"$W/objs" 2>&1
check "-O lists the slot's keys with manifest labels" sh -c "for l in openbao-unseal sign-ec sign-rsa auth-ec auth-rsa; do grep -q \"label: *\$l\$\" $W/objs || exit 1; done"
check "-O shows manifest IDs (sign-ec = 02)" grep -q "ID: *02" "$W/objs"
check "no attest key, no key the client was not approved for" sh -c "! grep -qE 'label: *(attest|unapproved)\$' $W/objs"

# Public keys, read through the provider.
for k in openbao-unseal sign-ec sign-rsa auth-ec auth-rsa; do
  p11 --token-label softcard-a --read-object --type pubkey --id "$(id_of $k)" -o "$W/$k.der" >/dev/null 2>&1
  openssl pkey -pubin -inform DER -in "$W/$k.der" -out "$W/$k.pem" 2>/dev/null
done
check "public keys exported through the provider" test -s "$W/sign-ec.pem" -a -s "$W/openbao-unseal.pem"

printf 'a release tag to sign\n' >"$W/msg"
openssl dgst -sha256 -binary "$W/msg" >"$W/dgst"

# --- sign keys: hash-and-sign ---
check "sign ECDSA-SHA256 (sign key), verified by OpenSSL" sh -c "
  pkcs11-tool --module $MOD --token-label softcard-a --sign -m ECDSA-SHA256 --id 02 --signature-format openssl -i $W/msg -o $W/sig1 &&
  openssl dgst -sha256 -verify $W/sign-ec.pem -signature $W/sig1 $W/msg"
check "sign SHA256-RSA-PKCS (sign key), verified by OpenSSL" sh -c "
  pkcs11-tool --module $MOD --token-label softcard-a --sign -m SHA256-RSA-PKCS --id 03 -i $W/msg -o $W/sig2 &&
  openssl dgst -sha256 -verify $W/sign-rsa.pem -signature $W/sig2 $W/msg"

# --- auth keys: raw digests ---
check "sign ECDSA (auth key), verified by OpenSSL" sh -c "
  pkcs11-tool --module $MOD --token-label softcard-a --sign -m ECDSA --id 04 --signature-format openssl -i $W/dgst -o $W/sig3 &&
  openssl pkeyutl -verify -pubin -inkey $W/auth-ec.pem -in $W/dgst -sigfile $W/sig3"
# DigestInfo for SHA-256, then the digest.
{ printf '\060\061\060\015\006\011\140\206\110\001\145\003\004\002\001\005\000\004\040'; cat "$W/dgst"; } >"$W/digestinfo"
check "sign RSA-PKCS (auth key), verified by OpenSSL" sh -c "
  pkcs11-tool --module $MOD --token-label softcard-a --sign -m RSA-PKCS --id 05 -i $W/digestinfo -o $W/sig4 &&
  openssl pkeyutl -verify -pubin -inkey $W/auth-rsa.pem -pkeyopt digest:sha256 -in $W/dgst -sigfile $W/sig4"

# --- encrypt key: OpenSSL encrypts to the exported key, the provider decrypts ---
printf 'the unseal key' >"$W/pt"
openssl pkeyutl -encrypt -pubin -inkey "$W/openbao-unseal.pem" -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$W/pt" -out "$W/ct"
check "decrypt RSA-PKCS-OAEP (SHA-256) recovers OpenSSL ciphertext" sh -c "
  pkcs11-tool --module $MOD --token-label softcard-a --decrypt -m RSA-PKCS-OAEP --hash-algorithm SHA256 --mgf MGF1-SHA256 --id 01 -i $W/ct -o $W/out-pt &&
  cmp $W/pt $W/out-pt"

# --- Refusals ---
expect_rv "role violation refused locally (decrypt with a sign key)" "CKR_KEY_FUNCTION_NOT_PERMITTED|\(0x68\)" \
  p11 --token-label softcard-a --decrypt -m RSA-PKCS-OAEP --hash-algorithm SHA256 --mgf MGF1-SHA256 --id 02 -i "$W/ct"
expect_rv "mechanism not allowed refused locally (raw ECDSA on a sign key)" "CKR_MECHANISM_INVALID|\(0x70\)" \
  p11 --token-label softcard-a --sign -m ECDSA --id 02 -i "$W/dgst"
expect_rv "signed denial → CKR_FUNCTION_REJECTED" "CKR_FUNCTION_REJECTED|\(0x200\)" \
  p11 --token-label softcard-b --sign -m ECDSA --id 07 -i "$W/dgst"
expect_rv "unattested device → CKR_DEVICE_ERROR" "CKR_DEVICE_ERROR|\(0x30\)" \
  p11 --token-label softcard-c --sign -m ECDSA --id 08 -i "$W/dgst"

# --- OpenSSL 3 with pkcs11-provider ---
export PKCS11_PROVIDER_MODULE="$MOD"
check "OpenSSL pkcs11-provider signs (auth-ec), verified by OpenSSL" sh -c "
  openssl pkeyutl -provider pkcs11 -provider default -sign -inkey 'pkcs11:token=softcard-a;object=auth-ec;type=private' -in $W/dgst -out $W/sig5 &&
  openssl pkeyutl -verify -pubin -inkey $W/auth-ec.pem -in $W/dgst -sigfile $W/sig5"

# --- OpenSSH ---
check "ssh-keygen -D lists the auth key the sshd trusts" sh -c "ssh-keygen -D $MOD 2>/dev/null | cut -d' ' -f1,2 | grep -qxF \"\$(cut -d' ' -f1,2 /fixtures/ssh_authorized_keys)\""
check "ssh -I authenticates to a test sshd with the auth key" \
  ssh -I "$MOD" -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=publickey tester@sshd true

if [ "$FAILS" -eq 0 ]; then echo "milestone 3 gate passed"; else echo "$FAILS check(s) failed"; exit 1; fi
