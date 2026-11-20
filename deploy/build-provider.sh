#!/usr/bin/env bash
# Build librelay_pkcs11.so for Linux in a container, for this machine's architecture:
#   deploy/build-provider.sh gnu    # Debian bookworm: glibc 2.36 and newer
#   deploy/build-provider.sh musl   # Alpine: musl, for Alpine-based processes
#     (needs Alpine's libgcc package at run time: `apk add libgcc`, for the unwinder that
#     catch_unwind at the FFI boundary depends on)
# Output: dist/librelay_pkcs11-<arch>-<libc>.so. CI builds x86_64 and aarch64 natively.
set -euo pipefail
libc="${1:?usage: deploy/build-provider.sh gnu|musl}"
root="$(cd "$(dirname "$0")/.." && pwd)"
# Rust version: kept equal to mise.toml by `mise run sync-rust`.
case "$libc" in
  gnu)  image=rust:1.95.0-bookworm; prep=true ;;
  # Rust's musl targets link statically by default, which rules out a cdylib; the provider
  # must link musl dynamically, as the processes that load it do.
  musl) image=rust:1.95.0-alpine; prep="apk add --no-cache musl-dev >/dev/null" ;;
  *) echo "libc must be gnu or musl" >&2; exit 2 ;;
esac
mkdir -p "$root/dist"
docker run --rm -v "$root:/src" -w /src -v relay-provider-target-$libc:/src/target \
  -v relay-cargo-registry:/usr/local/cargo/registry \
  -e RUSTFLAGS="$( [ "$libc" = musl ] && echo '-C target-feature=-crt-static' )" "$image" sh -c "
    $prep && cargo build --release --locked -p relay-pkcs11 &&
    arch=\$(uname -m) && cp target/release/librelay_pkcs11.so dist/librelay_pkcs11-\$arch-$libc.so &&
    echo built dist/librelay_pkcs11-\$arch-$libc.so"
