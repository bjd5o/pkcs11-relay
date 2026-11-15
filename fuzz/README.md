# Fuzz targets

One cargo-fuzz target per `relay-core` parser:

| Target | Parser |
|---|---|
| `cbor_messages` | deterministic CBOR and every message decoder (must re-encode identically) |
| `manifest_json` | manifest JSON and its validation |
| `openpgp_signature` | detached signatures and signer keys (rPGP) |
| `apdu_responses` | PIV response chaining, TLV and result parsing |

Run with a nightly toolchain and `cargo-fuzz` 0.13.2:

    cargo +nightly fuzz run cbor_messages

`cargo check --manifest-path fuzz/Cargo.toml` on stable keeps the targets compiling in CI.
