# Fuzz targets

cargo-fuzz targets for every `relay-core` parser (CBOR messages, manifest JSON, OpenPGP
signatures, APDU responses). Added in milestone 1. Run with a nightly toolchain:

    cargo +nightly fuzz run <target>
