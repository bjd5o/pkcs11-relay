# PKCS#11 headers

`pkcs11.h`, `pkcs11t.h` and `pkcs11f.h` are the OASIS PKCS#11 3.2 headers, unmodified:

- Source: <https://github.com/oasis-tcs/pkcs11>, directory `published/3-02`, commit
  `1d5e40ed5e1842b6c2be0231833373531603929d` (2025-10-22, "Issue #24"), fetched 2026-11-20.
  The published 3.2 headers changed after release (June 2025), so update by commit, not by
  directory.
- SHA-256:
  - `pkcs11.h`  `bbc8a26569ce56e0dea540f03dffd56be305175e8e61cad2b8fffd7c65dbf6d8`
  - `pkcs11f.h` `3a205ff9a12247108193d124571fac88e38b59f1273e462baa1b5e00cd182fa0`
  - `pkcs11t.h` `95738fdcd9b5c9c73f55f9132aefa87354556cec1c46f681b8a2000b8b5dbccb`
- Licence: Copyright (c) OASIS Open 2016, 2019, 2024. Distributed under the terms of the OASIS
  IPR Policy (<https://www.oasis-open.org/policies-guidelines/ipr>), as stated at the top of
  each file; the repository's `LICENSE.md` gives the same terms (TC IPR mode: RF on RAND).

`RelayPKCS11.h` (ours) defines the platform macros `pkcs11.h` asks for and includes it;
`module.modulemap` (ours) makes it the Swift module `RelayPKCS11`.
`apps/apple/build-provider-xcframework.sh` copies this directory into the XCFramework.

The 3.2 headers declare more than the provider implements: it fills the 2.40
`CK_FUNCTION_LIST` (`CK_VERSION` 0.1 in `C_GetInfo`) and exports only `C_GetFunctionList`,
so callers go through the function list and never link the other `C_*` symbols directly.
