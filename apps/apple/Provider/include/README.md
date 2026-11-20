# PKCS#11 headers

`pkcs11.h`, `pkcs11t.h` and `pkcs11f.h` are the OASIS PKCS#11 3.1 headers, unmodified:

- Source: <https://github.com/oasis-tcs/pkcs11>, directory `published/3-01`, commit
  `188b0b1024403f1907b6cf5fedc0bc148c2221a2` (2021-11-16), fetched 2026-11-19.
- SHA-256:
  - `pkcs11.h`  `fb113f0bc62e0d0894dd1c499b10659e6c47a8ec00d467a186770e07f9c9e293`
  - `pkcs11f.h` `11ee1d5026b1590a6c4a12be1023a2aec9ee185ba31bfb470084e4b6254779ee`
  - `pkcs11t.h` `80f53a40b8e13109cf5b6cb4c736515270f2acb7f5c280ae582f80ca38dc850b`
- Licence: Copyright (c) OASIS Open 2016, 2019. Distributed under the terms of the OASIS IPR
  Policy (<https://www.oasis-open.org/policies-guidelines/ipr>), as stated at the top of each
  file; the repository's `LICENSE.md` gives the same terms (TC IPR mode: RF on RAND).

`RelayPKCS11.h` (ours) defines the platform macros `pkcs11.h` asks for and includes it;
`module.modulemap` (ours) makes it the Swift module `RelayPKCS11`.
`apps/apple/build-provider-xcframework.sh` copies this directory into the XCFramework.

The 3.1 headers declare more than the provider implements: it fills the 2.40
`CK_FUNCTION_LIST` (`CK_VERSION` 0.1 in `C_GetInfo`) and exports only `C_GetFunctionList`,
so callers go through the function list and never link the other `C_*` symbols directly.
