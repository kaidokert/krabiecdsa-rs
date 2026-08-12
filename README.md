### krabiecdsa

[![crate](https://img.shields.io/crates/v/krabiecdsa.svg)](https://crates.io/crates/krabiecdsa)
[![documentation](https://docs.rs/krabiecdsa/badge.svg)](https://docs.rs/krabiecdsa/)
[![Rust](https://github.com/kaidokert/krabiecdsa-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabiecdsa-rs/actions/workflows/rust.yml)
[![Coverage Status](https://coveralls.io/repos/github/kaidokert/krabiecdsa-rs/badge.svg?branch=main)](https://coveralls.io/github/kaidokert/krabiecdsa-rs?branch=main)

ECDSA over NIST P-256, secp256k1 and NIST P-384 for microcontrollers. The
arithmetic is generic over bigint backend traits, built on
[modmath](https://crates.io/crates/modmath), with
[fixed-bigint](https://crates.io/crates/fixed-bigint) as the tested backend.
`no_std`, no allocator, no panics. RustCrypto [signature](https://crates.io/crates/signature) traits are supported both ways: `PrehashVerifier`/`DigestVerifier` for verification, and `PrehashSigner`/`RandomizedPrehashSigner`/`DigestSigner`/`RandomizedDigestSigner`/`Keypair` for constant-time signing. ECDH key agreement is exposed through the RustCrypto [kem](https://crates.io/crates/kem) traits (`Encapsulate`/`TryDecapsulate`).

#### Resource usage (as of 0.6.0)

| Target | Curve | Backend | .text (KiB) | Stack (bytes) |
| ------ | ----- | ------- | ----------: | ------------: |
| Cortex-M0 | P-256 | u32×8 | 7.7 | 1304 |
| Cortex-M0 | P-384 | u32×12 | 8.0 | 1960 |
| Cortex-M3 | P-256 | u32×8 | 7.6 | 1272 |
| Cortex-M3 | P-384 | u32×12 | 7.8 | 1928 |
| RV32IMAC | P-256 | u32×8 | 8.7 | 1280 |
| RV32IMAC | P-384 | u32×12 | 9.0 | 1936 |
| AVR ATmega2560 | P-256 | u8×32 | 10.8 | 2418 |
| AVR ATmega2560 | P-384 | u8×48 | 11.0 | 3586 |

These numbers are what verification adds over a bare-firmware baseline,
measured on emulators (QEMU for Cortex-M and RISC-V, simavr for AVR) and
refreshed by CI. secp256k1 comes out close enough to P-256 that it isn't
listed separately. The `footprint/` directory has the fuller data, including
the byte-limb backends and rough timing.

Constant-time signing and ECDH cost more — RCB complete formulas, `FieldCt`
arithmetic, and the RFC 6979 HMAC-SHA256 DRBG. The guarantee is timing-only;
the randomized signer and ECDH add projective-coordinate and scalar (`k + r·n`)
blinding against power/EM DPA. See the `signing` module docs for the full
side-channel scope.

| Target | Op | Curve | .text (KiB) | Stack (bytes) |
| ------ | -- | ----- | ----------: | ------------: |
| Cortex-M3 | sign | P-256 (u32) | 12.1 | 3392 |
