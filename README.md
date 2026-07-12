### krabiecdsa

[![crate](https://img.shields.io/crates/v/krabiecdsa.svg)](https://crates.io/crates/krabiecdsa)
[![documentation](https://docs.rs/krabiecdsa/badge.svg)](https://docs.rs/krabiecdsa/)
[![Rust](https://github.com/kaidokert/krabiecdsa-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabiecdsa-rs/actions/workflows/rust.yml)

ECDSA over NIST P-256, secp256k1 and NIST P-384 for microcontrollers. The
arithmetic is generic over bigint backend traits, built on
[modmath](https://crates.io/crates/modmath), with
[fixed-bigint](https://crates.io/crates/fixed-bigint) as the tested backend.
`no_std`, no allocator, no panics. RustCrypto [signature](https://crates.io/crates/signature) traits are supported through `PrehashVerifier`.

#### Resource usage (as of 0.1.0)

| Target | Curve | Backend | .text (KiB) | Stack (bytes) |
| ------ | ----- | ------- | ----------: | ------------: |
| Cortex-M0 | P-256 | u32×8 | 5.8 | 1576 |
| Cortex-M0 | secp256k1 | u32×8 | 5.8 | 1576 |
| Cortex-M0 | P-384 | u32×12 | 5.9 | 2368 |
| Cortex-M3 | P-256 | u32×8 | 6.0 | 1536 |
| Cortex-M3 | secp256k1 | u32×8 | 6.0 | 1536 |
| Cortex-M3 | P-384 | u32×12 | 6.0 | 2320 |

Verify-minus-baseline deltas from the QEMU harness in `footprint/`;
u8-limb backends and approximate cycle counts in its full matrix.
