### krabiecdsa

[![crate](https://img.shields.io/crates/v/krabiecdsa.svg)](https://crates.io/crates/krabiecdsa)
[![documentation](https://docs.rs/krabiecdsa/badge.svg)](https://docs.rs/krabiecdsa/)
[![Rust](https://github.com/kaidokert/krabiecdsa-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/krabiecdsa-rs/actions/workflows/rust.yml)

ECDSA over NIST P-256, secp256k1 and NIST P-384 for microcontrollers. The
arithmetic is generic over bigint backend traits, built on
[modmath](https://crates.io/crates/modmath), with
[fixed-bigint](https://crates.io/crates/fixed-bigint) as the tested backend.
`no_std`, no allocator, no panics. RustCrypto [signature](https://crates.io/crates/signature) traits are supported through `PrehashVerifier`.
