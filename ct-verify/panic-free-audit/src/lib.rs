//! Linker-DCE audit for krabiecdsa's CT sign path.
//!
//! The `#[no_mangle] pub extern "C"` symbols exercise the whole RCB
//! scalar-multiply sign the way a deployed consumer would, observing the
//! `bool` outcome through `black_box` rather than acting on it. After
//! cross-building with the workspace release profile, krabi-caliper
//! asserts the archive contains no `core::panicking` machinery — for a
//! signer a reachable panic is both a DoS edge and a timing oracle (the
//! panic-formatting path's cost depends on the values being formatted).
//!
//! Scope matches the taint/asm gates: `sign_prehashed_ct_with_k` by
//! default, and the whole `sign_prehashed_ct` plus the hedged
//! `sign_prehashed_ct_hedged` (RFC 6979 §3.6 additional data) under the
//! `deterministic` feature.

#![cfg_attr(feature = "panic-handler", no_std)]

#[cfg(feature = "neg-controls")]
mod neg_controls;

use core::hint::black_box;
use fixed_bigint::FixedUInt;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::p256::P256;
use krabiecdsa::p384::P384;
use krabiecdsa::signing::sign_prehashed_ct_with_k;

#[cfg(feature = "deterministic")]
use hmac::Hmac;
#[cfg(feature = "deterministic")]
use krabiecdsa::signing::{sign_prehashed_ct, sign_prehashed_ct_hedged};
#[cfg(feature = "deterministic")]
use sha2::{Sha256, Sha384};

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}
const fn hx<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

const D256: [u8; 32] = hx("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
const K256: [u8; 32] = hx("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
const DIGEST256: [u8; 32] = hx("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");
const D384: [u8; 48] = hx("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5");
const K384: [u8; 48] = hx("94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9");
const DIGEST384: [u8; 48] = hx("9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe");
const PEER256: [u8; 65] = hx("04c00cebaf052b8d8720f20639a891a6093727d460631d1e1ba909e0c4b41687b508abf40702be0e8fb6c6139737fcfee5d67a00d291dc7588faf3aa92307b27b7");
const PEER384: [u8; 97] = hx("04d3f47bc49bb2cf79fd577c1c441f6f6fbcf5d341c7b7f76c1350a13c67e600d6cf32027e3f829179022823dbd7d65f086ea10729bb01453455287d3f816f4d70e705e871bd6a14e2710b40bbd2267d0ef08afc6a8114e4ed982cd4df41b6dda7");

macro_rules! panic_audit_fixture {
    ($name:ident, $curve:ty, $carrier:ty, $bytes:literal, $d:expr, $k:expr, $digest:expr) => {
        /// # Safety
        /// `out_ptr` must be a valid pointer to a writable byte.
        #[no_mangle]
        pub unsafe extern "C" fn $name(out_ptr: *mut u8) {
            let d = black_box($d);
            let k = black_box($k);
            let digest = black_box($digest);
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            let ok = sign_prehashed_ct_with_k::<$curve, $carrier>(
                &d[..],
                &digest[..],
                &k[..],
                &mut r,
                &mut s,
            );
            // Keep the serialized r/s live: with only the bool observed,
            // LLVM may DCE the final serialization writes and the audit
            // would vacuously skip that step.
            black_box(&r);
            black_box(&s);
            unsafe { *out_ptr = black_box(ok as u8) }
        }
    };
}

panic_audit_fixture!(panic_audit__ecdsa_sign_withk_p256__fb32, P256, FixedUInt<u32, 8, Ct>, 32, D256, K256, DIGEST256);
panic_audit_fixture!(panic_audit__ecdsa_sign_withk_p256__fb8, P256, FixedUInt<u8, 32, Ct>, 32, D256, K256, DIGEST256);
panic_audit_fixture!(panic_audit__ecdsa_sign_withk_p256__fb64, P256, FixedUInt<u64, 4, Ct>, 32, D256, K256, DIGEST256);
panic_audit_fixture!(panic_audit__ecdsa_sign_withk_p384__fb32, P384, FixedUInt<u32, 12, Ct>, 48, D384, K384, DIGEST384);

// ECDH agreement (`ecdh_diffie_hellman_ct`): peer-point validation + the
// variable-base `d·P` scalar multiply + affine readout. Crate-owned, no
// HMAC/SHA — audited unconditionally like the sign-with-`k` leg.
macro_rules! panic_audit_ecdh_fixture {
    ($name:ident, $curve:ty, $carrier:ty, $bytes:literal, $d:expr, $peer:expr) => {
        /// # Safety
        /// `out_ptr` must be a valid pointer to a writable byte.
        #[no_mangle]
        pub unsafe extern "C" fn $name(out_ptr: *mut u8) {
            let d = black_box($d);
            let peer = black_box($peer);
            let mut out = [0u8; $bytes];
            let ok = krabiecdsa::signing::ecdh_diffie_hellman_ct::<$curve, $carrier>(
                &d[..],
                &peer[..],
                &mut out,
            );
            black_box(&out);
            unsafe { *out_ptr = black_box(ok as u8) }
        }
    };
}

panic_audit_ecdh_fixture!(panic_audit__ecdh_p256__fb32, P256, FixedUInt<u32, 8, Ct>, 32, D256, PEER256);
panic_audit_ecdh_fixture!(panic_audit__ecdh_p384__fb32, P384, FixedUInt<u32, 12, Ct>, 48, D384, PEER384);

// Fully-blinded sign (`sign_prehashed_ct_with_k_blinded`): the coordinate-λ
// base randomization plus the `k' = k + r·n` scalar blinding (`blind_scalar`
// + the widened ladder). λ and `r` are public; audited unconditionally.
const LAMBDA256: [u8; 32] = hx("0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff00");
const LAMBDA384: [u8; 48] = hx("0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff00fedcba98765432100123456789abcdef");
const SBLIND: [u8; 8] = hx("0123456789abcdef");

macro_rules! panic_audit_blinded_fixture {
    ($name:ident, $curve:ty, $carrier:ty, $bytes:literal, $d:expr, $k:expr, $digest:expr, $lambda:expr) => {
        /// # Safety
        /// `out_ptr` must be a valid pointer to a writable byte.
        #[no_mangle]
        pub unsafe extern "C" fn $name(out_ptr: *mut u8) {
            let d = black_box($d);
            let k = black_box($k);
            let digest = black_box($digest);
            let lambda = black_box($lambda);
            let sb = black_box(SBLIND);
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            let ok = krabiecdsa::signing::sign_prehashed_ct_with_k_blinded::<$curve, $carrier>(
                &d[..],
                &digest[..],
                &k[..],
                &lambda[..],
                &sb[..],
                &mut r,
                &mut s,
            );
            black_box(&r);
            black_box(&s);
            unsafe { *out_ptr = black_box(ok as u8) }
        }
    };
}

panic_audit_blinded_fixture!(panic_audit__ecdsa_sign_blinded_p256__fb32, P256, FixedUInt<u32, 8, Ct>, 32, D256, K256, DIGEST256, LAMBDA256);
panic_audit_blinded_fixture!(panic_audit__ecdsa_sign_blinded_p384__fb32, P384, FixedUInt<u32, 12, Ct>, 48, D384, K384, DIGEST384, LAMBDA384);

// Full RFC 6979 deterministic sign (nonce derivation + sign). Pulls the
// HMAC-DRBG (`hmac`/`sha2`) into the audited archive — krabiecdsa's own
// derivation byte-plumbing is panic-free (audited crate-scoped); the
// upstream `hmac`/`sha2` block buffering carries its own panic branches,
// out of scope here.
#[cfg(feature = "deterministic")]
macro_rules! panic_audit_det_fixture {
    ($name:ident, $curve:ty, $carrier:ty, $mac:ty, $bytes:literal, $d:expr, $digest:expr) => {
        /// # Safety
        /// `out_ptr` must be a valid pointer to a writable byte.
        #[no_mangle]
        pub unsafe extern "C" fn $name(out_ptr: *mut u8) {
            let d = black_box($d);
            let digest = black_box($digest);
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            let ok =
                sign_prehashed_ct::<$curve, $carrier, $mac>(&d[..], &digest[..], &mut r, &mut s);
            black_box(&r);
            black_box(&s);
            unsafe { *out_ptr = black_box(ok as u8) }
        }
    };
}

#[cfg(feature = "deterministic")]
panic_audit_det_fixture!(panic_audit__ecdsa_sign_det_p256__fb32, P256, FixedUInt<u32, 8, Ct>, Hmac<Sha256>, 32, D256, DIGEST256);
#[cfg(feature = "deterministic")]
panic_audit_det_fixture!(panic_audit__ecdsa_sign_det_p256__fb8, P256, FixedUInt<u8, 32, Ct>, Hmac<Sha256>, 32, D256, DIGEST256);
#[cfg(feature = "deterministic")]
panic_audit_det_fixture!(panic_audit__ecdsa_sign_det_p384__fb32, P384, FixedUInt<u32, 12, Ct>, Hmac<Sha384>, 48, D384, DIGEST384);

// Hedged deterministic sign (§3.6 additional data). Same crate-owned scope
// as the plain deterministic leg — the §3.6 plumbing is krabiecdsa-owned,
// while the upstream hmac/sha2 block buffering stays out of scope.
#[cfg(feature = "deterministic")]
macro_rules! panic_audit_hedged_fixture {
    ($name:ident, $curve:ty, $carrier:ty, $mac:ty, $bytes:literal, $d:expr, $digest:expr) => {
        /// # Safety
        /// `out_ptr` must be a valid pointer to a writable byte.
        #[no_mangle]
        pub unsafe extern "C" fn $name(out_ptr: *mut u8) {
            let d = black_box($d);
            let digest = black_box($digest);
            let added = black_box([0x5au8; 32]);
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            let ok = sign_prehashed_ct_hedged::<$curve, $carrier, $mac>(
                &d[..],
                &digest[..],
                &added[..],
                &mut r,
                &mut s,
            );
            black_box(&r);
            black_box(&s);
            unsafe { *out_ptr = black_box(ok as u8) }
        }
    };
}

#[cfg(feature = "deterministic")]
panic_audit_hedged_fixture!(panic_audit__ecdsa_sign_hedged_p256__fb32, P256, FixedUInt<u32, 8, Ct>, Hmac<Sha256>, 32, D256, DIGEST256);
#[cfg(feature = "deterministic")]
panic_audit_hedged_fixture!(panic_audit__ecdsa_sign_hedged_p384__fb32, P384, FixedUInt<u32, 12, Ct>, Hmac<Sha384>, 48, D384, DIGEST384);

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
