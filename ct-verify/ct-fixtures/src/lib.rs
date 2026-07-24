//! Constant-time fixtures for krabiecdsa's experimental CT sign path.
//!
//! Each `#[no_mangle] pub unsafe extern "C"` symbol pins one
//! instantiation of the secret-dependent sign so the driver
//! (`ct-driver`) can disassemble it per target ISA and the taint harness
//! (`ct-ctgrind`) can run it under Valgrind with the private inputs
//! marked undefined.
//!
//! Everything reaches the CT surface through the public deployment API
//! ([`krabiecdsa::dangerous::sign_prehashed_ct_with_k`]), so no
//! krabiecdsa source is instrumented. The one discipline these fixtures
//! must never break: wrap every secret input and every output in
//! [`core::hint::black_box`], or fat-LTO `opt-level="z"` folds the body
//! into an ABI stub and the inspection passes vacuously.
//!
//! # Scope boundary — why `_with_k`, not `sign_prehashed_ct`
//!
//! The gates attest the **RCB scalar-multiply sign** given a nonce
//! (`sign_prehashed_ct_with_k`): CT range checks, the branchless
//! double-and-add-always ladder, and `k⁻¹`. They deliberately do **not**
//! drive `sign_prehashed_ct`, whose RFC 6979 nonce derivation still runs
//! on the variable-time (`Nct`) backend — tainting `d` through that path
//! would (correctly) trip the taint gate on the HMAC-DRBG. Closing that
//! last gap is a prerequisite to attesting the full deterministic sign;
//! until then the nonce `k` is a tainted *input* here, exactly as if a
//! CT deriver had produced it.
//!
//! Naming contract the gates key off:
//! - `ct_fix__<op>__<carrier>` — a positive; its emitted code must be
//!   branch-free / taint-clean.
//! - `nct_fix__neg__<op>` — a negative control; it MUST trip each gate,
//!   proving the harness still has teeth.

#![cfg_attr(feature = "panic-handler", no_std)]

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::hint::black_box;
use fixed_bigint::FixedUInt;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::dangerous::sign_prehashed_ct_with_k;
use krabiecdsa::p256::P256;
use krabiecdsa::p384::P384;

// --- deterministic secret material -----------------------------------
//
// Real RFC 6979 §A.2.5/§A.2.6 scalars (validated in
// `ecdsa/tests/rfc6979.rs`), so the sign *happy path* is the code under
// inspection rather than an early `false` return. `pub` so the taint
// harness can copy `d`/`k` into a buffer and mark it undefined: Valgrind
// taint is metadata — the real bytes must be present for the sign to run
// while their V-bits carry the "secret" mark. The digest is public.

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

/// P-256 private key `d` (RFC 6979 §A.2.5).
pub const D256: [u8; 32] = hx("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
/// P-256 nonce `k` for `DIGEST256` (RFC 6979 §A.2.5, "sample").
pub const K256: [u8; 32] = hx("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
/// P-256 prehash (SHA-256 of "sample").
pub const DIGEST256: [u8; 32] =
    hx("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");

/// P-384 private key `d` (RFC 6979 §A.2.6).
pub const D384: [u8; 48] = hx("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5");
/// P-384 nonce `k` for `DIGEST384` (RFC 6979 §A.2.6, "sample").
pub const K384: [u8; 48] = hx("94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9");
/// P-384 prehash (SHA-384 of "sample").
pub const DIGEST384: [u8; 48] = hx("9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe");

// --- positive fixtures ------------------------------------------------
//
// The gates verify *fixture instantiations, not generic code*, so each
// shipped carrier flavor at the curve's field width gets its own
// whole-operation fixture (limb width changes which per-limb code
// folds).

macro_rules! ct_sign_fixture {
    ($name:ident, $curve:ty, $carrier:ty, $bytes:literal) => {
        /// Whole RCB scalar-multiply sign driven by the secret `d` and
        /// nonce `k`. The digest is public.
        ///
        /// # Safety
        /// All pointers must be valid, aligned pointers to `$bytes`-byte
        /// arrays (`digest`/`r`/`s` writable where applicable).
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            d_ptr: *const [u8; $bytes],
            k_ptr: *const [u8; $bytes],
            digest_ptr: *const [u8; $bytes],
            r_ptr: *mut [u8; $bytes],
            s_ptr: *mut [u8; $bytes],
        ) {
            let d = black_box(unsafe { *d_ptr });
            let k = black_box(unsafe { *k_ptr });
            let digest = unsafe { *digest_ptr };
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            let ok = sign_prehashed_ct_with_k::<$curve, $carrier>(
                black_box(&d[..]),
                &digest[..],
                black_box(&k[..]),
                &mut r,
                &mut s,
            );
            unsafe {
                *r_ptr = black_box(r);
                *s_ptr = black_box(s);
            }
            let _ = black_box(ok);
        }
    };
}

// P-256, `u32` limbs — the Cortex-M / RISC-V deployment shape.
ct_sign_fixture!(ct_fix__ecdsa_sign_withk_p256__fb32, P256, FixedUInt<u32, 8, Ct>, 32);
// P-256, `u8` limbs — the AVR-class flavor.
ct_sign_fixture!(ct_fix__ecdsa_sign_withk_p256__fb8, P256, FixedUInt<u8, 32, Ct>, 32);
// P-256, `u64` limbs — the 64-bit-host flavor (double-word intermediates).
ct_sign_fixture!(ct_fix__ecdsa_sign_withk_p256__fb64, P256, FixedUInt<u64, 4, Ct>, 32);
// P-384, `u32` limbs — the deployment shape at the wider field.
ct_sign_fixture!(ct_fix__ecdsa_sign_withk_p384__fb32, P384, FixedUInt<u32, 12, Ct>, 48);

// --- full RFC 6979 deterministic sign ---------------------------------
//
// Nonce derivation (now constant-time) + the RCB sign, driven by the
// secret `d` alone — the taint harness marks only `d` undefined and the
// nonce is derived internally. The digest is public. This is the whole
// deterministic sign the ladder + taint gates attest end to end (up to
// RFC 6979's inherent rejection-loop count).

#[cfg(feature = "deterministic")]
macro_rules! ct_sign_det_fixture {
    ($name:ident, $curve:ty, $carrier:ty, $mac:ty, $bytes:literal) => {
        /// Whole deterministic sign driven by the secret `d`; the digest
        /// is public and the nonce is derived internally.
        ///
        /// # Safety
        /// All pointers must be valid, aligned pointers to `$bytes`-byte
        /// arrays (`digest`/`r`/`s` writable where applicable).
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            d_ptr: *const [u8; $bytes],
            digest_ptr: *const [u8; $bytes],
            r_ptr: *mut [u8; $bytes],
            s_ptr: *mut [u8; $bytes],
        ) {
            let d = black_box(unsafe { *d_ptr });
            let digest = unsafe { *digest_ptr };
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            let ok = krabiecdsa::dangerous::sign_prehashed_ct::<$curve, $carrier, $mac>(
                black_box(&d[..]),
                &digest[..],
                &mut r,
                &mut s,
            );
            unsafe {
                *r_ptr = black_box(r);
                *s_ptr = black_box(s);
            }
            let _ = black_box(ok);
        }
    };
}

#[cfg(feature = "deterministic")]
ct_sign_det_fixture!(ct_fix__ecdsa_sign_det_p256__fb32, P256, FixedUInt<u32, 8, Ct>, hmac::Hmac<sha2::Sha256>, 32);
#[cfg(feature = "deterministic")]
ct_sign_det_fixture!(ct_fix__ecdsa_sign_det_p384__fb32, P384, FixedUInt<u32, 12, Ct>, hmac::Hmac<sha2::Sha384>, 48);

// --- negative controls ------------------------------------------------
//
// Same `extern "C"` + `black_box` shape as the positives, so a passing
// run proves the gates catch a leak in fixture-shaped code — not just in
// a synthetic snippet. Both MUST trip.

/// Negative control — a data-dependent branch on the secret bytes. MUST
/// trip: the early `break` on a tainted byte is a conditional jump that
/// survives optimization on every target.
///
/// # Safety
/// `s_ptr` must be a valid, aligned pointer to a 32-byte array;
/// `out_ptr` to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn nct_fix__neg__secret_branch__p256(
    s_ptr: *const [u8; 32],
    out_ptr: *mut u8,
) {
    let s = black_box(unsafe { *s_ptr });
    let mut n = 0u8;
    for &b in s.iter() {
        if b != 0 {
            break;
        }
        n = n.wrapping_add(1);
    }
    unsafe { *out_ptr = black_box(n) }
}

/// Negative control — a non-constant-time comparison (early-exit on the
/// first differing byte, like a naive `memcmp`). MUST trip.
///
/// # Safety
/// `s_ptr` must be a valid, aligned pointer to a 32-byte array;
/// `out_ptr` to a writable byte.
#[no_mangle]
pub unsafe extern "C" fn nct_fix__neg__vartime_cmp__p256(s_ptr: *const [u8; 32], out_ptr: *mut u8) {
    let s = black_box(unsafe { *s_ptr });
    let reference = [0u8; 32];
    let mut equal = 1u8;
    for i in 0..32 {
        if s[i] != reference[i] {
            equal = 0;
            break;
        }
    }
    unsafe { *out_ptr = black_box(equal) }
}

/// No-op that forces this rlib onto a consumer's link line. The taint
/// harness links `ct-fixtures` as an rlib and calls its `#[no_mangle]`
/// symbols by name across the C ABI; without a referenced Rust item the
/// linker may drop the rlib entirely (and with it every fixture symbol).
pub fn link_anchor() {}
