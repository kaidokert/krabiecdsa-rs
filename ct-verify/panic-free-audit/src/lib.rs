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
//! Scope matches the taint/asm gates: `sign_prehashed_ct_with_k`, not
//! the still-`Nct` RFC 6979 nonce derivation.

#![cfg_attr(feature = "panic-handler", no_std)]

#[cfg(feature = "neg-controls")]
mod neg_controls;

use core::hint::black_box;
use fixed_bigint::FixedUInt;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::dangerous::sign_prehashed_ct_with_k;
use krabiecdsa::p256::P256;
use krabiecdsa::p384::P384;

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

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
