//! Taint wrappers, one per `ct-fixtures` symbol. Each mirrors its
//! fixture's ABI one-for-one; extending the fixture set means adding the
//! symbol there and the matching wrapper here.
//!
//! Taint model: the private key `d` and the nonce `k` are the secrets.
//! The digest is public (a signer commits to it), so it is not tainted —
//! a secret-dependent branch anywhere in the reachable sign path
//! (including inlined modmath / fixed-bigint primitives) trips memcheck,
//! while the many legitimate branches on public lengths / curve
//! structure pass by construction.
//!
//! The `r`/`s` output is untainted before we `black_box` it: an ECDSA
//! signature is secret-*derived* but public-by-design (it is what the
//! caller publishes), so reads of it downstream are not leaks.

use core::hint::black_box;
use krabi_caliper::ctgrind_fixture;
use krabi_caliper::host::ctgrind::{taint_val, untaint_val};

// Three synthetic detector controls (branch / equality / table-index on
// a tainted secret) — proves memcheck still has teeth on this build.
krabi_caliper::ctgrind_standard_controls!();

macro_rules! taint_sign_fixture {
    ($name:ident, $bytes:literal, $d:expr, $k:expr, $digest:expr) => {
        unsafe extern "C" {
            fn $name(
                d_ptr: *const [u8; $bytes],
                k_ptr: *const [u8; $bytes],
                digest_ptr: *const [u8; $bytes],
                r_ptr: *mut [u8; $bytes],
                s_ptr: *mut [u8; $bytes],
            );
        }
        ctgrind_fixture!($name, {
            let d = $d;
            let k = $k;
            let digest = $digest;
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            taint_val(&d);
            taint_val(&k);
            unsafe { $name(&d, &k, &digest, &mut r, &mut s) }
            untaint_val(&r);
            untaint_val(&s);
            let _ = black_box((r, s));
        });
    };
}

taint_sign_fixture!(
    ct_fix__ecdsa_sign_withk_p256__fb32,
    32,
    ct_fixtures::D256,
    ct_fixtures::K256,
    ct_fixtures::DIGEST256
);
taint_sign_fixture!(
    ct_fix__ecdsa_sign_withk_p256__fb8,
    32,
    ct_fixtures::D256,
    ct_fixtures::K256,
    ct_fixtures::DIGEST256
);
taint_sign_fixture!(
    ct_fix__ecdsa_sign_withk_p256__fb64,
    32,
    ct_fixtures::D256,
    ct_fixtures::K256,
    ct_fixtures::DIGEST256
);
taint_sign_fixture!(
    ct_fix__ecdsa_sign_withk_p384__fb32,
    48,
    ct_fixtures::D384,
    ct_fixtures::K384,
    ct_fixtures::DIGEST384
);

// ECDH agreement — taints the secret scalar `d` only; the peer point is
// public (a cleartext `key_share`), so it is not tainted. A secret-
// dependent branch in the `d·P` ladder or the `d` range check trips
// memcheck; the legitimate branches validating the public peer point pass.
macro_rules! taint_ecdh_fixture {
    ($name:ident, $bytes:literal, $pkbytes:literal, $d:expr, $peer:expr) => {
        unsafe extern "C" {
            fn $name(
                d_ptr: *const [u8; $bytes],
                peer_ptr: *const [u8; $pkbytes],
                out_ptr: *mut [u8; $bytes],
            );
        }
        ctgrind_fixture!($name, {
            let d = $d;
            let peer = $peer;
            let mut out = [0u8; $bytes];
            taint_val(&d);
            unsafe { $name(&d, &peer, &mut out) }
            untaint_val(&out);
            let _ = black_box(out);
        });
    };
}

taint_ecdh_fixture!(
    ct_fix__ecdh_p256__fb32,
    32,
    65,
    ct_fixtures::D256,
    ct_fixtures::PEER256
);
taint_ecdh_fixture!(
    ct_fix__ecdh_p384__fb32,
    48,
    97,
    ct_fixtures::D384,
    ct_fixtures::PEER384
);

// Full RFC 6979 deterministic sign — taints `d` only; the nonce is
// derived internally by the constant-time RFC 6979 DRBG. This taints the
// secret key through the *whole* deterministic sign, not just the scalar
// multiply. The digest is public; `r`/`s` are untainted before
// `black_box` (secret-derived but published).
macro_rules! taint_det_fixture {
    ($name:ident, $bytes:literal, $d:expr, $digest:expr) => {
        unsafe extern "C" {
            fn $name(
                d_ptr: *const [u8; $bytes],
                digest_ptr: *const [u8; $bytes],
                r_ptr: *mut [u8; $bytes],
                s_ptr: *mut [u8; $bytes],
            );
        }
        ctgrind_fixture!($name, {
            let d = $d;
            let digest = $digest;
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            taint_val(&d);
            unsafe { $name(&d, &digest, &mut r, &mut s) }
            untaint_val(&r);
            untaint_val(&s);
            let _ = black_box((r, s));
        });
    };
}

taint_det_fixture!(
    ct_fix__ecdsa_sign_det_p256__fb32,
    32,
    ct_fixtures::D256,
    ct_fixtures::DIGEST256
);
taint_det_fixture!(
    ct_fix__ecdsa_sign_det_p384__fb32,
    48,
    ct_fixtures::D384,
    ct_fixtures::DIGEST384
);

// Hedged deterministic sign (RFC 6979 §3.6 additional data) — taints `d`
// only; the nonce is derived internally with public hedge entropy `added`
// folded into the DRBG seed. Same CT expectation as the plain deterministic
// sign; this pins the §3.6 additional-data plumbing taint-clean.
macro_rules! taint_hedged_fixture {
    ($name:ident, $bytes:literal, $d:expr, $digest:expr) => {
        unsafe extern "C" {
            fn $name(
                d_ptr: *const [u8; $bytes],
                digest_ptr: *const [u8; $bytes],
                added_ptr: *const [u8; 32],
                r_ptr: *mut [u8; $bytes],
                s_ptr: *mut [u8; $bytes],
            );
        }
        ctgrind_fixture!($name, {
            let d = $d;
            let digest = $digest;
            let added = ct_fixtures::ADDED; // public, not tainted
            let mut r = [0u8; $bytes];
            let mut s = [0u8; $bytes];
            taint_val(&d);
            unsafe { $name(&d, &digest, &added, &mut r, &mut s) }
            untaint_val(&r);
            untaint_val(&s);
            let _ = black_box((r, s));
        });
    };
}

taint_hedged_fixture!(
    ct_fix__ecdsa_sign_hedged_p256__fb32,
    32,
    ct_fixtures::D256,
    ct_fixtures::DIGEST256
);
taint_hedged_fixture!(
    ct_fix__ecdsa_sign_hedged_p384__fb32,
    48,
    ct_fixtures::D384,
    ct_fixtures::DIGEST384
);

// Negative controls in the fixture crate's own ABI shape (data-dependent
// branch + early-exit compare on tainted bytes). Both MUST trip.
unsafe extern "C" {
    fn nct_fix__neg__secret_branch__p256(s_ptr: *const [u8; 32], out_ptr: *mut u8);
    fn nct_fix__neg__vartime_cmp__p256(s_ptr: *const [u8; 32], out_ptr: *mut u8);
    fn nct_fix__neg__vartime_serialize__p256(s_ptr: *const [u8; 32], out_ptr: *mut u8);
}
ctgrind_fixture!(nct_fix__neg__secret_branch__p256, {
    let s = [0u8; 32];
    let mut out = 0u8;
    taint_val(&s);
    unsafe { nct_fix__neg__secret_branch__p256(&s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});
ctgrind_fixture!(nct_fix__neg__vartime_cmp__p256, {
    let s = [0u8; 32];
    let mut out = 0u8;
    taint_val(&s);
    unsafe { nct_fix__neg__vartime_cmp__p256(&s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});
ctgrind_fixture!(nct_fix__neg__vartime_serialize__p256, {
    let s = [0u8; 32];
    let mut out = 0u8;
    taint_val(&s);
    unsafe { nct_fix__neg__vartime_serialize__p256(&s, &mut out) }
    untaint_val(&out);
    let _ = black_box(out);
});
