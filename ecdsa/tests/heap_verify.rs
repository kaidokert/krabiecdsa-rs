//! Verify-only on a **heap / `Clone` (non-`Copy`)** carrier.
//!
//! Drives `verify_for_curve_ref` (and the typed `RefVerifyingKey`) with
//! `num-bigint`'s `FixedWidthBigUint` — a heap-backed `Nct` bigint that
//! is *not* `Copy` and so can never reach a constant-time / sign path.
//! The vector is an openssl-3.6.1-verified P-256 signature (same one the
//! cross-impl suite uses); accept/reject must match the fixed-width
//! backends.

use krabiecdsa::p256::P256;
use krabiecdsa::verify_for_curve_ref;
use num_bigint::FixedWidthBigUint as Heap;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

// openssl-verified P-256/SHA-256 vector (from tests/cross_impl.rs).
const PUB: &str = "04d689bb62743a19acf4ad0e3c887970bf32c7496dfb85138b1c967dcc0b79ec1148e1aafdc504a00a4fa512556036c35933e7c420dc27f2f730a0fcc8bc24a10e";
const DIGEST: &str = "560e5d45a50ef303418fd3a1a481a7c93dca42b3729611717c2b67c2cc1c4374";
const R: &str = "812ce3175938bb6cd6f8fd1ff4f8326281fd3ef917ad6f60478b2c38e2864aa3";
const S: &str = "2e762b57bf9e833febe145bc9e0250e60c7f3c825dd0b53c3e1ee57d84bacd70";

#[test]
fn heap_carrier_verifies_p256() {
    let (pk, digest, r, s) = (hx(PUB), hx(DIGEST), hx(R), hx(S));
    assert!(verify_for_curve_ref::<P256, Heap>(&pk, &digest, &r, &s));

    // tampered digest rejects
    let mut bad = digest.clone();
    bad[0] ^= 1;
    assert!(!verify_for_curve_ref::<P256, Heap>(&pk, &bad, &r, &s));
    // swapped r/s rejects
    assert!(!verify_for_curve_ref::<P256, Heap>(&pk, &digest, &s, &r));
    // out-of-range r (zero) rejects
    assert!(!verify_for_curve_ref::<P256, Heap>(
        &pk, &digest, &[0u8; 32], &s
    ));
}

#[test]
fn heap_verifying_key_p256() {
    use krabiecdsa::p256::RefVerifyingKey;
    use signature::hazmat::PrehashVerifier;

    let pk: [u8; 65] = hx(PUB).try_into().unwrap();
    let key = RefVerifyingKey::<Heap>::from_sec1_bytes(pk);
    let digest = hx(DIGEST);
    let mut sig = hx(R);
    sig.extend_from_slice(&hx(S));

    assert!(key.verify_prehash(&digest, &sig).is_ok());
    let mut bad = digest.clone();
    bad[0] ^= 1;
    assert!(key.verify_prehash(&bad, &sig).is_err());
    // wrong-length signature rejects
    assert!(key.verify_prehash(&digest, &[0u8; 63]).is_err());
}
