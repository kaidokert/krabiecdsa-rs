//! Wycheproof ECDSA vector suites via the `wycheproof` crate
//! (<https://github.com/randombit/wycheproof-rs>). Dev-dep only —
//! no vendored data. P1363 (raw `r || s`) variants, so no DER
//! decoding stands between the vectors and `verify_for_curve`.
//!
//! * `TestResult::Valid` → must verify.
//! * `TestResult::Invalid` → must reject.
//! * `TestResult::Acceptable` → either outcome; informational only.
//!
//! Signatures that are not exactly `r || s` of 2·`ELEM_BYTES` cannot
//! be split for the unpacked API; those count as rejected-before-
//! verify, which must coincide with an expected-Invalid outcome.
//! The digest is computed here (SHA-256/384 of the vector's `msg`)
//! because the crate's API is prehashed.

use krabiecdsa::k256::K256;
use krabiecdsa::p256::P256;
use krabiecdsa::p384::P384;
use krabiecdsa::{Curve, VerifyBackend, verify_for_curve};
use sha2::{Digest, Sha256, Sha384};
use wycheproof::TestResult;
use wycheproof::ecdsa::{TestName, TestSet};

type U256 = fixed_bigint::FixedUInt<u32, 8>;
type U384 = fixed_bigint::FixedUInt<u32, 12>;

fn run<C: Curve, T: VerifyBackend>(name: TestName, hash: fn(&[u8]) -> Vec<u8>) {
    let set = TestSet::load(name).expect("wycheproof corpus failed to load");

    let mut ran = 0usize;
    let mut rejected_at_parse = 0usize;
    let mut failures = 0usize;

    for group in &set.test_groups {
        let pubkey: &[u8] = group.key.key.as_ref();
        for tc in &group.tests {
            let digest = hash(tc.msg.as_ref());
            let sig: &[u8] = tc.sig.as_ref();

            if sig.len() != 2 * C::ELEM_BYTES {
                if tc.result.must_fail() {
                    rejected_at_parse += 1;
                } else {
                    eprintln!(
                        "tcId {} ({:?}): sig length {} unrepresentable but expected {:?}",
                        tc.tc_id,
                        tc.comment,
                        sig.len(),
                        tc.result
                    );
                    failures += 1;
                }
                continue;
            }

            let (r, s) = sig.split_at(C::ELEM_BYTES);
            let ok = verify_for_curve::<C, T>(pubkey, &digest, r, s);
            ran += 1;

            match tc.result {
                TestResult::Valid if !ok => {
                    eprintln!("tcId {} ({:?}): valid but rejected", tc.tc_id, tc.comment);
                    failures += 1;
                }
                TestResult::Invalid if ok => {
                    eprintln!("tcId {} ({:?}): invalid but accepted", tc.tc_id, tc.comment);
                    failures += 1;
                }
                _ => {}
            }
        }
    }

    println!(
        "wycheproof {name:?}: ran={ran} rejected_at_parse={rejected_at_parse} failed={failures}"
    );
    assert!(ran > 0, "no Wycheproof vectors executed");
    assert_eq!(failures, 0, "{failures} Wycheproof vectors mismatched");
}

fn sha256(msg: &[u8]) -> Vec<u8> {
    Sha256::digest(msg).to_vec()
}

fn sha384(msg: &[u8]) -> Vec<u8> {
    Sha384::digest(msg).to_vec()
}

#[test]
fn wycheproof_p256() {
    run::<P256, U256>(TestName::EcdsaSecp256r1Sha256P1363, sha256);
}

#[test]
fn wycheproof_k256() {
    run::<K256, U256>(TestName::EcdsaSecp256k1Sha256P1363, sha256);
}

#[test]
fn wycheproof_p384() {
    run::<P384, U384>(TestName::EcdsaSecp384r1Sha384P1363, sha384);
}
