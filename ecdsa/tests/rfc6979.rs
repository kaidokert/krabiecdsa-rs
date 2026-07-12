//! RFC 6979 §A.2.5 signing vectors — the fixed set validating the
//! proof-of-concept signer. NIST P-256 / SHA-256, the RFC's private
//! key `x` and its published deterministic `k`, `r`, `s` for the
//! messages "sample" and "test". `k` is fed in explicitly (the POC
//! signer does not derive it); each signature must reproduce the
//! RFC's `r`/`s` byte-for-byte, and must then verify under the
//! matching public key.
//!
//! Digests are the precomputed SHA-256 of the RFC messages, since the
//! crate's signing API (like its verify API) is prehashed.

#![cfg(feature = "signing")]

use krabiecdsa::dangerous::sign_prehashed_with_k;
use krabiecdsa::p256::P256;
use krabiecdsa::verify_for_curve;

type U256 = fixed_bigint::FixedUInt<u32, 8>;

fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

// RFC 6979 §A.2.5 private key x and the derived public key U (checked
// against the RFC and recomputed independently).
const D: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const QX: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const QY: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

struct Vector {
    /// SHA-256 of the RFC message.
    digest: &'static str,
    /// The RFC's deterministic nonce for this message.
    k: &'static str,
    /// Expected signature halves.
    r: &'static str,
    s: &'static str,
}

// "sample" and "test", SHA-256.
const VECTORS: &[Vector] = &[
    Vector {
        digest: "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        k: "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
        r: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        s: "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    },
    Vector {
        digest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        k: "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
        r: "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
        s: "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    },
];

fn pubkey() -> Vec<u8> {
    let mut pk = vec![0x04u8];
    pk.extend_from_slice(&hex_to_vec(QX));
    pk.extend_from_slice(&hex_to_vec(QY));
    pk
}

#[test]
fn rfc6979_p256_vectors_reproduce_r_s() {
    let d = hex_to_vec(D);
    for v in VECTORS {
        let digest = hex_to_vec(v.digest);
        let k = hex_to_vec(v.k);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        assert!(
            sign_prehashed_with_k::<P256, U256>(&d, &digest, &k, &mut r, &mut s),
            "signing failed for digest {}",
            v.digest
        );
        assert_eq!(r.to_vec(), hex_to_vec(v.r), "r mismatch for {}", v.digest);
        assert_eq!(s.to_vec(), hex_to_vec(v.s), "s mismatch for {}", v.digest);
    }
}

#[test]
fn rfc6979_signatures_verify() {
    let d = hex_to_vec(D);
    let pk = pubkey();
    for v in VECTORS {
        let digest = hex_to_vec(v.digest);
        let k = hex_to_vec(v.k);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        assert!(sign_prehashed_with_k::<P256, U256>(
            &d, &digest, &k, &mut r, &mut s
        ));
        assert!(
            verify_for_curve::<P256, U256>(&pk, &digest, &r, &s),
            "self-produced signature failed to verify for {}",
            v.digest
        );
    }
}

#[test]
fn rejects_out_of_range_scalars() {
    let d = hex_to_vec(D);
    let digest = hex_to_vec(VECTORS[0].digest);
    let k = hex_to_vec(VECTORS[0].k);
    let n = hex_to_vec("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let zero = [0u8; 32];
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];

    // zero / n private key
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &zero, &digest, &k, &mut r, &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &n, &digest, &k, &mut r, &mut s
    ));
    // zero / n nonce
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d, &digest, &zero, &mut r, &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d, &digest, &n, &mut r, &mut s
    ));
    // empty digest, wrong output length
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d,
        &[],
        &k,
        &mut r,
        &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d,
        &digest,
        &k,
        &mut r[..31],
        &mut s
    ));

    // wrong-length private key / nonce / out_s
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d[..31],
        &digest,
        &k,
        &mut r,
        &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d,
        &digest,
        &k[..31],
        &mut r,
        &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d,
        &digest,
        &k,
        &mut r,
        &mut s[..31]
    ));
}
