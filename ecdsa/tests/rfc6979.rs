//! RFC 6979 signing vectors — the fixed set validating the
//! experimental signer. Two layers:
//!
//! - the low-level `sign_prehashed_with_k` fed the RFC's own `k`, to
//!   pin the pure ECDSA math (§A.2.5, P-256/SHA-256);
//! - the deterministic `derive_nonce_rfc6979` / `sign_prehashed`,
//!   which must **derive** the RFC's `k` and reproduce its `r`/`s`
//!   with no caller nonce, across curve (P-256, P-384) and HMAC hash
//!   (SHA-256/384/512) — the last exercising `hlen > qlen`.
//!
//! Digests are the precomputed hash of each RFC message (the API is
//! prehashed). All r/s/k and the public keys were recomputed
//! independently, not copied from the RFC.

#![cfg(feature = "experimental-signing")]

use hmac::Hmac;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::dangerous::{
    SigningKey, derive_nonce_rfc6979, sign_prehashed, sign_prehashed_ct, sign_prehashed_ct_with_k,
    sign_prehashed_with_k,
};
use krabiecdsa::p256::P256;
use krabiecdsa::p384::P384;
use krabiecdsa::{Curve, FieldFor, UnsignedModularInt, verify_for_curve};
use sha2::{Sha256, Sha384, Sha512};

type U256 = fixed_bigint::FixedUInt<u32, 8>;
type U384 = fixed_bigint::FixedUInt<u32, 12>;
// Ct-personality backends for the constant-time signing path.
type U256Ct = fixed_bigint::FixedUInt<u32, 8, Ct>;
type U384Ct = fixed_bigint::FixedUInt<u32, 12, Ct>;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn pubkey(x: &str, y: &str) -> Vec<u8> {
    let mut pk = vec![0x04u8];
    pk.extend_from_slice(&hx(x));
    pk.extend_from_slice(&hx(y));
    pk
}

// RFC 6979 §A.2.5 (P-256) and §A.2.6 (P-384) private keys + public keys.
const D256: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const QX256: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const QY256: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const D384: &str = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";
const QX384: &str = "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13";
const QY384: &str = "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";

struct Vec2 {
    digest: &'static str,
    k: &'static str,
    r: &'static str,
    s: &'static str,
}

// --- low-level with-k, P-256/SHA-256 (§A.2.5, "sample"/"test") ---
const WITHK: &[Vec2] = &[
    Vec2 {
        digest: "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        k: "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
        r: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        s: "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    },
    Vec2 {
        digest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        k: "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
        r: "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
        s: "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    },
];

// --- deterministic P-256/SHA-256 (§A.2.5), same two messages ---
const P256_SHA256: &[Vec2] = WITHK;

// --- deterministic P-256/SHA-512 (§A.2.5, "sample"): hlen 64 > qlen 32 ---
const P256_SHA512: &[Vec2] = &[Vec2 {
    digest: "39a5e04aaff7455d9850c605364f514c11324ce64016960d23d5dc57d3ffd8f49a739468ab8049bf18eef820cdb1ad6c9015f838556bc7fad4138b23fdf986c7",
    k: "5fa81c63109badb88c1f367b47da606da28cad69aa22c4fe6ad7df73a7173aa5",
    r: "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00",
    s: "2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe",
}];

// --- deterministic P-384/SHA-384 (§A.2.6, "sample"/"test") ---
const P384_SHA384: &[Vec2] = &[
    Vec2 {
        digest: "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe",
        k: "94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9",
        r: "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
        s: "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
    },
    Vec2 {
        digest: "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9",
        k: "015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d225092ada71f4a459bc0da98adb95837db8312ea",
        r: "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db",
        s: "ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5",
    },
];

/// Deterministic path: derive k == RFC k, sign reproduces r/s with no
/// caller nonce, and the signature verifies. Generic over curve `C`,
/// backend `T`, and HMAC `M`, with `eb`-byte scalars.
fn check_deterministic<C, T, M>(d: &str, pk: &[u8], vectors: &[Vec2], eb: usize)
where
    C: Curve,
    T: UnsignedModularInt + FieldFor,
    M: digest::KeyInit + digest::Mac,
{
    let d = hx(d);
    for v in vectors {
        let digest = hx(v.digest);
        let mut k = vec![0u8; eb];
        assert!(
            derive_nonce_rfc6979::<C, T, M>(&d, &digest, &mut k),
            "nonce derivation failed for {}",
            v.digest
        );
        assert_eq!(k, hx(v.k), "derived k mismatch for {}", v.digest);

        let mut r = vec![0u8; eb];
        let mut s = vec![0u8; eb];
        assert!(sign_prehashed::<C, T, M>(&d, &digest, &mut r, &mut s));
        assert_eq!(r, hx(v.r), "r mismatch for {}", v.digest);
        assert_eq!(s, hx(v.s), "s mismatch for {}", v.digest);
        assert!(
            verify_for_curve::<C, T>(pk, &digest, &r, &s),
            "deterministic signature failed to verify for {}",
            v.digest
        );
    }
}

#[test]
fn with_k_reproduces_and_verifies() {
    let d = hx(D256);
    let pk = pubkey(QX256, QY256);
    for v in WITHK {
        let digest = hx(v.digest);
        let k = hx(v.k);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        assert!(sign_prehashed_with_k::<P256, U256>(
            &d, &digest, &k, &mut r, &mut s
        ));
        assert_eq!(r.to_vec(), hx(v.r));
        assert_eq!(s.to_vec(), hx(v.s));
        assert!(verify_for_curve::<P256, U256>(&pk, &digest, &r, &s));
    }
}

#[test]
fn deterministic_p256_sha256() {
    check_deterministic::<P256, U256, Hmac<Sha256>>(D256, &pubkey(QX256, QY256), P256_SHA256, 32);
}

#[test]
fn deterministic_p256_sha512() {
    check_deterministic::<P256, U256, Hmac<Sha512>>(D256, &pubkey(QX256, QY256), P256_SHA512, 32);
}

#[test]
fn deterministic_p384_sha384() {
    check_deterministic::<P384, U384, Hmac<Sha384>>(D384, &pubkey(QX384, QY384), P384_SHA384, 48);
}

// The constant-time path (RCB complete formulas on the Ct surface)
// must produce byte-for-byte the same signatures as the vartime path.

#[test]
fn ct_with_k_reproduces_rfc_p256() {
    let d = hx(D256);
    let pk = pubkey(QX256, QY256);
    for v in WITHK {
        let digest = hx(v.digest);
        let k = hx(v.k);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        assert!(sign_prehashed_ct_with_k::<P256, U256Ct>(
            &d, &digest, &k, &mut r, &mut s
        ));
        assert_eq!(r.to_vec(), hx(v.r), "ct r mismatch for {}", v.digest);
        assert_eq!(s.to_vec(), hx(v.s), "ct s mismatch for {}", v.digest);
        assert!(verify_for_curve::<P256, U256>(&pk, &digest, &r, &s));
    }
}

#[test]
fn ct_deterministic_p256_sha256() {
    let d = hx(D256);
    let pk = pubkey(QX256, QY256);
    for v in P256_SHA256 {
        let digest = hx(v.digest);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        assert!(sign_prehashed_ct::<P256, U256, U256Ct, Hmac<Sha256>>(
            &d, &digest, &mut r, &mut s
        ));
        assert_eq!(r.to_vec(), hx(v.r), "ct r mismatch for {}", v.digest);
        assert_eq!(s.to_vec(), hx(v.s), "ct s mismatch for {}", v.digest);
        assert!(verify_for_curve::<P256, U256>(&pk, &digest, &r, &s));
    }
}

#[test]
fn ct_deterministic_p384_sha384() {
    let d = hx(D384);
    let pk = pubkey(QX384, QY384);
    for v in P384_SHA384 {
        let digest = hx(v.digest);
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        assert!(sign_prehashed_ct::<P384, U384, U384Ct, Hmac<Sha384>>(
            &d, &digest, &mut r, &mut s
        ));
        assert_eq!(r.to_vec(), hx(v.r), "ct r mismatch for {}", v.digest);
        assert_eq!(s.to_vec(), hx(v.s), "ct s mismatch for {}", v.digest);
        assert!(verify_for_curve::<P384, U384>(&pk, &digest, &r, &s));
    }
}

// SigningKey: owns the secret (Zeroizing), signs via the CT path, and
// derives its own public key.

#[test]
fn signing_key_p256() {
    let key = SigningKey::<P256>::from_bytes(&hx(D256)).unwrap();
    // derives the RFC public key
    let mut pk = [0u8; 65];
    assert!(key.verifying_key_sec1::<U256Ct>(&mut pk));
    assert_eq!(pk.to_vec(), pubkey(QX256, QY256));
    // signs the RFC vectors
    for v in P256_SHA256 {
        let digest = hx(v.digest);
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        assert!(key.sign_prehashed::<U256, U256Ct, Hmac<Sha256>>(&digest, &mut r, &mut s));
        assert_eq!(r.to_vec(), hx(v.r));
        assert_eq!(s.to_vec(), hx(v.s));
        assert!(verify_for_curve::<P256, U256>(&pk, &digest, &r, &s));
    }
}

#[test]
fn signing_key_p384() {
    let key = SigningKey::<P384>::from_bytes(&hx(D384)).unwrap();
    let mut pk = [0u8; 97];
    assert!(key.verifying_key_sec1::<U384Ct>(&mut pk));
    assert_eq!(pk.to_vec(), pubkey(QX384, QY384));
    let v = &P384_SHA384[0];
    let digest = hx(v.digest);
    let mut r = [0u8; 48];
    let mut s = [0u8; 48];
    assert!(key.sign_prehashed::<U384, U384Ct, Hmac<Sha384>>(&digest, &mut r, &mut s));
    assert_eq!(r.to_vec(), hx(v.r));
    assert_eq!(s.to_vec(), hx(v.s));
    assert!(verify_for_curve::<P384, U384>(&pk, &digest, &r, &s));
}

#[test]
fn signing_key_wrong_length_rejected() {
    assert!(SigningKey::<P256>::from_bytes(&hx(D256)[..31]).is_none());
    let n = hx("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let digest = hx(P256_SHA256[0].digest);

    // Out-of-range scalars are accepted at construction (length is the
    // only constructor check) but rejected in constant time at use —
    // both the low `d = 0` and the high `d = n` boundary.
    for bad in [[0u8; 32].as_slice(), n.as_slice()] {
        let key = SigningKey::<P256>::from_bytes(bad).unwrap();
        let mut pk = [0u8; 65];
        assert!(!key.verifying_key_sec1::<U256Ct>(&mut pk));
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        assert!(!key.sign_prehashed::<U256, U256Ct, Hmac<Sha256>>(&digest, &mut r, &mut s));
    }

    // Wrong output-buffer lengths are rejected for an otherwise valid key.
    let key = SigningKey::<P256>::from_bytes(&hx(D256)).unwrap();
    assert!(!key.verifying_key_sec1::<U256Ct>(&mut [0u8; 64]));
    assert!(!key.verifying_key_sec1::<U256Ct>(&mut [0u8; 66]));
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    assert!(!key.sign_prehashed::<U256, U256Ct, Hmac<Sha256>>(&digest, &mut r[..31], &mut s));
    assert!(!key.sign_prehashed::<U256, U256Ct, Hmac<Sha256>>(&digest, &mut r, &mut s[..31]));
}

#[test]
fn rejects_out_of_range_and_malformed() {
    let d = hx(D256);
    let digest = hx(WITHK[0].digest);
    let k = hx(WITHK[0].k);
    let n = hx("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let zero = [0u8; 32];
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];

    // with-k: out-of-range d / k
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &zero, &digest, &k, &mut r, &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &n, &digest, &k, &mut r, &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d, &digest, &zero, &mut r, &mut s
    ));
    assert!(!sign_prehashed_with_k::<P256, U256>(
        &d, &digest, &n, &mut r, &mut s
    ));
    // with-k: empty digest, wrong lengths
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

    // deterministic: out-of-range d, empty digest, wrong lengths
    assert!(!sign_prehashed::<P256, U256, Hmac<Sha256>>(
        &zero, &digest, &mut r, &mut s
    ));
    assert!(!sign_prehashed::<P256, U256, Hmac<Sha256>>(
        &d,
        &[],
        &mut r,
        &mut s
    ));
    // deterministic: wrong-length output buffers
    assert!(!sign_prehashed::<P256, U256, Hmac<Sha256>>(
        &d,
        &digest,
        &mut r[..31],
        &mut s
    ));
    assert!(!sign_prehashed::<P256, U256, Hmac<Sha256>>(
        &d,
        &digest,
        &mut r,
        &mut s[..31]
    ));

    // nonce derivation: short key, empty digest, short and oversized out_k
    let mut kbuf = [0u8; 32];
    let mut kbuf_over = [0u8; 33];
    assert!(!derive_nonce_rfc6979::<P256, U256, Hmac<Sha256>>(
        &d[..31],
        &digest,
        &mut kbuf
    ));
    assert!(!derive_nonce_rfc6979::<P256, U256, Hmac<Sha256>>(
        &d,
        &[],
        &mut kbuf
    ));
    assert!(!derive_nonce_rfc6979::<P256, U256, Hmac<Sha256>>(
        &d,
        &digest,
        &mut kbuf[..31]
    ));
    assert!(!derive_nonce_rfc6979::<P256, U256, Hmac<Sha256>>(
        &d,
        &digest,
        &mut kbuf_over
    ));
}
