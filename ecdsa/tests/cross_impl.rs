//! Cross-implementation signing vectors.
//!
//! Unlike RFC 6979's self-vectors, these use **fresh** keypairs and
//! close the loop against an independent implementation: each `(r, s)`
//! below is the deterministic RFC 6979 signature of the digest under
//! the private key `d`, and every one was **verified by openssl
//! 3.6.1** (`pkeyutl -verify`) before being recorded. The tests then
//! assert that both signers — variable-time and constant-time —
//! reproduce that exact signature and that our own verifier accepts
//! it. So each vector is signed by us, accepted by openssl, and
//! round-tripped through our verify.
//!
//! (NIST CAVP SigGen is *not* usable here: its ECDSA vectors withhold
//! `d`/`k`, so a deterministic signer cannot reproduce their `r`/`s`.)

#![cfg(feature = "experimental-signing")]

use hmac::Hmac;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::dangerous::{sign_prehashed, sign_prehashed_ct};
use krabiecdsa::p256::P256;
use krabiecdsa::p384::P384;
use krabiecdsa::{Curve, UnsignedModularInt, verify_for_curve};
use sha2::{Sha256, Sha384};

type U256 = fixed_bigint::FixedUInt<u32, 8>;
type U384 = fixed_bigint::FixedUInt<u32, 12>;
type U256Ct = fixed_bigint::FixedUInt<u32, 8, Ct>;
type U384Ct = fixed_bigint::FixedUInt<u32, 12, Ct>;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

struct XVec {
    d: &'static str,
    /// SEC1 uncompressed `0x04 || X || Y`.
    pubkey: &'static str,
    digest: &'static str,
    r: &'static str,
    s: &'static str,
}

const P256_VECS: &[XVec] = &[
    XVec {
        d: "39a2d6fd0803382a59bf237b1624f92802fd277691bc7537408c34c3bf4d2122",
        pubkey: "04d689bb62743a19acf4ad0e3c887970bf32c7496dfb85138b1c967dcc0b79ec1148e1aafdc504a00a4fa512556036c35933e7c420dc27f2f730a0fcc8bc24a10e",
        digest: "560e5d45a50ef303418fd3a1a481a7c93dca42b3729611717c2b67c2cc1c4374",
        r: "812ce3175938bb6cd6f8fd1ff4f8326281fd3ef917ad6f60478b2c38e2864aa3",
        s: "2e762b57bf9e833febe145bc9e0250e60c7f3c825dd0b53c3e1ee57d84bacd70",
    },
    XVec {
        d: "80133a97a121adcd7ad3e227e00c7a705c54fd335878173fe3f073eba9a60ed9",
        pubkey: "044c6f9cc8150ffad6d6119f2ee7a3c6bfc97061940cfce569ed423bfc3025e8077a828fbde00de778c113744ef90e80d9a919c9b9532255c1af207da8c54a4447",
        digest: "ff96a818612fe532c64a13f55415c2a9f51c94760232a6d588bbf686adb28bb9",
        r: "9b5a6bafacffb3cc2a5d037091e691c151c30e9bb08b81fbcf7c3370d470b1bc",
        s: "3436b389fc25eb6702be8a4f9e68dc60da40bfcf01559103dd510a595c034909",
    },
];

const P384_VECS: &[XVec] = &[
    XVec {
        d: "6470b542bf92d91e49080c1ac610362321256590fc89ebe51a8f3d51841f87253b1f78be62ee80e40dc58a02e7876d04",
        pubkey: "0435a41f47f1ef3c8908c0482f3e81ce93546d5d35e0a637d4d738affb27732826f64ba8934f69f06cfae290230e36120d3a606b52f6a5a6bd7f617f15065d80e24153b0da4b19f3735589ee45114b8e3a3c830e3a470a6704e3ecddd1d55cc97d",
        digest: "814b972506aff8bf547e28df50faaff783f11d669ef7575c57bec2303f8f6ebc9fcdc4acbfe68139b3a90638701e1a96",
        r: "cffe4f1a9fa04a1a4376eba7fe480b6fc670aba3154085b65e48a2cb7ccc4583e2b6d1ae0524af173b5b2d6f813d090c",
        s: "108804b80c08e32500ec1abd0b7b5c269efab74259a19eb33e4c3612c576408e6f690859df4eb8fdb04813f9343b0da5",
    },
    XVec {
        d: "f1a10959aba9ab11a287dc3f5a40db2a54ad1e4fabc5e524b1b5a0bcdcc640fef29266a532b8e06ca394ee484ebd8a40",
        pubkey: "04d9cd11ae26498e71bb3d07e47d5cbaa2f948f2223d1c9e7a3b641852a9dcb81e520175e194163ad4d39c25a6ca2d75660e514ff77da46cf787860d60c457879df1ecc0471112b40b78e37ef0a056f90afa900a05e321c0dd65b0044387209fda",
        digest: "13ba6dfbe419f2d63909948bc68de89af6ef2b1f8bd26f21b689220d8d5bd2354ec9a3a9d910b2da50d51e67a3368b66",
        r: "e4e5f2dedb08022c5de67216ac00f34e17ae621fe899432f8773f9c8fba3a44751da158aa22c125113a84d7c37c78a6d",
        s: "6a174aa50a6dda2ee5879641d7dc35dbdf13ca12998c14ff14fc047ec51a5151c0d82ec9323b6dae4ddf5e7130627161",
    },
];

/// Both signers reproduce the openssl-verified `(r, s)`, and our
/// verifier accepts it. Generic over curve `C`, Nct backend `T`, Ct
/// backend `Tct`, and HMAC `M`, `eb`-byte scalars.
fn check<C, T, Tct, M>(vectors: &[XVec], eb: usize)
where
    C: Curve,
    T: UnsignedModularInt,
    Tct: krabiecdsa::dangerous::ConstantTimeInt,
    M: digest::KeyInit + digest::Mac,
{
    for v in vectors {
        let d = hx(v.d);
        let digest = hx(v.digest);
        let pk = hx(v.pubkey);
        let (want_r, want_s) = (hx(v.r), hx(v.s));

        let mut r = vec![0u8; eb];
        let mut s = vec![0u8; eb];
        assert!(sign_prehashed::<C, T, M>(&d, &digest, &mut r, &mut s));
        assert_eq!(r, want_r, "vartime r mismatch");
        assert_eq!(s, want_s, "vartime s mismatch");

        let mut rc = vec![0u8; eb];
        let mut sc = vec![0u8; eb];
        assert!(sign_prehashed_ct::<C, T, Tct, M>(
            &d, &digest, &mut rc, &mut sc
        ));
        assert_eq!(rc, want_r, "ct r mismatch");
        assert_eq!(sc, want_s, "ct s mismatch");

        assert!(
            verify_for_curve::<C, T>(&pk, &digest, &want_r, &want_s),
            "openssl-accepted signature failed our verify"
        );
    }
}

#[test]
fn openssl_cross_impl_p256() {
    check::<P256, U256, U256Ct, Hmac<Sha256>>(P256_VECS, 32);
}

#[test]
fn openssl_cross_impl_p384() {
    check::<P384, U384, U384Ct, Hmac<Sha384>>(P384_VECS, 48);
}
