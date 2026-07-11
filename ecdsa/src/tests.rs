use super::*;
use fixed_bigint::FixedUInt;
use modmath::FieldNct;

type U256 = FixedUInt<u32, 8>;
type U384 = FixedUInt<u32, 12>;
// Oversized backend: proves the verifier is width-agnostic.
type U512 = FixedUInt<u32, 16>;

/// One openssl-produced known-good signature plus the curve's
/// precomputed `n − s` (for the malleability-acceptance check).
struct Vector {
    pubkey: &'static [u8],
    digest: &'static [u8],
    r: &'static [u8],
    s: &'static [u8],
    n_minus_s: &'static [u8],
}

/// The standard accept/reject battery, generic over curve and
/// backend: every verify-path rejection case that can be exercised
/// without curve-specific data lives here.
fn suite<C: Curve, T: UnsignedModularInt>(v: &Vector) {
    let ok = verify_for_curve::<C, T>(v.pubkey, v.digest, v.r, v.s);
    assert!(ok, "known-good vector must verify");

    // (r, n−s) is a valid signature whenever (r, s) is; TLS does not
    // require low-s, so this must be accepted, not rejected.
    assert!(verify_for_curve::<C, T>(
        v.pubkey,
        v.digest,
        v.r,
        v.n_minus_s
    ));

    let mut digest = v.digest.to_vec();
    digest[0] ^= 0x01;
    assert!(!verify_for_curve::<C, T>(v.pubkey, &digest, v.r, v.s));

    // swapped halves
    assert!(!verify_for_curve::<C, T>(v.pubkey, v.digest, v.s, v.r));

    let zero = vec![0u8; C::ELEM_BYTES];
    let ones = vec![0xffu8; C::ELEM_BYTES];
    assert!(!verify_for_curve::<C, T>(v.pubkey, v.digest, &zero, v.s));
    assert!(!verify_for_curve::<C, T>(v.pubkey, v.digest, v.r, &zero));
    assert!(!verify_for_curve::<C, T>(v.pubkey, v.digest, C::N, v.s));
    assert!(!verify_for_curve::<C, T>(v.pubkey, v.digest, v.r, C::N));
    assert!(!verify_for_curve::<C, T>(v.pubkey, v.digest, &ones, v.s));

    // wrong SEC1 prefix
    let mut pk = v.pubkey.to_vec();
    pk[0] = 0x02;
    assert!(!verify_for_curve::<C, T>(&pk, v.digest, v.r, v.s));

    // off-curve point (tweaked y)
    let mut pk = v.pubkey.to_vec();
    let last = pk.len() - 1;
    pk[last] ^= 0x01;
    assert!(!verify_for_curve::<C, T>(&pk, v.digest, v.r, v.s));

    // x coordinate ≥ p
    let mut pk = v.pubkey.to_vec();
    pk[1..1 + C::ELEM_BYTES].copy_from_slice(C::P);
    assert!(!verify_for_curve::<C, T>(&pk, v.digest, v.r, v.s));

    // y coordinate ≥ p
    let mut pk = v.pubkey.to_vec();
    pk[1 + C::ELEM_BYTES..].copy_from_slice(C::P);
    assert!(!verify_for_curve::<C, T>(&pk, v.digest, v.r, v.s));

    // wrong lengths reject rather than panic
    assert!(!verify_for_curve::<C, T>(
        &v.pubkey[..v.pubkey.len() - 1],
        v.digest,
        v.r,
        v.s
    ));
    assert!(!verify_for_curve::<C, T>(
        v.pubkey,
        v.digest,
        &v.r[..C::ELEM_BYTES - 1],
        v.s
    ));
    assert!(!verify_for_curve::<C, T>(v.pubkey, v.digest, v.r, &[]));

    // empty digest is API misuse, rejected before any math
    assert!(!verify_for_curve::<C, T>(v.pubkey, &[], v.r, v.s));
}

/// Point-arithmetic sanity: G is on the curve, 2G matches an independently
/// computed reference, and the exceptional cases (P+P dispatch,
/// P+(−P) = O) behave.
fn point_arithmetic_suite<C: Curve, T: UnsignedModularInt + core::fmt::Debug>(
    g2x: &[u8],
    g2y: &[u8],
) {
    let fp = FieldNct::new(from_be::<T>(C::P)).unwrap();
    let a = fp.reduce(&from_be::<T>(C::A));
    let b = fp.reduce(&from_be::<T>(C::B));
    let g = Point {
        x: fp.reduce(&from_be::<T>(C::GX)),
        y: fp.reduce(&from_be::<T>(C::GY)),
        z: fp.one(),
    };
    assert!(is_on_curve(&fp, &g, &a, &b));

    let g2 = double(&fp, &a, &g);
    let zinv = fp.inv_fermat(&g2.z).unwrap();
    let zinv2 = fp.mul(&zinv, &zinv);
    let zinv3 = fp.mul(&zinv2, &zinv);
    let x_aff = fp.into_raw(&fp.mul(&g2.x, &zinv2));
    let y_aff = fp.into_raw(&fp.mul(&g2.y, &zinv3));
    assert_eq!(x_aff, from_be::<T>(g2x), "2G.x mismatch");
    assert_eq!(y_aff, from_be::<T>(g2y), "2G.y mismatch");

    // add(G, G) must route to the doubling formula, not divide by H == 0
    let via_add = add(&fp, &a, &g, &g);
    assert_eq!(to_affine_x(&fp, &via_add), to_affine_x(&fp, &g2));

    let neg_g = Point {
        x: g.x.clone(),
        y: fp.sub(&fp.zero(), &g.y),
        z: fp.one(),
    };
    let sum = add(&fp, &a, &g, &neg_g);
    assert!(is_infinity(&fp, &sum));
    assert!(to_affine_x(&fp, &sum).is_none());
}

// ---------------------------------------------------------------------------
// hash_to_scalar: the leftmost-bitlen(n)-bits rule, including the
// sub-byte shift no shipped (byte-aligned) curve exercises. Expected
// values computed independently in Python.
// ---------------------------------------------------------------------------

#[test]
fn bitlen_be_counts_leading_zeros() {
    assert_eq!(bitlen_be(&[0x00, 0x00]), 0);
    assert_eq!(bitlen_be(&[0x01]), 1);
    assert_eq!(bitlen_be(&[0x00, 0x80, 0x00]), 16);
    assert_eq!(bitlen_be(p256::P256::N), 256);
    assert_eq!(bitlen_be(k256::K256::N), 256);
    assert_eq!(bitlen_be(p384::P384::N), 384);
}

#[test]
fn hash_to_scalar_byte_aligned_truncation() {
    // 64-byte digest, 256-bit n: leftmost 32 bytes.
    let digest: [u8; 64] = hx(
        "17ad4e0ef448133bede9f49ee417b902f752cef9394ec1e2feb49c28128bd6a0dc71d5c689533efa151115807d37d9df10aabd4d4c7512cea7e7792b27984136",
    );
    let want = from_be::<U256>(&hx::<32>(
        "17ad4e0ef448133bede9f49ee417b902f752cef9394ec1e2feb49c28128bd6a0",
    ));
    assert_eq!(hash_to_scalar::<U256>(&digest, 256), want);
}

#[test]
fn hash_to_scalar_sub_byte_shift() {
    // 32-byte digest, 250-bit n: leftmost 32 bytes shifted right 6.
    let digest: Vec<u8> = (0u8..32).collect();
    let want = from_be::<U256>(&hx::<32>(
        "000004080c1014181c2024282c3034383c4044484c5054585c6064686c707478",
    ));
    assert_eq!(hash_to_scalar::<U256>(&digest, 250), want);

    // 33-byte digest, 260-bit n (a P-521-shaped non-aligned n at a
    // width U512 can hold): leftmost 33 bytes shifted right 4.
    let mut digest = vec![0xabu8; 33];
    digest[0] = 0x80;
    let want = from_be::<U512>(&hx::<33>(
        "080abababababababababababababababababababababababababababababababa",
    ));
    assert_eq!(hash_to_scalar::<U512>(&digest, 260), want);
}

#[test]
fn hash_to_scalar_short_digest_zero_extends() {
    let digest = [0xcdu8; 20];
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&digest);
    assert_eq!(
        hash_to_scalar::<U256>(&digest, 256),
        from_be::<U256>(&padded)
    );
}

// ---------------------------------------------------------------------------
// P-256. OpenSSL 3.6.1 vectors: ecparam -genkey | pkeyutl -sign on a
// SHA-256 digest, r/s unpacked from the DER SEQUENCE.
// ---------------------------------------------------------------------------

mod p256_tests {
    use super::*;
    use crate::p256::{P256, PUBKEY_BYTES};

    // Message "sample message for krabiecdsa".
    const PUB: [u8; 65] = hx(
        "04dec34713540fe2b1f1734a03c4a9332ed2b403e8f24bb05ab626bb0cd40b36aa33ea26baa96b27d7497876a7934a8e9e384484556a2d942f6e4ce56419c04a96",
    );
    const DIGEST: [u8; 32] = hx("b965f29d7c66cd5ca7406ce09463f3008460a403ab172246565de3afac40a360");
    const R: [u8; 32] = hx("a994d67f622c58d869c4351cedcbdf54bf76fd153fa824943106bf50f14d28fc");
    const S: [u8; 32] = hx("299a09fc29835d392ed98a1f72f50b2a6ad66abe95b75ae4e7d996956e7948ba");
    const N_MINUS_S: [u8; 32] =
        hx("d665f602d67ca2c7d12675e08d0af4d552108fef116043a00be0342d8de9dc97");

    // Message "a second, longer message: The quick brown fox jumps
    // over the lazy dog"; `s` is high (> n/2) as OpenSSL emitted it.
    const PUB2: [u8; 65] = hx(
        "04661d34ec26e905422a98dd0cc08b375ff687259906537d0e81faa4d772dd87403e4fcc879f7b3b91f89641406395bdeed997e2e4314004691daa2dd01786132f",
    );
    const DIGEST2: [u8; 32] =
        hx("171055f36c4e23668796fe5817b5c39c7ee1bf818266c413a6c5c84c64525923");
    const R2: [u8; 32] = hx("7c68ec9e69b93226d763fe6d3755d2bef1540081d25f2776878452db8d8d9525");
    const S2: [u8; 32] = hx("fedbe3e91fa10753883b6194ba5904c35dd56e0586686b68091d55c48066e364");

    const VEC: Vector = Vector {
        pubkey: &PUB,
        digest: &DIGEST,
        r: &R,
        s: &S,
        n_minus_s: &N_MINUS_S,
    };

    #[test]
    fn full_suite() {
        suite::<P256, U256>(&VEC);
    }

    #[test]
    fn high_s_vector_verifies() {
        assert!(verify_for_curve::<P256, U256>(&PUB2, &DIGEST2, &R2, &S2));
    }

    #[test]
    fn wrong_key_rejects() {
        assert!(!verify_for_curve::<P256, U256>(&PUB2, &DIGEST, &R, &S));
    }

    #[test]
    fn long_digest_truncates_like_openssl() {
        // SHA-512 digest of "long digest truncation test" signed by
        // the PUB key with openssl pkeyutl: openssl applies the
        // leftmost-256-bits rule internally, so agreeing with it
        // pins our digest.len() > ELEM_BYTES branch.
        let digest: [u8; 64] = hx(
            "17ad4e0ef448133bede9f49ee417b902f752cef9394ec1e2feb49c28128bd6a0dc71d5c689533efa151115807d37d9df10aabd4d4c7512cea7e7792b27984136",
        );
        let r: [u8; 32] = hx("7d3bb4d466c6b955eb82219d9421a74bf3bb81f1fac5d7ba189543dcc5deed9f");
        let s: [u8; 32] = hx("411e4534e16645f3cd84e721af2d74e7db19236f5db740216c80a0cf04376a14");
        assert!(verify_for_curve::<P256, U256>(&PUB, &digest, &r, &s));
        // and a mutated long digest still rejects
        let mut bad = digest;
        bad[0] ^= 0x01;
        assert!(!verify_for_curve::<P256, U256>(&PUB, &bad, &r, &s));
    }

    #[test]
    fn digest_above_n_reduces() {
        // digest = 2^256 - 1 > n, signed by openssl over the PUB key:
        // exercises the e >= n reduction in hash-to-scalar.
        let digest = [0xffu8; 32];
        let r: [u8; 32] = hx("d931bfd402bbfa3e2e09c31f3c154d8f6fe504b9bbbe07ad043f99363d3e00c7");
        let s: [u8; 32] = hx("b40bc2565f7e7d8fa6d47e713a80e45ef3bb55eeccd6220251abcb39ca31c2ae");
        assert!(verify_for_curve::<P256, U256>(&PUB, &digest, &r, &s));
    }

    #[test]
    fn oversized_backend() {
        suite::<P256, U512>(&VEC);
    }

    #[test]
    fn point_arithmetic() {
        point_arithmetic_suite::<P256, U256>(
            &hx::<32>("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"),
            &hx::<32>("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"),
        );
    }

    #[test]
    fn fixed_size_wrapper() {
        assert_eq!(PUB.len(), PUBKEY_BYTES);
        assert!(crate::p256::verify_prehashed::<U256>(&PUB, &DIGEST, &R, &S));
    }
}

// ---------------------------------------------------------------------------
// secp256k1. OpenSSL 3.6.1 vector, SHA-256 digest of
// "krabiecdsa k256 test message"; `s` is high as emitted.
// ---------------------------------------------------------------------------

mod k256_tests {
    use super::*;
    use crate::k256::K256;

    const PUB: [u8; 65] = hx(
        "0403a6c551585c95166062778491a3319bcbd2956d942dec2e2f878bd7ac6efa047ca6f4e79dc69f06f9e06981f0e8b4975f629870b2cda540d276f8b06a1b2e83",
    );
    const DIGEST: [u8; 32] = hx("a137c17d34fc71a7d9150651cdb6321bb96d28e2828d463259b28ac0d2ca050c");
    const R: [u8; 32] = hx("cf510678d4d795fc50852f849779cdfb69302e9c7b188dee7839d55bbabe0165");
    const S: [u8; 32] = hx("ade734ea3003e3985e47a93e6a231fed499438b296a42ba670025c3ef923d2e1");
    const N_MINUS_S: [u8; 32] =
        hx("5218cb15cffc1c67a1b856c195dce011711aa43418a474954fd0024dd7126e60");

    const VEC: Vector = Vector {
        pubkey: &PUB,
        digest: &DIGEST,
        r: &R,
        s: &S,
        n_minus_s: &N_MINUS_S,
    };

    #[test]
    fn full_suite() {
        suite::<K256, U256>(&VEC);
    }

    #[test]
    fn oversized_backend() {
        suite::<K256, U512>(&VEC);
    }

    #[test]
    fn point_arithmetic() {
        point_arithmetic_suite::<K256, U256>(
            &hx::<32>("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            &hx::<32>("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
        );
    }

    #[test]
    fn fixed_size_wrapper() {
        assert!(crate::k256::verify_prehashed::<U256>(&PUB, &DIGEST, &R, &S));
    }
}

// ---------------------------------------------------------------------------
// P-384. OpenSSL 3.6.1 vector, SHA-384 digest of
// "krabiecdsa p384 test message"; `s` is high as emitted.
// ---------------------------------------------------------------------------

mod p384_tests {
    use super::*;
    use crate::p384::P384;

    const PUB: [u8; 97] = hx(
        "04b7af0877010232acdb95e67449f029079a8753201e80eb3cf2b5c3621e7b9698f6ccf5d26a2b101be9f360e12c51335a6e9cf458d078ae755ffa9ed0505c402650ba6b7928ef32e99f16c6057e34bf9a6d6a0dd7bcb64d3046a53e355299c5d6",
    );
    const DIGEST: [u8; 48] = hx(
        "bb798affdd2ef9ceb595f4852d6fb58dd756b3e65569a7df6a10f3267ce83d1fd055cfe1c6ffd73ebfce2d05a00d455c",
    );
    const R: [u8; 48] = hx(
        "41ef41fcc68bdfbd99c7f1358973d2471f11826f71feba38ec257244cb86c9352559c05700636bb27b5a710ea531dd19",
    );
    const S: [u8; 48] = hx(
        "b048269bb0603d5d53ff921448458975c3884a39827d971be315e7549e2f1f3fbfe3c7fad90f357bc8b4f43040f8081a",
    );
    const N_MINUS_S: [u8; 48] = hx(
        "4fb7d9644f9fc2a2ac006debb7ba768a3c77b5c67d8268e3e44d662d56080e9f983645b76fa171ff2437253a8bcd2159",
    );

    const VEC: Vector = Vector {
        pubkey: &PUB,
        digest: &DIGEST,
        r: &R,
        s: &S,
        n_minus_s: &N_MINUS_S,
    };

    #[test]
    fn full_suite() {
        suite::<P384, U384>(&VEC);
    }

    #[test]
    fn oversized_backend() {
        suite::<P384, U512>(&VEC);
    }

    #[test]
    fn point_arithmetic() {
        point_arithmetic_suite::<P384, U384>(
            &hx::<48>(
                "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61",
            ),
            &hx::<48>(
                "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80",
            ),
        );
    }

    #[test]
    fn fixed_size_wrapper() {
        assert!(crate::p384::verify_prehashed::<U384>(&PUB, &DIGEST, &R, &S));
    }

    #[test]
    fn short_digest_zero_extends() {
        // A 32-byte digest against P-384 exercises the "hash shorter
        // than n" branch of the hash-to-scalar rule. Not a real
        // TLS shape (secp384r1 pairs with SHA-384) — this pins the
        // zero-extension semantics on both sides: a genuine openssl
        // signature over a SHA-256 digest must verify, and a wrong
        // short digest must reject without tripping any length
        // assumption.
        let digest: [u8; 32] =
            hx("20c7adb1e429d0201d387b65edc420084ee4c21125bc2ce099125da552630f94");
        let r: [u8; 48] = hx(
            "1e6466e22054efc9778ff3278b53381c8c4d51485e94377d76efe6e634b0d6db7408ea38ffcb4335dd9bf23fb14c0383",
        );
        let s: [u8; 48] = hx(
            "8787bcc7ddb710eabf99ece127a33ca687f0856e54c21ca6cfa1d2357d583b02f3cbf7b1a759c618b860a8208233b014",
        );
        assert!(verify_for_curve::<P384, U384>(&PUB, &digest, &r, &s));

        let short = [0xabu8; 32];
        assert!(!verify_for_curve::<P384, U384>(&PUB, &short, &R, &S));
    }
}
