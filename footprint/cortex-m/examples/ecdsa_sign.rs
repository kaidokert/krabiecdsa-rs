//! ECDSA signing footprint (P-256, u32, RFC 6979). Measures the
//! incremental cost of one `SigningKey::sign_prehashed` over the shared
//! baseline. The signature math is constant-time; RFC 6979 nonce
//! derivation runs on the Nct backend (the documented residual gap).
//! Experimental signing path.

#![no_main]
#![no_std]

use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;
use hmac::Hmac;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::dangerous::SigningKey;
use krabiecdsa::p256::P256;
use krabiecdsa_footprint_cortex_m::test_fixture;
use sha2::Sha256;

mod fixture {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p256.rs"));
}

type Nct = FixedUInt<u32, 8>;
type CtBackend = FixedUInt<u32, 8, Ct>;

#[entry]
fn main() -> ! {
    test_fixture::<2048>(
        || {
            let Some(key) = SigningKey::<P256>::from_bytes(&fixture::PRIVATE_KEY) else {
                return false;
            };
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            let ok =
                key.sign_prehashed::<Nct, CtBackend, Hmac<Sha256>>(&fixture::DIGEST, &mut r, &mut s);
            // Keep the serialized signature observable: under LTO +
            // opt-level="z" the optimizer could otherwise discard the
            // r/s write-back and undercount the measured work.
            core::hint::black_box(&r);
            core::hint::black_box(&s);
            ok
        },
        "sign-u32",
    );
    loop {}
}
