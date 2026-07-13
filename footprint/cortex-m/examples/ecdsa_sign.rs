//! ECDSA signing footprint (P-256, u32, constant-time RFC 6979).
//! Measures the incremental cost of one `SigningKey::sign_prehashed`
//! over the shared baseline. Experimental signing path.

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
            key.sign_prehashed::<Nct, CtBackend, Hmac<Sha256>>(&fixture::DIGEST, &mut r, &mut s)
        },
        "sign-u32",
    );
    loop {}
}
