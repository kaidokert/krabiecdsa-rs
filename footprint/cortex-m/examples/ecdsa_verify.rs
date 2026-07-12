//! Unified ECDSA verify example for all (curve × limb-size)
//! combinations we measure. Picks the fixture, curve marker, and
//! `FixedUInt` backend from cfg features so the same source builds
//! for every entry in the suite.
//!
//! Exactly one `curve_*` feature and exactly one `limb_*` feature
//! must be enabled.

#![no_main]
#![no_std]

const _: () = {
    const N: usize = cfg!(feature = "curve_p256") as usize
        + cfg!(feature = "curve_k256") as usize
        + cfg!(feature = "curve_p384") as usize;
    assert!(N == 1, "exactly one `curve_*` feature must be enabled");
};
const _: () = {
    const N: usize = cfg!(feature = "limb_u8") as usize + cfg!(feature = "limb_u32") as usize;
    assert!(N == 1, "exactly one `limb_*` feature must be enabled");
};

use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;
use krabiecdsa::verify_for_curve;
use krabiecdsa_footprint_cortex_m::test_fixture;

mod fixture {
    #[cfg(feature = "curve_p256")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p256.rs"));
    #[cfg(feature = "curve_k256")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/k256.rs"));
    #[cfg(feature = "curve_p384")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p384.rs"));
}

#[cfg(feature = "curve_p256")]
use krabiecdsa::p256::P256 as Curve;
#[cfg(feature = "curve_k256")]
use krabiecdsa::k256::K256 as Curve;
#[cfg(feature = "curve_p384")]
use krabiecdsa::p384::P384 as Curve;

#[cfg(all(any(feature = "curve_p256", feature = "curve_k256"), feature = "limb_u8"))]
type Backend = FixedUInt<u8, 32>;
#[cfg(all(any(feature = "curve_p256", feature = "curve_k256"), feature = "limb_u32"))]
type Backend = FixedUInt<u32, 8>;
#[cfg(all(feature = "curve_p384", feature = "limb_u8"))]
type Backend = FixedUInt<u8, 48>;
#[cfg(all(feature = "curve_p384", feature = "limb_u32"))]
type Backend = FixedUInt<u32, 12>;

#[cfg(feature = "limb_u8")]
const BACKEND: &str = "u8";
#[cfg(feature = "limb_u32")]
const BACKEND: &str = "u32";

#[entry]
fn main() -> ! {
    test_fixture::<2048>(
        || {
            verify_for_curve::<Curve, Backend>(
                &fixture::PUBKEY,
                &fixture::DIGEST,
                &fixture::R,
                &fixture::S,
            )
        },
        BACKEND,
    );
    loop {}
}
