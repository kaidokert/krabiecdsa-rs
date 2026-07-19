//! Unified ECDSA verify example for all measured curves on AVR.
//! Picks the fixture and curve marker from cfg features so the same
//! source builds for every entry in the suite. AVR uses u8 limbs
//! throughout.
//!
//! Exactly one `curve_*` feature must be enabled.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

const _: () = {
    const N: usize = cfg!(feature = "curve_p256") as usize
        + cfg!(feature = "curve_k256") as usize
        + cfg!(feature = "curve_p384") as usize;
    assert!(N == 1, "exactly one `curve_*` feature must be enabled");
};

use fixed_bigint::FixedUInt;
use krabi_caliper::avr::FootprintConfig;
use krabi_caliper::report::{Field, UfmtReporter};
use krabiecdsa::verify_for_curve;
use krabiecdsa_footprint_avr as _;

mod fixture {
    #[cfg(feature = "curve_p256")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p256.rs"));
    #[cfg(feature = "curve_k256")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/k256.rs"));
    #[cfg(feature = "curve_p384")]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p384.rs"));
}

#[cfg(feature = "curve_k256")]
use krabiecdsa::k256::K256 as Curve;
#[cfg(feature = "curve_p256")]
use krabiecdsa::p256::P256 as Curve;
#[cfg(feature = "curve_p384")]
use krabiecdsa::p384::P384 as Curve;

#[cfg(any(feature = "curve_p256", feature = "curve_k256"))]
type Backend = FixedUInt<u8, 32>;
#[cfg(feature = "curve_p384")]
type Backend = FixedUInt<u8, 48>;

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let serial = arduino_hal::default_serial!(dp, pins, 57600);

    let fields = [
        Field::token("target", "atmega2560"),
        Field::token("operation", "verify"),
    ];
    let mut reporter = UfmtReporter::new(serial);
    // SAFETY: ATmega2560 SRAM above `_end` is reserved for this single stack.
    unsafe {
        krabi_caliper::avr::run_atmega2560_footprint::<64, _>(
            &dp.TC1,
            &mut reporter,
            FootprintConfig::new("krabiecdsa-footprint", &fields).sentinel(0xce),
            || {
                verify_for_curve::<Curve, Backend>(
                    &fixture::PUBKEY,
                    &fixture::DIGEST,
                    &fixture::R,
                    &fixture::S,
                )
            },
        )
    }
    .unwrap();
    krabi_caliper::avr::park_simavr()
}
