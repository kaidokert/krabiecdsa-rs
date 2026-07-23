//! Cortex-M footprint harness for krabiecdsa.

#![no_std]

use core::hint::black_box;
use krabi_caliper::cortex_m::FootprintConfig;
use krabi_caliper::report::Field;

krabi_caliper::cortex_m_systick_overflow_handler!();

pub fn test_fixture<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    let fields = [
        Field::token(
            "architecture",
            krabi_caliper::stack::cortex_m_architecture_name(),
        ),
        Field::token("backend", backend),
    ];
    let config = FootprintConfig::new("krabiecdsa-footprint", &fields);
    // SAFETY: cortex-m-rt owns the single stack described by its linker symbols.
    let result = unsafe {
        krabi_caliper::cortex_m::run_footprint::<SAFE_ZONE_BYTES, _>(
            || {
                krabi_caliper::protocol::semihosting::init()
                    .expect("failed to open semihosting stdout")
            },
            config,
            testable,
        )
    }
    .unwrap();
    if result {
        krabi_caliper::protocol::semihosting::exit_success();
    } else {
        krabi_caliper::protocol::semihosting::exit_failure();
    }
}

#[inline(never)]
pub fn fake_verify(pubkey: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let folded = pubkey[0] ^ digest[0] ^ r[0] ^ s[0] ^ (pubkey.len() as u8);
    black_box(folded);
    true
}

use panic_semihosting as _;
