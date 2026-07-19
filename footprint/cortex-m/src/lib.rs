//! Cortex-M footprint harness for krabiecdsa.

#![no_std]

use core::hint::black_box;
use krabi_caliper::cortex_m::FootprintConfig;
use krabi_caliper::report::Field;

krabi_caliper::cortex_m_systick_overflow_handler!();

pub fn test_fixture<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    let fields = [
        Field::token("target", krabi_caliper::stack::cortex_m_architecture_name()),
        Field::token("backend", backend),
    ];
    let config = FootprintConfig::new("krabiecdsa-footprint", &fields)
        .enable_dwt(cfg!(feature = "jtrace-f407"));
    #[cfg(feature = "jtrace-f407")]
    let config = config.frequency_hz(16_000_000);
    // SAFETY: cortex-m-rt owns the single stack described by its linker symbols.
    let result = unsafe {
        krabi_caliper::cortex_m::run_footprint::<SAFE_ZONE_BYTES, _>(
            || krabi_caliper::cortex_m_reporter!("jtrace-f407"),
            config,
            testable,
        )
    }
    .unwrap();
    krabi_caliper::finish_cortex_m_report!(result, "jtrace-f407");
}

#[inline(never)]
pub fn fake_verify(pubkey: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let folded = pubkey[0] ^ digest[0] ^ r[0] ^ s[0] ^ (pubkey.len() as u8);
    black_box(folded);
    true
}

#[cfg(not(feature = "jtrace-f407"))]
use panic_semihosting as _;

#[cfg(feature = "jtrace-f407")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    krabi_caliper::rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
