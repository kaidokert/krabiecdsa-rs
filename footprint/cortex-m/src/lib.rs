//! Cortex-M footprint harness for krabiecdsa.

#![no_std]

use core::hint::black_box;
#[cfg(not(feature = "jtrace-f407"))]
use cortex_m_semihosting::{debug, hprintln};
#[cfg(feature = "jtrace-f407")]
use rtt_target::{rprintln, rtt_init_print};

pub mod cyclecount;
pub mod stack;

use cyclecount::CycleCounter;
use stack::paint_stack;

pub fn target_arch_name() -> &'static str {
    #[cfg(thumbv6m)]
    {
        "thumbv6m"
    }
    #[cfg(thumbv7m)]
    {
        "thumbv7m"
    }
    #[cfg(thumbv7em)]
    {
        "thumbv7em"
    }
}

pub fn test_fixture<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    #[cfg(feature = "jtrace-f407")]
    rtt_init_print!();
    let stack_probe = paint_stack::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let elapsed = measurement.systick / 1000;
    let stack = stack_probe.measure().high_water_bytes;

    #[cfg(not(feature = "jtrace-f407"))]
    {
        if result {
            hprintln!("ecdsa ACCEPT");
        } else {
            hprintln!("ecdsa REJECT");
        }
        hprintln!(
            "METRIC stack:{} cycles:{} target:{} backend:{}",
            stack,
            elapsed,
            target_arch_name(),
            backend
        );
        if result {
            debug::exit(debug::EXIT_SUCCESS);
        } else {
            debug::exit(debug::EXIT_FAILURE);
        }
    }

    #[cfg(feature = "jtrace-f407")]
    {
        if result {
            rprintln!("ecdsa ACCEPT");
        } else {
            rprintln!("ecdsa REJECT");
        }
        rprintln!(
            "METRIC stack:{} cycles:{} target:{} backend:{} dwt_cycles:{} systick_cycles:{}",
            stack,
            elapsed,
            target_arch_name(),
            backend,
            measurement.dwt,
            measurement.systick
        );
    }
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
    rprintln!("PANIC: {}", info);
    loop {
        cortex_m::asm::nop();
    }
}
