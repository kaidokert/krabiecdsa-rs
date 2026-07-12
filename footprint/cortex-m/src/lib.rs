//! Footprint-measurement harness for krabiecdsa on Cortex-M under
//! QEMU. Same shape as the rsa_heapless footprint harness: paint the
//! stack, run one verify, report high-water mark + approximate cycle
//! count over semihosting, exit with the verify outcome.

#![no_std]

use core::hint::black_box;
use cortex_m_semihosting::{debug, hprintln};

pub mod cyclecount;
pub mod stack;

use cyclecount::CycleCounter;
use stack::{check_stack_high_water_mark_inner, paint_stack_inner};

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
    paint_stack_inner::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000;
    let stack = check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>();
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

/// Baseline stand-in for a verify: touches the same fixture bytes so
/// the baseline binary carries the harness + fixture data, and the
/// verify-minus-baseline delta isolates the crypto itself.
#[inline(never)]
pub fn fake_verify(pubkey: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let folded = pubkey[0] ^ digest[0] ^ r[0] ^ s[0] ^ (pubkey.len() as u8);
    black_box(folded);
    true
}

use panic_semihosting as _;
