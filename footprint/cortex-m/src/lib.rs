//! Cortex-M footprint harness for krabiecdsa.

#![no_std]

use core::{fmt::Write, hint::black_box};
use krabi_caliper::report::Field;
use krabi_caliper::{Measurement, Unit};

pub mod cyclecount;

use cyclecount::CycleCounter;

pub fn test_fixture<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) {
    // SAFETY: cortex-m-rt owns the single stack described by its linker symbols.
    let stack_probe =
        unsafe { krabi_caliper::stack::paint_cortex_m_runtime::<SAFE_ZONE_BYTES>() }.unwrap();
    let counter = CycleCounter::start(cfg!(feature = "jtrace-f407"), None).unwrap();
    let result = testable();
    let measurement = counter.elapsed_since_start();
    let elapsed = measurement.systick / 1000;
    let stack = stack_probe.measure();
    let fields = [
        Field::token("target", krabi_caliper::stack::cortex_m_architecture_name()),
        Field::token("backend", backend),
    ];

    let mut reporter = krabi_caliper::cortex_m_reporter!("jtrace-f407");
    let cycles = Measurement::new(measurement.systick, Unit::CoreCycles);
    #[cfg(feature = "jtrace-f407")]
    let cycles = cycles.with_frequency(16_000_000);
    writeln!(
        reporter,
        "ecdsa {}",
        if result { "ACCEPT" } else { "REJECT" }
    )
    .unwrap();
    write!(
        reporter,
        "METRIC stack:{} cycles:{} target:{} backend:{}",
        stack.high_water_bytes,
        elapsed,
        krabi_caliper::stack::cortex_m_architecture_name(),
        backend
    )
    .unwrap();
    #[cfg(feature = "jtrace-f407")]
    write!(
        reporter,
        " dwt_cycles:{} systick_cycles:{}",
        measurement.dwt.unwrap(),
        measurement.systick
    )
    .unwrap();
    writeln!(reporter).unwrap();
    krabi_caliper::report_completed!(
        &mut reporter,
        benchmark: "krabiecdsa-footprint",
        passed: result,
        fields: &fields,
        stack: stack,
        measurements: [
            ("systick", cycles),
            #[cfg(feature = "jtrace-f407")]
            (
                "dwt",
                Measurement::new(measurement.dwt.unwrap() as u64, Unit::CoreCycles)
                    .with_frequency(16_000_000)
            ),
        ]
    )
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
