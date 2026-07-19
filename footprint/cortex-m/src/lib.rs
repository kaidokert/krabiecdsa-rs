//! Cortex-M footprint harness for krabiecdsa.

#![no_std]

use core::{fmt::Write, hint::black_box};
use krabi_caliper::report::{Field, MeasurementRecord, OutcomeRecord, Reporter, StackRecord};
use krabi_caliper::{Measurement, Unit};

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
    let stack_probe = paint_stack::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    let elapsed = measurement.systick / 1000;
    let stack = stack_probe.measure();
    let fields = [
        Field::token("target", target_arch_name()),
        Field::token("backend", backend),
    ];

    #[cfg(not(feature = "jtrace-f407"))]
    let mut reporter = krabi_caliper::semihosting::init().unwrap();
    #[cfg(feature = "jtrace-f407")]
    let mut reporter = krabi_caliper::rtt::init_blocking();
    reporter
        .stack_measurement(&StackRecord {
            benchmark: "krabiecdsa-footprint",
            measurement: stack,
            fields: &fields,
        })
        .unwrap();
    let cycles = Measurement::new(measurement.systick, Unit::CoreCycles);
    #[cfg(feature = "jtrace-f407")]
    let cycles = cycles.with_frequency(16_000_000);
    let systick_fields = [
        Field::token("target", target_arch_name()),
        Field::token("backend", backend),
        Field::token("counter", "systick"),
    ];
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "krabiecdsa-footprint",
            measurement: cycles,
            fields: &systick_fields,
        })
        .unwrap();
    #[cfg(feature = "jtrace-f407")]
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "krabiecdsa-footprint",
            measurement: Measurement::new(measurement.dwt as u64, Unit::CoreCycles)
                .with_frequency(16_000_000),
            fields: &[
                Field::token("target", target_arch_name()),
                Field::token("backend", backend),
                Field::token("counter", "dwt"),
            ],
        })
        .unwrap();
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
        target_arch_name(),
        backend
    )
    .unwrap();
    #[cfg(feature = "jtrace-f407")]
    write!(
        reporter,
        " dwt_cycles:{} systick_cycles:{}",
        measurement.dwt, measurement.systick
    )
    .unwrap();
    writeln!(reporter).unwrap();
    reporter
        .outcome(&OutcomeRecord {
            benchmark: "krabiecdsa-footprint",
            passed: result,
            fields: &fields,
        })
        .unwrap();

    #[cfg(not(feature = "jtrace-f407"))]
    if result {
        krabi_caliper::semihosting::exit_success();
    } else {
        krabi_caliper::semihosting::exit_failure();
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
    krabi_caliper::rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
