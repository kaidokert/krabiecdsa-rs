#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use embedded_measure::report::{Field, StackRecord, write_stack_ufmt};
use krabiecdsa_footprint_avr as _;
use krabiecdsa_footprint_avr::fake_verify;
use krabiecdsa_footprint_avr::stack_measurement::*;

mod fixture {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p256.rs"));
}

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    let stack_probe = fill_stack_with_watermark();
    let counter = krabiecdsa_footprint_avr::cyclecount::CycleCounter::start(&dp.TC1);
    let result = fake_verify(&fixture::PUBKEY, &fixture::DIGEST, &fixture::R, &fixture::S);
    let ticks = counter.elapsed_ticks(&dp.TC1);
    let ms = counter.elapsed_ms(&dp.TC1);
    let stack = measure_stack(&stack_probe);
    write_stack_ufmt(
        &mut serial,
        &StackRecord {
            benchmark: "krabiecdsa-footprint",
            measurement: stack,
            fields: &[
                Field::token("target", "atmega2560"),
                Field::token("operation", "baseline"),
            ],
        },
    )
    .unwrap();

    if result {
        ufmt::uwriteln!(&mut serial, "ecdsa ACCEPT").ok();
    } else {
        ufmt::uwriteln!(&mut serial, "ecdsa REJECT").ok();
    }
    ufmt::uwriteln!(&mut serial, "Time: {} ms ({} ticks)", ms, ticks).ok();
    ufmt::uwriteln!(
        &mut serial,
        "Max stack usage: {} bytes",
        stack.high_water_bytes
    )
    .ok();

    // Interrupts off before parking: simavr detects sleep-with-
    // interrupts-disabled and exits instead of burning the wrapper
    // timeout.
    avr_device::interrupt::disable();
    loop {
        unsafe { core::arch::asm!("sleep") }
    }
}
