//! Footprint-measurement harness for krabiecdsa on AVR ATmega2560
//! under simavr. Same methodology as the Cortex-M/RISC-V harnesses;
//! measurement plumbing (watermark painting, Timer1 wrap counting)
//! comes from krabi-caliper; the examples drive it inline since the
//! arduino-hal peripherals can't cross a fn boundary by value.

#![no_std]
#![feature(abi_avr_interrupt)]
#![feature(asm_experimental_arch)]

use core::hint::black_box;

krabi_caliper::atmega2560_timer1_overflow_handler!();

/// Baseline stand-in for a verify: touches the same fixture bytes so
/// the verify-minus-baseline delta isolates the crypto itself.
#[inline(never)]
pub fn fake_verify(pubkey: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let folded = pubkey[0] ^ digest[0] ^ r[0] ^ s[0] ^ (pubkey.len() as u8);
    black_box(folded);
    true
}

// Panic handler - registered automatically when crate is imported
#[inline(never)]
fn inner_panic_handler() -> ! {
    loop {}
}

#[panic_handler]
pub fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    inner_panic_handler();
}
