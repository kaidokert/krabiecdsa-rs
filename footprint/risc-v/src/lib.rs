//! Footprint-measurement harness for krabiecdsa on RISC-V (QEMU
//! sifive_e). Same shape as the Cortex-M harness: paint the stack,
//! run one verify, report high-water mark + approximate cycle count
//! over the UART, then park — the QEMU wrapper kills the machine
//! after the METRIC line (sifive_e has no exit mechanism).

#![no_std]

use core::fmt::Write;
use core::hint::black_box;

pub mod cyclecount;
pub mod stack;
pub mod uart;

use cyclecount::CycleCounter;
use stack::paint_stack;
use uart::{UartWriter, uart_init};

pub fn test_fixture<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) -> ! {
    uart_init();

    let stack_probe = paint_stack::<SAFE_ZONE_BYTES>();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000;
    let stack = stack_probe.measure().high_water_bytes;

    let mut w = UartWriter;
    if result {
        let _ = writeln!(w, "ecdsa ACCEPT");
    } else {
        let _ = writeln!(w, "ecdsa REJECT");
    }
    let _ = write!(
        w,
        "METRIC stack:{} cycles:{} target:riscv32 backend:",
        stack, elapsed
    );
    let _ = w.write_str(backend);
    let _ = w.write_str("\n");

    loop {
        unsafe { core::arch::asm!("wfi") }
    }
}

/// Baseline stand-in for a verify: touches the same fixture bytes so
/// the verify-minus-baseline delta isolates the crypto itself.
#[inline(never)]
pub fn fake_verify(pubkey: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let folded = pubkey[0] ^ digest[0] ^ r[0] ^ s[0] ^ (pubkey.len() as u8);
    black_box(folded);
    true
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    uart_init();
    let mut w = UartWriter;
    let _ = writeln!(w, "PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("wfi") }
    }
}
