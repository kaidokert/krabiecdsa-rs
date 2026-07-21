//! Footprint-measurement harness for krabiecdsa on RISC-V (QEMU
//! sifive_e). Same shape as the Cortex-M harness: paint the stack,
//! run one verify, report high-water mark + approximate cycle count
//! over the UART, then park — the QEMU wrapper kills the machine
//! after the METRIC line (sifive_e has no exit mechanism).

#![no_std]

use core::fmt::Write;
use core::hint::black_box;
use krabi_caliper::report::Field;
use krabi_caliper::risc_v::{FootprintConfig, MmioTxFifo32, write_mmio32};
use krabi_caliper::protocol::uart::{UartReporter, reporter};

type SifiveReporter = UartReporter<MmioTxFifo32<0x1001_3000>>;

fn uart_init() {
    // SAFETY: sifive_e UART0 is exclusively owned by this single-core fixture.
    unsafe { write_mmio32(0x1001_3008, 1) }
}

fn uart_reporter() -> SifiveReporter {
    // SAFETY: sifive_e UART0 is exclusively owned by this single-core fixture.
    reporter(unsafe { MmioTxFifo32::new() })
}

pub fn test_fixture<const SAFE_ZONE_BYTES: usize>(testable: fn() -> bool, backend: &str) -> ! {
    uart_init();
    let fields = [
        Field::token("target", "riscv32"),
        Field::token("backend", backend),
    ];
    // SAFETY: riscv-rt owns the single stack described by its linker symbols.
    unsafe {
        krabi_caliper::risc_v::run_footprint::<SAFE_ZONE_BYTES, _>(
            uart_reporter,
            FootprintConfig::new("krabiecdsa-footprint", &fields),
            testable,
        )
    }
    .unwrap();
    krabi_caliper::risc_v::park()
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
    let mut reporter = uart_reporter();
    let _ = writeln!(reporter, "PANIC: {}", info);
    loop {
        core::hint::spin_loop()
    }
}
