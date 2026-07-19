//! Footprint-measurement harness for krabiecdsa on RISC-V (QEMU
//! sifive_e). Same shape as the Cortex-M harness: paint the stack,
//! run one verify, report high-water mark + approximate cycle count
//! over the UART, then park — the QEMU wrapper kills the machine
//! after the METRIC line (sifive_e has no exit mechanism).

#![no_std]

use core::fmt::Write;
use core::hint::black_box;
use krabi_caliper::Counter;
use krabi_caliper::report::Field;
use krabi_caliper::risc_v::{McycleCounter, MinstretCounter, MmioTxFifo32, write_mmio32};
use krabi_caliper::uart::{UartReporter, reporter};

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

    // SAFETY: riscv-rt owns the single stack described by its linker symbols.
    let stack_probe =
        unsafe { krabi_caliper::stack::paint_riscv_runtime::<SAFE_ZONE_BYTES>() }.unwrap();
    let mut counter = McycleCounter::new(None);
    let mut instructions = MinstretCounter::new(None);
    let start = counter.now();
    let instructions_start = instructions.now();
    let result = testable();
    let instruction_measurement = instructions.elapsed(instructions_start);
    let measurement = counter.elapsed(start);
    let elapsed = measurement.ticks / 1000;
    let stack = stack_probe.measure();

    let mut reporter = uart_reporter();
    let fields = [
        Field::token("target", "riscv32"),
        Field::token("backend", backend),
    ];
    if result {
        let _ = writeln!(reporter, "ecdsa ACCEPT");
    } else {
        let _ = writeln!(reporter, "ecdsa REJECT");
    }
    let _ = write!(
        reporter,
        "METRIC stack:{} cycles:{} target:riscv32 backend:",
        stack.high_water_bytes, elapsed
    );
    let _ = reporter.write_str(backend);
    let _ = reporter.write_str("\n");
    krabi_caliper::report_completed!(
        &mut reporter,
        benchmark: "krabiecdsa-footprint",
        passed: result,
        fields: &fields,
        stack: stack,
        measurements: [
            ("minstret", instruction_measurement),
            ("mcycle", measurement),
        ]
    )
    .unwrap();

    loop {
        core::hint::spin_loop()
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
    let mut reporter = uart_reporter();
    let _ = writeln!(reporter, "PANIC: {}", info);
    loop {
        core::hint::spin_loop()
    }
}
