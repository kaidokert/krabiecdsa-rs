//! Per-target specifications: triple, toolchain pin, and the mnemonic
//! tables the disassembly parser keys off.

use krabi_caliper::host::ct_asm::LadderTarget as TargetSpec;
use krabi_caliper::host::isa as mnemonics;

/// All targets we know how to verify, in priority order.
///
/// The ladder budget is the bit loop's own control. Thumb-2 needs 2: at
/// opt-level "s" the loop becomes a zero-trip guard plus a bottom-tested
/// back edge whose counter is reloaded from a spill slot, so neither is
/// accepted as a counted loop. RV32 keeps a single branch at both levels.
pub const TARGETS: &[TargetSpec] = &[
    // Priority 1: Cortex-M3/M4 (the primary sign-footprint targets).
    TargetSpec {
        triple: "thumbv7em-none-eabi",
        priority: 1,
        toolchain: "1.88.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 2,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "thumbv7m-none-eabi",
        priority: 1,
        toolchain: "1.88.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 2,
        extra_cargo_args: &[],
    },
    // Priority 2: Cortex-M0. Plain branch count, see `counted_loops`.
    TargetSpec {
        triple: "thumbv6m-none-eabi",
        priority: 2,
        toolchain: "1.88.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 2,
        extra_cargo_args: &[],
    },
    // Priority 3: 32-bit RISC-V.
    TargetSpec {
        triple: "riscv32imc-unknown-none-elf",
        priority: 3,
        toolchain: "1.88.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "riscv32imac-unknown-none-elf",
        priority: 3,
        toolchain: "1.88.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
];

/// Whether the gate accepts loops over public bounds structurally.
///
/// thumbv6m's conditional branches reach only ±256 bytes, so every branch
/// controlling the ladder's loop is an inverted trampoline (`bne` over a
/// `b`), which the counted-loop model can't classify. Its ladder carries
/// no per-limb loops at either opt-level, so a plain count covers it.
pub fn counted_loops(triple: &str) -> bool {
    triple != "thumbv6m-none-eabi"
}
