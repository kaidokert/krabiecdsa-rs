//! Per-target specifications: triple, toolchain pin, and the mnemonic
//! tables the disassembly parser keys off.

use krabi_caliper::host::ct_asm::LadderTarget as TargetSpec;
use krabi_caliper::host::isa as mnemonics;

/// All targets we know how to verify, in priority order.
///
/// `ladder_allowed_branches` is the budget at opt-level "z": the bit
/// loop's single back edge. [`ladder_budget`] raises it where "s" needs
/// more.
pub const TARGETS: &[TargetSpec] = &[
    // Priority 1: Cortex-M3/M4 (the primary sign-footprint targets).
    TargetSpec {
        triple: "thumbv7em-none-eabi",
        priority: 1,
        toolchain: "1.88.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "thumbv7m-none-eabi",
        priority: 1,
        toolchain: "1.88.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    // Priority 2: Cortex-M0. Plain branch count, see `counted_loops`.
    TargetSpec {
        triple: "thumbv6m-none-eabi",
        priority: 2,
        toolchain: "1.88.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
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

/// Ladder branch budget for `triple` at `opt_level`.
///
/// At "s" the Thumb bit loop becomes a zero-trip guard plus a
/// bottom-tested back edge. On Thumb-2 the counter is reloaded from a
/// spill slot, so the counted-loop model accepts neither; thumbv6m uses a
/// plain count. Both need 2 there. RV32 keeps a single branch at both
/// levels.
pub fn ladder_budget(policy: &TargetSpec, opt_level: &str) -> usize {
    if opt_level == "s" && policy.triple.starts_with("thumb") {
        2
    } else {
        policy.ladder_allowed_branches
    }
}
