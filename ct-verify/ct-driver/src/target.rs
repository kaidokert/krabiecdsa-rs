//! Per-target specifications: triple, toolchain pin, and the mnemonic
//! tables the disassembly parser keys off.

use krabi_caliper::host::ct_asm::LadderTarget as TargetSpec;
use krabi_caliper::host::isa as mnemonics;

/// All targets we know how to verify, in priority order.
pub const TARGETS: &[TargetSpec] = &[
    // Priority 1: Cortex-M3/M4 (the primary sign-footprint targets).
    TargetSpec {
        triple: "thumbv7em-none-eabi",
        priority: 1,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "thumbv7m-none-eabi",
        priority: 1,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    // Priority 2: Cortex-M0.
    TargetSpec {
        triple: "thumbv6m-none-eabi",
        priority: 2,
        toolchain: "1.87.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        ladder_allowed_branches: 1,
        extra_cargo_args: &[],
    },
    // Priority 3: 32-bit RISC-V.
    TargetSpec {
        triple: "riscv32imc-unknown-none-elf",
        priority: 3,
        toolchain: "1.87.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 2,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "riscv32imac-unknown-none-elf",
        priority: 3,
        toolchain: "1.87.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        ladder_allowed_branches: 2,
        extra_cargo_args: &[],
    },
];
