//! Secret-scalar ladder assembly gate.
//!
//! Cross-builds the `ct-fixtures` staticlib per ISA, disassembles it,
//! and asserts krabiecdsa's constant-time scalar-multiply ladder
//! (`scalar_mul_ct`, the branchless double-and-add-always inner loop)
//! carries at most the reviewed public branch budget per target — no
//! secret-dependent control flow.

mod target;

use std::path::Path;
use std::process::ExitCode;

use krabi_caliper::host::ct_asm::{run_ladder, DriverConfig, LadderConfig};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    run_ladder(
        target::TARGETS,
        LadderConfig {
            driver: DriverConfig {
                workspace,
                fixture_package: "ct-fixtures",
                fixture_features: &["panic-handler"],
            },
            // Legacy-mangled monomorphizations of
            // `krabiecdsa::dangerous::scalar_mul_ct`.
            default_ladder: r"scalar_mul_ct",
        },
    )
}
