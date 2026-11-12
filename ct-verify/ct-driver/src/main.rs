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

use krabi_caliper::host::ct_asm::{
    run_ladder, DriverConfig, LadderConfig, LadderTarget as TargetSpec, Surface,
};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    // CI sets the opt-level through this variable; unset means the
    // workspace profile's "z".
    let opt_level =
        std::env::var("CARGO_PROFILE_RELEASE_OPT_LEVEL").unwrap_or_else(|_| "z".to_string());
    let opt_level = opt_level.trim_matches('"');
    // At opt-level "s" the per-limb field loops inline into the ladder;
    // accept loops over public bounds structurally so the budget still
    // counts only the ladder's own bit-loop control.
    let targets: Vec<_> = target::TARGETS
        .iter()
        .map(|&policy| Surface {
            policy: TargetSpec {
                ladder_allowed_branches: target::ladder_budget(&policy, opt_level),
                ..policy
            },
            counted_loops: target::counted_loops(policy.triple),
            excluded_fixtures: &[],
        })
        .collect();
    run_ladder(
        &targets,
        LadderConfig {
            driver: DriverConfig {
                workspace,
                fixture_package: "ct-fixtures",
                fixture_features: &["panic-handler"],
            },
            // Legacy-mangled monomorphizations of
            // `krabiecdsa::signing::scalar_mul_ct`.
            default_ladder: r"scalar_mul_ct",
        },
    )
}
