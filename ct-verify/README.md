# Constant-time verification harness

Checks for the constant-time and panic-free claims of krabiecdsa's
experimental signing and ECDH paths. There are four layers. Each checks
something the others cannot.

This is a nested cargo workspace, outside the published crate in
[`ecdsa/`](../ecdsa). Its release profile in [`Cargo.toml`](Cargo.toml)
is `lto = "fat"`, `codegen-units = 1`, `opt-level = "z"`,
`panic = "abort"`, which is what a size-conscious embedded build uses.
CI pins the toolchain too, so a codegen change shows up as a failing or
changed gate.

Cargo ignores a dependency's `[profile]`, so a deployment picks its own
opt-level. CI runs the ladder check, the panic audit, the taint gate and
the hardware campaigns at both `"z"` and `"s"` by setting
`CARGO_PROFILE_RELEASE_OPT_LEVEL`. Set the same variable to reproduce a
run locally.

## What the fixtures cover

Every fixture calls a public entry point in `krabiecdsa::signing`. No
library source is instrumented.

- **`sign_prehashed_ct_with_k`**: sign with a caller-supplied nonce. This
  covers the range checks on `d` and `k`, the scalar-multiply ladder
  (`scalar_mul_ct`, RCB complete addition over projective coordinates),
  `k⁻¹`, and `s = k⁻¹(z + r·d)`.
- **`sign_prehashed_ct`**: the RFC 6979 deterministic sign, which adds
  the HMAC-DRBG nonce derivation to the above.
- **`sign_prehashed_ct_hedged`**: the deterministic sign with RFC 6979
  §3.6 additional data folded into the DRBG seed. The additional data is
  public and is not tainted.
- **`sign_prehashed_ct_with_k_blinded`**: sign with projective-coordinate
  blinding (λ) and scalar blinding (`k + r·n`). The blinds are public
  per-signature randomness and are not tainted.
- **`ecdh_diffie_hellman_ct`**: ECDH agreement. The peer point is public
  and is not tainted.

The gates check concrete instantiations, not generic code. The limb
width changes which per-limb code gets folded, so the with-nonce sign
has one fixture per carrier at the width it ships at:

| fixture suffix | curve | limbs | used for |
| -------------- | ----- | ----- | -------- |
| `p256__fb32`   | P-256 | `u32` | Cortex-M / RISC-V |
| `p256__fb8`    | P-256 | `u8`  | AVR-class |
| `p256__fb64`   | P-256 | `u64` | 64-bit hosts |
| `p384__fb32`   | P-384 | `u32` | Cortex-M / RISC-V |

The other entry points have P-256 and P-384 fixtures on `u32` limbs.
They reuse the with-nonce sign's `scalar_mul_ct` instances, so the
ladder check does not build them (the `deterministic`, `ecdh` and
`scalar-blind` features of `ct-fixtures`); the taint gate and the panic
audit do.

The secret `d` and `k` are the RFC 6979 §A.2.5/§A.2.6 scalars, checked
in [`ecdsa/tests/rfc6979.rs`](../ecdsa/tests/rfc6979.rs), so the code
under test is the successful sign path, not an early return.

## Layers

The commands below run from this directory (`ct-verify/`).

**Ladder branch check** ([`ct-driver`](ct-driver/)). Cross-builds the
fixture staticlib for thumbv7em, thumbv7m, thumbv6m, riscv32imc and
riscv32imac, disassembles it, and checks each `scalar_mul_ct` instance.
Each may contain only the branches that control the loop over the
scalar's public bit width: one at `"z"`, two on Thumb at `"s"`. The
budgets are in [`ct-driver/src/target.rs`](ct-driver/src/target.rs).

At `"s"` the per-limb field loops are inlined into the ladder. Loops
over public bounds are accepted by shape: krabi-caliper's counted-loop
model recognises their constant-step counters. The model cannot tell
where a loop bound came from, so a loop with a secret bound passes this
check; the taint gate reports it, because the loop's exit branch reads
tainted data. thumbv6m uses a plain branch count, because its
short-range conditional branches turn every loop branch into a
trampoline the model cannot classify.

The check fails if any positive fixture lacks its ladder symbol, because
a ladder that was inlined or renamed would otherwise pass unchecked. It
also fails if a negative control is not reported. There are three:
- a loop that exits on a secret byte,
- an early-exit compare,
- a variable-time serializer.

It looks only at the ladder. Telling secret from public branches in the
rest of the sign is left to the taint gate.

```sh
cargo run --release -p ct-driver -- --target thumbv7m-none-eabi
```

**Taint gate** ([`ct-ctgrind`](ct-ctgrind/)). This is the main check
over whole operations. krabi-caliper marks `d` and `k` undefined
(`MAKE_MEM_UNDEFINED`, through crabgrind), and Valgrind memcheck reports
any conditional jump or memory address that depends on them, anywhere
in the operation, inlined code included. It runs on x86_64 and aarch64
Linux; on macOS use the [Dockerfile](ct-ctgrind/Dockerfile). Six
negative controls must be reported: krabi-caliper's standard branch,
equality and index controls, and the three ladder-check controls.

```sh
cargo build --release -p ct-ctgrind
cargo krabi-caliper ctgrind target/release/ct-ctgrind \
  --valgrind-arg=--suppressions=ct-ctgrind/ct-ctgrind.supp
```

Each entry in [`ct-ctgrind.supp`](ct-ctgrind/ct-ctgrind.supp) has been
reviewed. They cover two things:
- The exit branch of RFC 6979's candidate loop in `rfc6979_nonce`. A
  candidate is rejected with probability about 2⁻³² for these curves, so
  the iteration count reveals almost nothing about the key. This is the
  only secret-dependent branch the gate accepts.
- Valgrind's imprecise tracking through `memcpy`, which does not branch
  on the bytes it copies.

`Addr` errors, a memory address that depends on a secret, are never
suppressed. The signature `r`/`s` and the ECDH shared secret are
computed from secrets but published, so the harness untaints them after
each call.

**Panic-free audit** ([`panic-free-audit`](panic-free-audit/)).
Cross-builds every entry point as a staticlib with unused code removed
and checks with `llvm-nm` that no `core::panicking` code was linked. In
a signer, a reachable panic is a denial-of-service path, and also a
timing signal, since formatting the panic message takes time that
depends on the values printed. There are two legs:
- With-nonce, blinded and ECDH: every linked symbol, dependencies
  included, must be panic-free.
- Deterministic and hedged (feature `deterministic`): only symbols owned
  by this crate are checked. See the first known gap.

```sh
cargo krabi-caliper panic-audit --workspace . --package panic-free-audit \
  --target thumbv7m-none-eabi --features panic-handler \
  --negative-features neg-controls --owned-symbol '.*' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect

cargo krabi-caliper panic-audit --workspace . --package panic-free-audit \
  --target thumbv7m-none-eabi --features panic-handler \
  --cargo-arg=--features=deterministic \
  --negative-features neg-controls --owned-symbol 'krabiecdsa|panic_audit__' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect
```

**Hardware cycle counts** ([`cyccnt-hardware`](cyccnt-hardware/)).
Runs signing layers with two independent private keys on a J-Trace
STM32F407VG and compares DWT cycle counts with a Welch t-test. The CI
gate uses `u32` limbs at 30 MHz with 0 wait states; a second campaign
runs `u8` limbs at 168 MHz as a functional check, not a gate. The
fixtures and the run commands are in the
[`cyccnt-hardware` README](cyccnt-hardware/README.md).

## Known gaps

- **The RFC 6979 DRBG's dependencies are outside the panic-free
  audit.** RustCrypto `hmac` and `sha2` have reachable slice-index and
  `copy_from_slice` panics in their block buffering. krabiecdsa's own
  derivation code passes the audit. The deterministic sign cannot drop
  `sha2`, because the HMAC is the DRBG.
- **Taint does not see branchless selects on secrets.** memcheck reports
  conditional jumps and addresses, not data flow through `csel`/`cmov`.
  The ladder check counts every conditional branch in `scalar_mul_ct`,
  but a secret-dependent select elsewhere would pass both. Closing this
  needs symbolic-execution tooling such as cargo-checkct or binsec.
- **Taint runs on host ISAs** (x86_64, aarch64), not on the Thumb or
  RV32 code that ships. The ladder check covers those targets for the
  scalar multiply only.
- **No negative control has a secret loop bound.** The claim that the
  taint gate reports one rests on memcheck's handling of the exit
  branch, not on a control in this harness.
- **Cache timing and speculative side channels are out of scope.** No
  tool here observes them.
- **The suppressions are reviewed judgments**, not proofs, that a value
  is public. The reasoning for each is next to it in the `.supp` file.
