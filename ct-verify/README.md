# Constant-time verification harness

Machine-checked evidence for krabiecdsa's experimental constant-time
sign path. Three gates, each answering a question the others can't, all
pinned to one toolchain and one release profile so a passing run "locks"
specific machine code rather than an optimizer's mood.

This is a nested cargo workspace, outside the published crate (which
lives in [`ecdsa/`](../ecdsa)). The pinned profile (`lto = "fat"`,
`codegen-units = 1`, `opt-level = "z"`, `panic = "abort"`) in
[`Cargo.toml`](Cargo.toml) matches what a size-conscious embedded
deployment builds; the gates pin rustc 1.87.0 (the crate MSRV) so
codegen drift surfaces as a reviewable diff, not silent rot.

## Scope — what is and isn't attested

The gates attest the **RCB scalar-multiply sign given a nonce**:
[`krabiecdsa::dangerous::sign_prehashed_ct_with_k`] — the constant-time
range checks (`ct_is_zero`/`ct_lt` on `d` and `k`), the branchless
double-and-add-always ladder (`scalar_mul_ct` over homogeneous
projective coordinates with RCB complete addition), `k⁻¹`, and the
`s = k⁻¹(z + r·d)` combination, all on the `FieldCt` surface.

They deliberately do **not** drive `sign_prehashed_ct`. That entry
derives the nonce with RFC 6979, which still runs on the **variable-time
(`Nct`) HMAC-DRBG** — tainting `d` through it would (correctly) trip the
taint gate on the derivation. So here the nonce `k` is a tainted
*input*, exactly as a constant-time deriver would hand it over. **Making
the nonce derivation constant-time is the prerequisite to attesting the
full deterministic sign; until then this is the honest boundary.**

Every fixture reaches the CT surface through the public API — no
krabiecdsa source is instrumented. The gates verify *fixture
instantiations, not generic code*, so the matrix covers each shipped
carrier flavor at the curve's field width:

| fixture suffix | curve | limbs | deployment shape |
| -------------- | ----- | ----- | ---------------- |
| `p256__fb32`   | P-256 | `u32` | Cortex-M / RISC-V |
| `p256__fb8`    | P-256 | `u8`  | AVR-class |
| `p256__fb64`   | P-256 | `u64` | 64-bit hosts |
| `p384__fb32`   | P-384 | `u32` | Cortex-M / RISC-V |

Secret `d`/`k` are the real RFC 6979 §A.2.5/§A.2.6 scalars (validated in
[`ecdsa/tests/rfc6979.rs`](../ecdsa/tests/rfc6979.rs)), so the sign
*happy path* is the code under inspection rather than an early return.

## The three gates

All commands assume this directory (`ct-verify/`) as the working
directory, and rustc 1.87.0.

**Ladder branch-freedom check** ([`ct-driver`](ct-driver/)).
Cross-builds the fixture staticlib per ISA (thumbv7em/7m/6m,
riscv32imc/imac), disassembles it, and asserts each `scalar_mul_ct`
monomorphization carries at most the reviewed public loop-guard branch
count (1 on Thumb, 2 on RV32) and nothing more. Fails closed: it
requires exactly one ladder symbol per positive fixture (a missing one
means a carrier's ladder was inlined/renamed and its attestation would
be vacuous), and the negative controls must trip the per-ISA mnemonic
tables. This is the only gate that inspects the Thumb/RV32 encodings
that actually deploy; it runs anywhere (no Valgrind).

```sh
cargo run --release -p ct-driver -- --target thumbv7m-none-eabi
```

**Taint (ctgrind) — the primary whole-operation gate**
([`ct-ctgrind`](ct-ctgrind/)). The secret `d` and `k` bytes are marked
undefined via crabgrind; Valgrind memcheck then flags any conditional
jump or memory access that depends on them, through every inlined
dependency, across the whole sign. Runs on x86_64/aarch64 **Linux only**
— on macOS use the [Dockerfile](ct-ctgrind/Dockerfile). Negative
controls (a secret-dependent early-exit loop, a vartime compare, and
three synthetic detector controls) must trip.

```sh
cargo build --release -p ct-ctgrind
cargo krabi-caliper ctgrind target/release/ct-ctgrind \
  --valgrind-arg=--suppressions=ct-ctgrind/ct-ctgrind.supp
```

Suppressions ([`ct-ctgrind.supp`](ct-ctgrind/ct-ctgrind.supp)) are
individually reviewed declassifications, not blanket: only
data-oblivious `memcpy` shadow-propagation artifacts in the fixture's
own secret-byte parse. Every entry requires a sign-fixture frame, and
every CT primitive is a separate symbol never matched by any entry, so
a real leak in the crypto path always surfaces.

**Panic-free audit** ([`panic-free-audit`](panic-free-audit/)).
Cross-builds the whole sign as a DCE'd staticlib and asserts via
`llvm-nm` that no `core::panicking` machinery was linked. For a signer a
reachable panic is both a DoS edge and a timing oracle (panic formatting
cost depends on the values formatted). Runs anywhere (no Valgrind).

```sh
cargo krabi-caliper panic-audit --workspace . --package panic-free-audit \
  --target thumbv7m-none-eabi --features panic-handler \
  --negative-features neg-controls --owned-symbol '.*' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect
```

## Honest gaps

- **The RFC 6979 nonce derivation is out of scope and still
  variable-time** (see *Scope* above). The deterministic
  `sign_prehashed_ct` is not yet CT end-to-end.
- **Branchless selects on secrets are invisible to taint.** memcheck
  flags conditional *jumps* and addresses, not `csel`/`cmov` data flow.
  The ladder gate partially compensates by counting every conditional
  branch in `scalar_mul_ct`; a secret-dependent select elsewhere would
  evade both. Inherent to the tool class until symbolic-execution
  tooling (cargo-checkct / binsec) is adopted.
- **Taint runs on host ISAs** (x86_64, aarch64), not the Thumb/RV32
  encodings that deploy. The ladder gate covers those encodings for the
  scalar multiply only.
