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

## Scope — what is attested

Two sign entry points, both constant-time:

- **`sign_prehashed_ct_with_k`** — the RCB scalar-multiply sign given a
  nonce: the constant-time range checks (`ct_is_zero`/`ct_lt` on `d` and
  `k`), the branchless double-and-add-always ladder (`scalar_mul_ct` over
  homogeneous projective coordinates with RCB complete addition), `k⁻¹`,
  and the `s = k⁻¹(z + r·d)` combination — all on the `FieldCt` surface.
- **`sign_prehashed_ct`** — the *full* RFC 6979 deterministic sign:
  the above, plus the nonce derivation. The derivation's HMAC-DRBG is
  data-oblivious (SHA-2/HMAC branch on neither key nor message) and its
  candidate range check runs on `subtle`'s constant-time comparisons, so
  the whole deterministic sign is constant-time **up to RFC 6979's
  inherent rejection-loop count** — reject probability ~2⁻³² for these
  curves, effectively always one iteration, revealing negligible
  information about the key. That one signal is a documented
  declassification (see the ctgrind [suppressions](ct-ctgrind/ct-ctgrind.supp)).

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
be vacuous), and the negative controls must trip. This is the only gate
that inspects the Thumb/RV32 encodings that actually deploy; it runs
anywhere (no Valgrind).

```sh
cargo run --release -p ct-driver -- --target thumbv7m-none-eabi
```

**Taint (ctgrind) — the primary whole-operation gate**
([`ct-ctgrind`](ct-ctgrind/)). Marks the secret `d` (and `k`, for the
with-nonce fixtures) undefined via crabgrind; Valgrind memcheck then
flags any conditional jump or memory access that depends on them,
through every inlined dependency, across the whole sign — including the
deterministic fixtures that derive the nonce internally. Runs on
x86_64/aarch64 **Linux only** — on macOS use the
[Dockerfile](ct-ctgrind/Dockerfile). Negative controls (a
secret-dependent early-exit loop, a vartime compare, and three synthetic
detector controls) must trip.

```sh
cargo build --release -p ct-ctgrind
cargo krabi-caliper ctgrind target/release/ct-ctgrind \
  --valgrind-arg=--suppressions=ct-ctgrind/ct-ctgrind.supp
```

Suppressions ([`ct-ctgrind.supp`](ct-ctgrind/ct-ctgrind.supp)) are
individually reviewed declassifications, not blanket: the public
pass/fail outcomes of the sign, RFC 6979's rejection-loop count, and
data-oblivious `memcpy` shadow-propagation artifacts. Their soundness
rests on the CT primitives being separate symbols (`scalar_mul_ct` and
`add_rcb` carry `#[inline(never)]` for exactly this) — a real leak in
the branchless crypto path surfaces at its own symbol, matched by no
entry. Verify with `nm libct_fixtures.a | grep scalar_mul_ct`.

**Panic-free audit** ([`panic-free-audit`](panic-free-audit/)).
Cross-builds the sign as a DCE'd staticlib and asserts via `llvm-nm`
that no `core::panicking` machinery was linked. For a signer a reachable
panic is both a DoS edge and a timing oracle (panic formatting cost
depends on the values formatted). Two legs, no Valgrind:

```sh
# with-nonce sign — strict: the whole path incl. deps must be panic-free
cargo krabi-caliper panic-audit --workspace . --package panic-free-audit \
  --target thumbv7m-none-eabi --features panic-handler \
  --negative-features neg-controls --owned-symbol '.*' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect

# deterministic sign — crate-owned scope (see gaps re: hmac/sha2)
cargo krabi-caliper panic-audit --workspace . --package panic-free-audit \
  --target thumbv7m-none-eabi --features panic-handler \
  --cargo-arg=--features=deterministic \
  --negative-features neg-controls --owned-symbol 'krabiecdsa|panic_audit__' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect
```

## Honest gaps

- **The RFC 6979 DRBG's upstream deps are out of the panic-free scope.**
  The deterministic sign pulls in RustCrypto `hmac`/`sha2`, whose block
  buffering carries its own reachable `copy_from_slice`/slice-index panic
  branches. krabiecdsa's *own* derivation byte-plumbing is panic-free
  (the deterministic leg audits crate-owned symbols and passes); the
  upstream branches are deferred, not fixed here — the same
  upstream-triage stance the with-nonce leg's strict `.*` audit applies
  to fixed-bigint/modmath. RSA's harness sidesteps this by keeping `sha2`
  out via prehash; RFC 6979 can't, the HMAC *is* the DRBG.
- **Branchless selects on secrets are invisible to taint.** memcheck
  flags conditional *jumps* and addresses, not `csel`/`cmov` data flow.
  The ladder gate partially compensates by counting every conditional
  branch in `scalar_mul_ct`; a secret-dependent select elsewhere would
  evade both. Inherent to the tool class until symbolic-execution
  tooling (cargo-checkct / binsec) is adopted.
- **Taint runs on host ISAs** (x86_64, aarch64), not the Thumb/RV32
  encodings that deploy. The ladder gate covers those encodings for the
  scalar multiply only.
