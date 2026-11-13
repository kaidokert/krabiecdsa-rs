# Constant-time verification harness

Checks for the constant-time and panic-free claims of krabiecdsa's
experimental signing and ECDH paths, in four layers.

This is a nested cargo workspace, outside the published crate in
[`ecdsa/`](../ecdsa). Its release profile in [`Cargo.toml`](Cargo.toml)
is `lto = "fat"`, `codegen-units = 1`, `opt-level = "z"`,
`panic = "abort"`. CI pins the toolchain, so codegen changes arrive only
with a toolchain bump.

Cargo ignores a dependency's `[profile]`, so a deployment picks its own
opt-level. CI runs every layer at both `"z"` and `"s"` by setting
`CARGO_PROFILE_RELEASE_OPT_LEVEL`; set it the same way locally.

## What the fixtures cover

Each fixture calls one public entry point in `krabiecdsa::signing`:
- `sign_prehashed_ct_with_k`: sign with a given nonce.
- `sign_prehashed_ct`: RFC 6979 deterministic sign.
- `sign_prehashed_ct_hedged`: RFC 6979 with §3.6 additional data.
- `sign_prehashed_ct_with_k_blinded`: sign with coordinate and scalar
  blinding.
- `ecdh_diffie_hellman_ct`: ECDH agreement.

`d` and `k` are the secrets, set to the RFC 6979 §A.2.5/§A.2.6 scalars
so the code under test is the successful sign path. The digest, peer
point, additional data and blinds are public.

The with-nonce sign has one fixture per carrier at the width it ships at:

| fixture suffix | curve | limbs | used for |
| -------------- | ----- | ----- | -------- |
| `p256__fb32`   | P-256 | `u32` | Cortex-M / RISC-V |
| `p256__fb8`    | P-256 | `u8`  | AVR-class |
| `p256__fb64`   | P-256 | `u64` | 64-bit hosts |
| `p384__fb32`   | P-384 | `u32` | Cortex-M / RISC-V |

The other entry points have P-256 and P-384 fixtures on `u32` limbs; the
panic audit also builds the deterministic sign on `u8`. They share the
with-nonce `scalar_mul_ct` instances, so the ladder check does not build
them.

## Layers

Commands run from this directory.

**Ladder branch check** ([`ct-driver`](ct-driver/)). Cross-builds the
fixtures for thumbv7em, thumbv7m, thumbv6m, riscv32imc and riscv32imac,
disassembles them, and checks that each `scalar_mul_ct` instance has
only the branches of its loop over the scalar's public bit width. The
per-target, per-opt-level budgets are in
[`ct-driver/src/target.rs`](ct-driver/src/target.rs).

At `"s"` the per-limb field loops are inlined into the ladder, and
krabi-caliper's counted-loop model accepts them by their constant-step
counters. The model cannot tell where a bound came from, so a loop with
a secret bound passes this check (see the last gap). thumbv6m uses a
plain branch count, because its short-range branches turn loop branches
into trampolines the model cannot classify.

The check fails if a ladder symbol is missing, because an inlined or
renamed ladder would otherwise pass unchecked. It also fails if one of
the `nct_fix__neg__*` controls in `ct-fixtures` is not reported:
- `secret_branch`: a loop that exits on a secret byte.
- `vartime_cmp`: an early-exit compare.
- `vartime_serialize`: a serializer that branches on secret bits.

```sh
cargo run --release -p ct-driver -- --target thumbv7m-none-eabi
```

**Taint gate** ([`ct-ctgrind`](ct-ctgrind/)). This is the main check
over whole operations. krabi-caliper marks the secrets undefined and
Valgrind memcheck reports any conditional jump or memory address that
depends on them. Linux x86_64 and aarch64 only; on macOS use the
[Dockerfile](ct-ctgrind/Dockerfile). Six negative controls must be
reported: krabi-caliper's standard branch, equality and index controls,
and the three ladder-check controls.

```sh
cargo build --release -p ct-ctgrind
cargo krabi-caliper ctgrind target/release/ct-ctgrind \
  --valgrind-arg=--suppressions=ct-ctgrind/ct-ctgrind.supp
```

[`ct-ctgrind.supp`](ct-ctgrind/ct-ctgrind.supp) suppresses two things,
each with its reasoning in the file:
- The exit branch of RFC 6979's candidate loop in `rfc6979_nonce`. A
  candidate is rejected with probability about 2⁻³².
- Valgrind's imprecise tracking through `memcpy`.

`Addr` errors are never suppressed. The harness untaints `r`/`s` and the
ECDH output after each call, since they are published.

**Panic-free audit** ([`panic-free-audit`](panic-free-audit/)).
Cross-builds every entry point with unused code removed and checks with
`llvm-nm` that no `core::panicking` code was linked. A reachable panic
in a signer is a denial-of-service path and a timing signal.

```sh
cargo krabi-caliper panic-audit --workspace . --package panic-free-audit \
  --target thumbv7m-none-eabi --features panic-handler \
  --negative-features neg-controls --owned-symbol '.*' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect
```

The second leg adds `--cargo-arg=--features=deterministic` and narrows
`--owned-symbol` to `'krabiecdsa|panic_audit__'`; see the first gap.

**Hardware cycle counts** ([`cyccnt-hardware`](cyccnt-hardware/)).
Compares DWT cycle counts for two private keys on a J-Trace STM32F407VG
with a Welch t-test. See its [README](cyccnt-hardware/README.md).

## Known gaps

- **`hmac`/`sha2` are outside the deterministic leg's audit scope.**
  Their block buffering has reachable panics. krabiecdsa's own RFC 6979
  code passes; the HMAC is the DRBG, so `sha2` cannot be dropped.
- **Taint does not see branchless selects** (`csel`/`cmov`) on secrets.
  The ladder check counts branches in `scalar_mul_ct` only, so a
  secret-dependent select elsewhere passes both.
- **Taint runs on host ISAs**, not the Thumb or RV32 code that ships.
  The ladder check covers those targets for the scalar multiply only.
- **No negative control has a secret loop bound**, so the taint gate's
  handling of one is untested here.
