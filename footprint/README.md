### Footprint harnesses

Measure the incremental `.text`, stack high-water mark, and
approximate cycle cost of one ECDSA verify, as verify-minus-baseline
deltas on emulated embedded targets — same methodology as the
ed25519_heapless / rsa_heapless harnesses.

- `cortex-m/` — Cortex-M0/M3/M4 under `qemu-system-arm`
  (semihosting). Run `python3 run_suite.py`; it builds every
  (curve × limb width) combination of the `ecdsa_verify` example plus
  a `baseline` binary, runs them under QEMU, and prints a markdown
  metrics table. The `ecdsa_sign` example (P-256, constant-time
  RFC 6979; `cargo run --example ecdsa_sign`) measures the
  experimental signer. Requires `qemu-system-arm`, `cargo-bloat`, and the
  thumb targets (`rustup target add thumbv6m-none-eabi
  thumbv7m-none-eabi thumbv7em-none-eabi`).
- `risc-v/` — RV32IMAC under `qemu-system-riscv32` (sifive_e; no
  exit mechanism, so `qemu_wrapper.py` kills the machine after the
  METRIC line). Run `python3 run_suite.py`; requires
  `qemu-system-riscv32` and the `riscv32imac-unknown-none-elf` target.
- `avr/` — ATmega2560 under `simavr`. Nightly-pinned
  (`rust-toolchain.toml`) with `build-std`; u8 limbs only — there is
  no wider word on AVR. Run `python3 run_suite.py` (add `--fast` for
  the baseline + P-256 subset); requires `simavr`.
- `fixtures/` — one verify fixture per curve, taken from the crate's
  openssl cross-check test vectors, shared by all three harnesses.
