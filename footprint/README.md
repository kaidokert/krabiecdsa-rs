### Footprint harnesses

Measure the incremental `.text`, stack high-water mark, and
approximate cycle cost of one ECDSA verify, as verify-minus-baseline
deltas on emulated embedded targets — same methodology as the
ed25519_heapless / rsa_heapless harnesses.

- `cortex-m/` — Cortex-M0/M3/M4 under `qemu-system-arm`
  (semihosting). The `cargo krabi-caliper` campaigns build every
  (curve × limb width) combination of the `ecdsa_verify` example plus
  a `baseline` binary, runs them under QEMU, and prints a markdown
  metrics table with ELF, stack, and cycle deltas. The `ecdsa_sign` example (P-256, constant-time
  RFC 6979; `cargo run --example ecdsa_sign`) measures the
  experimental signer. Requires `qemu-system-arm` and the
  thumb targets (`rustup target add thumbv6m-none-eabi
  thumbv7m-none-eabi thumbv7em-none-eabi`).
  The measured examples also support the J-Trace STM32F407VG with
  `--target thumbv7em-none-eabihf --features jtrace-f407,...`; this path uses
  RTT and reports stack, raw DWT `dwt_cycles`, and raw `systick_cycles` while
  preserving the legacy QEMU metric fields.
- `risc-v/` — RV32IMAC under `qemu-system-riscv32` (sifive_e). The Rust
  runner stops QEMU after its final `EM_OUTCOME` record, so no wrapper process
  is required. Run `cargo krabi-caliper run ecdsa-riscv32`; requires
  `qemu-system-riscv32` and the `riscv32imac-unknown-none-elf` target.
- `avr/` — ATmega2560 under `simavr`. Nightly-pinned
  (`rust-toolchain.toml`) with `build-std`; u8 limbs only — there is
  no wider word on AVR. Run `cargo krabi-caliper run ecdsa-avr` or
  `cargo krabi-caliper run ecdsa-avr-fast`; requires `simavr` and the
  `krabi-caliper` CLI.
- `fixtures/` — one verify fixture per curve, taken from the crate's
  openssl cross-check test vectors, shared by all three harnesses.
