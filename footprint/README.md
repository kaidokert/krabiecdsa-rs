### Footprint harnesses

Measure the incremental `.text`, stack high-water mark, and
approximate cycle cost of one ECDSA verify, as verify-minus-baseline
deltas on emulated embedded targets — same methodology as the
ed25519_heapless / rsa_heapless harnesses.

- `cortex-m/` — Cortex-M0/M3/M4 under `qemu-system-arm`
  (semihosting). Run `python3 run_suite.py`; it builds every
  (curve × limb width) combination of the `ecdsa_verify` example plus
  a `baseline` binary, runs them under QEMU, and prints a markdown
  metrics table. Requires `qemu-system-arm`, `cargo-bloat`, and the
  thumb targets (`rustup target add thumbv6m-none-eabi
  thumbv7m-none-eabi thumbv7em-none-eabi`).
- `fixtures/` — one verify fixture per curve, taken from the crate's
  openssl cross-check test vectors.

RISC-V and AVR harnesses follow the same pattern and are planned next.
