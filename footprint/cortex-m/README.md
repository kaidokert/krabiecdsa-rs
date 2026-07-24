# Cortex-M footprint harness

The shared Rust runner owns the QEMU M0/M3/M4 matrix, semihosting capture,
ELF accounting, deadlines, baseline deltas, and reports. Run
`cargo krabi-caliper run ecdsa-cortex-m0` (or the `m3`/`m4` campaign) in
this directory; configuration lives in `krabi-caliper.toml`.

The fixtures emit canonical `EM_MEASUREMENT` and `EM_STACK` records over
semihosting. Stack painting, SysTick acquisition, and reporting use the shared
`krabi-caliper` lifecycle adapter.
