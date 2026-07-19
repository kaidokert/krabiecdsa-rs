# Cortex-M footprint harness

The shared Rust runner owns the QEMU M0/M3/M4 matrix, semihosting capture,
ELF accounting, deadlines, baseline deltas, and reports. Run
`cargo krabi-caliper run ecdsa-cortex-m0` (or the `m3`/`m4` campaign) in
this directory; configuration lives in `krabi-caliper.toml`.

The same case set runs on the J-Trace reference board through the declarative
`probe-rs` profile. For a focused P-256 run:

```sh
cargo krabi-caliper run ecdsa-jtrace-f407 \
  --case baseline --case p256-u32
```

The equivalent direct command remains useful when diagnosing probe failures:

```sh
cargo build --release --target thumbv7em-none-eabihf \
  --example ecdsa_verify --features jtrace-f407,curve_p256,limb_u32
probe-rs run --chip STM32F407VGTx --protocol swd \
  --probe 1366:1020:001224000224 \
  target/thumbv7em-none-eabihf/release/examples/ecdsa_verify
```

The hardware metrics include the stack high-water mark, raw DWT `CYCCNT` as
`dwt_cycles`, and raw `systick_cycles`. The legacy `cycles` field remains
SysTick cycles divided by 1,000 for QEMU compatibility. DWT measurements must
be shorter than 2^32 core cycles. Stack painting and scanning use the shared
`krabi-caliper` probe also used by the RISC-V and AVR harnesses.
Stack results are emitted as versioned `EM_STACK` records; the legacy
`METRIC stack:` field remains during parser migration.
