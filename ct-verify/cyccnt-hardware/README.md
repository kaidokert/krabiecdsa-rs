# krabiecdsa P-256 signing CYCCNT fixture

Compares signing under two independent valid P-256 private scalars on the
J-Trace STM32F407VG. Both scalars are copied into the same stack slot before
measurement, avoiding address/alignment differences between the A and B
classes. Preflight derives each public key, signs the common digest, and
verifies the result before timing evidence is accepted.

The fixture separates the experimental signer into three measurements:

- RFC 6979 nonce derivation on `FixedUInt<u32, 8>` (Nct), the crate's
  documented residual timing gap.
- Signature math with a common fixed nonce on `FixedUInt<u32, 8, Ct>`.
- The public `SigningKey::sign_prehashed` whole-operation boundary, containing
  both layers.

Four trials per key use balanced ABBA order, equal warm-up, interrupt masking,
DWT barriers, observable outputs, and a 32-cycle positive-spread gate. An
obvious early-exit loop is the required timing-negative control. RTT reports
the configured HCLK and stack high-water mark.

The carrier uses the shared `embedded-measure` paired-suite, DWT, policy, and
reporting primitives. Its prepared-input path copies raw scalars or constructs
`SigningKey` values in one local slot before entering the measured region, so
setup remains outside the declared timing boundary without reintroducing
address bias. Output includes both the versioned `EM_*` records and the legacy
`CT_*` compatibility records.

Run at the default 168 MHz HSI/PLL profile:

```sh
cargo run --release
```

Build or run at the 16 MHz reset clock with:

```sh
cargo run --release --no-default-features
```

## STM32F407 results at 168 MHz

The final same-address campaign produced:

- `rfc6979_nonce`: **FAIL**, A 1,224,822–1,224,836 cycles versus B
  1,219,898–1,219,903 cycles; 4,938-cycle combined spread with a stable
  key-dependent separation.
- `ct_sign_fixed_nonce`: **PASS**, 122,627,792–122,627,796 cycles with a
  4-cycle combined spread and overlapping A/B ranges.
- `signing_key_rfc6979`: **FAIL**, A 123,853,290–123,853,292 cycles versus B
  123,848,366–123,848,370 cycles; 4,926-cycle combined spread with a stable
  key-dependent separation.
- `negative_early_exit`: **PASS**, 253-cycle combined separation.
- Stack high-water mark: 6,652 bytes.
- Summary: `passed:2 failed:2`.

Whole signing averages about 123.851 million cycles: approximately 0.7372
seconds or 1.3565 signing operations per second at the qualified 168 MHz
clock. The release image contains 38,248 bytes of text and 4,164 bytes of
static RAM.

Two earlier runs with keys at distinct addresses reproduced a 5,258-cycle
nonce gap and 5,262-cycle whole-operation gap exactly. Their fixed-nonce
result missed the gate narrowly at 34 cycles while the A/B ranges overlapped.
Moving both keys to one address reduced that control to 26 cycles and PASS,
while the nonce and whole-operation separations remained. This localizes the
actionable leak to deterministic nonce derivation rather than the CT signature
math. The shared-fixture migration tightened that control further to 4 cycles
and independently preserved the same localization.

CYCCNT is regression evidence, not proof of identical instruction or memory
traces. The failing whole signer must not be represented as constant-time until
RFC 6979 derivation is moved off the Nct backend and the layered campaign is
rerun.
