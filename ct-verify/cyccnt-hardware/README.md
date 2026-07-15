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

- `rfc6979_nonce`: **FAIL**, A 1,234,625 cycles versus B 1,229,364 cycles;
  stable 5,261-cycle secret-key separation.
- `ct_sign_fixed_nonce`: **PASS**, 123,154,049–123,154,075 cycles with
  26-cycle combined spread and overlapping A/B ranges.
- `signing_key_rfc6979`: **FAIL**, A 124,218,249 cycles versus B 124,212,989
  cycles; stable 5,260-cycle secret-key separation.
- `negative_early_exit`: **PASS**, 274-cycle combined separation.
- Stack high-water mark: 5,212 bytes.
- Summary: `passed:2 failed:2`.

Whole signing averages about 124.216 million cycles: approximately 0.7394
seconds or 1.3525 signing operations per second at the qualified 168 MHz
clock. The release image contains 27,184 bytes of text and 1,092 bytes of
static RAM.

Two earlier runs with keys at distinct addresses reproduced a 5,258-cycle
nonce gap and 5,262-cycle whole-operation gap exactly. Their fixed-nonce
result missed the gate narrowly at 34 cycles while the A/B ranges overlapped.
Moving both keys to one address reduced that control to 26 cycles and PASS,
while the nonce and whole-operation separations remained. This localizes the
actionable leak to deterministic nonce derivation rather than the CT signature
math.

CYCCNT is regression evidence, not proof of identical instruction or memory
traces. The failing whole signer must not be represented as constant-time until
RFC 6979 derivation is moved off the Nct backend and the layered campaign is
rerun.
