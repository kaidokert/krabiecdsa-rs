# krabiecdsa P-256 signing CYCCNT fixtures

Runs the experimental P-256 signer's constant-time layers on the J-Trace
STM32F407VG and checks that two independent private scalars produce
indistinguishable cycle counts.

Both scalars are copied into the same stack slot before measurement (no
address/alignment bias between the A and B classes), and preflight derives each
public key, signs the common digest, and verifies before any timing evidence is
accepted. Four trials per key run in balanced ABBA order with equal warm-up,
interrupts masked, DWT barriers, observable outputs, and a 32-cycle
positive-spread gate.

## Two clock tiers (coverage vs. speed)

The whole-signer is ~120M cycles; running every carrier at 30 MHz would take
~½ hour and time out. So, following the RSA/ed25519 pattern, the CT verdict is
taken at one representative carrier under the deterministic clock, and the slow
carrier runs faster as functional smoke — together ~15 min:

- **CT gate — `u32x8` at 30 MHz / 0 wait states.** 0 WS means no ART
  prefetch/I-cache, so core-cycle counts carry no fetch jitter and the tight
  32-cycle spread gate holds; determinism makes a small sample count valid.
  The real gate.
- **Smoke — `u8x32` (byte limb) at 168 MHz, `gate = false`.** The byte-limb
  sign is ~10× u32x8 and would time out at 30 MHz; 168 MHz keeps wall time
  bounded. Not a CT gate — u8x32's constant-time property is proven at the
  instruction level by ctgrind + the asm-ladder audit; this confirms it signs
  on hardware and captures rough timing.

Each **(tier, fixture)** pair runs as its own probe-rs session (build:
`--no-default-features` + one `carrier-*` + one `clock-*` + one `fix-*`), so
cross-fixture probe/bus state can't perturb a later fixture's first samples.
Every chunk includes the negative control, so each attachment is independently
trustworthy.

Four protected positives (must be constant-time across keys):

- **`rfc6979_nonce`** — RFC 6979 nonce derivation, `derive_nonce_rfc6979_ct`.
  Since the constant-time derivation work this is an ordinary protected
  positive, not a residual gap: the HMAC-DRBG is data-oblivious and the
  candidate range check is `ct_lt`/`ct_is_zero`.
- **`ct_sign_fixed_nonce`** — the RCB signature math given a fixed nonce
  (`sign_prehashed_ct_with_k`), isolating the scalar-multiply + `k⁻¹` layer.
- **`signing_key_rfc6979`** — the whole `SigningKey::sign_prehashed` boundary
  (derivation + sign), the deployment surface.
- **`verifying_key`** — public-key derivation `d·G` (`verifying_key_sec1`), the
  constant-time base-point scalar multiply.

Plus **`negative_early_exit`** in every chunk — a leading-zero early-exit loop;
the timing-negative control, whose A/B ranges must be disjoint.

RTT emits versioned `EM_*` records (plus legacy `CT_*`) over a blocking channel,
the configured HCLK, and the stack high-water mark.

## Running

Two campaigns, one per tier, driven by the campaign runner (each profile owns
its build, SWD/J-Trace selection, RTT completion, and per-case timeouts):

```sh
cargo krabi-caliper run krabiecdsa-ct-jtrace-f407-30mhz      # CT gate (u32x8, 30 MHz)
cargo krabi-caliper run krabiecdsa-smoke-jtrace-f407-168mhz  # smoke (u8x32, 168 MHz)
```

The profiles own the probe binding (`${KRABI_PROBE}`, supplied by the bench,
never committed) and write JSON/Markdown results on the bench under
`target/krabi-caliper/…`. CI runs both on pushes to `main` and pull requests via
`.github/workflows/hw-ct.yml` on a self-hosted `rig-stm32f407-dwt` bench. To
troubleshoot one chunk outside the runner (the default build is `carrier-u32x8`
+ `clock-30mhz` + `fix-wholesign`; pick another with `--no-default-features`):

```sh
cargo run --release
cargo run --release --no-default-features --features carrier-u8x32,clock-168mhz,fix-nonce
```

## Results

Each campaign writes an `EM_SUMMARY` per chunk to `target/krabi-caliper/…` on
the bench. The 30 MHz baseline run confirmed the CT tier: every u32x8 positive —
`rfc6979_nonce`, `ct_sign_fixed_nonce`, `signing_key_rfc6979`, `verifying_key` —
holds constant across keys (Welch `|t|` well below the 4.5 threshold) while
`negative_early_exit` separates deterministically. On that baseline the **30 MHz
CT tier is gated** (`gate = true`, matching ed25519/RSA): a protected-class
timing regression now fails CI. The 168 MHz u8x32 smoke stays `gate = false` by
design — it confirms the byte-limb carrier signs on hardware and captures rough
timing, but its wait-state fetch jitter (positives can exceed the threshold
there) makes it unsuitable as a gate; u8x32's constant-time property is proven at
the instruction level by ctgrind + the asm-ladder audit.

CYCCNT is timing-regression evidence, not proof of identical instruction or
memory traces — it complements, and does not replace, the ctgrind taint gate
and the cross-target conditional-branch audit.
