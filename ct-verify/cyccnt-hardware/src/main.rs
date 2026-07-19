#![no_main]
#![no_std]

use core::hint::black_box;
use cortex_m_rt::entry;
use krabi_caliper::Unit;
use krabi_caliper::cortex_m::DwtCycleCounter;
use krabi_caliper::paired::MaxSpread;
use krabi_caliper::report::Field;
use krabi_caliper::rtt::print;
use krabi_caliper::stack::{CortexM, LinkerStack, StackConfig, StackProbe};
use krabi_caliper::suite::{FixtureSpec, PairedSuite, PairedSuiteConfig, PairedSuiteFields};
use fixed_bigint::FixedUInt;
use hmac::Hmac;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::dangerous::{SigningKey, derive_nonce_rfc6979, sign_prehashed_ct_with_k};
use krabiecdsa::p256::{self, P256};
use sha2::Sha256;

const TRIALS: usize = 4;
const MAX_POSITIVE_SPREAD: u64 = 32;
const SUITE: &str = "krabiecdsa-p256-sign";
const STACK_SAFE_ZONE: usize = 512;

type Nct = FixedUInt<u32, 8>;
type CtBackend = FixedUInt<u32, 8, Ct>;
type P256SigningKey = SigningKey<P256>;

// Two independently generated, openssl-verified private scalars from the
// crate's cross-implementation test vectors.
const KEY_A: [u8; 32] = [
    0x39, 0xa2, 0xd6, 0xfd, 0x08, 0x03, 0x38, 0x2a, 0x59, 0xbf, 0x23, 0x7b, 0x16, 0x24, 0xf9, 0x28,
    0x02, 0xfd, 0x27, 0x76, 0x91, 0xbc, 0x75, 0x37, 0x40, 0x8c, 0x34, 0xc3, 0xbf, 0x4d, 0x21, 0x22,
];
const KEY_B: [u8; 32] = [
    0x80, 0x13, 0x3a, 0x97, 0xa1, 0x21, 0xad, 0xcd, 0x7a, 0xd3, 0xe2, 0x27, 0xe0, 0x0c, 0x7a, 0x70,
    0x5c, 0x54, 0xfd, 0x33, 0x58, 0x78, 0x17, 0x3f, 0xe3, 0xf0, 0x73, 0xeb, 0xa9, 0xa6, 0x0e, 0xd9,
];
const DIGEST: [u8; 32] = [
    0x56, 0x0e, 0x5d, 0x45, 0xa5, 0x0e, 0xf3, 0x03, 0x41, 0x8f, 0xd3, 0xa1, 0xa4, 0x81, 0xa7, 0xc9,
    0x3d, 0xca, 0x42, 0xb3, 0x72, 0x96, 0x11, 0x71, 0x7c, 0x2b, 0x67, 0xc2, 0xcc, 0x1c, 0x43, 0x74,
];
// RFC 6979 P-256 nonce for the standard "sample" vector. Reusing it across
// test keys is safe only in this non-production fixture and isolates the CT
// signature-math layer from deterministic nonce derivation.
const FIXED_K: [u8; 32] = [
    0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90, 0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xdd, 0x4c,
    0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2, 0x4d, 0x61, 0x29, 0x49, 0x3d, 0x8a, 0xad, 0x60,
];

#[cfg(feature = "clock-168mhz")]
const CLOCK_PROFILE: &str = "hsi-pll-168mhz";
#[cfg(not(feature = "clock-168mhz"))]
const CLOCK_PROFILE: &str = "reset-hsi-16mhz";

#[cfg(feature = "clock-168mhz")]
fn configure_clock() -> u32 {
    use stm32f4xx_hal::{pac, prelude::*, rcc::Config};

    let device = pac::Peripherals::take().unwrap();
    let rcc = device.RCC.freeze(
        Config::hsi()
            .sysclk(168.MHz())
            .hclk(168.MHz())
            .pclk1(42.MHz())
            .pclk2(84.MHz()),
    );
    let hclk_hz = rcc.clocks.hclk().raw();
    assert_eq!(hclk_hz, 168_000_000);
    hclk_hz
}

#[cfg(not(feature = "clock-168mhz"))]
fn configure_clock() -> u32 {
    16_000_000
}

fn paint_stack() -> StackProbe {
    // SAFETY: cortex-m-rt defines the writable descending-stack allocation.
    let stack = unsafe { LinkerStack::<CortexM>::cortex_m_runtime() };
    StackProbe::paint(&stack, StackConfig::new(STACK_SAFE_ZONE)).unwrap()
}

fn nonce_once(key: &[u8; 32]) -> bool {
    let mut nonce = [0u8; 32];
    let ok = derive_nonce_rfc6979::<P256, Nct, Hmac<Sha256>>(
        black_box(key),
        black_box(&DIGEST),
        &mut nonce,
    );
    let _ = black_box(nonce);
    ok
}

fn fixed_nonce_sign_once(key: &[u8; 32]) -> bool {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let ok = sign_prehashed_ct_with_k::<P256, CtBackend>(
        black_box(key),
        black_box(&DIGEST),
        black_box(&FIXED_K),
        &mut r,
        &mut s,
    );
    let _ = black_box((r, s));
    ok
}

fn whole_sign_once(key: &P256SigningKey) -> bool {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let ok = key.sign_prehashed::<Nct, CtBackend, Hmac<Sha256>>(black_box(&DIGEST), &mut r, &mut s);
    let _ = black_box((r, s));
    ok
}

#[inline(never)]
fn negative_early_exit(key: &[u8; 32]) -> bool {
    let mut leading_zeroes = 0usize;
    for &byte in black_box(key) {
        if byte != 0 {
            break;
        }
        leading_zeroes += 1;
    }
    let _ = black_box(leading_zeroes);
    true
}

fn copy_key(input: &[u8; 32]) -> [u8; 32] {
    let mut key = [0; 32];
    key.copy_from_slice(input);
    key
}

fn prepare_signing_key(input: &[u8; 32]) -> P256SigningKey {
    P256SigningKey::from_bytes(input).unwrap()
}

fn preflight(key_bytes: &[u8; 32]) -> Option<P256SigningKey> {
    let key = P256SigningKey::from_bytes(key_bytes)?;
    let mut pubkey = [0u8; 65];
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    if !key.verifying_key_sec1::<CtBackend>(&mut pubkey)
        || !key.sign_prehashed::<Nct, CtBackend, Hmac<Sha256>>(&DIGEST, &mut r, &mut s)
        || !p256::verify_prehashed::<Nct>(&pubkey, &DIGEST, &r, &s)
    {
        return None;
    }
    Some(key)
}

fn stop() -> ! {
    loop {
        cortex_m::asm::nop();
    }
}

#[entry]
fn main() -> ! {
    let mut reporter = krabi_caliper::rtt::init_ct_compatible();
    let hclk_hz = configure_clock();
    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    let mut counter = DwtCycleCounter::enable(
        &mut peripherals.DCB,
        &mut peripherals.DWT,
        Some(hclk_hz as u64),
    )
    .unwrap();
    let stack_probe = paint_stack();

    let Some(key_a) = preflight(&KEY_A) else {
        print(format_args!("SETUP_FAIL key:A\n"));
        stop();
    };
    let Some(key_b) = preflight(&KEY_B) else {
        print(format_args!("SETUP_FAIL key:B\n"));
        stop();
    };

    let _ = black_box((&key_a, &key_b));
    let run_fields = [
        Field::token("carrier", "u32x8"),
        Field::token("clock_profile", CLOCK_PROFILE),
        Field::u64("hclk_hz", hclk_hz as u64),
        Field::u64("trials", TRIALS as u64),
        Field::u64("max_positive_spread", MAX_POSITIVE_SPREAD),
    ];
    let mut suite = PairedSuite::<_, _, TRIALS>::start(
        &mut counter,
        &mut reporter,
        PairedSuiteConfig {
            suite: SUITE,
            target: "cortex-m4f",
            board: Some("j-trace-stm32f407vg"),
            unit: Unit::CoreCycles,
            frequency_hz: Some(hclk_hz as u64),
            warmup_blocks: 1,
            batches: 1,
            positive_max_spread: MAX_POSITIVE_SPREAD,
            positive_require_overlap: false,
            fields: PairedSuiteFields {
                run: &run_fields,
                fixture: &[],
                summary: &[],
            },
        },
    )
    .unwrap();
    suite
        .fixture_prepared(
            FixtureSpec {
                name: "rfc6979_nonce",
                class: "positive-residual-gap",
                policy: "max-spread",
            },
            &KEY_A,
            &KEY_B,
            MaxSpread {
                ticks: MAX_POSITIVE_SPREAD,
                require_overlap: false,
            },
            copy_key,
            nonce_once,
        )
        .unwrap();
    suite
        .positive_prepared(
            "ct_sign_fixed_nonce",
            &KEY_A,
            &KEY_B,
            copy_key,
            fixed_nonce_sign_once,
        )
        .unwrap();
    suite
        .fixture_prepared(
            FixtureSpec {
                name: "signing_key_rfc6979",
                class: "positive-whole-operation",
                policy: "max-spread",
            },
            &KEY_A,
            &KEY_B,
            MaxSpread {
                ticks: MAX_POSITIVE_SPREAD,
                require_overlap: false,
            },
            prepare_signing_key,
            whole_sign_once,
        )
        .unwrap();
    const ZERO: [u8; 32] = [0; 32];
    suite
        .negative("negative_early_exit", &ZERO, &KEY_A, negative_early_exit)
        .unwrap();
    let stack = stack_probe.measure();
    suite
        .stack_measurement(stack, &[Field::token("carrier", "u32x8")])
        .unwrap();
    assert!(!stack.overflowed);
    suite.finish().unwrap();
    stop();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(format_args!("PANIC: {}\n", info));
    stop();
}
