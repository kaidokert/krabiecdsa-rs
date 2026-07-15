#![no_main]
#![no_std]

use core::hint::black_box;
use cortex_m::peripheral::DWT;
use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;
use hmac::Hmac;
use krabiecdsa::const_num_traits::Ct;
use krabiecdsa::dangerous::{SigningKey, derive_nonce_rfc6979, sign_prehashed_ct_with_k};
use krabiecdsa::p256::{self, P256};
use rtt_target::{rprintln, rtt_init_print};
use sha2::Sha256;

const TRIALS: usize = 4;
const MAX_POSITIVE_SPREAD: u32 = 32;
const ORDER: [bool; TRIALS * 2] = [false, true, true, false, true, false, false, true];
const STACK_PAINT: u8 = 0xaa;
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

unsafe extern "C" {
    static _stack_start: u32;
    static _stack_end: u32;
}

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

fn paint_stack() {
    unsafe {
        let stack_end = &_stack_end as *const u32 as usize;
        let sp: usize;
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
        let paint_end = sp.saturating_sub(STACK_SAFE_ZONE).max(stack_end);
        core::ptr::write_bytes(stack_end as *mut u8, STACK_PAINT, paint_end - stack_end);
    }
}

fn stack_high_water_mark() -> usize {
    unsafe {
        let stack_start = &_stack_start as *const u32 as usize;
        let stack_end = &_stack_end as *const u32 as usize;
        let mut current = stack_end;
        while current < stack_start && core::ptr::read_volatile(current as *const u8) == STACK_PAINT
        {
            current += 1;
        }
        stack_start - current
    }
}

#[derive(Clone, Copy)]
struct Samples {
    a: [u32; TRIALS],
    b: [u32; TRIALS],
    outputs_ok: bool,
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

#[inline(always)]
fn timed(operation: impl FnOnce() -> bool) -> (u32, bool) {
    cortex_m::interrupt::free(|_| {
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        let start = DWT::cycle_count();
        let ok = operation();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        (DWT::cycle_count().wrapping_sub(start), ok)
    })
}

fn measure_keys(operation: fn(&[u8; 32]) -> bool) -> Samples {
    let _ = black_box(operation(&KEY_A));
    let _ = black_box(operation(&KEY_B));
    let _ = black_box(operation(&KEY_B));
    let _ = black_box(operation(&KEY_A));
    let mut samples = Samples {
        a: [0; TRIALS],
        b: [0; TRIALS],
        outputs_ok: true,
    };
    let (mut ai, mut bi) = (0, 0);
    for use_b in ORDER {
        let mut key = [0u8; 32];
        key.copy_from_slice(if use_b { &KEY_B } else { &KEY_A });
        let (cycles, ok) = timed(|| operation(black_box(&key)));
        samples.outputs_ok &= ok;
        if use_b {
            samples.b[bi] = cycles;
            bi += 1;
        } else {
            samples.a[ai] = cycles;
            ai += 1;
        }
    }
    samples
}

fn measure_whole(key_a: &P256SigningKey, key_b: &P256SigningKey) -> Samples {
    let _ = black_box(whole_sign_once(key_a));
    let _ = black_box(whole_sign_once(key_b));
    let _ = black_box(whole_sign_once(key_b));
    let _ = black_box(whole_sign_once(key_a));
    let mut samples = Samples {
        a: [0; TRIALS],
        b: [0; TRIALS],
        outputs_ok: true,
    };
    let (mut ai, mut bi) = (0, 0);
    for use_b in ORDER {
        let key_bytes = if use_b { &KEY_B } else { &KEY_A };
        let key = P256SigningKey::from_bytes(key_bytes).unwrap();
        let (cycles, ok) = timed(|| whole_sign_once(black_box(&key)));
        samples.outputs_ok &= ok;
        if use_b {
            samples.b[bi] = cycles;
            bi += 1;
        } else {
            samples.a[ai] = cycles;
            ai += 1;
        }
    }
    samples
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

fn measure_negative() -> Samples {
    const ZERO: [u8; 32] = [0; 32];
    let mut samples = Samples {
        a: [0; TRIALS],
        b: [0; TRIALS],
        outputs_ok: true,
    };
    let (mut ai, mut bi) = (0, 0);
    for use_b in ORDER {
        let key = if use_b { &KEY_A } else { &ZERO };
        let (cycles, ok) = timed(|| negative_early_exit(key));
        samples.outputs_ok &= ok;
        if use_b {
            samples.b[bi] = cycles;
            bi += 1;
        } else {
            samples.a[ai] = cycles;
            ai += 1;
        }
    }
    samples
}

fn bounds(values: &[u32; TRIALS]) -> (u32, u32) {
    let mut min = u32::MAX;
    let mut max = 0;
    for &value in values {
        min = min.min(value);
        max = max.max(value);
    }
    (min, max)
}

fn report(name: &str, class: &str, samples: Samples, expect_equal: bool) -> bool {
    let (a_min, a_max) = bounds(&samples.a);
    let (b_min, b_max) = bounds(&samples.b);
    let spread = a_min.min(b_min).abs_diff(a_max.max(b_max));
    let timing_ok = if expect_equal {
        spread <= MAX_POSITIVE_SPREAD
    } else {
        a_max < b_min || b_max < a_min
    };
    let passed = samples.outputs_ok && timing_ok;
    rprintln!(
        "CT_RESULT fixture:{} class:{} a_min:{} a_max:{} b_min:{} b_max:{} spread:{} output_ok:{} status:{}",
        name,
        class,
        a_min,
        a_max,
        b_min,
        b_max,
        spread,
        samples.outputs_ok as u8,
        if passed { "PASS" } else { "FAIL" }
    );
    passed
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
    rtt_init_print!();
    let hclk_hz = configure_clock();
    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    assert!(DWT::has_cycle_counter());
    peripherals.DCB.enable_trace();
    peripherals.DWT.set_cycle_count(0);
    peripherals.DWT.enable_cycle_counter();
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    paint_stack();

    let Some(key_a) = preflight(&KEY_A) else {
        rprintln!("SETUP_FAIL key:A");
        stop();
    };
    let Some(key_b) = preflight(&KEY_B) else {
        rprintln!("SETUP_FAIL key:B");
        stop();
    };

    rprintln!(
        "CT_BEGIN suite:krabiecdsa-p256-sign carrier:u32x8 clock_profile:{} hclk_hz:{} trials:{} max_positive_spread:{}",
        CLOCK_PROFILE,
        hclk_hz,
        TRIALS,
        MAX_POSITIVE_SPREAD
    );
    let nonce = report(
        "rfc6979_nonce",
        "positive-residual-gap",
        measure_keys(nonce_once),
        true,
    );
    let fixed = report(
        "ct_sign_fixed_nonce",
        "positive",
        measure_keys(fixed_nonce_sign_once),
        true,
    );
    let whole = report(
        "signing_key_rfc6979",
        "positive-whole-operation",
        measure_whole(&key_a, &key_b),
        true,
    );
    let negative = report("negative_early_exit", "negative", measure_negative(), false);
    let stack = stack_high_water_mark();
    rprintln!(
        "CT_STACK suite:krabiecdsa-p256-sign carrier:u32x8 bytes:{}",
        stack
    );
    let passed = nonce as u32 + fixed as u32 + whole as u32 + negative as u32;
    rprintln!(
        "CT_SUMMARY suite:krabiecdsa-p256-sign passed:{} failed:{}",
        passed,
        4 - passed
    );
    stop();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rprintln!("PANIC: {}", info);
    stop();
}
