#![cfg_attr(not(test), no_std)]

//! ECDSA signature verification on `modmath`, over short-Weierstrass
//! curves: NIST P-256 ([`p256`]), secp256k1 ([`k256`]), and NIST
//! P-384 ([`p384`]).
//!
//! `no_std`, no-alloc, verify-only, generic over the bigint backend:
//! any type satisfying [`UnsignedModularInt`] (a blanket-implemented
//! bound bundle) and at least as wide
//! as the curve can carry the arithmetic. This crate names no
//! backend — the consumer brings one (a 256-bit type for P-256 /
//! secp256k1, 384-bit for P-384; narrower fails the build):
//!
//! ```
//! use krabiecdsa::p256;
//! # type Backend = fixed_bigint::FixedUInt<u32, 8>; // dev-dependency backend for this doctest
//!
//! let pubkey = [4u8; 65]; // SEC1 uncompressed: 0x04 || X || Y
//! let digest = [0u8; 32]; // SHA-256 of the message
//! let (r, s) = ([1u8; 32], [1u8; 32]);
//! assert!(!p256::verify_prehashed::<Backend>(&pubkey, &digest, &r, &s));
//! ```
//!
//! The verifiers take an unpacked `(r, s)` pair — DER decoding
//! belongs to the certificate layer. Verify operates on public data,
//! so it needs no constant-time arithmetic and is generic over the
//! modmath field backend — the `Nct` surface by default, or `Ct` to
//! share one carrier with a signer.

pub use modmath::{FieldFor, FieldOps};

// [`UnsignedModularInt`]'s supertraits are spelled in these crates'
// vocabularies, which makes their versions part of this crate's public
// contract. Re-exported so a downstream backend implementor names
// exactly the copies krabiecdsa was built against instead of adding
// separately-versioned dependencies that may fail to unify.
pub use const_num_traits;
pub use modmath;
pub use subtle;
pub use zeroize;

/// Bound bundle for the generic bigint backend the verifiers build
/// on. Marker trait, blanket-implemented for every conforming type
/// (same arrangement as ed25519's `UnsignedModularInt`) — do not
/// implement it manually. Any bigint
/// implementing the `modmath` + `const-num-traits` surface qualifies
/// automatically (use this crate's re-exports of both so the trait
/// identities unify).
///
/// The bounds are exactly what `modmath::FieldNct` needs for its
/// Montgomery precompute, `mul`/`add`/`sub`, and Fermat inversion,
/// plus by-value shift/mask for scalar bit extraction and fallible
/// big-endian deserialization ([`const_num_traits::FromByteSlice`]).
/// Backends must be **at least as wide as the curve's field prime**
/// (256 or 384 bits); a too-narrow instantiation is rejected at
/// compile time by [`verify_for_curve`].
pub trait UnsignedModularInt:
    Copy
    + PartialEq
    + PartialOrd
    + const_num_traits::Zero
    + const_num_traits::One
    + const_num_traits::WrappingMul<Output = Self>
    + const_num_traits::WrappingAdd<Output = Self>
    + const_num_traits::WrappingSub<Output = Self>
    + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
    + const_num_traits::FromByteSlice
    + const_num_traits::BitsPrecision
    + const_num_traits::WithPrecision
    + core::ops::Shr<usize, Output = Self>
    + core::ops::ShrAssign<usize>
    + core::ops::BitAnd<Output = Self>
    + modmath::Parity
    + modmath::NonCt
    + modmath::WideMul
    + modmath::CiosMontMul
    // modmath's MontStorage requires Zeroize when the dependency
    // graph enables modmath/zeroize (feature unification in a larger
    // build can do that even though this crate never asks for it);
    // carrying DefaultIsZeroes here keeps the generic verify code
    // compiling in both worlds. Same bound ed25519's bundle carries.
    + zeroize::DefaultIsZeroes
{
}

impl<T> UnsignedModularInt for T where
    T: Copy
        + PartialEq
        + PartialOrd
        + const_num_traits::Zero
        + const_num_traits::One
        + const_num_traits::WrappingMul<Output = Self>
        + const_num_traits::WrappingAdd<Output = Self>
        + const_num_traits::WrappingSub<Output = Self>
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
        + const_num_traits::FromByteSlice
        + const_num_traits::BitsPrecision
        + const_num_traits::WithPrecision
        + core::ops::Shr<usize, Output = Self>
        + core::ops::ShrAssign<usize>
        + core::ops::BitAnd<Output = Self>
        + modmath::Parity
        + modmath::NonCt
        + modmath::WideMul
        + modmath::CiosMontMul
        + zeroize::DefaultIsZeroes
{
}

/// The byte-and-shift surface the personality-agnostic scalar helpers
/// (`from_be`, `to_be`, `hash_to_scalar`, `lt`, `bit`) need. Both the
/// Nct verify backend ([`UnsignedModularInt`]) and the Ct signing
/// backend ([`dangerous::ConstantTimeInt`]) carry these, so the
/// helpers are written once against this subset and reused by both.
pub trait ScalarBytes:
    Clone
    + PartialEq
    + PartialOrd
    + const_num_traits::Zero
    + const_num_traits::One
    + const_num_traits::FromByteSlice
    + core::ops::Shr<usize, Output = Self>
    + core::ops::ShrAssign<usize>
    + core::ops::BitAnd<Output = Self>
{
}

impl<T> ScalarBytes for T where
    T: Clone
        + PartialEq
        + PartialOrd
        + const_num_traits::Zero
        + const_num_traits::One
        + const_num_traits::FromByteSlice
        + core::ops::Shr<usize, Output = Self>
        + core::ops::ShrAssign<usize>
        + core::ops::BitAnd<Output = Self>
{
}

/// Load big-endian bytes into `T`, failing closed.
///
/// `FromByteSlice::from_be_slice` zero-extends short input and rejects
/// empty or wider-than-`T` input. Every call site in this crate feeds
/// it at most `ELEM_BYTES ≤ size_of::<T>()` bytes (compile-time
/// guard in [`verify_for_curve`]) and never an empty slice (empty
/// digests are rejected at the input gate), so the `Err` branch is
/// structurally unreachable; mapping it to zero rather than
/// unwrapping avoids linking a panic path.
fn from_be<T: ScalarBytes>(bytes: &[u8]) -> T {
    T::from_be_slice(bytes).unwrap_or_else(|_| T::zero())
}

/// Short-Weierstrass curve `y² = x³ + ax + b` over a prime field.
///
/// All constants are big-endian and exactly `ELEM_BYTES` long —
/// [`verify_for_curve`] checks the lengths at compile time, so a
/// mis-sized constant in a downstream `Curve` impl fails the build
/// instead of verifying on a silently wrong curve.
///
/// # Implementor contract — the verifier assumes, and cannot check:
///
/// - `P` is an odd **prime** (field arithmetic, on-curve check).
/// - `N` is an odd **prime** — load-bearing: `s⁻¹ mod n` uses
///   Fermat's little theorem, so a composite `N` yields silently
///   wrong inverses, not an error.
/// - `(GX, GY)` lies on the curve and generates a group of order
///   exactly `N` with **cofactor 1** (no subgroup check is performed).
/// - `A` and `B` are already reduced mod `P`.
///
/// The curves shipped by this crate satisfy all of this; a downstream impl
/// (e.g. P-521) is asserting it.
pub trait Curve {
    /// Field-element / scalar width in bytes (e.g. 32 or 48).
    const ELEM_BYTES: usize;
    /// Field prime `p`.
    const P: &'static [u8];
    /// Curve coefficient `a` (reduced mod p, e.g. `p − 3`).
    const A: &'static [u8];
    /// Curve coefficient `b`.
    const B: &'static [u8];
    /// Group order `n` (prime; cofactor must be 1).
    const N: &'static [u8];
    /// Generator affine x.
    const GX: &'static [u8];
    /// Generator affine y.
    const GY: &'static [u8];
}

/// Decode a `2·N`-char lowercase-hex string into `N` big-endian
/// bytes. Const so the curve constants stay readable; panics at
/// compile time on malformed input.
const fn hx<const N: usize>(s: &str) -> [u8; N] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex digit in curve constant"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len() == 2 * N);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = nib(s[2 * i]) << 4 | nib(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// Stamp out a curve module: constants, marker type, `Curve` impl,
/// and the fixed-size `verify_prehashed` wrapper. The per-curve doc
/// comments stay at the invocation site.
macro_rules! define_curve {
    (
        $(#[$mod_doc:meta])*
        pub mod $m:ident {
            $(#[$marker_doc:meta])*
            marker: $marker:ident,
            elem_bytes: $eb:expr,
            digest_bytes: $db:expr,
            p: $p:expr,
            a: $a:expr,
            b: $b:expr,
            n: $n:expr,
            gx: $gx:expr,
            gy: $gy:expr,
            $(#[$fn_doc:meta])*
            fn verify_prehashed;
        }
    ) => {
        $(#[$mod_doc])*
        pub mod $m {
            use super::*;

            /// SEC1 uncompressed public key: `0x04 || X || Y`.
            pub const PUBKEY_BYTES: usize = 1 + 2 * $eb;

            const P_B: [u8; $eb] = hx($p);
            const A_B: [u8; $eb] = hx($a);
            const B_B: [u8; $eb] = hx($b);
            const N_B: [u8; $eb] = hx($n);
            const GX_B: [u8; $eb] = hx($gx);
            const GY_B: [u8; $eb] = hx($gy);

            $(#[$marker_doc])*
            pub enum $marker {}
            impl Curve for $marker {
                const ELEM_BYTES: usize = $eb;
                const P: &'static [u8] = &P_B;
                const A: &'static [u8] = &A_B;
                const B: &'static [u8] = &B_B;
                const N: &'static [u8] = &N_B;
                const GX: &'static [u8] = &GX_B;
                const GY: &'static [u8] = &GY_B;
            }

            $(#[$fn_doc])*
            #[must_use]
            pub fn verify_prehashed<T: FieldFor + ScalarBytes>(
                pubkey: &[u8; PUBKEY_BYTES],
                digest: &[u8; $db],
                r: &[u8; $eb],
                s: &[u8; $eb],
            ) -> bool {
                verify_for_curve::<$marker, T>(pubkey, digest, r, s)
            }

            /// SEC1-uncompressed verifying key, carrying the bigint
            /// backend as a type parameter. Exists for the RustCrypto
            /// [`signature::hazmat::PrehashVerifier`] integration;
            /// the plain [`verify_prehashed`] function is the native
            /// API.
            #[derive(Copy, Clone, PartialEq, Eq)]
            pub struct VerifyingKey<T: FieldFor + ScalarBytes> {
                sec1: [u8; PUBKEY_BYTES],
                // fn() -> T rather than T: the key names a backend,
                // it doesn't own one, so auto traits (Send/Sync) hold
                // unconditionally. Same marker convention as
                // modmath's Field personality parameter.
                _backend: core::marker::PhantomData<fn() -> T>,
            }

            impl<T: FieldFor + ScalarBytes> VerifyingKey<T> {
                /// Wrap SEC1 uncompressed bytes (`0x04 || X || Y`).
                /// No validation happens here — the point is checked
                /// on every verify, which returns `Err` for a key
                /// that is malformed or off-curve.
                pub const fn from_sec1_bytes(sec1: [u8; PUBKEY_BYTES]) -> Self {
                    Self {
                        sec1,
                        _backend: core::marker::PhantomData,
                    }
                }

                /// The wrapped SEC1 bytes.
                pub const fn as_sec1_bytes(&self) -> &[u8; PUBKEY_BYTES] {
                    &self.sec1
                }
            }

            /// `prehash` is the message digest (see
            /// [`verify_for_curve`] for the truncation rule);
            /// `signature` is IEEE P1363 `r || s`, fixed-width. Any
            /// other signature length is an error.
            impl<T: FieldFor + ScalarBytes, S: AsRef<[u8]>>
                signature::hazmat::PrehashVerifier<S> for VerifyingKey<T>
            {
                fn verify_prehash(
                    &self,
                    prehash: &[u8],
                    signature: &S,
                ) -> Result<(), signature::Error> {
                    let sig = signature.as_ref();
                    if sig.len() != 2 * $eb {
                        return Err(signature::Error::new());
                    }
                    let (r, s) = sig.split_at($eb);
                    if verify_for_curve::<$marker, T>(&self.sec1, prehash, r, s) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    }
                }
            }

            /// Heap / non-`Copy` analog of [`verify_prehashed`], verifying
            /// through the schoolbook field ([`verify_for_curve_ref`]).
            #[must_use]
            pub fn verify_prehashed_ref<T>(
                pubkey: &[u8; PUBKEY_BYTES],
                digest: &[u8; $db],
                r: &[u8; $eb],
                s: &[u8; $eb],
            ) -> bool
            where
                T: ScalarBytes,
                modmath::SchoolbookFieldRef<T>: FieldOps<Backend = T>,
            {
                verify_for_curve_ref::<$marker, T>(pubkey, digest, r, s)
            }

            /// SEC1-uncompressed verifying key for a **heap / non-`Copy`**
            /// carrier — the [`RefVerifyingKey`] analog of [`VerifyingKey`],
            /// verifying through [`verify_for_curve_ref`] (the variable-time
            /// schoolbook field). Same RustCrypto
            /// [`signature::hazmat::PrehashVerifier`] surface, for a
            /// verify-only single-carrier build.
            #[derive(Clone, PartialEq, Eq)]
            pub struct RefVerifyingKey<T>
            where
                T: ScalarBytes,
                modmath::SchoolbookFieldRef<T>: FieldOps<Backend = T>,
            {
                sec1: [u8; PUBKEY_BYTES],
                _backend: core::marker::PhantomData<fn() -> T>,
            }

            impl<T> RefVerifyingKey<T>
            where
                T: ScalarBytes,
                modmath::SchoolbookFieldRef<T>: FieldOps<Backend = T>,
            {
                /// Wrap SEC1 uncompressed bytes (`0x04 || X || Y`).
                pub const fn from_sec1_bytes(sec1: [u8; PUBKEY_BYTES]) -> Self {
                    Self {
                        sec1,
                        _backend: core::marker::PhantomData,
                    }
                }

                /// The wrapped SEC1 bytes.
                pub const fn as_sec1_bytes(&self) -> &[u8; PUBKEY_BYTES] {
                    &self.sec1
                }
            }

            impl<T, S: AsRef<[u8]>> signature::hazmat::PrehashVerifier<S>
                for RefVerifyingKey<T>
            where
                T: ScalarBytes,
                modmath::SchoolbookFieldRef<T>: FieldOps<Backend = T>,
            {
                fn verify_prehash(
                    &self,
                    prehash: &[u8],
                    signature: &S,
                ) -> Result<(), signature::Error> {
                    let sig = signature.as_ref();
                    if sig.len() != 2 * $eb {
                        return Err(signature::Error::new());
                    }
                    let (r, s) = sig.split_at($eb);
                    if verify_for_curve_ref::<$marker, T>(&self.sec1, prehash, r, s) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    }
                }
            }

            /// RustCrypto signer: `sign_prehash` returns the P1363
            /// `r || s` (fixed `2·ELEM_BYTES`), RFC 6979-deterministic.
            /// The whole deterministic sign — nonce derivation included —
            /// is constant-time up to RFC 6979's inherent rejection-loop
            /// count. Experimental — see [`dangerous`](crate::dangerous).
            #[cfg(feature = "experimental-signing")]
            impl<Tct, M> signature::hazmat::PrehashSigner<[u8; 2 * $eb]>
                for crate::dangerous::PrehashSigningKey<$marker, Tct, M>
            where
                Tct: crate::dangerous::ConstantTimeInt,
                M: digest::KeyInit + digest::Mac,
            {
                fn sign_prehash(
                    &self,
                    prehash: &[u8],
                ) -> Result<[u8; 2 * $eb], signature::Error> {
                    let mut sig = [0u8; 2 * $eb];
                    let (r, s) = sig.split_at_mut($eb);
                    if self.sign_prehashed(prehash, r, s) {
                        Ok(sig)
                    } else {
                        Err(signature::Error::new())
                    }
                }
            }

            /// RustCrypto randomized signer: draws fresh entropy from
            /// `rng`, hedges the RFC 6979 nonce with it (§3.6), and runs a
            /// verify-after-sign fault check before returning the P1363
            /// `r || s`. Requires `signature`'s `rand_core` feature, which
            /// `experimental-signing` enables. Experimental — see
            /// [`dangerous`](crate::dangerous).
            #[cfg(feature = "experimental-signing")]
            impl<Tct, Tv, M> signature::hazmat::RandomizedPrehashSigner<[u8; 2 * $eb]>
                for crate::dangerous::RandomizedSigningKey<$marker, Tct, Tv, M>
            where
                Tct: crate::dangerous::ConstantTimeInt,
                Tv: FieldFor + ScalarBytes,
                M: digest::KeyInit + digest::Mac,
            {
                fn sign_prehash_with_rng<R: signature::rand_core::TryCryptoRng + ?Sized>(
                    &self,
                    rng: &mut R,
                    prehash: &[u8],
                ) -> Result<[u8; 2 * $eb], signature::Error> {
                    // 256 bits of hedge entropy, wiped after use. A weak or
                    // all-zero draw degrades to RFC 6979 determinism, never
                    // to nonce reuse (key + digest still seed the DRBG), so
                    // a failing RNG can't be catastrophic — but it must not
                    // panic, hence the fallible fill mapped to an error.
                    let mut z = zeroize::Zeroizing::new([0u8; 32]);
                    signature::rand_core::TryRng::try_fill_bytes(rng, &mut z[..])
                        .map_err(|_| signature::Error::new())?;
                    let mut sig = [0u8; 2 * $eb];
                    let (r, s) = sig.split_at_mut($eb);
                    if self.sign_prehashed_hedged(&z[..], prehash, r, s) {
                        Ok(sig)
                    } else {
                        Err(signature::Error::new())
                    }
                }
            }
        }
    };
}

define_curve! {
    /// NIST P-256 / secp256r1 (TLS `ecdsa_secp256r1_sha256`, X.509
    /// `ecdsa-with-SHA256`).
    pub mod p256 {
        /// Curve marker for [`verify_for_curve`].
        marker: P256,
        elem_bytes: 32,
        digest_bytes: 32,
        p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        /// Verify an ECDSA-P256 signature over a SHA-256 digest. See
        /// [`verify_for_curve`] for the input contract.
        ///
        /// The digest size is fixed to the TLS 1.3 pairing (SHA-256).
        /// X.509 allows other hash/curve pairings; for those, call
        /// [`verify_for_curve`] directly — it implements the general
        /// digest-truncation rule for any digest length.
        fn verify_prehashed;
    }
}

define_curve! {
    /// secp256k1 (Bitcoin/Ethereum's curve; `a = 0`).
    pub mod k256 {
        /// Curve marker for [`verify_for_curve`].
        marker: K256,
        elem_bytes: 32,
        digest_bytes: 32,
        p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        a: "0000000000000000000000000000000000000000000000000000000000000000",
        b: "0000000000000000000000000000000000000000000000000000000000000007",
        n: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        gx: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        gy: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        /// Verify an ECDSA-secp256k1 signature over a SHA-256 digest.
        /// See [`verify_for_curve`] for the input contract. High-`s`
        /// signatures are accepted — low-`s` enforcement (Bitcoin
        /// consensus rules) is the caller's policy, not this crate's.
        ///
        /// For other digest lengths, call [`verify_for_curve`]
        /// directly — it implements the general digest-truncation
        /// rule for any digest length.
        fn verify_prehashed;
    }
}

define_curve! {
    /// NIST P-384 / secp384r1 (TLS `ecdsa_secp384r1_sha384`, X.509
    /// `ecdsa-with-SHA384`).
    pub mod p384 {
        /// Curve marker for [`verify_for_curve`].
        marker: P384,
        elem_bytes: 48,
        digest_bytes: 48,
        p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
        b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        /// Verify an ECDSA-P384 signature over a SHA-384 digest. See
        /// [`verify_for_curve`] for the input contract.
        ///
        /// The digest size is fixed to the TLS 1.3 pairing (SHA-384).
        /// X.509 allows other hash/curve pairings (e.g. a P-384 key
        /// with `ecdsa-with-SHA256`); for those, call
        /// [`verify_for_curve`] directly — it implements the general
        /// digest-truncation rule for any digest length.
        fn verify_prehashed;
    }
}

/// Jacobian projective point over the field `F`. The identity is
/// encoded as `Z == 0` (X, Y then carry no information).
// Manual `Clone` (not derived): the derive would demand `F: Clone` on
// the field type, but only the residues are cloned and they carry the
// `Clone` bound via the `Residue` GAT.
struct Point<'f, F: FieldOps + 'f> {
    x: F::Residue<'f>,
    y: F::Residue<'f>,
    z: F::Residue<'f>,
}

impl<'f, F: FieldOps + 'f> Clone for Point<'f, F> {
    fn clone(&self) -> Self {
        Point {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
        }
    }
}

fn infinity<F: FieldOps>(f: &F) -> Point<'_, F> {
    Point {
        x: f.one(),
        y: f.one(),
        z: f.zero(),
    }
}

fn is_infinity<'f, F: FieldOps>(f: &'f F, pt: &Point<'f, F>) -> bool {
    pt.z == f.zero()
}

/// Strict `a < b` that fails closed: an incomparable pair (a broken
/// `PartialOrd` on a third-party backend) reads as "not less", so
/// every range check that gates on this rejects rather than accepts.
fn lt<T: ScalarBytes>(a: &T, b: &T) -> bool {
    matches!(a.partial_cmp(b), Some(core::cmp::Ordering::Less))
}

/// `y² == x³ + ax + b`, for an affine point (`z` assumed 1).
fn is_on_curve<'f, F: FieldOps>(
    f: &'f F,
    pt: &Point<'f, F>,
    a: &F::Residue<'f>,
    b: &F::Residue<'f>,
) -> bool {
    let y2 = f.mul(&pt.y, &pt.y);
    let x2 = f.mul(&pt.x, &pt.x);
    let x3 = f.mul(&x2, &pt.x);
    let ax = f.mul(a, &pt.x);
    let rhs = f.add(&f.add(&x3, &ax), b);
    y2 == rhs
}

/// Point doubling, Jacobian, general `a` (EFD dbl-2007-bl) — one
/// formula serves both `a = −3` (P-256/P-384) and `a = 0` (secp256k1)
/// at the cost of the `a·ZZ²` multiply a specialized version would
/// fold away. A `y == 0` input (its double is the identity) falls out
/// as `z3 = 2yz = 0`.
fn double<'f, F: FieldOps>(f: &'f F, a: &F::Residue<'f>, pt: &Point<'f, F>) -> Point<'f, F> {
    if is_infinity(f, pt) {
        return infinity(f);
    }
    let xx = f.mul(&pt.x, &pt.x);
    let yy = f.mul(&pt.y, &pt.y);
    let yyyy = f.mul(&yy, &yy);
    let zz = f.mul(&pt.z, &pt.z);

    // S = 2·((X+YY)² − XX − YYYY)
    let x_plus_yy = f.add(&pt.x, &yy);
    let t = f.sub(&f.sub(&f.mul(&x_plus_yy, &x_plus_yy), &xx), &yyyy);
    let s = f.add(&t, &t);

    // M = 3·XX + a·ZZ²
    let xx3 = f.add(&f.add(&xx, &xx), &xx);
    let m = f.add(&xx3, &f.mul(a, &f.mul(&zz, &zz)));

    // X3 = M² − 2S
    let x3 = f.sub(&f.sub(&f.mul(&m, &m), &s), &s);

    // Y3 = M·(S − X3) − 8·YYYY
    let yyyy8 = {
        let y2_ = f.add(&yyyy, &yyyy);
        let y4 = f.add(&y2_, &y2_);
        f.add(&y4, &y4)
    };
    let y3 = f.sub(&f.mul(&m, &f.sub(&s, &x3)), &yyyy8);

    // Z3 = (Y+Z)² − YY − ZZ
    let yz = f.add(&pt.y, &pt.z);
    let z3 = f.sub(&f.sub(&f.mul(&yz, &yz), &yy), &zz);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// General Jacobian addition (EFD add-2007-bl), with the short-
/// Weierstrass exceptional cases handled explicitly: identity
/// operands, `P + P` (dispatches to [`double`]), and `P + (−P) = O`.
fn add<'f, F: FieldOps>(
    f: &'f F,
    curve_a: &F::Residue<'f>,
    a: &Point<'f, F>,
    b: &Point<'f, F>,
) -> Point<'f, F> {
    if is_infinity(f, a) {
        return b.clone();
    }
    if is_infinity(f, b) {
        return a.clone();
    }
    let z1z1 = f.mul(&a.z, &a.z);
    let z2z2 = f.mul(&b.z, &b.z);
    let u1 = f.mul(&a.x, &z2z2);
    let u2 = f.mul(&b.x, &z1z1);
    let s1 = f.mul(&f.mul(&a.y, &b.z), &z2z2);
    let s2 = f.mul(&f.mul(&b.y, &a.z), &z1z1);
    let h = f.sub(&u2, &u1);
    let sd = f.sub(&s2, &s1);
    if h == f.zero() {
        return if sd == f.zero() {
            double(f, curve_a, a)
        } else {
            infinity(f)
        };
    }
    let h2 = f.add(&h, &h);
    let i = f.mul(&h2, &h2);
    let j = f.mul(&h, &i);
    let rr = f.add(&sd, &sd);
    let v = f.mul(&u1, &i);

    let x3 = f.sub(&f.sub(&f.mul(&rr, &rr), &j), &f.add(&v, &v));
    let s1j = f.mul(&s1, &j);
    let y3 = f.sub(&f.mul(&rr, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
    let z12 = f.add(&a.z, &b.z);
    let z3 = f.mul(&f.sub(&f.sub(&f.mul(&z12, &z12), &z1z1), &z2z2), &h);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn bit<T: ScalarBytes>(v: &T, i: usize) -> bool {
    // `v.clone() >> i` rather than `*v >> i`: the shift is by-value but
    // must not move out of the `&T` borrow (a heap carrier isn't `Copy`).
    (v.clone() >> i) & T::one() != T::zero()
}

/// `u1·G + u2·Q` via Shamir's trick: one shared double-and-add pass
/// with a precomputed `G + Q`. Variable-time — both scalars are
/// public on the verify path. Both scalars are `< n < 2^bits`, so
/// `bits` iterations cover them regardless of the backend's width.
fn double_scalar_mul<'f, F: FieldOps>(
    f: &'f F,
    curve_a: &F::Residue<'f>,
    bits: usize,
    u1: &F::Backend,
    g: &Point<'f, F>,
    u2: &F::Backend,
    q: &Point<'f, F>,
) -> Point<'f, F>
where
    F::Backend: ScalarBytes,
{
    let gq = add(f, curve_a, g, q);
    let mut acc = infinity(f);
    for i in (0..bits).rev() {
        acc = double(f, curve_a, &acc);
        match (bit(u1, i), bit(u2, i)) {
            (true, true) => acc = add(f, curve_a, &acc, &gq),
            (true, false) => acc = add(f, curve_a, &acc, g),
            (false, true) => acc = add(f, curve_a, &acc, q),
            (false, false) => {}
        }
    }
    acc
}

/// Affine x-coordinate `X/Z²`, or `None` for the identity.
fn to_affine_x<'f, F: FieldOps>(f: &'f F, pt: &Point<'f, F>) -> Option<F::Backend> {
    let zinv = f.inv(&pt.z)?;
    let zinv2 = f.mul(&zinv, &zinv);
    Some(f.into_raw(&f.mul(&pt.x, &zinv2)))
}

/// Number of significant bits in a big-endian byte string.
fn bitlen_be(bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    if i == bytes.len() {
        return 0;
    }
    (bytes.len() - i) * 8 - bytes[i].leading_zeros() as usize
}

/// The ECDSA hash-to-scalar rule (FIPS 186-4 §6.4 / SEC1 §4.1.4):
/// `e` is the integer formed by the **leftmost `min(bitlen(digest),
/// n_bits)` bits** of the digest. A digest no longer than `n` is used
/// whole (zero-extending on the left); a longer one is truncated to
/// its leading `n_bits` bits — whole bytes first, then a right shift
/// for the sub-byte remainder when `n_bits` is not a multiple of 8
/// (all shipped curves are byte-aligned, so their shift is 0, but the
/// rule is encoded in full for downstream `Curve` impls).
fn hash_to_scalar<T: ScalarBytes>(digest: &[u8], n_bits: usize) -> T {
    // len <= n_bits/8 is the overflow-free spelling of len*8 <= n_bits
    // (equivalent for integers): a pathological digest length must not
    // wrap the multiplication on 32-bit targets.
    if digest.len() <= n_bits / 8 {
        return from_be::<T>(digest);
    }
    let nb = n_bits.div_ceil(8);
    let mut e = from_be::<T>(&digest[..nb]);
    let excess = nb * 8 - n_bits;
    if excess > 0 {
        e >>= excess;
    }
    e
}

/// Verify an ECDSA signature over curve `C` with backend `T`.
///
/// `pubkey` is SEC1 uncompressed (`0x04 || X || Y`); `r` and `s` are
/// the unpacked big-endian signature halves, `C::ELEM_BYTES` each
/// (DER decoding is the caller's job). `digest` is the message hash
/// — pass the hash, never the raw message. An empty digest is
/// rejected; any non-empty length is accepted, mapped to a scalar by
/// the standard ECDSA rule
/// (FIPS 186-4 §6.4 / SEC1 §4.1.4): the leftmost
/// `min(bitlen(digest), bitlen(n))` bits, so a digest longer than
/// `n` is truncated and a shorter one zero-extends on the left.
/// Returns `false` on any malformed
/// input — wrong lengths or point prefix, coordinates ≥ p, off-curve
/// point, `r`/`s` outside `[1, n−1]` — and never panics.
///
/// A backend narrower than `C::ELEM_BYTES` or a `Curve` impl whose
/// constants are not `ELEM_BYTES` long is rejected at compile time
/// (post-monomorphization error).
///
/// High-`s` signatures are accepted: `(r, n−s)` verifying alongside
/// `(r, s)` is inherent ECDSA malleability and TLS does not require
/// low-`s`.
#[must_use]
pub fn verify_for_curve<C: Curve, T: FieldFor + ScalarBytes>(
    pubkey: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> bool {
    const {
        assert!(
            core::mem::size_of::<T>() >= C::ELEM_BYTES,
            "backend type narrower than the curve's field element"
        );
    }
    // Both moduli are odd curve constants; `None` is unreachable but
    // maps to a clean reject rather than a panic path.
    let (Some(fp), Some(fn_)) = (T::field(from_be::<T>(C::P)), T::field(from_be::<T>(C::N))) else {
        return false;
    };
    verify_inner::<C, T::Field>(&fp, &fn_, pubkey, digest, r, s)
}

/// Like [`verify_for_curve`], for a **heap / `Clone` (non-`Copy`)**
/// carrier — a verify-only path over modmath's variable-time schoolbook
/// field ([`modmath::SchoolbookFieldRef`]) instead of the `Copy`-gated
/// Montgomery field. Verify is public data, so the variable-time field
/// is a correctness-equivalent footprint/allocation trade. The carrier
/// physically cannot reach any constant-time (sign) path — it isn't
/// `Copy`, so it can never be a [`dangerous::ConstantTimeInt`].
#[must_use]
pub fn verify_for_curve_ref<C: Curve, T>(pubkey: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool
where
    T: ScalarBytes,
    modmath::SchoolbookFieldRef<T>: FieldOps<Backend = T>,
{
    let (Some(fp), Some(fn_)) = (
        modmath::SchoolbookFieldRef::new(from_be::<T>(C::P)),
        modmath::SchoolbookFieldRef::new(from_be::<T>(C::N)),
    ) else {
        return false;
    };
    verify_inner::<C, modmath::SchoolbookFieldRef<T>>(&fp, &fn_, pubkey, digest, r, s)
}

/// Shared verify core over a caller-built field pair (`fp` mod p, `fn_`
/// mod n), generic over any [`FieldOps`]. The two public entries differ
/// only in how they build the field: [`verify_for_curve`] via the
/// `Copy` Montgomery [`FieldFor`] selector, [`verify_for_curve_ref`] via
/// the `Clone` schoolbook field.
fn verify_inner<C: Curve, F: FieldOps>(
    fp: &F,
    fn_: &F,
    pubkey: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> bool
where
    F::Backend: ScalarBytes,
{
    const {
        assert!(
            C::P.len() == C::ELEM_BYTES
                && C::A.len() == C::ELEM_BYTES
                && C::B.len() == C::ELEM_BYTES
                && C::N.len() == C::ELEM_BYTES
                && C::GX.len() == C::ELEM_BYTES
                && C::GY.len() == C::ELEM_BYTES,
            "Curve constants must all be exactly ELEM_BYTES long"
        );
    }
    let eb = C::ELEM_BYTES;
    if pubkey.len() != 1 + 2 * eb || pubkey[0] != 0x04 || r.len() != eb || s.len() != eb {
        return false;
    }
    // An empty digest is always API misuse (the argument is a hash);
    // reject it outright rather than letting it map to e = 0.
    if digest.is_empty() {
        return false;
    }
    let p = fp.modulus();
    let n = fn_.modulus();
    let zero = <F::Backend as const_num_traits::Zero>::zero();

    let qx = from_be::<F::Backend>(&pubkey[1..1 + eb]);
    let qy = from_be::<F::Backend>(&pubkey[1 + eb..1 + 2 * eb]);
    if !(lt(&qx, p) && lt(&qy, p)) {
        return false;
    }

    let r_int = from_be::<F::Backend>(r);
    let s_int = from_be::<F::Backend>(s);
    if r_int == zero || !lt(&r_int, n) || s_int == zero || !lt(&s_int, n) {
        return false;
    }

    let a_res = fp.reduce(&from_be::<F::Backend>(C::A));
    let b_res = fp.reduce(&from_be::<F::Backend>(C::B));
    let q = Point {
        x: fp.reduce(&qx),
        y: fp.reduce(&qy),
        z: fp.one(),
    };
    // SEC1-uncompressed can't encode the identity, so on-curve is the
    // whole point-validation story (cofactor 1: no subgroup check).
    if !is_on_curve(fp, &q, &a_res, &b_res) {
        return false;
    }

    let e = fn_.reduce(&hash_to_scalar(digest, bitlen_be(C::N)));
    let s_res = fn_.reduce(&s_int);
    let Some(s_inv) = fn_.inv(&s_res) else {
        return false;
    };
    let r_res = fn_.reduce(&r_int);
    let u1 = fn_.into_raw(&fn_.mul(&e, &s_inv));
    let u2 = fn_.into_raw(&fn_.mul(&r_res, &s_inv));

    let g = Point {
        x: fp.reduce(&from_be::<F::Backend>(C::GX)),
        y: fp.reduce(&from_be::<F::Backend>(C::GY)),
        z: fp.one(),
    };
    let rp = double_scalar_mul(fp, &a_res, eb * 8, &u1, &g, &u2, &q);

    // R == identity → reject; otherwise r ≟ R.x mod n (reduce()
    // lands both sides in canonical mod-n form).
    let Some(x_affine) = to_affine_x(fp, &rp) else {
        return false;
    };
    fn_.reduce(&x_affine) == r_res
}

/// **Experimental ECDSA signing — NOT production-safe. Do not use on
/// real keys.**
///
/// Off by default behind the `experimental-signing` cargo feature and
/// gated behind this deliberately-named module. Two families live here:
///
/// - **Variable-time POC** — [`dangerous::sign_prehashed`] (RFC 6979
///   deterministic) and [`dangerous::sign_prehashed_with_k`] (caller
///   `k`). These run on the non-constant-time (`Nct`) modmath surface
///   and leak the secret scalar and nonce through timing; correctness
///   demonstrators only.
/// - **Constant-time** — [`dangerous::sign_prehashed_ct`],
///   [`dangerous::SigningKey`], [`dangerous::PrehashSigningKey`], and the
///   hedged [`dangerous::RandomizedSigningKey`]. The secret operations
///   run on the `Ct` surface (RCB complete formulas, branch-free ladder,
///   Fermat inverse), constant-time up to RFC 6979's inherent
///   rejection-loop count.
///
/// The constant-time guarantee is **timing only**. It does NOT cover:
///
/// - **Power / EM side channels (DPA/CPA).** There is no scalar blinding
///   or projective-coordinate randomization, so a physical attacker with
///   trace access is not defended. [`dangerous::RandomizedSigningKey`]
///   hedges the nonce (fresh entropy per signature, RFC 6979 §3.6) and
///   runs a verify-after-sign fault check — defeating same-message trace
///   averaging and the deterministic-ECDSA fault break — but that is
///   defense-in-depth, not DPA resistance.
/// - **Comprehensive fault attacks.** Only the randomized path
///   re-verifies its own output.
///
/// And, gating everything:
///
/// - **Unaudited.** Correctness is pinned to RFC 6979 fixed vectors and
///   the timing property to the ct-verify harness; neither is a physical
///   side-channel evaluation.
///
/// Until an audit says otherwise, this stays behind the feature gate.
#[cfg(feature = "experimental-signing")]
pub mod dangerous {
    use super::*;
    use zeroize::{Zeroize, Zeroizing};

    /// Fixed-iteration double-and-add `scalar · base`. Variable-time
    /// (POC only — see the module warning).
    fn scalar_mul<'f, F: FieldOps>(
        f: &'f F,
        curve_a: &F::Residue<'f>,
        bits: usize,
        scalar: &F::Backend,
        base: &Point<'f, F>,
    ) -> Point<'f, F>
    where
        F::Backend: ScalarBytes,
    {
        let mut acc = infinity(f);
        for i in (0..bits).rev() {
            acc = double(f, curve_a, &acc);
            if bit(scalar, i) {
                acc = add(f, curve_a, &acc, base);
            }
        }
        acc
    }

    /// Serialize `v` to `out.len()` big-endian bytes (no `ToBytes`
    /// bound needed on the backend). Consumes a running copy one bit
    /// at a time — single-bit shifts rather than one wide shift per
    /// bit, so it stays linear in the backend's width.
    // `#[inline(never)]`: the per-bit `if` below is variable-time, so this
    // must never be reachable from a secret on the constant-time path.
    // Keeping it a distinct symbol means the taint gate reports any such
    // misuse at *this* frame (unsuppressed) instead of letting it hide
    // inside a suppressed sign frame — use `to_be_ct` for secret scalars.
    #[inline(never)]
    fn to_be<T: ScalarBytes>(v: &T, out: &mut [u8]) {
        let mut acc = v.clone();
        for slot in out.iter_mut().rev() {
            let mut b = 0u8;
            for j in 0..8 {
                // `acc.clone() & one` — by-value `&` consumes its lhs, but
                // `acc` is reused by the `>>=` below, so don't move it.
                if acc.clone() & T::one() != T::zero() {
                    b |= 1 << j;
                }
                acc >>= 1;
            }
            *slot = b;
        }
    }

    /// Branch-free big-endian serialization for a **secret** scalar on the
    /// Ct backend. [`to_be`]'s per-bit `if` leaks the value's bits in
    /// variable time; here the bit selects via `subtle`'s branch-free
    /// `conditional_select` instead. Used for the secret nonce and the
    /// signature scalars so the constant-time sign never serializes a
    /// secret through a data-dependent branch.
    #[inline(never)]
    fn to_be_ct<T: ConstantTimeInt>(v: &T, out: &mut [u8]) {
        use subtle::ConditionallySelectable;
        let mut acc = *v;
        for slot in out.iter_mut().rev() {
            let mut b = 0u8;
            for j in 0..8 {
                let set = !(acc & T::one()).ct_is_zero();
                b |= u8::conditional_select(&0u8, &(1u8 << j), set);
                acc >>= 1;
            }
            *slot = b;
        }
    }

    /// Sign `digest` under `private_key` with an **externally supplied
    /// nonce** `k`, writing the signature halves to `out_r` / `out_s`.
    ///
    /// All scalars are big-endian, `C::ELEM_BYTES` long. Returns
    /// `false` (writing nothing meaningful) on any malformed input,
    /// on `d`/`k` outside `[1, n−1]`, or on the degenerate `r == 0` /
    /// `s == 0` outcomes (RFC 6979 says resample `k` — here the caller
    /// must supply a different `k`). Produces the possibly-high-`s`
    /// signature; low-`s` normalization is the caller's policy.
    ///
    /// **`k` MUST be unique and unpredictable per signature.** See the
    /// [module warning](self); this is not a safe API.
    #[must_use]
    pub fn sign_prehashed_with_k<C: Curve, T: UnsignedModularInt + FieldFor>(
        private_key: &[u8],
        digest: &[u8],
        k: &[u8],
        out_r: &mut [u8],
        out_s: &mut [u8],
    ) -> bool {
        const {
            assert!(
                core::mem::size_of::<T>() >= C::ELEM_BYTES,
                "backend type narrower than the curve's field element"
            );
            assert!(
                C::P.len() == C::ELEM_BYTES
                    && C::A.len() == C::ELEM_BYTES
                    && C::B.len() == C::ELEM_BYTES
                    && C::N.len() == C::ELEM_BYTES
                    && C::GX.len() == C::ELEM_BYTES
                    && C::GY.len() == C::ELEM_BYTES,
                "Curve constants must all be exactly ELEM_BYTES long"
            );
        }
        let eb = C::ELEM_BYTES;
        if private_key.len() != eb
            || k.len() != eb
            || out_r.len() != eb
            || out_s.len() != eb
            || digest.is_empty()
        {
            return false;
        }
        let p = from_be::<T>(C::P);
        let n = from_be::<T>(C::N);
        let zero = T::zero();

        let d = from_be::<T>(private_key);
        let k_int = from_be::<T>(k);
        if d == zero || !lt(&d, &n) || k_int == zero || !lt(&k_int, &n) {
            return false;
        }

        let (Some(fp), Some(fn_)) = (T::field(p), T::field(n)) else {
            return false;
        };
        let a_res = fp.reduce(&from_be::<T>(C::A));
        let g = Point {
            x: fp.reduce(&from_be::<T>(C::GX)),
            y: fp.reduce(&from_be::<T>(C::GY)),
            z: fp.one(),
        };

        // r = x(k·G) mod n.
        let kg = scalar_mul(&fp, &a_res, eb * 8, &k_int, &g);
        let Some(rx) = to_affine_x(&fp, &kg) else {
            return false;
        };
        let r = fn_.into_raw(&fn_.reduce(&rx));
        if r == zero {
            return false;
        }

        // s = k⁻¹ · (e + r·d) mod n.
        let e = fn_.reduce(&hash_to_scalar(digest, bitlen_be(C::N)));
        let Some(k_inv) = fn_.inv(&fn_.reduce(&k_int)) else {
            return false;
        };
        let rd = fn_.mul(&fn_.reduce(&r), &fn_.reduce(&d));
        let s_res = fn_.mul(&k_inv, &fn_.add(&e, &rd));
        let s = fn_.into_raw(&s_res);
        if s == zero {
            return false;
        }

        to_be::<T>(&r, out_r);
        to_be::<T>(&s, out_s);
        true
    }

    // RFC 6979 §3.2 HMAC-DRBG. `MAX_HLEN` covers SHA-512 output;
    // `MAX_QLEN_BYTES` covers the widest curve order this crate would
    // carry (P-521 = 66 bytes). Fixed stack buffers keep it no-alloc;
    // the generic HMAC output length is read at runtime and bounded
    // against MAX_HLEN.
    const MAX_HLEN: usize = 64;
    const MAX_QLEN_BYTES: usize = 66;

    /// Copy `src` into the front of `dst`, panic-free; `None` if `dst` is
    /// too short. A byte loop, not `copy_from_slice`: the latter's
    /// `self.len() == src.len()` assert isn't reliably elided when `dst`
    /// is sliced on a runtime `hlen`, leaving a reachable `len_mismatch`
    /// panic in the DRBG. `zip` needs no such proof.
    fn copy_prefix(dst: &mut [u8], src: &[u8]) -> Option<()> {
        let d = dst.get_mut(..src.len())?;
        for (di, si) in d.iter_mut().zip(src.iter()) {
            *di = *si;
        }
        Some(())
    }

    /// `HMAC_key(parts…)` into `out`, returning the tag length. `key`
    /// and `out` must not alias (the K-update steps copy K aside).
    fn hmac_into<M: digest::KeyInit + digest::Mac>(
        key: &[u8],
        parts: &[&[u8]],
        out: &mut [u8],
    ) -> Option<usize> {
        let mut mac = <M as digest::KeyInit>::new_from_slice(key).ok()?;
        for p in parts {
            mac.update(p);
        }
        let tag = mac.finalize().into_bytes();
        copy_prefix(out, &tag)?;
        Some(tag.len())
    }

    /// RFC 6979 §3.2 deterministic nonce: the HMAC-DRBG seeded by the
    /// private key octets and `bits2octets(H(m))`, yielding the first
    /// candidate in `[1, n−1]`. `M` is the HMAC (e.g. `Hmac<Sha256>`);
    /// its hash MUST match the one that produced `digest`.
    ///
    /// Constant-time-ness follows the caller's `in_range` predicate; the
    /// only secret-dependent branch is the rejection-loop count, RFC
    /// 6979's inherent signal (experimental — see the [module warning](self)).
    // Distinct symbol so the ct-verify taint gate can scope the
    // rejection-loop-count declassification to this frame — see `add_rcb`.
    #[inline(never)]
    fn rfc6979_nonce<C: Curve, T: ScalarBytes, M: digest::KeyInit + digest::Mac>(
        x_octets: &[u8],
        h1_octets: &[u8],
        // RFC 6979 §3.6 additional data, appended to the two DRBG seeding
        // HMACs. Empty for the pure-deterministic derivation (yields the
        // RFC's `k` byte-for-byte); the hedged signer passes fresh entropy
        // here so repeated signatures over one message differ. Public, not
        // secret — the DRBG stays data-oblivious either way.
        added: &[u8],
        n: &T,
        qlen: usize,
        // Candidate acceptance test `1 <= cand < n`, supplied by the
        // caller so one HMAC-DRBG loop serves both derivations without
        // drift — the Nct caller passes a `<`-based test, the Ct caller a
        // `ct_lt`/`ct_is_zero` one it keeps constant-time.
        in_range: impl Fn(&T, &T) -> bool,
    ) -> Option<T> {
        let hlen = <M as digest::OutputSizeUser>::output_size();
        if hlen > MAX_HLEN {
            return None;
        }
        let eb = C::ELEM_BYTES;
        // Secret DRBG state — wiped on every return (incl. `?`) via
        // Zeroizing's Drop.
        let mut v = Zeroizing::new([0x01u8; MAX_HLEN]);
        let mut k = Zeroizing::new([0x00u8; MAX_HLEN]);
        // Scratch so no HMAC output aliases its own input: the K-update
        // key is copied here, and V-updates land here before copy-back
        // (input and output V would otherwise be the same buffer).
        let mut scratch = Zeroizing::new([0u8; MAX_HLEN]);

        // V = HMAC_K(V) via scratch. Fallible slicing keeps the whole
        // DRBG panic-free (see `copy_prefix`).
        let update_v = |k: &[u8], v: &mut [u8], scratch: &mut [u8]| -> Option<()> {
            hmac_into::<M>(k, &[v.get(..hlen)?], scratch)?;
            copy_prefix(v, scratch.get(..hlen)?)
        };

        // K = HMAC_K(V || 0x00 || x || h1 || added); V = HMAC_K(V)
        copy_prefix(&mut scratch[..], k.get(..hlen)?)?;
        hmac_into::<M>(
            scratch.get(..hlen)?,
            &[v.get(..hlen)?, &[0x00], x_octets, h1_octets, added],
            &mut k[..],
        )?;
        update_v(k.get(..hlen)?, &mut v[..], &mut scratch[..])?;
        // K = HMAC_K(V || 0x01 || x || h1 || added); V = HMAC_K(V)
        copy_prefix(&mut scratch[..], k.get(..hlen)?)?;
        hmac_into::<M>(
            scratch.get(..hlen)?,
            &[v.get(..hlen)?, &[0x01], x_octets, h1_octets, added],
            &mut k[..],
        )?;
        update_v(k.get(..hlen)?, &mut v[..], &mut scratch[..])?;

        loop {
            // T = leftmost qlen bits, accumulated hlen bytes at a time.
            let mut t = Zeroizing::new([0u8; MAX_QLEN_BYTES]);
            let mut tlen = 0usize;
            while tlen < eb {
                update_v(k.get(..hlen)?, &mut v[..], &mut scratch[..])?;
                let take = core::cmp::min(hlen, eb - tlen);
                copy_prefix(t.get_mut(tlen..)?, v.get(..take)?)?;
                tlen += take;
            }
            let cand = hash_to_scalar::<T>(t.get(..eb)?, qlen);
            if in_range(&cand, n) {
                return Some(cand);
            }
            // Candidate out of range (astronomically rare): reseed.
            copy_prefix(&mut scratch[..], k.get(..hlen)?)?;
            hmac_into::<M>(scratch.get(..hlen)?, &[v.get(..hlen)?, &[0x00]], &mut k[..])?;
            update_v(k.get(..hlen)?, &mut v[..], &mut scratch[..])?;
        }
    }

    /// The RFC 6979 nonce for `(private_key, digest)`, written
    /// big-endian to `out_k`. Exposed so the deterministic derivation
    /// can be checked directly against the RFC vectors. Returns
    /// `false` on malformed input or an out-of-range key.
    ///
    /// Same experimental caveats as the rest of this module.
    #[must_use]
    pub fn derive_nonce_rfc6979<
        C: Curve,
        T: UnsignedModularInt + FieldFor,
        M: digest::KeyInit + digest::Mac,
    >(
        private_key: &[u8],
        digest: &[u8],
        out_k: &mut [u8],
    ) -> bool {
        const {
            assert!(
                C::ELEM_BYTES <= MAX_QLEN_BYTES,
                "Curve's ELEM_BYTES exceeds MAX_QLEN_BYTES"
            );
        }
        let eb = C::ELEM_BYTES;
        if private_key.len() != eb || out_k.len() != eb || digest.is_empty() {
            return false;
        }
        let n = from_be::<T>(C::N);
        let d = from_be::<T>(private_key);
        if d == T::zero() || !lt(&d, &n) {
            return false;
        }
        let Some(fn_) = T::field(n) else {
            return false;
        };
        let qlen = bitlen_be(C::N);

        // h1 = bits2octets(digest) = int2octets(bits2int(digest) mod n).
        let mut h1 = Zeroizing::new([0u8; MAX_QLEN_BYTES]);
        let e = fn_.into_raw(&fn_.reduce(&hash_to_scalar::<T>(digest, qlen)));
        to_be::<T>(&e, &mut h1[..eb]);

        let Some(mut k) =
            rfc6979_nonce::<C, T, M>(private_key, &h1[..eb], &[], &n, qlen, |cand, n| {
                *cand != T::zero() && lt(cand, n)
            })
        else {
            return false;
        };
        to_be::<T>(&k, out_k);
        k.zeroize();
        true
    }

    /// **Constant-time** RFC 6979 nonce derivation — the `Ct`-backend
    /// analogue of [`derive_nonce_rfc6979`], written big-endian to
    /// `out_k`. Reproduces the same deterministic `k` byte-for-byte
    /// (validated against the RFC vectors), but the secret-dependent
    /// candidate range check runs on `subtle`'s constant-time
    /// comparisons instead of the vartime `<`. The HMAC-DRBG is
    /// data-oblivious to begin with (SHA-2/HMAC branch on neither key
    /// nor message), so this closes the derivation's timing gap up to
    /// the RFC's inherent rejection-loop count (reject probability
    /// ~2⁻³², i.e. effectively always one iteration).
    ///
    /// Same experimental caveats as the rest of this module.
    #[must_use]
    pub fn derive_nonce_rfc6979_ct<
        C: Curve,
        Tct: ConstantTimeInt,
        M: digest::KeyInit + digest::Mac,
    >(
        private_key: &[u8],
        digest: &[u8],
        out_k: &mut [u8],
    ) -> bool {
        derive_nonce_rfc6979_ct_added::<C, Tct, M>(private_key, digest, &[], out_k)
    }

    /// Hedged variant of [`derive_nonce_rfc6979_ct`]: `added` is RFC 6979
    /// §3.6 additional data (fresh entropy) mixed into the DRBG seed, so
    /// the derived `k` varies per call while the derivation stays
    /// constant-time. With `added` empty this reproduces
    /// [`derive_nonce_rfc6979_ct`] byte-for-byte.
    fn derive_nonce_rfc6979_ct_added<
        C: Curve,
        Tct: ConstantTimeInt,
        M: digest::KeyInit + digest::Mac,
    >(
        private_key: &[u8],
        digest: &[u8],
        added: &[u8],
        out_k: &mut [u8],
    ) -> bool {
        const {
            assert!(
                C::ELEM_BYTES <= MAX_QLEN_BYTES,
                "Curve's ELEM_BYTES exceeds MAX_QLEN_BYTES"
            );
        }
        let eb = C::ELEM_BYTES;
        if private_key.len() != eb || out_k.len() != eb || digest.is_empty() {
            return false;
        }
        let n = from_be::<Tct>(C::N);
        let d = from_be::<Tct>(private_key);
        // d is secret — its validity folds into the returned `Choice`
        // rather than an early branch, so this frame stays branch-free
        // (nothing suppressed). The derivation below runs regardless; on
        // an invalid `d` the caller sees `false` and ignores `out_k`.
        let d_valid = !d.ct_is_zero() & d.ct_lt(&n);
        // `n` is `Copy` (ConstantTimeInt: Copy), so building the field
        // leaves the local `n` live for the range predicate below.
        let Some(fn_) = FieldCt::new(n) else {
            return false;
        };
        let qlen = bitlen_be(C::N);

        // h1 = bits2octets(digest) = int2octets(bits2int(digest) mod n).
        // The digest is public, so this reduction carries no secret; it
        // runs on the Ct field only for uniformity with the sign path.
        let mut h1 = Zeroizing::new([0u8; MAX_QLEN_BYTES]);
        let e = fn_.into_raw(&fn_.reduce(&hash_to_scalar::<Tct>(digest, qlen)));
        let Some(h1_slot) = h1.get_mut(..eb) else {
            return false;
        };
        to_be_ct::<Tct>(&e, h1_slot);
        let Some(h1_octets) = h1.get(..eb) else {
            return false;
        };

        let Some(mut k) =
            rfc6979_nonce::<C, Tct, M>(private_key, h1_octets, added, &n, qlen, |cand, n| {
                bool::from(!cand.ct_is_zero() & cand.ct_lt(n))
            })
        else {
            return false;
        };
        to_be_ct::<Tct>(&k, out_k);
        k.zeroize();
        bool::from(d_valid)
    }

    /// Sign `digest` under `private_key` with an **RFC 6979
    /// deterministic** nonce — no caller-supplied `k`, so the nonce
    /// cannot be reused or biased by the caller. `M` is the HMAC whose
    /// hash matches the digest's (e.g. `Hmac<Sha256>` for a SHA-256
    /// digest).
    ///
    /// Still experimental and **not constant-time** — see the
    /// [module warning](self). Same slice contract, range checks, and
    /// `false`-on-degenerate behavior as [`sign_prehashed_with_k`];
    /// the vanishingly rare `r == 0` / `s == 0` resample is not
    /// implemented (it would thread the DRBG state through signing).
    #[must_use]
    pub fn sign_prehashed<
        C: Curve,
        T: UnsignedModularInt + FieldFor,
        M: digest::KeyInit + digest::Mac,
    >(
        private_key: &[u8],
        digest: &[u8],
        out_r: &mut [u8],
        out_s: &mut [u8],
    ) -> bool {
        const {
            assert!(
                C::ELEM_BYTES <= MAX_QLEN_BYTES,
                "Curve's ELEM_BYTES exceeds MAX_QLEN_BYTES"
            );
        }
        let eb = C::ELEM_BYTES;
        // Zeroizing: the nonce is wiped on the early-return and normal
        // paths alike.
        let mut k = Zeroizing::new([0u8; MAX_QLEN_BYTES]);
        if !derive_nonce_rfc6979::<C, T, M>(private_key, digest, &mut k[..eb]) {
            return false;
        }
        sign_prehashed_with_k::<C, T>(private_key, digest, &k[..eb], out_r, out_s)
    }

    // ===================================================================
    // Constant-time signing (RCB complete formulas on the Ct surface)
    // ===================================================================

    use const_num_traits::CtIsZero;
    use modmath::{FieldCt, ResidueCt};

    /// Constant-time bigint backend for signing: the Ct-personality
    /// analog of [`UnsignedModularInt`]. Blanket-implemented for every
    /// conforming type; in practice `fixed_bigint::FixedUInt<_, _, Ct>`.
    /// The Nct verify backend does **not** qualify — the personalities
    /// are distinct types by design, so secret signing arithmetic runs
    /// on this `Ct` backend, separate from the `Nct` one.
    ///
    /// The bounds are what `modmath::FieldCt` needs for its
    /// constant-time `mul`/`add`/`sub`/`inv_fermat` plus the
    /// branchless point selection in the scalar-multiply ladder.
    pub trait ConstantTimeInt:
        ScalarBytes
        + const_num_traits::WrappingMul<Output = Self>
        + const_num_traits::WrappingAdd<Output = Self>
        + const_num_traits::WrappingSub<Output = Self>
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
        + const_num_traits::BitsPrecision
        + const_num_traits::WithPrecision
        + CtIsZero
        + modmath::Parity
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + zeroize::DefaultIsZeroes
    {
    }

    impl<T> ConstantTimeInt for T where
        T: ScalarBytes
            + const_num_traits::WrappingMul<Output = Self>
            + const_num_traits::WrappingAdd<Output = Self>
            + const_num_traits::WrappingSub<Output = Self>
            + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
            + const_num_traits::BitsPrecision
            + const_num_traits::WithPrecision
            + CtIsZero
            + modmath::Parity
            + modmath::WideMul
            + modmath::CiosMontMulCt
            + subtle::ConditionallySelectable
            + subtle::ConstantTimeLess
            + zeroize::DefaultIsZeroes
    {
    }

    /// Standard (homogeneous) projective point for the RCB formulas —
    /// `(X:Y:Z)` maps to affine `(X/Z, Y/Z)`, identity is `(0:1:0)`.
    /// **Not** the Jacobian convention the verify path uses.
    struct PointCt<'f, T: ConstantTimeInt> {
        x: ResidueCt<'f, T>,
        y: ResidueCt<'f, T>,
        z: ResidueCt<'f, T>,
    }

    fn identity_ct<T: ConstantTimeInt>(f: &FieldCt<T>) -> PointCt<'_, T> {
        PointCt {
            x: f.zero(),
            y: f.one(),
            z: f.zero(),
        }
    }

    /// Renes–Costello–Batina 2015 complete addition (Algorithm 1,
    /// arbitrary `a`), translated step-for-step from RustCrypto's
    /// `primeorder`. Exception-free: correct for equal points,
    /// inverses, and the identity, with **no data-dependent branches**
    /// — which is what makes the ladder constant-time. `b3` is `3·b`.
    #[allow(clippy::many_single_char_names)]
    // Kept a distinct symbol (never inlined into the sign) so the
    // ct-verify gates can attest it in isolation: the taint gate's
    // declassification suppressions for the public pass/fail outcomes are
    // scoped to the sign frame, and a real leak in this branchless
    // primitive must surface here, not there.
    #[inline(never)]
    fn add_rcb<'f, T: ConstantTimeInt>(
        f: &'f FieldCt<T>,
        a: &ResidueCt<'f, T>,
        b3: &ResidueCt<'f, T>,
        p: &PointCt<'f, T>,
        q: &PointCt<'f, T>,
    ) -> PointCt<'f, T> {
        let t0 = f.mul(&p.x, &q.x);
        let t1 = f.mul(&p.y, &q.y);
        let t2 = f.mul(&p.z, &q.z);
        let t3 = f.add(&p.x, &p.y);
        let t4 = f.add(&q.x, &q.y);
        let t3 = f.mul(&t3, &t4);
        let t4 = f.add(&t0, &t1);
        let t3 = f.sub(&t3, &t4);
        let t4 = f.add(&p.x, &p.z);
        let t5 = f.add(&q.x, &q.z);
        let t4 = f.mul(&t4, &t5);
        let t5 = f.add(&t0, &t2);
        let t4 = f.sub(&t4, &t5);
        let t5 = f.add(&p.y, &p.z);
        let x3 = f.add(&q.y, &q.z);
        let t5 = f.mul(&t5, &x3);
        let x3 = f.add(&t1, &t2);
        let t5 = f.sub(&t5, &x3);
        let z3 = f.mul(a, &t4);
        let x3 = f.mul(b3, &t2);
        let z3 = f.add(&x3, &z3);
        let x3 = f.sub(&t1, &z3);
        let z3 = f.add(&t1, &z3);
        let y3 = f.mul(&x3, &z3);
        let t1 = f.add(&t0, &t0);
        let t1 = f.add(&t1, &t0);
        let t2 = f.mul(a, &t2);
        let t4 = f.mul(b3, &t4);
        let t1 = f.add(&t1, &t2);
        let t2 = f.sub(&t0, &t2);
        let t2 = f.mul(a, &t2);
        let t4 = f.add(&t4, &t2);
        let t0 = f.mul(&t1, &t4);
        let y3 = f.add(&y3, &t0);
        let t0 = f.mul(&t5, &t4);
        let x3 = f.mul(&t3, &x3);
        let x3 = f.sub(&x3, &t0);
        let t0 = f.mul(&t3, &t1);
        let z3 = f.mul(&t5, &z3);
        let z3 = f.add(&z3, &t0);
        PointCt {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `scalar · base`, constant-time: fixed `bits` iterations,
    /// double-and-add-*always* with a branchless `cswap` selecting the
    /// add result on set bits. Every iteration does the same two
    /// complete additions and one conditional swap regardless of the
    /// scalar, so timing carries no information about it.
    // Distinct symbol for the ct-verify gates — see `add_rcb`.
    #[inline(never)]
    fn scalar_mul_ct<'f, T: ConstantTimeInt>(
        f: &'f FieldCt<T>,
        a: &ResidueCt<'f, T>,
        b3: &ResidueCt<'f, T>,
        bits: usize,
        scalar: &T,
        base: &PointCt<'f, T>,
    ) -> PointCt<'f, T> {
        let mut r = identity_ct(f);
        for i in (0..bits).rev() {
            r = add_rcb(f, a, b3, &r, &r);
            let mut r_add = add_rcb(f, a, b3, &r, base);
            let bit = !((*scalar >> i) & T::one()).ct_is_zero();
            ResidueCt::cswap(bit, &mut r.x, &mut r_add.x);
            ResidueCt::cswap(bit, &mut r.y, &mut r_add.y);
            ResidueCt::cswap(bit, &mut r.z, &mut r_add.z);
        }
        r
    }

    /// Affine x-coordinate `X/Z` (RCB projective) and whether the point
    /// is non-identity, as `(x, valid)`. Branch-free: `Z⁻¹` is a
    /// `CtOption` whose `is_some` becomes `valid`, and the `unwrap_or`
    /// default keeps the multiply running even at the identity (where `x`
    /// is meaningless and `valid` is false). The caller folds `valid`
    /// into its accumulated `Choice` rather than branching here.
    /// The Fermat inversion exponent `m − 2` (so `a⁻¹ ≡ a^(m−2) mod m`
    /// for prime `m`). The field's `exp` is branch-free and always
    /// defined — it yields 0 at `a = 0` — so it replaces the
    /// `CtOption`-returning `inv_fermat` on the branch-free sign path,
    /// where the `a = 0` case is folded into a validity `Choice` instead.
    fn fermat_exp<T: ConstantTimeInt>(modulus: &T) -> T {
        (*modulus).wrapping_sub(T::one().wrapping_add(T::one()))
    }

    fn affine_x_ct<T: ConstantTimeInt>(f: &FieldCt<T>, pt: &PointCt<'_, T>) -> (T, subtle::Choice) {
        // `valid` is false at the identity (`Z = 0`); the caller folds it
        // into its accumulated `Choice` rather than branching here.
        let valid = !f.into_raw(&pt.z).ct_is_zero();
        let zinv = f.exp(&pt.z, &fermat_exp(f.modulus()));
        let x = f.into_raw(&f.mul(&pt.x, &zinv));
        (x, valid)
    }

    /// **Constant-time** ECDSA signing over curve `C` with the Ct
    /// backend `T`, given the nonce `k`. The secret scalar multiply
    /// `k·G` uses RCB complete formulas on the `Ct` modmath surface,
    /// and `k⁻¹`, `s` run through `FieldCt` — no secret-dependent
    /// branches. Same slice/`false` contract as
    /// [`sign_prehashed_with_k`]; `k` must still be unique and
    /// unpredictable (use [`sign_prehashed_ct`] for RFC 6979).
    ///
    /// Experimental — see the [module warning](self).
    #[must_use]
    pub fn sign_prehashed_ct_with_k<C: Curve, T: ConstantTimeInt>(
        private_key: &[u8],
        digest: &[u8],
        k: &[u8],
        out_r: &mut [u8],
        out_s: &mut [u8],
    ) -> bool {
        const {
            assert!(
                core::mem::size_of::<T>() >= C::ELEM_BYTES,
                "backend type narrower than the curve's field element"
            );
            assert!(
                C::P.len() == C::ELEM_BYTES
                    && C::A.len() == C::ELEM_BYTES
                    && C::B.len() == C::ELEM_BYTES
                    && C::N.len() == C::ELEM_BYTES
                    && C::GX.len() == C::ELEM_BYTES
                    && C::GY.len() == C::ELEM_BYTES,
                "Curve constants must all be exactly ELEM_BYTES long"
            );
        }
        let eb = C::ELEM_BYTES;
        if private_key.len() != eb
            || k.len() != eb
            || out_r.len() != eb
            || out_s.len() != eb
            || digest.is_empty()
        {
            return false;
        }
        let p = from_be::<T>(C::P);
        let n = from_be::<T>(C::N);
        let d = from_be::<T>(private_key);
        let k_int = from_be::<T>(k);

        // Every secret-derived validity test folds into one `Choice`,
        // returned once at the end — no secret-dependent early return, so
        // the taint gate checks this whole frame with nothing suppressed.
        // The key/nonce range, `r`/`s == 0`, the RCB identity, and
        // `k⁻¹`-exists are all public-by-design outcomes (the signer
        // returns `false`), but declassifying them branch-free instead of
        // by early return keeps a real secret branch from ever hiding here.
        let mut ok = !d.ct_is_zero() & d.ct_lt(&n) & !k_int.ct_is_zero() & k_int.ct_lt(&n);

        let (Some(fp), Some(fn_)) = (FieldCt::new(p), FieldCt::new(n)) else {
            return false;
        };
        let a_res = fp.reduce(&from_be::<T>(C::A));
        let b_res = fp.reduce(&from_be::<T>(C::B));
        let b3 = fp.add(&fp.add(&b_res, &b_res), &b_res);
        let g = PointCt {
            x: fp.reduce(&from_be::<T>(C::GX)),
            y: fp.reduce(&from_be::<T>(C::GY)),
            z: fp.one(),
        };

        // r = x(k·G) mod n.
        let kg = scalar_mul_ct(&fp, &a_res, &b3, eb * 8, &k_int, &g);
        let (rx, rx_ok) = affine_x_ct(&fp, &kg);
        ok &= rx_ok;
        let r = fn_.into_raw(&fn_.reduce(&rx));
        ok &= !r.ct_is_zero();

        // s = k⁻¹ · (e + r·d) mod n.
        let e = fn_.reduce(&hash_to_scalar::<T>(digest, bitlen_be(C::N)));
        // k⁻¹ via Fermat exp — branch-free; `k ≠ 0` is already folded into
        // `ok`, and `exp` yields 0 at k = 0 (making `s = 0`, also rejected).
        let k_inv = fn_.exp(&fn_.reduce(&k_int), &fermat_exp(fn_.modulus()));
        let rd = fn_.mul(&fn_.reduce(&r), &fn_.reduce(&d));
        let s = fn_.into_raw(&fn_.mul(&k_inv, &fn_.add(&e, &rd)));
        ok &= !s.ct_is_zero();

        to_be_ct::<T>(&r, out_r);
        to_be_ct::<T>(&s, out_s);
        bool::from(ok)
    }

    /// **Constant-time** ECDSA signing with an RFC 6979 deterministic
    /// nonce. Both halves run on the Ct backend `Tct`: the nonce is
    /// derived via [`derive_nonce_rfc6979_ct`], then the secret
    /// signature math runs constant-time via
    /// [`sign_prehashed_ct_with_k`]. `M` is the HMAC whose hash matches
    /// the digest's (e.g. `Hmac<Sha256>` for a SHA-256 digest).
    ///
    /// Experimental — see the [module warning](self).
    #[must_use]
    pub fn sign_prehashed_ct<C: Curve, Tct: ConstantTimeInt, M: digest::KeyInit + digest::Mac>(
        private_key: &[u8],
        digest: &[u8],
        out_r: &mut [u8],
        out_s: &mut [u8],
    ) -> bool {
        sign_prehashed_ct_added::<C, Tct, M>(private_key, digest, &[], out_r, out_s)
    }

    /// **Hedged** constant-time ECDSA signing: identical to
    /// [`sign_prehashed_ct`] but mixes `added` (fresh entropy) into the
    /// RFC 6979 nonce per §3.6, so repeated signatures over the same
    /// `(private_key, digest)` differ. This keeps RFC 6979's
    /// no-catastrophic-RNG-failure property — a weak or empty `added`
    /// degrades to the deterministic nonce, never to nonce reuse — while
    /// adding the per-signature variability that defeats same-message
    /// trace averaging and the deterministic-ECDSA fault break. The
    /// entropy is public (not secret), so the derivation stays
    /// constant-time.
    ///
    /// Experimental — see the [module warning](self).
    #[must_use]
    pub fn sign_prehashed_ct_hedged<
        C: Curve,
        Tct: ConstantTimeInt,
        M: digest::KeyInit + digest::Mac,
    >(
        private_key: &[u8],
        digest: &[u8],
        added: &[u8],
        out_r: &mut [u8],
        out_s: &mut [u8],
    ) -> bool {
        sign_prehashed_ct_added::<C, Tct, M>(private_key, digest, added, out_r, out_s)
    }

    fn sign_prehashed_ct_added<C: Curve, Tct: ConstantTimeInt, M: digest::KeyInit + digest::Mac>(
        private_key: &[u8],
        digest: &[u8],
        added: &[u8],
        out_r: &mut [u8],
        out_s: &mut [u8],
    ) -> bool {
        let eb = C::ELEM_BYTES;
        let mut k = Zeroizing::new([0u8; MAX_QLEN_BYTES]);
        // Both halves run unconditionally and their validity bools combine
        // branch-free. The derivation returns a *tainted* validity bool
        // (folded from the secret key), so branching on it would just move
        // the leak up into this frame; `&` keeps it branch-free.
        let derived =
            derive_nonce_rfc6979_ct_added::<C, Tct, M>(private_key, digest, added, &mut k[..eb]);
        let signed =
            sign_prehashed_ct_with_k::<C, Tct>(private_key, digest, &k[..eb], out_r, out_s);
        derived & signed
    }

    /// Hedged constant-time sign **with a verify-after-sign fault check**.
    /// Signs via [`sign_prehashed_ct_hedged`], then recomputes the public
    /// key `d·G` (constant-time, backend `Tct`) and verifies the fresh
    /// `(r, s)` through the variable-time verify path (backend `Tv`)
    /// before accepting. A computational fault in the signature math is
    /// caught here; on any failure the outputs are zeroed and `false` is
    /// returned, so a faulted signature is never released.
    ///
    /// The verify runs variable-time, which is sound: `(r, s)`, the
    /// digest, and the public key are all public the instant the
    /// signature is emitted. `Tv` is an ordinary (non-Ct) verify backend
    /// (`FieldFor + ScalarBytes`), distinct from the Ct signing backend
    /// `Tct`.
    ///
    /// Experimental — see the [module warning](self).
    #[must_use]
    pub fn sign_prehashed_ct_hedged_verified<
        C: Curve,
        Tct: ConstantTimeInt,
        Tv: FieldFor + ScalarBytes,
        M: digest::KeyInit + digest::Mac,
    >(
        private_key: &[u8],
        digest: &[u8],
        added: &[u8],
        out_r: &mut [u8],
        out_s: &mut [u8],
    ) -> bool {
        let eb = C::ELEM_BYTES;
        if out_r.len() != eb || out_s.len() != eb {
            return false;
        }
        let signed = sign_prehashed_ct_added::<C, Tct, M>(private_key, digest, added, out_r, out_s);

        // Recompute Q = d·G and verify (r, s); a fault in the sign math
        // fails this check. Q is derived fresh from the same key so no
        // caller-supplied public key can mask a mismatch.
        let mut pubkey = [0u8; 1 + 2 * MAX_ELEM];
        let pk = &mut pubkey[..1 + 2 * eb];
        let q_ok = SigningKey::<C>::from_bytes(private_key)
            .is_some_and(|sk| sk.verifying_key_sec1::<Tct>(pk));
        let verified = q_ok && verify_for_curve::<C, Tv>(pk, digest, out_r, out_s);

        if !(signed && verified) {
            // Never release a signature that failed the fault check.
            out_r.iter_mut().for_each(|b| *b = 0);
            out_s.iter_mut().for_each(|b| *b = 0);
            return false;
        }
        true
    }

    /// Affine `(X/Z, Y/Z)` (RCB projective), or `None` at the
    /// identity. Constant-time inversion via Fermat.
    fn affine_xy_ct<T: ConstantTimeInt>(f: &FieldCt<T>, pt: &PointCt<'_, T>) -> Option<(T, T)> {
        let zinv = Option::from(f.inv_fermat(&pt.z))?;
        Some((
            f.into_raw(&f.mul(&pt.x, &zinv)),
            f.into_raw(&f.mul(&pt.y, &zinv)),
        ))
    }

    /// Widest curve scalar this crate carries (P-384 = 48 bytes); the
    /// `SigningKey` byte buffer is sized to it and sliced per curve.
    const MAX_ELEM: usize = 48;

    /// An ECDSA private scalar that **wipes itself on drop**. Owning
    /// the key in this wrapper (rather than passing raw `&[u8]`) keeps
    /// the secret in a `Zeroizing` buffer for its whole lifetime.
    ///
    /// Curve-fixed (`C`); the arithmetic backends are chosen per call,
    /// since the key material is personality-agnostic bytes. The
    /// scalar is stored as bytes rather than a typed `T` so the struct
    /// stays free of a backend type parameter — same reason ed25519's
    /// `SigningKey` stores its clamped scalar as bytes.
    ///
    /// Experimental — see the [module warning](self).
    pub struct SigningKey<C: Curve> {
        d: Zeroizing<[u8; MAX_ELEM]>,
        _c: core::marker::PhantomData<fn() -> C>,
    }

    impl<C: Curve> SigningKey<C> {
        /// Wrap a private scalar (big-endian, `C::ELEM_BYTES` long).
        /// Returns `None` on the wrong length. The `[1, n−1]` range is
        /// checked at sign / verifying-key time (it needs a backend).
        #[must_use]
        pub fn from_bytes(private_key: &[u8]) -> Option<Self> {
            const {
                assert!(
                    C::ELEM_BYTES <= MAX_ELEM,
                    "Curve's ELEM_BYTES exceeds MAX_ELEM"
                );
            }
            if private_key.len() != C::ELEM_BYTES {
                return None;
            }
            let mut d = Zeroizing::new([0u8; MAX_ELEM]);
            d[..C::ELEM_BYTES].copy_from_slice(private_key);
            Some(Self {
                d,
                _c: core::marker::PhantomData,
            })
        }

        /// Sign `digest` with an RFC 6979 nonce (see
        /// [`sign_prehashed_ct`]). `Tct` is the Ct backend for both the
        /// nonce derivation and the secret signature math; `M` the HMAC.
        /// The whole deterministic sign is constant-time up to RFC
        /// 6979's inherent rejection-loop count.
        #[must_use]
        pub fn sign_prehashed<Tct: ConstantTimeInt, M: digest::KeyInit + digest::Mac>(
            &self,
            digest: &[u8],
            out_r: &mut [u8],
            out_s: &mut [u8],
        ) -> bool {
            sign_prehashed_ct::<C, Tct, M>(&self.d[..C::ELEM_BYTES], digest, out_r, out_s)
        }

        /// Derive the SEC1-uncompressed public key `0x04 || X || Y`
        /// into `out` (`1 + 2·C::ELEM_BYTES` bytes) via a constant-time
        /// `d·G`. Returns `false` on the wrong output length or an
        /// out-of-range scalar.
        #[must_use]
        pub fn verifying_key_sec1<Tct: ConstantTimeInt>(&self, out: &mut [u8]) -> bool {
            const {
                assert!(
                    core::mem::size_of::<Tct>() >= C::ELEM_BYTES,
                    "backend type narrower than the curve's field element"
                );
            }
            let eb = C::ELEM_BYTES;
            if out.len() != 1 + 2 * eb {
                return false;
            }
            let p = from_be::<Tct>(C::P);
            let n = from_be::<Tct>(C::N);
            let d = from_be::<Tct>(&self.d[..eb]);
            if !bool::from(!d.ct_is_zero() & d.ct_lt(&n)) {
                return false;
            }
            let Some(fp) = FieldCt::new(p) else {
                return false;
            };
            let a_res = fp.reduce(&from_be::<Tct>(C::A));
            let b_res = fp.reduce(&from_be::<Tct>(C::B));
            let b3 = fp.add(&fp.add(&b_res, &b_res), &b_res);
            let g = PointCt {
                x: fp.reduce(&from_be::<Tct>(C::GX)),
                y: fp.reduce(&from_be::<Tct>(C::GY)),
                z: fp.one(),
            };
            let q = scalar_mul_ct(&fp, &a_res, &b3, eb * 8, &d, &g);
            let Some((qx, qy)) = affine_xy_ct(&fp, &q) else {
                return false;
            };
            out[0] = 0x04;
            to_be_ct::<Tct>(&qx, &mut out[1..1 + eb]);
            to_be_ct::<Tct>(&qy, &mut out[1 + eb..1 + 2 * eb]);
            true
        }
    }

    /// Zero-size marker binding the backend/HMAC without owning them
    /// (so auto traits stay unconditional), factored out to keep the
    /// struct field readable.
    type BackendMarker<Tct, M> = core::marker::PhantomData<fn() -> (Tct, M)>;

    /// Three-backend marker (Ct sign / vartime verify / HMAC) for the
    /// randomized signer — same purpose as [`BackendMarker`].
    type RandBackendMarker<Tct, Tv, M> = core::marker::PhantomData<fn() -> (Tct, Tv, M)>;

    /// A [`SigningKey`] with its backend and HMAC bound, so it can
    /// carry the RustCrypto `signature::hazmat::PrehashSigner` impl
    /// (which has no room for per-call type parameters). The impl is
    /// emitted per curve because the signature is a fixed
    /// `[u8; 2·ELEM_BYTES]` — the same reason
    /// [`PrehashVerifier`](signature::hazmat::PrehashVerifier) lives
    /// in the curve modules. `Tct` is the Ct backend (nonce derivation
    /// and secret math both), `M` the HMAC.
    ///
    /// Experimental — see the [module warning](self).
    pub struct PrehashSigningKey<C: Curve, Tct, M> {
        key: SigningKey<C>,
        _p: BackendMarker<Tct, M>,
    }

    impl<C: Curve, Tct: ConstantTimeInt, M: digest::KeyInit + digest::Mac>
        PrehashSigningKey<C, Tct, M>
    {
        /// Wrap a private scalar (see [`SigningKey::from_bytes`]).
        ///
        /// Unlike [`SigningKey`] — whose backend is bound late, at sign
        /// time — this key is fully monomorphized over the Ct backend
        /// `Tct`, so it can reject `d ∉ [1, n-1]` eagerly here. The check
        /// runs in constant time (the scalar is secret); it returns
        /// `None` for out-of-range keys instead of deferring to the
        /// use-time rejection the raw signing functions already perform.
        #[must_use]
        pub fn from_bytes(private_key: &[u8]) -> Option<Self> {
            let key = SigningKey::from_bytes(private_key)?;
            let d = from_be::<Tct>(private_key);
            let n = from_be::<Tct>(C::N);
            if !bool::from(!d.ct_is_zero() & d.ct_lt(&n)) {
                return None;
            }
            Some(Self {
                key,
                _p: core::marker::PhantomData,
            })
        }

        /// Sign into `out_r` / `out_s` (see [`SigningKey::sign_prehashed`]).
        #[must_use]
        pub fn sign_prehashed(&self, digest: &[u8], out_r: &mut [u8], out_s: &mut [u8]) -> bool {
            self.key.sign_prehashed::<Tct, M>(digest, out_r, out_s)
        }

        /// Derive the SEC1 public key (see
        /// [`SigningKey::verifying_key_sec1`]).
        #[must_use]
        pub fn verifying_key_sec1(&self, out: &mut [u8]) -> bool {
            self.key.verifying_key_sec1::<Tct>(out)
        }
    }

    /// A [`SigningKey`] bound to a Ct signing backend `Tct`, a
    /// variable-time verify backend `Tv`, and an HMAC `M`, carrying the
    /// RustCrypto [`signature::hazmat::RandomizedPrehashSigner`] impl.
    /// Its sign path is **hedged** (fresh entropy folded into the RFC
    /// 6979 nonce, §3.6) and **verify-after-sign** fault-checked — the
    /// hardened counterpart to the deterministic [`PrehashSigningKey`].
    /// `Tv` is a normal (non-Ct) backend, used only for the post-sign
    /// verification whose inputs are public.
    ///
    /// Experimental — see the [module warning](self).
    pub struct RandomizedSigningKey<C: Curve, Tct, Tv, M> {
        key: SigningKey<C>,
        _p: RandBackendMarker<Tct, Tv, M>,
    }

    impl<
        C: Curve,
        Tct: ConstantTimeInt,
        Tv: FieldFor + ScalarBytes,
        M: digest::KeyInit + digest::Mac,
    > RandomizedSigningKey<C, Tct, Tv, M>
    {
        /// Wrap a private scalar, rejecting `d ∉ [1, n-1]` eagerly in
        /// constant time (see [`PrehashSigningKey::from_bytes`]).
        #[must_use]
        pub fn from_bytes(private_key: &[u8]) -> Option<Self> {
            let key = SigningKey::from_bytes(private_key)?;
            let d = from_be::<Tct>(private_key);
            let n = from_be::<Tct>(C::N);
            if !bool::from(!d.ct_is_zero() & d.ct_lt(&n)) {
                return None;
            }
            Some(Self {
                key,
                _p: core::marker::PhantomData,
            })
        }

        /// Hedged constant-time sign with a verify-after-sign fault check
        /// (see [`sign_prehashed_ct_hedged_verified`]). `added` is fresh
        /// entropy — distinct entropy per call makes repeated signatures
        /// over one digest differ.
        #[must_use]
        pub fn sign_prehashed_hedged(
            &self,
            added: &[u8],
            digest: &[u8],
            out_r: &mut [u8],
            out_s: &mut [u8],
        ) -> bool {
            sign_prehashed_ct_hedged_verified::<C, Tct, Tv, M>(
                &self.key.d[..C::ELEM_BYTES],
                digest,
                added,
                out_r,
                out_s,
            )
        }

        /// Derive the SEC1 public key (see
        /// [`SigningKey::verifying_key_sec1`]).
        #[must_use]
        pub fn verifying_key_sec1(&self, out: &mut [u8]) -> bool {
            self.key.verifying_key_sec1::<Tct>(out)
        }
    }
}

#[cfg(test)]
mod tests;
