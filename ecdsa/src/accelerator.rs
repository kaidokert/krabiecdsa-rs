//! Complete P-256 operation providers for PKA peripherals and secure elements.
//!
//! The ordinary `krabiecdsa` implementation remains generic over `modmath`
//! field carriers. This optional surface is intentionally coarser: hardware
//! that already implements an ECC command should not impersonate dozens of
//! freely-copyable field values or expose an opaque private scalar.

use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
use zeroize::{Zeroize, Zeroizing};

/// Perform P-256 ECDSA signing with a backend-owned private key.
pub trait P256SignOperation {
    /// Backend-specific failure.
    type Error;

    /// Return the matching uncompressed SEC1 public key.
    fn verifying_key_sec1(&self, output: &mut [u8; 65]) -> Result<(), Self::Error>;

    /// Sign `prehash`, returning an IEEE P1363 `r || s` signature.
    ///
    /// `entropy` is fresh caller-provided hedge/blinding entropy. A backend
    /// with an internal approved RNG may consume or deliberately ignore it,
    /// but must document that decision.
    fn sign_prehash(
        &self,
        prehash: &[u8],
        entropy: &[u8; 32],
        signature: &mut [u8; 64],
    ) -> Result<(), Self::Error>;
}

/// Security marker for P-256 private-key operations.
///
/// # Safety
///
/// The backend must generate a unique nonce for every effective key/prehash
/// pair, protect the private key and nonce under its documented side-channel
/// model, reject invalid scalar results, and verify the produced signature
/// before returning it. Power/EM resistance is not implied unless documented.
pub unsafe trait HardenedP256SignOperation: P256SignOperation {}

/// Perform complete P-256 ECDSA verification.
pub trait P256VerifyOperation {
    /// Backend-specific failure.
    type Error;

    /// Verify an uncompressed SEC1 key and IEEE P1363 `r || s` signature.
    ///
    /// The backend is responsible for SEC1 shape, on-curve, scalar-range, and
    /// signature-equation validation. Inputs are public; variable-time
    /// execution is permitted.
    fn verify_prehash(
        &self,
        public_key_sec1: &[u8; 65],
        prehash: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Self::Error>;
}

/// RustCrypto `signature` adapter for a hardware-backed P-256 private key.
pub struct P256SigningKey<A> {
    operation: A,
}

impl<A> P256SigningKey<A> {
    /// Wrap a complete P-256 signing provider.
    pub const fn new(operation: A) -> Self {
        Self { operation }
    }

    /// Borrow the provider for lifecycle or diagnostics.
    pub fn operation(&self) -> &A {
        &self.operation
    }
}

impl<A: P256SignOperation> P256SigningKey<A> {
    /// Export only the public half of the backend-owned key.
    pub fn verifying_key_sec1(&self) -> Result<[u8; 65], A::Error> {
        let mut public_key = [0u8; 65];
        self.operation.verifying_key_sec1(&mut public_key)?;
        Ok(public_key)
    }
}

impl<A: HardenedP256SignOperation> RandomizedPrehashSigner<[u8; 64]> for P256SigningKey<A> {
    fn sign_prehash_with_rng<R: signature::rand_core::TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> Result<[u8; 64], signature::Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        signature::rand_core::TryRng::try_fill_bytes(rng, &mut entropy[..])
            .map_err(|_| signature::Error::new())?;
        let mut signature = [0u8; 64];
        if self
            .operation
            .sign_prehash(prehash, &entropy, &mut signature)
            .is_err()
        {
            signature.zeroize();
            return Err(signature::Error::new());
        }
        Ok(signature)
    }
}

/// RustCrypto `signature` adapter for P-256 hardware verification.
pub struct P256VerifyingKey<A> {
    operation: A,
    public_key_sec1: [u8; 65],
}

impl<A> P256VerifyingKey<A> {
    /// Wrap a provider and uncompressed SEC1 public key.
    pub const fn new(operation: A, public_key_sec1: [u8; 65]) -> Self {
        Self {
            operation,
            public_key_sec1,
        }
    }

    /// Return the public key passed at construction.
    pub const fn as_sec1_bytes(&self) -> &[u8; 65] {
        &self.public_key_sec1
    }

    /// Borrow the provider for lifecycle or diagnostics.
    pub fn operation(&self) -> &A {
        &self.operation
    }
}

impl<A, S> PrehashVerifier<S> for P256VerifyingKey<A>
where
    A: P256VerifyOperation,
    S: AsRef<[u8]>,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &S) -> Result<(), signature::Error> {
        let signature: &[u8; 64] = signature
            .as_ref()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        self.operation
            .verify_prehash(&self.public_key_sec1, prehash, signature)
            .map_err(|_| signature::Error::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    struct MockPka {
        sign_calls: Cell<u32>,
        verify_calls: Cell<u32>,
    }

    impl MockPka {
        const fn new() -> Self {
            Self {
                sign_calls: Cell::new(0),
                verify_calls: Cell::new(0),
            }
        }
    }

    impl P256SignOperation for MockPka {
        type Error = ();

        fn verifying_key_sec1(&self, output: &mut [u8; 65]) -> Result<(), Self::Error> {
            output.fill(0x42);
            output[0] = 4;
            Ok(())
        }

        fn sign_prehash(
            &self,
            prehash: &[u8],
            entropy: &[u8; 32],
            signature: &mut [u8; 64],
        ) -> Result<(), Self::Error> {
            self.sign_calls.set(self.sign_calls.get() + 1);
            signature[..32].copy_from_slice(&prehash[..32]);
            signature[32..].copy_from_slice(entropy);
            Ok(())
        }
    }

    unsafe impl HardenedP256SignOperation for MockPka {}

    impl P256VerifyOperation for MockPka {
        type Error = ();

        fn verify_prehash(
            &self,
            _: &[u8; 65],
            prehash: &[u8],
            signature: &[u8; 64],
        ) -> Result<(), Self::Error> {
            self.verify_calls.set(self.verify_calls.get() + 1);
            (signature[..32] == prehash[..32]).then_some(()).ok_or(())
        }
    }

    struct SeqRng(u8);

    impl signature::rand_core::TryRng for SeqRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut output = [0u8; 4];
            self.try_fill_bytes(&mut output)?;
            Ok(u32::from_le_bytes(output))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut output = [0u8; 8];
            self.try_fill_bytes(&mut output)?;
            Ok(u64::from_le_bytes(output))
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for byte in output {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }

    impl signature::rand_core::TryCryptoRng for SeqRng {}

    #[test]
    fn signature_adapters_preserve_prehash_entropy_and_p1363_shape() {
        let signer = P256SigningKey::new(MockPka::new());
        let prehash = [0xa5; 32];
        let signature = signer
            .sign_prehash_with_rng(&mut SeqRng(0), &prehash)
            .unwrap();
        let mut expected_entropy = [0u8; 32];
        for (index, byte) in expected_entropy.iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }
        assert_eq!(&signature[..32], &prehash);
        assert_eq!(&signature[32..], &expected_entropy);
        assert_eq!(signer.operation().sign_calls.get(), 1);

        let verifying_key = P256VerifyingKey::new(MockPka::new(), [4; 65]);
        verifying_key.verify_prehash(&prehash, &signature).unwrap();
        assert_eq!(verifying_key.operation().verify_calls.get(), 1);
    }

    #[test]
    fn public_key_export_never_exposes_private_material() {
        let signer = P256SigningKey::new(MockPka::new());
        let public_key = signer.verifying_key_sec1().unwrap();
        assert_eq!(public_key[0], 4);
        assert!(public_key[1..].iter().all(|byte| *byte == 0x42));
    }
}
