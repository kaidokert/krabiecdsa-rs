#![cfg_attr(not(test), no_std)]

//! ECDSA signature verification, `no_std` and no-alloc.
//!
//! Scaffold only — the verifier lands in subsequent PRs.

/// Placeholder so the crate has something to build and test until
/// the real API lands.
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(add(2, 2), 4);
    }
}
