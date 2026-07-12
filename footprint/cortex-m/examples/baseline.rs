#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabiecdsa_footprint_cortex_m::{fake_verify, test_fixture};

mod fixture {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p256.rs"));
}

#[entry]
fn main() -> ! {
    test_fixture::<2048>(
        || fake_verify(&fixture::PUBKEY, &fixture::DIGEST, &fixture::R, &fixture::S),
        "baseline",
    );
    loop {}
}
