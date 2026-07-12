#![no_main]
#![no_std]

use krabiecdsa_footprint_riscv::{fake_verify, test_fixture};

mod fixture {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/p256.rs"));
}

#[riscv_rt::entry]
fn main() -> ! {
    test_fixture::<2048>(
        || fake_verify(&fixture::PUBKEY, &fixture::DIGEST, &fixture::R, &fixture::S),
        "baseline",
    )
}
