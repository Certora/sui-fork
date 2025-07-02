#[test_only]
module spec::summaries;

use cvlm::manifest::{ summary, ghost };

public fun cvlm_manifest() {
    ghost(b"peel_u64_be");
    summary(b"peel_u64_be", @bridge, b"message", b"peel_u64_be");
}

// #[summary(bridge::message::peel_u64_be), ghost]
public native fun peel_u64_be(_: &mut sui::bcs::BCS): u64;