#[test_only]
#[allow(unused_function)]
module bridge_rules::certora_summaries;

use cvlm::manifest::{ summary, ghost };

public fun cvlm_manifest() {
    ghost(b"peel_u64_be");
    summary(b"peel_u64_be", @bridge, b"message", b"peel_u64_be");
}

// #[summary(bridge::message::peel_u64_be), ghost]
native fun peel_u64_be(_: &mut sui::bcs::BCS): u64;