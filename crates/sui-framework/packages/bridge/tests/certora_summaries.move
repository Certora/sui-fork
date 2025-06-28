#[test_only]
#[allow(unused_function)]
module bridge::certora_summaries;

use cvlm::manifest::summary;
use cvlm::nondet::nondet;

public fun cvlm_manifest() {
    summary(b"peel_u64_be", @bridge, b"message", b"peel_u64_be");
}

// #[summary(bridge::message::peel_u64_be)]
fun peel_u64_be(_: &mut sui::bcs::BCS): u64 { nondet() }