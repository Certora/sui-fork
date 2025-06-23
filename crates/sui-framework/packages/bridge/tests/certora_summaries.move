#[test_only]
#[allow(unused_function)]
module bridge::certora_summaries;

use bridge::committee::BridgeCommittee;

use cvlm::manifest::summary;
use cvlm::nondet::nondet;

public fun cvlm_manifest() {
    summary(b"active_validator_addresses", @sui_system, b"validator_set", b"active_validator_addresses");    
    summary(b"check_uniqueness_bridge_keys", @bridge, b"committee", b"check_uniqueness_bridge_keys");
}

// #[summary(sui_system::validator_set::active_validator_addresses_summary)]
fun active_validator_addresses(_: &sui_system::validator_set::ValidatorSet): vector<address> { nondet() }

// #[summary(bridge::committee::check_uniqueness_bridge_keys)]
fun check_uniqueness_bridge_keys(_: &BridgeCommittee, _: vector<u8>) {}
