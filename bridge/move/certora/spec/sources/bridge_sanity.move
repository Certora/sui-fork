#[test_only]
#[allow(unused_function)]
module spec::bridge_sanity;

use bridge::bridge::Bridge;
use bridge::message::BridgeMessage;
use bridge::eth::ETH;
use sui::package::UpgradeCap;
use sui::coin::{ Coin, TreasuryCap, CoinMetadata };
use sui::clock::Clock;
use sui_system::sui_system::SuiSystemState;

use cvlm::asserts::cvlm_satisfy;
use cvlm::manifest::rule;

public fun cvlm_manifest() {
    rule(b"committee_registration_sanity");
    // Needs optimistic loop mode due to loop in committee::update_node_url:
    rule(b"update_node_url_sanity");
    rule(b"register_foreign_token_sanity");
    rule(b"send_token_sanity");
    // Needs optimistic loop mode due to loop in committee::verify_signatures:
    rule(b"approve_token_transfer_sanity");
    // Needs optimistic loop mode due to loop in limiter::adjust_transfer_records
    rule(b"claim_token_sanity");
    rule(b"claim_and_transfer_token_sanity");
    // Needs optimistic loop mode due to loop in committee::verify_signatures:
    rule(b"execute_system_message_sanity");
}

// #[rule]
public fun committee_registration_sanity(
    bridge: &mut Bridge,
    system_state: &mut SuiSystemState,
    bridge_pubkey_bytes: vector<u8>,
    http_rest_url: vector<u8>,
    ctx: &TxContext,
) {
    bridge.committee_registration(system_state, bridge_pubkey_bytes, http_rest_url, ctx);
    cvlm_satisfy!(true);
}

// #[rule]
public fun update_node_url_sanity(bridge: &mut Bridge, new_url: vector<u8>, ctx: &TxContext) {
    bridge.update_node_url(new_url, ctx);
    cvlm_satisfy!(true);
}

// #[rule]
fun register_foreign_token_sanity(
    bridge: &mut Bridge,
    tc: TreasuryCap<ETH>,
    uc: UpgradeCap,
    metadata: &CoinMetadata<ETH>,
) {
    bridge.register_foreign_token<ETH>(tc, uc, metadata);
    cvlm_satisfy!(true);
}

// #[rule]
fun send_token_sanity(
    bridge: &mut Bridge,
    target_chain: u8,
    target_address: vector<u8>,
    token: Coin<ETH>,
    ctx: &mut TxContext,
) {
    bridge.send_token(target_chain, target_address, token, ctx);
    cvlm_satisfy!(true);
}

// #[rule]
fun approve_token_transfer_sanity(
    bridge: &mut Bridge,
    message: BridgeMessage,
    signatures: vector<vector<u8>>,
) {
    bridge.approve_token_transfer(message, signatures);
    cvlm_satisfy!(true);
}

// #[rule]
fun claim_token_sanity(
    bridge: &mut Bridge,
    clock: &Clock,
    source_chain: u8,
    bridge_seq_num: u64,
    ctx: &mut TxContext,
): Coin<ETH> {
    let result = bridge.claim_token<ETH>(clock, source_chain, bridge_seq_num, ctx);
    cvlm_satisfy!(true);
    result
}

// #[rule]
fun claim_and_transfer_token_sanity(
    bridge: &mut Bridge,
    clock: &Clock,
    source_chain: u8,
    bridge_seq_num: u64,
    ctx: &mut TxContext,
) {
    bridge.claim_and_transfer_token<ETH>(clock, source_chain, bridge_seq_num, ctx);
    cvlm_satisfy!(true);
}

// #[rule]
fun execute_system_message_sanity(
    bridge: &mut Bridge,
    message: BridgeMessage,
    signatures: vector<vector<u8>>,
) {
    bridge.execute_system_message(message, signatures);
    cvlm_satisfy!(true);
}