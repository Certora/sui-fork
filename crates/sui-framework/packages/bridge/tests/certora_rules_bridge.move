#[test_only]
#[allow(unused_function)]
module bridge::certora_rules_bridge;

use bridge::bridge::{ 
    Bridge, 
    TokenDepositedEvent, 
    unwrap_deposited_event, 
};
use bridge::eth::ETH;
use bridge::message_types;
use bridge::bridge_env::get_total_supply;
use sui::coin::{ Coin, value };
use sui::event::events_by_type;

use cvlm::asserts::cvlm_assert;
use cvlm::manifest::rule;

public fun cvlm_manifest() {
    rule(b"send_token_sends_the_token");
}

// #[rule]
public fun send_token_sends_the_token(
    bridge: &mut Bridge, 
    target_chain: u8,
    target_address: vector<u8>,
    coin: Coin<ETH>,
    ctx: &mut TxContext,    
) {
    let initial_events_length = events_by_type<TokenDepositedEvent>().length();
    let coin_value = coin.value();
    let total_supply_before = get_total_supply<ETH>(bridge);

    let seq_num = bridge.get_seq_num_for(message_types::token());
    bridge.send_token(target_chain, target_address, coin, ctx);

    // verify reduction in total supply
    cvlm_assert!(total_supply_before - coin_value == get_total_supply<ETH>(bridge));

    // verify send event
    let deposited_events = events_by_type<TokenDepositedEvent>();
    cvlm_assert!(deposited_events.length() - initial_events_length == 1);
    let (
        event_seq_num,
        _event_source_chain,
        _event_sender_address,
        _event_target_chain,
        _event_target_address,
        _event_token_type,
        event_amount,
    ) = deposited_events[deposited_events.length() - 1].unwrap_deposited_event();
    cvlm_assert!(event_seq_num == seq_num);
    cvlm_assert!(event_amount == coin_value);
}
