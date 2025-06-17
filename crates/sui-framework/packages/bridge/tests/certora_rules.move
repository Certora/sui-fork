#[test_only]
module bridge::certora_rules;

use bridge::bridge::{ 
    Bridge, 
    TokenDepositedEvent, 
    unwrap_deposited_event, 
};
use bridge::eth::ETH;
use bridge::message_types;
use sui::coin::{ Coin, value };
use sui::event;

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
    token: Coin<ETH>,
    ctx: &mut TxContext,    
) {
    let initial_events_length = event::events_by_type<TokenDepositedEvent>().length();

    bridge.send_token(target_chain, target_address, token, ctx);

    let events = event::events_by_type<TokenDepositedEvent>();
    let event_count = events.length() - initial_events_length;
    cvlm_assert!(event_count == 1);
}

    // let (
    //     _event_seq_num, 
    //     _event_source_chain, 
    //     _event_sender_address, 
    //     _event_target_chain, 
    //     _event_target_address, 
    //     _event_token_type, 
    //     _event_amount
    // ) = unwrap_deposited_event(events[0]);

//    cvlm_assert!(event_seq_num >= prev_seq_num);
//    cvlm_assert!(_event_target_chain == target_chain);
//    cvlm_assert!(event_target_address == target_address);
//    cvlm_assert!(event_token_type == eth());
//    cvlm_assert!(event_amount == tokenValue);
