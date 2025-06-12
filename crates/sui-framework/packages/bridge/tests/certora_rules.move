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

use sui::vec_map::{ VecMap, size };

native fun CVT_summarize(func: vector<u8>);
native fun CVT_assert(cond: bool);
native fun CVT_assume(cond: bool);
native fun CVT_havoc<T>(): T;

#[allow(unused_function)]
fun summary__vec_map__get_idx<K: copy, V>(self: &VecMap<K,V>, key: &K): u64 {
    CVT_summarize(b"sui::vec_map::get_idx");

    let idx = CVT_havoc<u64>();
    CVT_assume(idx < self.size());
    let (entry_key, _) = self.get_entry_by_idx(idx);
    CVT_assume(entry_key == key);
    idx
}

#[allow(unused_function)]
fun summary__vec_map__get_idx_opt<K: copy, V>(self: &VecMap<K,V>, _: &K): Option<u64> {
    CVT_summarize(b"sui::vec_map::get_idx_opt");
    if (CVT_havoc<bool>()) { 
        let idx = CVT_havoc<u64>();
        CVT_assume(idx < self.size());
        option::some(idx) 
    } else { 
        option::none() 
    }
}

public fun send_token_sends_the_token(
    bridge: &mut Bridge, 
    target_chain: u8,
    target_address: vector<u8>,
    token: Coin<ETH>,
    ctx: &mut TxContext,    
) {
    let tokenValue = token.value();
    let inner = bridge.test_load_inner_mut();
    let prev_seq_num = inner.test_get_current_seq_num_and_increment(message_types::token());

    bridge.send_token(target_chain, target_address, token, ctx);

    let events = event::events_by_type<TokenDepositedEvent>();
    CVT_assert(events.length() == 1);

    let (
        event_seq_num, 
        _event_source_chain, 
        _event_sender_address, 
        event_target_chain, 
        _event_target_address, 
        _event_token_type, 
        event_amount
    ) = unwrap_deposited_event(events[0]);

    CVT_assert(event_seq_num > prev_seq_num);
    CVT_assert(event_target_chain == target_chain);
//    CVT_assert(event_target_address == target_address);
//    CVT_assert(event_token_type == eth());
    CVT_assert(event_amount == tokenValue);
}
