#[test_only]
module spec::bridge_rules;

use bridge::bridge::{ 
    Bridge, 
    TokenDepositedEvent,
    TokenTransferClaimed,
    TokenTransferAlreadyClaimed,
    TokenTransferLimitExceed,
    TokenTransferApproved,
    TokenTransferAlreadyApproved,
    unwrap_deposited_event, 
};
use bridge::message::BridgeMessage;
use bridge::eth::ETH;
use bridge::message_types;
use bridge::bridge_env::get_total_supply;
use sui::coin::{ Coin, value };
use sui::event::events_by_type;
use sui::clock::Clock;

use cvlm::asserts::{ cvlm_assert, cvlm_assume_msg };
use cvlm::manifest::rule;

public fun cvlm_manifest() {
    rule(b"send_token_effects");
    rule(b"approve_token_transfer_effects");
    rule(b"claim_token_effects");
    rule(b"claim_and_transfer_token_effects");
}

// #[rule]
public fun send_token_effects(
    bridge: &mut Bridge, 
    target_chain: u8,
    target_address: vector<u8>,
    coin: Coin<ETH>,
    ctx: &mut TxContext,    
) {
    cvlm_assume_msg!(events_by_type<TokenDepositedEvent>().length() == 0, b"start with zero TokenDepositedEvent");

    let coin_value = coin.value();
    let total_supply_before = get_total_supply<ETH>(bridge);

    let seq_num = bridge.get_seq_num_for(message_types::token());
    bridge.send_token(target_chain, target_address, coin, ctx);

    // verify reduction in total supply
    cvlm_assert!(total_supply_before - coin_value == get_total_supply<ETH>(bridge));

    // verify send event
    let deposited_events = events_by_type<TokenDepositedEvent>();
    cvlm_assert!(deposited_events.length() == 1);
    let (
        event_seq_num,
        _event_source_chain,
        _event_sender_address,
        _event_target_chain,
        _event_target_address,
        _event_token_type,
        event_amount,
    ) = deposited_events[0].unwrap_deposited_event();
    cvlm_assert!(event_seq_num == seq_num);
    cvlm_assert!(event_amount == coin_value);
}

// #[rule]
public fun approve_token_transfer_effects(
    bridge: &mut Bridge,
    message: BridgeMessage,
    signatures: vector<vector<u8>>,
) {
    cvlm_assume_msg!(events_by_type<TokenTransferApproved>().length() == 0, b"start with zero TokenTransferApproved");
    cvlm_assume_msg!(events_by_type<TokenTransferAlreadyApproved>().length() == 0, b"start with zero TokenTransferAlreadyApproved");

    bridge.approve_token_transfer(message, signatures);

    // verify approval events
    let approved_events = events_by_type<TokenTransferApproved>();
    let already_approved_events = events_by_type<TokenTransferAlreadyApproved>();

    cvlm_assert!(approved_events.length() + already_approved_events.length() == 1);

    let key = if (approved_events.length() == 1) {
        approved_events[0].transfer_approve_key()
    } else {
        already_approved_events[0].transfer_already_approved_key()
    };

    let (_sc, mt, sn) = key.unpack_message();

    cvlm_assert!(mt == message_types::token());
    cvlm_assert!(sn == message.seq_num());
}

// #[rule]
public fun claim_token_effects(
    bridge: &mut Bridge,
    clock: &Clock,
    source_chain: u8,
    bridge_seq_num: u64,
    ctx: &mut TxContext,
): Coin<ETH> {
    cvlm_assume_msg!(events_by_type<TokenTransferClaimed>().length() == 0, b"start with zero TokenTransferClaimed");
    cvlm_assume_msg!(events_by_type<TokenTransferAlreadyClaimed>().length() == 0, b"start with zero TokenTransferAlreadyClaimed");
    cvlm_assume_msg!(events_by_type<TokenTransferLimitExceed>().length() == 0, b"start with zero TokenTransferLimitExceed");

    let total_supply_before = get_total_supply<ETH>(bridge);

    let token = bridge.claim_token<ETH>(clock, source_chain, bridge_seq_num, ctx);

    let token_value = token.value();
    cvlm_assert!(total_supply_before + token_value == get_total_supply<ETH>(bridge));

    let claimed = events_by_type<TokenTransferClaimed>();
    let already_claimed = events_by_type<TokenTransferAlreadyClaimed>();
    let limit_exceeded = events_by_type<TokenTransferLimitExceed>();

    cvlm_assert!(claimed.length() + already_claimed.length() + limit_exceeded.length() == 1);

    let key = if (claimed.length() == 1) {
        claimed[0].transfer_claimed_key()
    } else if (already_claimed.length() == 1) {
        already_claimed[0].transfer_already_claimed_key()
    } else {
        limit_exceeded[0].transfer_limit_exceed_key()
    };

    let (sc, mt, sn) = key.unpack_message();

    cvlm_assert!(source_chain == sc);
    cvlm_assert!(mt == message_types::token());
    cvlm_assert!(sn == bridge_seq_num);

    token
}

// #[rule]
public fun claim_and_transfer_token_effects(
    bridge: &mut Bridge,
    clock: &Clock,
    source_chain: u8,
    bridge_seq_num: u64,
    ctx: &mut TxContext,
) {
    cvlm_assume_msg!(events_by_type<TokenTransferClaimed>().length() == 0, b"start with zero TokenTransferClaimed");
    cvlm_assume_msg!(events_by_type<TokenTransferAlreadyClaimed>().length() == 0, b"start with zero TokenTransferAlreadyClaimed");
    cvlm_assume_msg!(events_by_type<TokenTransferLimitExceed>().length() == 0, b"start with zero TokenTransferLimitExceed");
    cvlm_assume_msg!(certora::sui_transfer_summaries::transfers<Coin<ETH>>().length() == 0, b"start with zero Sui transfers");

    let total_supply_before = get_total_supply<ETH>(bridge);

    bridge.claim_and_transfer_token<ETH>(clock, source_chain, bridge_seq_num, ctx);

    let claimed = events_by_type<TokenTransferClaimed>();
    let already_claimed = events_by_type<TokenTransferAlreadyClaimed>();
    let limit_exceeded = events_by_type<TokenTransferLimitExceed>();

    cvlm_assert!(claimed.length() + already_claimed.length() + limit_exceeded.length() == 1);

    let key = if (claimed.length() == 1) {
        claimed[0].transfer_claimed_key()
    } else if (already_claimed.length() == 1) {
        already_claimed[0].transfer_already_claimed_key()
    } else {
        limit_exceeded[0].transfer_limit_exceed_key()
    };

    let (sc, mt, sn) = key.unpack_message();

    cvlm_assert!(source_chain == sc);
    cvlm_assert!(mt == message_types::token());
    cvlm_assert!(sn == bridge_seq_num);

    let total_supply_after = get_total_supply<ETH>(bridge);

    let transfers = certora::sui_transfer_summaries::transfers<Coin<ETH>>();
    let mut total_value_transferred = 0;
    transfers.do_ref!(|transfer| {
        total_value_transferred = total_value_transferred + transfer.value().value();
    });
    cvlm_assert!(total_supply_after == total_supply_before + total_value_transferred);
}
