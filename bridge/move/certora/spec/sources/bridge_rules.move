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
  transfer_status_not_found,
  transfer_status_pending,
  transfer_status_approved,
  transfer_status_claimed,
  test_get_parsed_token_transfer_message,
};
use bridge::bridge_env::{get_total_supply, get_total_supply_if_registered};
use bridge::message::{BridgeMessage,  get_transfer_payload};
use bridge::message_types;
use certora::sui_object_summaries::deleted;
use cvlm::asserts::{cvlm_assert, cvlm_assert_msg, cvlm_assume_msg};
use cvlm::ghost::{ghost_destroy, };
use cvlm::manifest::{rule, target, invoker, target_sanity};
use sui::address;
use sui::clock::Clock;
use sui::coin::{Coin, value};
use sui::event::events_by_type;
use cvlm::nondet::nondet;
use cvlm::function::Function;
use sui_system::sui_system::SuiSystemState;
use sui_system::test_runner::start_epoch;



public fun cvlm_manifest() {
  target(@bridge, b"bridge", b"committee_registration");
  target(@bridge, b"bridge", b"update_node_url");
  target(@bridge, b"bridge", b"register_foreign_token");
  target(@bridge, b"bridge", b"send_token");
  target(@bridge, b"bridge", b"approve_token_transfer");
  target(@bridge, b"bridge", b"claim_token");
  target(@bridge, b"bridge", b"claim_and_transfer_token");
  target(@bridge, b"bridge", b"execute_system_message");

  target_sanity();

  invoker(b"invoke");
  
  rule(b"send_token_burns_coin");
  rule(b"only_owner_can_claim");
  rule(b"only_claiming_mints_tokens");
  rule(b"seq_nums_monotonically_increase");
  rule(b"transfer_records_are_valid");
  
  rule(b"send_token_effects");
  rule(b"approve_token_transfer_effects");
  rule(b"claim_token_effects");
  rule(b"claim_and_transfer_token_effects");
  rule(b"transfer_record_status_changes");
  rule(b"check_invariant_pending_status_only_for_internal_transfers");
  rule(b"only_approveTransfer_can_approve_transfer");
}


fun log<T>(_obj: &T) {}

native fun invoke(
  fn: Function, 
  bridge: &mut Bridge, 
  ctx: &mut TxContext, 
  state: &mut SuiSystemState
);


/// Sending a token to the bridge destroys the token.
/// This is tracked using the `deleted()` function, that returns for any object-address whether is was deleted.
public fun send_token_burns_coin<T>(
  bridge: &mut Bridge,
  target_chain: u8,
  target_address: vector<u8>,
  token: Coin<T>,
  ctx: &mut TxContext,
) {
  let token_address = object::borrow_id(&token).to_address();
  bridge.send_token(target_chain, target_address, token, ctx);
  cvlm_assert(*deleted(token_address));
}


/// If coins/tokens are minted, then either because "claim_token" or "claim_and_transfer_token" has been called
public fun only_claiming_mints_tokens<T>(
  bridge: &mut Bridge,
  fn: Function,
  ctx: &mut TxContext,
  state: &mut SuiSystemState
) {
  let balance_pre = get_total_supply_if_registered<T>(bridge);

  invoke(fn, bridge, ctx, state);

  let balance_post = get_total_supply_if_registered<T>(bridge);

  match (fn.name()) {
    b"claim_token" | b"claim_and_transfer_token" => {},
    _ => cvlm_assert(balance_post.get_with_default(0) <= balance_pre.get_with_default(0))
  }
}


/// If a call to "claim_token" succeeds, then the tx sender must be the owner of the tokens, 
/// as specified in the corresponding transfer record.
public fun only_owner_can_claim<T>(
  bridge: &mut Bridge,
  clock: &Clock,
  ctx: &mut TxContext,
  source_chain: u8,
  bridge_seq_num: u64,
) {
  let c: Coin<T> = bridge.claim_token(clock, source_chain, bridge_seq_num, ctx);
  log(&c);

  let msg = bridge.test_get_parsed_token_transfer_message(source_chain, bridge_seq_num).destroy_some();
  let payload = get_transfer_payload(&msg);
  let target_address = payload.token_target_address();

  log(&ctx.sender());
  log( &target_address);
  
  let target = address::from_bytes(target_address);
  log(&target);

  cvlm_assert(target == ctx.sender());
  ghost_destroy(c)
}


/// If a new transfer records is registered at the bridge, then it either must be verified or the source chain is the bridge itself.
/// For now, verified here just checks that the list of signatures is not empty.
public fun transfer_records_are_valid(bridge: &mut Bridge,
  fn: Function,
  ctx: &mut TxContext,
  state: &mut SuiSystemState
) {
    let records_pre = bridge.test_load_inner().inner_token_transfer_records().length();

    invoke(fn, bridge, ctx, state);


    let records = bridge.test_load_inner_mut().inner_token_transfer_records_mut();

    if (records.length() > records_pre) {
      // at most one record can be approved
      cvlm_assert(records.length() == records_pre+1);
      let (_, record) = records.pop_back();

      let self_is_source = record.message().source_chain() == bridge.test_load_inner().chain_id();

      let is_verified = if (record.verified_signatures().is_some()) {
        // could actually check integrity of signatures:
        // let sigs: &vector<vector<u8>> = record.verified_signatures().borrow();
        // bridge.test_load_inner().inner_committee().verify_signatures(*record.message(), *sigs)
        true
      } else {
        false
      };
      

      // Must be verified exactly if self is inner chain id is not the source
      cvlm_assert(!self_is_source == is_verified)
    }
}

/// Asserts that sequence number never decrease
public fun seq_nums_monotonically_increase(
  bridge: &mut Bridge,
  fn: Function,
  ctx: &mut TxContext,
  state: &mut SuiSystemState
) {
  let message_type: u8 = nondet();
  let seq_pre = bridge.get_seq_num_for(message_type);

  invoke(fn, bridge, ctx, state);

  let seq_post = bridge.get_seq_num_for(message_type);
  cvlm_assert(seq_pre <= seq_post);
}


// #[rule]
public fun send_token_effects<T>(
  bridge: &mut Bridge,
  target_chain: u8,
  target_address: vector<u8>,
  coin: Coin<T>,
  ctx: &mut TxContext,
) {
  cvlm_assume_msg(
    events_by_type<TokenDepositedEvent>().length() == 0,
    b"start with zero TokenDepositedEvent",
  );

  let coin_value = coin.value();
  let total_supply_before = get_total_supply<T>(bridge);

  let seq_num = bridge.get_seq_num_for(message_types::token());
  bridge.send_token(target_chain, target_address, coin, ctx);

  // verify reduction in total supply
  cvlm_assert(total_supply_before - coin_value == get_total_supply<T>(bridge));

  // verify send event
  let deposited_events = events_by_type<TokenDepositedEvent>();
  cvlm_assert(deposited_events.length() == 1);
  let (
    event_seq_num,
    _event_source_chain,
    _event_sender_address,
    _event_target_chain,
    _event_target_address,
    _event_token_type,
    event_amount,
  ) = deposited_events[0].unwrap_deposited_event();
  cvlm_assert(event_seq_num == seq_num);
  cvlm_assert(event_amount == coin_value);
}

// #[rule]
public fun approve_token_transfer_effects(
  bridge: &mut Bridge,
  message: BridgeMessage,
  signatures: vector<vector<u8>>,
) {
  cvlm_assume_msg(
    events_by_type<TokenTransferApproved>().length() == 0,
    b"start with zero TokenTransferApproved",
  );
  cvlm_assume_msg(
    events_by_type<TokenTransferAlreadyApproved>().length() == 0,
    b"start with zero TokenTransferAlreadyApproved",
  );

  let statusBefore = bridge.test_get_token_transfer_action_status(message.source_chain(), message.seq_num());
  bridge.approve_token_transfer(message, signatures);
  let statusAfter = bridge.test_get_token_transfer_action_status(message.source_chain(), message.seq_num());


  // verify approval events
  let approved_events = events_by_type<TokenTransferApproved>();
  let already_approved_events = events_by_type<TokenTransferAlreadyApproved>();

  cvlm_assert(approved_events.length() + already_approved_events.length() == 1);

  let key = if (approved_events.length() == 1) {
    approved_events[0].transfer_approve_key()
  } else {
    already_approved_events[0].transfer_already_approved_key()
  };
  if (approved_events.length() ==1) {
    cvlm_assert(statusBefore == transfer_status_not_found() || statusBefore == transfer_status_pending());
  } else {
    cvlm_assert(statusBefore == transfer_status_approved());
  };

  let (sc, mt, sn) = key.unpack_message();

  cvlm_assert(sc == message.source_chain());
  cvlm_assert(mt == message_types::token());
  cvlm_assert(sn == message.seq_num());
  cvlm_assert(statusAfter == transfer_status_approved());
}

// #[rule]
public fun claim_token_effects<T>(
  bridge: &mut Bridge,
  clock: &Clock,
  source_chain: u8,
  bridge_seq_num: u64,
  ctx: &mut TxContext,
): Coin<T> {
  cvlm_assume_msg(
    events_by_type<TokenTransferClaimed>().length() == 0,
    b"start with zero TokenTransferClaimed",
  );
  cvlm_assume_msg(
    events_by_type<TokenTransferAlreadyClaimed>().length() == 0,
    b"start with zero TokenTransferAlreadyClaimed",
  );
  cvlm_assume_msg(
    events_by_type<TokenTransferLimitExceed>().length() == 0,
    b"start with zero TokenTransferLimitExceed",
  );

  let total_supply_before = get_total_supply<T>(bridge);

  let statusBefore = bridge.test_get_token_transfer_action_status(source_chain, bridge_seq_num);
  let token = bridge.claim_token<T>(clock, source_chain, bridge_seq_num, ctx);
  let statusAfter = bridge.test_get_token_transfer_action_status(source_chain, bridge_seq_num);

  let token_value = token.value();
  cvlm_assert(total_supply_before + token_value == get_total_supply<T>(bridge));

  let claimed = events_by_type<TokenTransferClaimed>();
  let already_claimed = events_by_type<TokenTransferAlreadyClaimed>();
  let limit_exceeded = events_by_type<TokenTransferLimitExceed>();

  //cvlm_assert(claimed.length() + already_claimed.length() + limit_exceeded.length() == 1);
  cvlm_assert(claimed.length() == 1);
  cvlm_assert(already_claimed.length() == 0);
  cvlm_assert(limit_exceeded.length() == 0);

  let key = claimed[0].transfer_claimed_key();

  let (sc, mt, sn) = key.unpack_message();

  cvlm_assert(source_chain == sc);
  cvlm_assert(mt == message_types::token());
  cvlm_assert(sn == bridge_seq_num);

  cvlm_assert(statusBefore == transfer_status_approved());
  cvlm_assert(statusAfter == transfer_status_claimed());

  let record = &bridge.test_load_inner().inner_token_transfer_records()[key];
  let token_payload = record.message().extract_token_bridge_payload();

  cvlm_assert(token_payload.token_amount() == token_value);

  token
}

// #[rule]
public fun claim_and_transfer_token_effects<T>(
  bridge: &mut Bridge,
  clock: &Clock,
  source_chain: u8,
  bridge_seq_num: u64,
  ctx: &mut TxContext,
) {
  cvlm_assume_msg(
    events_by_type<TokenTransferClaimed>().length() == 0,
    b"start with zero TokenTransferClaimed",
  );
  cvlm_assume_msg(
    events_by_type<TokenTransferAlreadyClaimed>().length() == 0,
    b"start with zero TokenTransferAlreadyClaimed",
  );
  cvlm_assume_msg(
    events_by_type<TokenTransferLimitExceed>().length() == 0,
    b"start with zero TokenTransferLimitExceed",
  );
  cvlm_assume_msg(
    certora::sui_transfer_summaries::transfers<Coin<T>>().length() == 0,
    b"start with zero Sui transfers",
  );

  let total_supply_before = get_total_supply<T>(bridge);

  bridge.claim_and_transfer_token<T>(clock, source_chain, bridge_seq_num, ctx);

  let claimed = events_by_type<TokenTransferClaimed>();
  let already_claimed = events_by_type<TokenTransferAlreadyClaimed>();
  let limit_exceeded = events_by_type<TokenTransferLimitExceed>();

  cvlm_assert(claimed.length() + already_claimed.length() + limit_exceeded.length() == 1);

  let key = if (claimed.length() == 1) {
    claimed[0].transfer_claimed_key()
  } else if (already_claimed.length() == 1) {
    already_claimed[0].transfer_already_claimed_key()
  } else {
    limit_exceeded[0].transfer_limit_exceed_key()
  };

  let (sc, mt, sn) = key.unpack_message();

  cvlm_assert(source_chain == sc);
  cvlm_assert(mt == message_types::token());
  cvlm_assert(sn == bridge_seq_num);

  let total_supply_after = get_total_supply<T>(bridge);

  let transfers = certora::sui_transfer_summaries::transfers<Coin<T>>();
  let record = &bridge.test_load_inner().inner_token_transfer_records()[key];
  let token_payload = record.message().extract_token_bridge_payload();
  if (claimed.length() == 1) {
    cvlm_assert(transfers.length() == 1);
    cvlm_assert(transfers[0].value().value() == token_payload.token_amount());
    cvlm_assert(total_supply_after == total_supply_before + token_payload.token_amount());
  } else {
    cvlm_assert(transfers.length() == 0);
    cvlm_assert(total_supply_after == total_supply_before);
  }
}

// #[rule]
/// The status of a transfer record can only change according to
/// the state machine `not_found -> pending -> approved -> claimed`.
/// Once it is claimed, it always stays claimed.
public fun transfer_record_status_changes(bridge: &mut Bridge,
  source_chain: u8,
  bridge_seq_num: u64,
  fn: Function,
  ctx: &mut TxContext,
  state: &mut SuiSystemState
) {

  let statusBefore = bridge.test_get_token_transfer_action_status(source_chain, bridge_seq_num);

  invoke(fn, bridge, ctx, state);

  let statusAfter = bridge.test_get_token_transfer_action_status(source_chain, bridge_seq_num);

  cvlm_assert(statusBefore != transfer_status_not_found() ||
    statusAfter == transfer_status_not_found() || statusAfter == transfer_status_pending() || statusAfter == transfer_status_approved());
  cvlm_assert(statusBefore != transfer_status_pending() ||
    statusAfter == transfer_status_pending() || statusAfter == transfer_status_approved());
  cvlm_assert(statusBefore != transfer_status_approved() ||
    statusAfter == transfer_status_approved() || statusAfter == transfer_status_claimed());
  cvlm_assert(statusBefore != transfer_status_claimed() || statusAfter == transfer_status_claimed());
}

public fun only_approveTransfer_can_approve_transfer(bridge: &mut Bridge,
  source_chain: u8,
  bridge_seq_num: u64,
  fn: Function,
  ctx: &mut TxContext,
  state: &mut SuiSystemState
) {
  let statusBefore = bridge.test_get_token_transfer_action_status(source_chain, bridge_seq_num);

  invoke(fn, bridge, ctx, state);

  let statusAfter = bridge.test_get_token_transfer_action_status(source_chain, bridge_seq_num);

  if (fn.name() != b"approve_token_transfer") {
    cvlm_assert(statusBefore == transfer_status_approved() || statusAfter != transfer_status_approved());
  }
}

/// Check that all pending transfers must be internal transfers (source_chain == inner.chain_id).
fun invariant_pending_status_only_for_internal_transfers(bridge: &mut Bridge, 
  source_chain: u8,
  bridge_seq_num: u64
) : bool {
  let status = bridge.test_get_token_transfer_action_status(source_chain, bridge_seq_num);
  status != transfer_status_pending() || source_chain == bridge.test_load_inner().chain_id()
}

/// Check that all pending transfers must be internal transfers (source_chain == inner.chain_id).
public fun check_invariant_pending_status_only_for_internal_transfers(bridge: &mut Bridge, 
  source_chain: u8,
  bridge_seq_num: u64,
  fn: Function,
  ctx: &mut TxContext,
  state: &mut SuiSystemState
) {
  cvlm_assume_msg(invariant_pending_status_only_for_internal_transfers(bridge, source_chain, bridge_seq_num), b"invariant holds before");
  invoke(fn, bridge, ctx, state);
  cvlm_assert_msg(invariant_pending_status_only_for_internal_transfers(bridge, source_chain, bridge_seq_num), b"invariant holds after");
}
