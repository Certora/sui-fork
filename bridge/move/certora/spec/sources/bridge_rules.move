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
  test_get_parsed_token_transfer_message,
};
use bridge::bridge_env::{get_total_supply};
use bridge::eth::ETH;
use bridge::message::{BridgeMessage,  get_transfer_payload};
use bridge::message_types;
use certora::sui_object_summaries::deleted;
use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::ghost::{ghost_destroy, };
use cvlm::manifest::rule;
use sui::address;
use sui::clock::Clock;
use sui::coin::{Coin, value};
use sui::event::events_by_type;
use cvlm::nondet::nondet;



public fun cvlm_manifest() {
  
  rule(b"send_token_burns_coin");
  rule(b"only_owner_can_claim");
  rule(b"only_claiming_mints_tokens");
  rule(b"seq_nums_monotonically_increase");
  rule(b"transfer_records_are_valid");
  
  rule(b"send_token_effects");
  rule(b"approve_token_transfer_effects");
  rule(b"claim_token_effects");
  rule(b"claim_and_transfer_token_effects");
}


fun log<T>(_obj: &T) {}

/* ---- */

/* This leads to an error in the prover:
 *
 * > An internal Prover error occurred, please double-check the provided configuration or command-line arguments, and see low-level crash details below:
 * > Unknown SerializedType 66/69/71
 * 
 * See eg: https://vaas-stg.certora.com/output/8195906/fa3f822ac85d453eb0ebc2fc9e769683?anonymousKey=6cf56e9729bddf5cc88453068197213a3838dd6e
 * 
 */

// /// Enum containing all relevant public bridge functions and their arguments
// public enum BridgeFun<phantom T> {
//   committee_registration {
//     system_state: sui_system::sui_system::SuiSystemState,
//     bridge_pubkey_bytes: vector<u8>,
//     http_rest_url: vector<u8>,
//   },
//   register_foreign_token { tc: TreasuryCap<T>, uc: UpgradeCap, metadata: CoinMetadata<T> },
//   send_token { target_chain: u8, target_address: vector<u8>, token: Coin<ETH> },
//   approve_token_transfer { message: BridgeMessage, signatures: vector<vector<u8>> },
//   claim_token { clock: Clock, source_chain: u8, bridge_seq_num: u64 },
//   claim_and_transfer_token { clock: Clock, source_chain: u8, bridge_seq_num: u64 },
//   execute_system_message { message: BridgeMessage, signatures: vector<vector<u8>> },
// }

// fun call<T>(fn:  BridgeFun<T>, bridge: &mut Bridge, ctx: &mut TxContext) {
//   match (fn) {
//     BridgeFun::committee_registration { mut system_state, bridge_pubkey_bytes, http_rest_url } => {
//       bridge.committee_registration(&mut system_state, bridge_pubkey_bytes, http_rest_url, ctx);
//       ghost_destroy(system_state);
//     },
//     BridgeFun::register_foreign_token { tc, uc, metadata } => {
//       bridge.register_foreign_token(tc, uc, &metadata);
//       ghost_destroy(metadata);
//     },
//     BridgeFun::send_token { target_chain, target_address, token } => {
//       bridge.send_token(target_chain, target_address, token, ctx);
//     },
//     BridgeFun::approve_token_transfer { message, signatures } => {
//       bridge.approve_token_transfer(message, signatures);
//     },
//     BridgeFun::claim_token { clock, source_chain, bridge_seq_num } => {
//       let c: Coin<T> = bridge.claim_token(&clock, source_chain, bridge_seq_num, ctx);
//       ghost_destroy(c);
//       ghost_destroy(clock);
//     },
//     BridgeFun::claim_and_transfer_token { clock, source_chain, bridge_seq_num } => {
//       bridge.claim_and_transfer_token<T>(&clock, source_chain, bridge_seq_num, ctx);
//       ghost_destroy(clock);
//     },
//     BridgeFun::execute_system_message { message, signatures } => {
//         bridge.execute_system_message(message, signatures);
//     },
//   }
// }

/* ----- */


/// Sending a token to the bridge destroys the token.
/// This is tracked using the `deleted()` function, that returns for any object-address whether is was deleted.
public fun send_token_burns_coin(
  bridge: &mut Bridge,
  target_chain: u8,
  target_address: vector<u8>,
  token: Coin<ETH>,
  ctx: &mut TxContext,
) {
  let token_address = object::borrow_id(&token).to_address();
  bridge.send_token(target_chain, target_address, token, ctx);
  cvlm_assert(*deleted(token_address));
}


/// If coins/tokens are minted, then either because "claim_token" or "claim_and_transfer_token" has been called
public fun only_claiming_mints_tokens(
  bridge: &mut Bridge,
  //fn: BridgeFun<ETH>,
  _ctx: &mut TxContext,
) {

  let balance_pre = get_total_supply<ETH>(bridge);

  //fn.call(bridge, ctx);

  let balance_post = get_total_supply<ETH>(bridge);

  if (balance_pre < balance_post) {
    //cvlm_assert(fn.name() == b"claim_token" || fn.name() == b"claim_and_transfer_token")
  }
}


/// If a call to "claim_token" succeeds, then the tx sender must be the owner of the tokens, 
/// as specified in the corresponding transfer record.
public fun only_owner_can_claim(
  bridge: &mut Bridge,
  clock: &Clock,
  ctx: &mut TxContext,
  source_chain: u8,
  bridge_seq_num: u64,
) {
  let c: Coin<ETH> = bridge.claim_token(clock, source_chain, bridge_seq_num, ctx);
  log(&c);

  let msg = bridge.test_get_parsed_token_transfer_message(source_chain, bridge_seq_num).destroy_some();
  let payload = get_transfer_payload(&msg);
  let target_address = payload.token_target_address();

  log(&ctx.sender());
  log( &target_address);
  
  let target = address::from_bytes(target_address);
  log(&target);

  // This fails because `target` here is different from  from the target_address when executing the claim function.
  // That should not happen.
  // 
  // My guess is that this is because the transfer record is stored as bytes that are deserialized in the `extract_token_bridge_payload` function.
  // Since the BCS summaries are nondet, they might be return different values for the same object.
  // It's hard to verify because the prover only shows the first 3 elements of a vector.
  cvlm_assert(target == ctx.sender());
  ghost_destroy(c)
}


/* 
  The following rule crashes with 
  
  > Got a conditional jump which is not conditional in 99_1_0_0_0_0: JumpiCmd 193_1_0_0_0_0 193_1_0_0_0_0 tacTmp57682:bool (4441:128:1:0x0) // bridge_rules.move

  https://vaas-stg.certora.com/output/8195906/e62daec033cb4c9c935702e4bfaa7c17?anonymousKey=4b3e1bc11acb35aac069added3b67bbbe97378fd
*/ 
/// If a new transfer records is registered at the bridge, then it either must be verified or the source chain is the bridge itself.
/// For now, verified here just checks that the list of signatures is not empty.
public fun transfer_records_are_valid(bridge: &mut Bridge,
  //fn: BridgeFun<ETH>,
  _ctx: &mut TxContext,
  msg: BridgeMessage,
  sigs: vector<vector<u8>>
  ) {
    let records_pre = bridge.test_load_inner().inner_token_transfer_records().length();

    // Instead call any method here:
    // fn.call(bridge, ctx)
    bridge.approve_token_transfer(msg, sigs);


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
      }else{
        false
      };
      

      // Must be verified exactly if self is inner chain id is not the source
      // (in lack of <=> operator)
      cvlm_assert((!self_is_source || is_verified) && (!is_verified || self_is_source))
    }
}

/// Asserts that sequence number never decrease
public fun seq_nums_monotonically_increase(
  bridge: &mut Bridge,
  //fn: BridgeFun<ETH>,
  _ctx: &mut TxContext,
) {
  let message_type: u8 = nondet();
  let seq_pre = bridge.get_seq_num_for(message_type);
  
  //fn.call(bridge, ctx);

  let seq_post = bridge.get_seq_num_for(message_type);
  cvlm_assert(seq_pre <= seq_post);
}


// #[rule]
public fun send_token_effects(
  bridge: &mut Bridge,
  target_chain: u8,
  target_address: vector<u8>,
  coin: Coin<ETH>,
  ctx: &mut TxContext,
) {
  cvlm_assume_msg(
    events_by_type<TokenDepositedEvent>().length() == 0,
    b"start with zero TokenDepositedEvent",
  );

  let coin_value = coin.value();
  let total_supply_before = get_total_supply<ETH>(bridge);

  let seq_num = bridge.get_seq_num_for(message_types::token());
  bridge.send_token(target_chain, target_address, coin, ctx);

  // verify reduction in total supply
  cvlm_assert(total_supply_before - coin_value == get_total_supply<ETH>(bridge));

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

  bridge.approve_token_transfer(message, signatures);

  // verify approval events
  let approved_events = events_by_type<TokenTransferApproved>();
  let already_approved_events = events_by_type<TokenTransferAlreadyApproved>();

  cvlm_assert(approved_events.length() + already_approved_events.length() == 1);

  let key = if (approved_events.length() == 1) {
    approved_events[0].transfer_approve_key()
  } else {
    already_approved_events[0].transfer_already_approved_key()
  };

  let (_sc, mt, sn) = key.unpack_message();

  cvlm_assert(mt == message_types::token());
  cvlm_assert(sn == message.seq_num());
}

// #[rule]
public fun claim_token_effects(
  bridge: &mut Bridge,
  clock: &Clock,
  source_chain: u8,
  bridge_seq_num: u64,
  ctx: &mut TxContext,
): Coin<ETH> {
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

  let total_supply_before = get_total_supply<ETH>(bridge);

  let token = bridge.claim_token<ETH>(clock, source_chain, bridge_seq_num, ctx);

  let token_value = token.value();
  cvlm_assert(total_supply_before + token_value == get_total_supply<ETH>(bridge));

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
    certora::sui_transfer_summaries::transfers<Coin<ETH>>().length() == 0,
    b"start with zero Sui transfers",
  );

  let total_supply_before = get_total_supply<ETH>(bridge);

  bridge.claim_and_transfer_token<ETH>(clock, source_chain, bridge_seq_num, ctx);

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

  let total_supply_after = get_total_supply<ETH>(bridge);

  let transfers = certora::sui_transfer_summaries::transfers<Coin<ETH>>();
  let mut total_value_transferred = 0;
  transfers.do_ref!(|transfer| {
    total_value_transferred = total_value_transferred + transfer.value().value();
  });
  cvlm_assert(total_supply_after == total_supply_before + total_value_transferred);
}
