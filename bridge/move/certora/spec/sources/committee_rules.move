// Copyright (c) Certora.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module spec::committee_rules {
	use bridge::{committee::BridgeCommittee, message::BridgeMessage};
	use cvlm::{asserts::cvlm_assert, manifest::{rule, target, target_sanity}};

	public fun cvlm_manifest() {
		target(@bridge, b"committee", b"verify_signatures");
		target_sanity();
		rule(b"verified_signatures_success_conditions");
	}

	const SUI_MESSAGE_PREFIX: vector<u8> = b"SUI_BRIDGE_MESSAGE";

	fun get_pubkey_from_signature(message: BridgeMessage, signature: &vector<u8>): vector<u8> {
		let mut message_bytes = SUI_MESSAGE_PREFIX;
		message_bytes.append(message.serialize_message());
		sui::ecdsa_k1::secp256k1_ecrecover(signature, &message_bytes, 0)
	}

	// #[rule]
	public fun verified_signatures_success_conditions(
		committee: &BridgeCommittee,
		message: BridgeMessage,
		signatures: vector<vector<u8>>,
	) {
		committee.verify_signatures(message, signatures);

		let mut total_voting_power = 0;
		signatures.do_ref!(|sig| {
			let member_key = get_pubkey_from_signature(message, sig);
			cvlm_assert(committee.members().contains(&member_key));
			let member = committee.members().get(&member_key);
			if (!member.blocklisted()) {
				total_voting_power = total_voting_power + member.voting_power();
			}
		});
		cvlm_assert(total_voting_power >= message.required_voting_power());
	}
}
