#[test_only]
#[allow(unused_function)]
module bridge::certora_rules_committee;

use bridge::committee::BridgeCommittee;
use bridge::message::BridgeMessage;

use cvlm::asserts::cvlm_assert;
use cvlm::manifest::rule;

public fun cvlm_manifest() {
    rule(b"verified_signatures_not_blocklisted");
}

const SUI_MESSAGE_PREFIX: vector<u8> = b"SUI_BRIDGE_MESSAGE";

fun get_pubkey_from_signature(
    message: BridgeMessage,
    signature: vector<u8>
): vector<u8> {
    let mut message_bytes = SUI_MESSAGE_PREFIX;
    message_bytes.append(message.serialize_message());
    sui::ecdsa_k1::secp256k1_ecrecover(&signature, &message_bytes, 0)
}

// #[rule]
public fun verified_signatures_not_blocklisted(
    committee: &BridgeCommittee,
    message: BridgeMessage,
    signatures: vector<vector<u8>>,
) {
    committee.verify_signatures(message, signatures);

    signatures.do!(|sig| {
        let member_key = get_pubkey_from_signature(message, sig);
        let member = committee.members().get(&member_key);
        cvlm_assert!(!member.blocklisted());
    });
}
