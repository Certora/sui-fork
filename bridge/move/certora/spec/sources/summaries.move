// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
#[allow(unused_function)]
module spec::summaries {
	use cvlm::{asserts::cvlm_assume_msg, manifest::{summary, ghost}};

	public fun cvlm_manifest() {
		ghost(b"peel_u64_be");
		ghost(b"map_ecdsa_pub_key_to_eth_address");
		summary(b"peel_u64_be", @bridge, b"message", b"peel_u64_be");
		summary(b"ecdsa_pub_key_to_eth_address", @bridge, b"crypto", b"ecdsa_pub_key_to_eth_address");
	}

	// #[summary(bridge::message::peel_u64_be), ghost]
	native fun peel_u64_be(_: &mut sui::bcs::BCS): u64;

	native fun map_ecdsa_pub_key_to_eth_address(compressed_pub_key: &vector<u8>): vector<u8>;

	fun ecdsa_pub_key_to_eth_address(compressed_pub_key: &vector<u8>): vector<u8> {
		let vec = map_ecdsa_pub_key_to_eth_address(compressed_pub_key);
		cvlm_assume_msg(vec.length() == 32, b"ecdsa_pub_key_to_eth_address returns 32 bytes");
		vec
	}
}
