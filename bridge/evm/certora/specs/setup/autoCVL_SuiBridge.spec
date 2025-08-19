import "dispatching_SuiBridge.spec";
import "setup_BridgeConfig.spec";
import "snippet_BridgeUtils.spec";
import "snippet_loopSummaries.spec";
import "snippet_uups.spec";

/*
 * _committee == address(0) || _vault == address(0) || _limiter == address(0) => revert
 *
 * What it means: The initialize function must revert if any of the three address parameters (_committee, _vault, _limiter) is the zero address
 *
 * Why it should hold: These three addresses are critical infrastructure components that the bridge depends on for committee verification, token storage, and rate limiting. Zero addresses would make these components non-functional
 *
 * Possible consequences: Complete bridge malfunction, inability to process transfers, loss of access control, and potential fund loss due to non-functional vault or limiter
 */
rule initialize_zero_addresses_revert_1(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _vault, _limiter);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((((_committee == 0) || (_vault == 0)) || (_limiter == 0)) => initialize_reverted);
}

/*
 * committee != address(0) => revert
 *
 * What it means: The initialize function must revert if the contract has already been initialized (committee address is not zero)
 *
 * Why it should hold: This is a standard initializer pattern to prevent re-initialization attacks on upgradeable contracts, ensuring the contract can only be initialized once
 *
 * Possible consequences: Re-initialization attacks where an attacker could reset critical addresses to malicious contracts they control, leading to complete compromise of the bridge
 */
rule initialize_already_initialized_reverts_2(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables
    address committee_before = currentContract.committee;

    // call function under test
    initialize@withrevert(e, _committee, _vault, _limiter);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee_before != 0) => initialize_reverted);
}

/*
 * _committee != address(0) && committee == address(0) => committee@after == _committee
 *
 * What it means: When initializing with a valid committee address and the contract is not already initialized, the committee storage variable must be set to the provided address
 *
 * Why it should hold: The committee is responsible for signature verification and bridge governance. Proper initialization ensures the bridge can verify validator signatures for cross-chain transfers
 *
 * Possible consequences: Bridge operations would fail due to inability to verify signatures, making cross-chain transfers impossible and potentially locking user funds
 */
rule initialize_sets_committee_address_3(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables
    address committee_before = currentContract.committee;

    // call function under test
    initialize(e, _committee, _vault, _limiter);

    // assign all the 'after' variables
    address committee_after = currentContract.committee;

    // verify integrity
    assert (((_committee != 0) && (committee_before == 0)) => (committee_after == _committee));
}

/*
 * _vault != address(0) && committee == address(0) => vault@after == _vault
 *
 * What it means: When initializing with a valid vault address and the contract is not already initialized, the vault storage variable must be set to the provided address
 *
 * Why it should hold: The vault is where all bridged tokens are stored and managed. Without a proper vault address, the bridge cannot hold or transfer tokens
 *
 * Possible consequences: Complete inability to handle token deposits and withdrawals, leading to fund loss and bridge malfunction
 */
rule initialize_sets_vault_address_4(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables
    address committee_before = currentContract.committee;

    // call function under test
    initialize(e, _committee, _vault, _limiter);

    // assign all the 'after' variables
    address vault_after = currentContract.vault;

    // verify integrity
    assert (((_vault != 0) && (committee_before == 0)) => (vault_after == _vault));
}

/*
 * _limiter != address(0) && committee == address(0) => limiter@after == _limiter
 *
 * What it means: When initializing with a valid limiter address and the contract is not already initialized, the limiter storage variable must be set to the provided address
 *
 * Why it should hold: The limiter enforces rate limits and transfer amounts to prevent abuse and large-scale attacks. Without proper initialization, these security measures would be bypassed
 *
 * Possible consequences: Unlimited token withdrawals, potential for large-scale fund drainage, and loss of security controls designed to prevent bridge abuse
 */
rule initialize_sets_limiter_address_5(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables
    address committee_before = currentContract.committee;

    // call function under test
    initialize(e, _committee, _vault, _limiter);

    // assign all the 'after' variables
    address limiter_after = currentContract.limiter;

    // verify integrity
    assert (((_limiter != 0) && (committee_before == 0)) => (limiter_after == _limiter));
}

/*
 * isTransferProcessed[message.nonce] => revert
 *
 * What it means: If a message with a specific nonce has already been processed (isTransferProcessed[message.nonce] is true), the function must revert
 *
 * Why it should hold: The contract uses nonces to prevent replay attacks. Once a transfer message is processed, it should never be processed again to prevent double-spending
 *
 * Possible consequences: Fund loss through replay attacks where the same transfer message can be executed multiple times, draining the vault
 */
rule transferBridgedTokensWithSignatures_duplicate_nonce_reverts_6(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 message_nonce_before = message.nonce;
    bool isTransferProcessed_message_nonce_before__before = currentContract.isTransferProcessed[message_nonce_before];

    // call function under test
    transferBridgedTokensWithSignatures@withrevert(e, signatures, message);
    bool transferBridgedTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (isTransferProcessed_message_nonce_before__before => transferBridgedTokensWithSignatures_reverted);
}

/*
 * message.messageType != BridgeUtils.TOKEN_TRANSFER => revert
 *
 * What it means: If the message type is not BridgeUtils.TOKEN_TRANSFER, the function must revert since this function only handles token transfers
 *
 * Why it should hold: This function is specifically designed for token transfers only. Other message types should be handled by different functions
 *
 * Possible consequences: State corruption and unexpected behavior if emergency operations or other message types are processed through the wrong function
 */
rule transferBridgedTokensWithSignatures_invalid_message_type_reverts_7(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_messageType_before = message.messageType;

    // call function under test
    transferBridgedTokensWithSignatures@withrevert(e, signatures, message);
    bool transferBridgedTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message_messageType_before != 0) => transferBridgedTokensWithSignatures_reverted);
}

/*
 * !committee.config().isChainSupported(message.chainID) => revert
 *
 * What it means: If the source chain ID in the message is not supported by the bridge configuration, the function must revert
 *
 * Why it should hold: The bridge only operates with pre-approved chains to ensure security and prevent unauthorized cross-chain transfers
 *
 * Possible consequences: Acceptance of transfers from malicious or compromised chains, potentially allowing attackers to mint tokens without proper backing
 */
rule transferBridgedTokensWithSignatures_unsupported_chain_reverts_8(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_chainID_before = message.chainID;
    bool committee_config_e__isChainSupported_e__message_chainID_before__before = currentContract.committee.config(e).isChainSupported(e, message_chainID_before);

    // call function under test
    transferBridgedTokensWithSignatures@withrevert(e, signatures, message);
    bool transferBridgedTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(committee_config_e__isChainSupported_e__message_chainID_before__before) => transferBridgedTokensWithSignatures_reverted);
}

/*
 * paused() => revert
 *
 * What it means: If the contract is in a paused state, the function must revert and not process any transfers
 *
 * Why it should hold: The pause mechanism is a critical safety feature to halt operations during emergencies or security incidents
 *
 * Possible consequences: Continued operation during security incidents, preventing emergency response and potentially allowing exploitation to continue
 */
rule transferBridgedTokensWithSignatures_paused_state_reverts_9(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);

    // call function under test
    transferBridgedTokensWithSignatures@withrevert(e, signatures, message);
    bool transferBridgedTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (paused_e__before => transferBridgedTokensWithSignatures_reverted);
}

/*
 * !isTransferProcessed[message.nonce] && message.messageType == BridgeUtils.TOKEN_TRANSFER && committee.config().isChainSupported(message.chainID) && !paused() => isTransferProcessed[message.nonce]@after == true
 *
 * What it means: When all conditions are met for a valid transfer, the nonce must be marked as processed to prevent future replay
 *
 * Why it should hold: This ensures that successfully processed transfers cannot be replayed, maintaining the one-to-one correspondence between source and destination transfers
 *
 * Possible consequences: Replay attacks become possible if nonces are not properly marked, leading to multiple withdrawals for single deposits
 */
rule transferBridgedTokensWithSignatures_valid_transfer_marks_processed_10(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 message_nonce_before = message.nonce;
    bool isTransferProcessed_message_nonce_before__before = currentContract.isTransferProcessed[message_nonce_before];
    uint8 message_messageType_before = message.messageType;
    uint8 message_chainID_before = message.chainID;
    bool committee_config_e__isChainSupported_e__message_chainID_before__before = currentContract.committee.config(e).isChainSupported(e, message_chainID_before);
    bool paused_e__before = paused(e);

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool isTransferProcessed_message_nonce_before__after = currentContract.isTransferProcessed[message_nonce_before];

    // verify integrity
    assert ((((!(isTransferProcessed_message_nonce_before__before) && (message_messageType_before == 0)) && committee_config_e__isChainSupported_e__message_chainID_before__before) && !(paused_e__before)) => (isTransferProcessed_message_nonce_before__after == true));
}

/*
 * nonce1 != nonce2 && isTransferProcessed[nonce1] => !isTransferProcessed[nonce2] || isTransferProcessed[nonce2]@before
 *
 * What it means: Each nonce can only be marked as processed once, ensuring that different nonces maintain their unique processed status
 *
 * Why it should hold: Nonce uniqueness is fundamental to preventing replay attacks and maintaining the integrity of the transfer tracking system
 *
 * Possible consequences: Nonce collision or confusion could allow replay attacks or prevent legitimate transfers from being processed
 */
rule transferBridgedTokensWithSignatures_processed_nonces_stay_unique_11(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint64 nonce1;
    uint64 nonce2;

    // assign all the 'before' variables
    bool isTransferProcessed_nonce1__before = currentContract.isTransferProcessed[nonce1];
    bool isTransferProcessed_nonce2__before = currentContract.isTransferProcessed[nonce2];

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables

    // verify integrity
    assert (((nonce1 != nonce2) && isTransferProcessed_nonce1__before) => (!(isTransferProcessed_nonce2__before) || isTransferProcessed_nonce2__before));
}

/*
 * message.messageType != BridgeUtils.EMERGENCY_OP => revert
 *
 * What it means: The function must revert if the message type is not EMERGENCY_OP, ensuring only emergency operation messages are processed
 *
 * Why it should hold: This function is specifically designed to handle emergency operations only. Processing other message types would violate the function's intended purpose and could lead to incorrect state changes
 *
 * Possible consequences: Wrong message types could be processed as emergency operations, leading to incorrect state changes or bypassing proper validation logic for other operation types
 */
rule executeEmergencyOpWithSignatures_invalid_message_type_reverts_12(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_messageType_before = message.messageType;

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message_messageType_before != 2) => executeEmergencyOpWithSignatures_reverted);
}

/*
 * isTransferProcessed[message.nonce] => revert
 *
 * What it means: The function must revert if the message nonce has already been processed, preventing replay attacks
 *
 * Why it should hold: Each emergency operation message should only be executed once. Allowing replay of the same nonce could lead to duplicate emergency operations being executed
 *
 * Possible consequences: Replay attacks could allow the same emergency operation to be executed multiple times, potentially causing unintended state changes or resource exhaustion
 */
rule executeEmergencyOpWithSignatures_processed_nonce_reverts_13(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 message_nonce_before = message.nonce;
    bool isTransferProcessed_message_nonce_before__before = currentContract.isTransferProcessed[message_nonce_before];

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (isTransferProcessed_message_nonce_before__before => executeEmergencyOpWithSignatures_reverted);
}

/*
 * !committee.config().isChainSupported(message.chainID) => revert
 *
 * What it means: The function must revert if the chain ID in the message is not supported by the bridge configuration
 *
 * Why it should hold: Emergency operations should only be processed for supported chains to maintain consistency with the bridge's operational scope and prevent operations on unsupported networks
 *
 * Possible consequences: Emergency operations could be executed for unsupported chains, potentially causing inconsistent state or wasting resources on chains the bridge doesn't operate on
 */
rule executeEmergencyOpWithSignatures_unsupported_chain_reverts_14(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_chainID_before = message.chainID;
    bool committee_config_e__isChainSupported_e__message_chainID_before__before = currentContract.committee.config(e).isChainSupported(e, message_chainID_before);

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(committee_config_e__isChainSupported_e__message_chainID_before__before) => executeEmergencyOpWithSignatures_reverted);
}

/*
 * !isTransferProcessed[message.nonce]@before => isTransferProcessed[message.nonce]@after
 *
 * What it means: When a valid emergency operation is executed, the message nonce must be marked as processed in the isTransferProcessed mapping
 *
 * Why it should hold: This prevents replay attacks by ensuring each emergency operation can only be executed once. The nonce tracking is essential for maintaining operation uniqueness
 *
 * Possible consequences: If nonces aren't marked as processed, the same emergency operation could be replayed multiple times, leading to unintended repeated state changes
 */
rule executeEmergencyOpWithSignatures_marks_nonce_as_processed_15(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 message_nonce_before = message.nonce;
    bool isTransferProcessed_message_nonce_before__before = currentContract.isTransferProcessed[message_nonce_before];

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool isTransferProcessed_message_nonce_before__after = currentContract.isTransferProcessed[message_nonce_before];

    // verify integrity
    assert (!(isTransferProcessed_message_nonce_before__before) => isTransferProcessed_message_nonce_before__after);
}

/*
 * nonces[BridgeUtils.EMERGENCY_OP]@after == nonces[BridgeUtils.EMERGENCY_OP]@before + 1
 *
 * What it means: The emergency operation nonce counter must be incremented after successfully processing an emergency operation
 *
 * Why it should hold: Nonce incrementation ensures each emergency operation has a unique identifier and maintains proper sequencing of operations for tracking and preventing replays
 *
 * Possible consequences: Without proper nonce incrementation, emergency operations might not be properly sequenced, potentially leading to confusion in operation tracking or replay vulnerabilities
 */
rule executeEmergencyOpWithSignatures_increments_emergency_op_nonce_16(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 nonces_2__before = currentContract.nonces[2];

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 nonces_2__after = currentContract.nonces[2];

    // verify integrity
    assert (nonces_2__after == nonces_2__before + 1);
}

/*
 * messageType != BridgeUtils.EMERGENCY_OP => nonces[messageType]@after == nonces[messageType]@before
 *
 * What it means: Nonces for other message types (like TOKEN_TRANSFER) should remain unchanged when processing emergency operations
 *
 * Why it should hold: Emergency operations should only affect their own nonce counter and not interfere with other operation types' sequencing to maintain proper isolation between different bridge functions
 *
 * Possible consequences: If other nonces are incorrectly modified, it could disrupt the sequencing of other bridge operations like token transfers, potentially causing operational confusion
 */
rule executeEmergencyOpWithSignatures_other_nonces_unchanged_17(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 messageType;

    // assign all the 'before' variables
    uint64 nonces_messageType__before = currentContract.nonces[messageType];

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 nonces_messageType__after = currentContract.nonces[messageType];

    // verify integrity
    assert ((messageType != 2) => (nonces_messageType__after == nonces_messageType__before));
}

/*
 * vault@after == vault@before
 *
 * What it means: The vault contract address should not be modified during emergency operation execution
 *
 * Why it should hold: The vault address is a critical infrastructure component that should only be changed through proper upgrade procedures, not through emergency operations which are meant for operational controls
 *
 * Possible consequences: Unauthorized vault address changes could redirect funds to malicious contracts or break the bridge's token management functionality
 */
rule executeEmergencyOpWithSignatures_vault_address_unchanged_18(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address vault_before = currentContract.vault;

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address vault_after = currentContract.vault;

    // verify integrity
    assert (vault_after == vault_before);
}

/*
 * limiter@after == limiter@before
 *
 * What it means: The limiter contract address should not be modified during emergency operation execution
 *
 * Why it should hold: The limiter address controls bridge transfer limits and should only be changed through proper governance procedures, not emergency operations which are for immediate operational responses
 *
 * Possible consequences: Unauthorized limiter changes could remove transfer limits or redirect limit checks to malicious contracts, enabling unlimited withdrawals or other limit bypass attacks
 */
rule executeEmergencyOpWithSignatures_limiter_address_unchanged_19(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address limiter_before = currentContract.limiter;

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address limiter_after = currentContract.limiter;

    // verify integrity
    assert (limiter_after == limiter_before);
}

/*
 * committee@after == committee@before
 *
 * What it means: The committee contract address should not be modified during emergency operation execution
 *
 * Why it should hold: The committee address controls authorization and governance for the bridge and should only be changed through proper upgrade procedures, not emergency operations
 *
 * Possible consequences: Unauthorized committee changes could transfer control of the bridge to malicious actors or break the authorization system entirely
 */
rule executeEmergencyOpWithSignatures_committee_address_unchanged_20(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address committee_before = currentContract.committee;

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address committee_after = currentContract.committee;

    // verify integrity
    assert (committee_after == committee_before);
}

/*
 * amount <= 0 => revert
 *
 * What it means: The function must revert when the amount parameter is zero or negative
 *
 * Why it should hold: Zero or negative amounts represent meaningless operations that waste gas and could be used to spam the bridge or manipulate nonce counters without transferring actual value
 *
 * Possible consequences: DoS attacks through gas-wasting spam transactions, nonce manipulation, and potential accounting inconsistencies in bridge operations
 */
rule bridgeERC20_invalid_amount_reverts_21(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount <= 0) => bridgeERC20_reverted);
}

/*
 * committee.config().tokenAddressOf(tokenID) == address(0) => revert
 *
 * What it means: The function must revert when the tokenID maps to address(0) in the bridge configuration
 *
 * Why it should hold: Address(0) indicates an unsupported or misconfigured token, and attempting to bridge such tokens would fail in subsequent operations or lead to undefined behavior
 *
 * Possible consequences: Fund loss through failed transfers, state corruption in bridge accounting, and potential exploitation of undefined token handling behavior
 */
rule bridgeERC20_unsupported_token_reverts_22(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    address committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee_config_e__tokenAddressOf_e__tokenID__before == 0) => bridgeERC20_reverted);
}

/*
 * recipientAddress.length != 32 => revert
 *
 * What it means: The function must revert when the recipient address length is not exactly 32 bytes (SUI_ADDRESS_LENGTH)
 *
 * Why it should hold: Sui addresses must be exactly 32 bytes long, and invalid recipient addresses would cause failed transfers on the destination chain
 *
 * Possible consequences: Fund loss through undeliverable transfers, stuck funds in the bridge, and failed cross-chain operations
 */
rule bridgeERC20_invalid_recipient_reverts_23(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    uint256 recipientAddress_length_before = recipientAddress.length;

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress_length_before != 32) => bridgeERC20_reverted);
}

/*
 * paused() => revert
 *
 * What it means: The function must revert when the contract is in a paused state
 *
 * Why it should hold: The whenNotPaused modifier is applied to prevent operations during emergency situations or maintenance periods
 *
 * Possible consequences: Bypass of emergency controls, continued operations during security incidents, and potential fund loss during vulnerable states
 */
rule bridgeERC20_paused_state_reverts_24(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (paused_e__before => bridgeERC20_reverted);
}

/*
 * !committee.config().isChainSupported(destinationChainID) => revert
 *
 * What it means: The function must revert when the destination chain ID is not supported by the bridge configuration
 *
 * Why it should hold: The onlySupportedChain modifier ensures tokens are only bridged to chains where the bridge infrastructure exists and is operational
 *
 * Possible consequences: Fund loss through transfers to non-existent or unsupported chains, stuck tokens, and failed cross-chain operations
 */
rule bridgeERC20_unsupported_chain_reverts_25(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(committee_config_e__isChainSupported_e__destinationChainID__before) => bridgeERC20_reverted);
}

/*
 * limiter.willAmountExceedLimit(destinationChainID, tokenID, amount) => revert
 *
 * What it means: The function must revert when the transfer amount would exceed the bridge's rate limiting thresholds
 *
 * Why it should hold: Rate limiting prevents large-scale fund drainage and protects against both malicious attacks and operational errors
 *
 * Possible consequences: Bypass of security controls, large-scale fund drainage, and potential bridge insolvency during attacks
 */
rule bridgeERC20_exceeds_limit_reverts_26(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before = currentContract.limiter.willAmountExceedLimit(e, destinationChainID, tokenID, amount);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before => bridgeERC20_reverted);
}

/*
 * IERC20(committee.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this)) < amount => revert
 *
 * What it means: The function must revert when the caller hasn't approved sufficient tokens for the bridge contract to transfer
 *
 * Why it should hold: ERC20 transfers require prior approval, and insufficient allowance would cause the transfer to fail, potentially leaving the bridge in an inconsistent state
 *
 * Possible consequences: Failed token transfers leading to inconsistent bridge state, potential reentrancy issues, and user funds being stuck
 */
rule bridgeERC20_insufficient_allowance_reverts_27(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    address committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before = committee_config_e__tokenAddressOf_e__tokenID__before.allowance(e, e.msg.sender, currentContract);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before < amount) => bridgeERC20_reverted);
}

/*
 * IERC20(committee.config().tokenAddressOf(tokenID)).balanceOf(msg.sender) < amount => revert
 *
 * What it means: The function must revert when the caller doesn't have enough tokens in their balance to complete the transfer
 *
 * Why it should hold: Attempting to transfer more tokens than available would cause the ERC20 transfer to fail, potentially corrupting bridge state
 *
 * Possible consequences: Failed transfers with partial state updates, bridge accounting errors, and potential exploitation of inconsistent states
 */
rule bridgeERC20_insufficient_balance_reverts_28(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    address committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before = committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before < amount) => bridgeERC20_reverted);
}

/*
 * amount > 0 && !paused() && committee.config().tokenAddressOf(tokenID) != address(0) && recipientAddress.length == 32 && committee.config().isChainSupported(destinationChainID) && !limiter.willAmountExceedLimit(destinationChainID, tokenID, amount) => IERC20(committee.config().tokenAddressOf(tokenID)).balanceOf(address(vault))@after == IERC20(committee.config().tokenAddressOf(tokenID)).balanceOf(address(vault))@before + amount
 *
 * What it means: When all conditions are met for a successful transfer, the vault's token balance must increase by the transferred amount
 *
 * Why it should hold: The bridge must properly custody deposited tokens in the vault for later withdrawal on other chains
 *
 * Possible consequences: Fund loss through tokens not being properly stored, accounting errors, and bridge insolvency
 */
rule bridgeERC20_valid_transfer_updates_vault_29(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    address committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 recipientAddress_length_before = recipientAddress.length;
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    bool limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before = currentContract.limiter.willAmountExceedLimit(e, destinationChainID, tokenID, amount);
    address vault_before = currentContract.vault;
    uint256 committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__vault_before__before = committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, vault_before);

    // call function under test
    bridgeERC20(e, tokenID, amount, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint256 committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__vault_before__after = committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, vault_before);

    // verify integrity
    assert (((((((amount > 0) && !(paused_e__before)) && (committee_config_e__tokenAddressOf_e__tokenID__before != 0)) && (recipientAddress_length_before == 32)) && committee_config_e__isChainSupported_e__destinationChainID__before) && !(limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before)) => (committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__vault_before__after == committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__vault_before__before + amount));
}

/*
 * amount > 0 && !paused() && committee.config().tokenAddressOf(tokenID) != address(0) && recipientAddress.length == 32 && committee.config().isChainSupported(destinationChainID) && !limiter.willAmountExceedLimit(destinationChainID, tokenID, amount) => IERC20(committee.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@after == IERC20(committee.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before - amount
 *
 * What it means: When all conditions are met for a successful transfer, the sender's token balance must decrease by the transferred amount
 *
 * Why it should hold: The sender must actually pay the tokens they claim to be bridging to prevent double-spending and maintain proper accounting
 *
 * Possible consequences: Double-spending attacks, bridge accounting errors, and unlimited token minting through failed deductions
 */
rule bridgeERC20_valid_transfer_updates_sender_30(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    address committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 recipientAddress_length_before = recipientAddress.length;
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    bool limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before = currentContract.limiter.willAmountExceedLimit(e, destinationChainID, tokenID, amount);
    uint256 committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before = committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);

    // call function under test
    bridgeERC20(e, tokenID, amount, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint256 committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__after = committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);

    // verify integrity
    assert (((((((amount > 0) && !(paused_e__before)) && (committee_config_e__tokenAddressOf_e__tokenID__before != 0)) && (recipientAddress_length_before == 32)) && committee_config_e__isChainSupported_e__destinationChainID__before) && !(limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before)) => (committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__after == committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before - amount));
}

/*
 * amount > 0 && !paused() && committee.config().tokenAddressOf(tokenID) != address(0) && recipientAddress.length == 32 && committee.config().isChainSupported(destinationChainID) && !limiter.willAmountExceedLimit(destinationChainID, tokenID, amount) => nonces[0]@after == nonces[0]@before + 1
 *
 * What it means: When a transfer succeeds, the token transfer nonce must increment by exactly 1
 *
 * Why it should hold: Nonces ensure unique identification of bridge operations and prevent replay attacks on cross-chain messages
 *
 * Possible consequences: Replay attacks, duplicate transfers, and cross-chain message confusion leading to fund loss or double-spending
 */
rule bridgeERC20_nonce_increments_on_success_31(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    address committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 recipientAddress_length_before = recipientAddress.length;
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    bool limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before = currentContract.limiter.willAmountExceedLimit(e, destinationChainID, tokenID, amount);
    uint64 nonces_0__before = currentContract.nonces[0];

    // call function under test
    bridgeERC20(e, tokenID, amount, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint64 nonces_0__after = currentContract.nonces[0];

    // verify integrity
    assert (((((((amount > 0) && !(paused_e__before)) && (committee_config_e__tokenAddressOf_e__tokenID__before != 0)) && (recipientAddress_length_before == 32)) && committee_config_e__isChainSupported_e__destinationChainID__before) && !(limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before)) => (nonces_0__after == nonces_0__before + 1));
}

/*
 * amount <= 0 || paused() || committee.config().tokenAddressOf(tokenID) == address(0) || recipientAddress.length != 32 || !committee.config().isChainSupported(destinationChainID) || limiter.willAmountExceedLimit(destinationChainID, tokenID, amount) => nonces[0]@after == nonces[0]@before
 *
 * What it means: When the function reverts due to any validation failure, the nonce must remain unchanged
 *
 * Why it should hold: Failed operations should not consume nonces to prevent gaps in the sequence and maintain proper cross-chain message ordering
 *
 * Possible consequences: Nonce sequence corruption, failed cross-chain message processing, and potential bridge operation failures
 */
rule bridgeERC20_no_nonce_change_on_revert_32(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    address committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 recipientAddress_length_before = recipientAddress.length;
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    bool limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before = currentContract.limiter.willAmountExceedLimit(e, destinationChainID, tokenID, amount);
    uint64 nonces_0__before = currentContract.nonces[0];

    // call function under test
    bridgeERC20(e, tokenID, amount, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint64 nonces_0__after = currentContract.nonces[0];

    // verify integrity
    assert (((((((amount <= 0) || paused_e__before) || (committee_config_e__tokenAddressOf_e__tokenID__before == 0)) || (recipientAddress_length_before != 32)) || !(committee_config_e__isChainSupported_e__destinationChainID__before)) || limiter_willAmountExceedLimit_e__destinationChainID__tokenID__amount__before) => (nonces_0__after == nonces_0__before));
}

/*
 * recipientAddress.length != 32 => revert
 *
 * What it means: The function must revert if the recipient address length is not exactly 32 bytes
 *
 * Why it should hold: The contract has a constant SUI_ADDRESS_LENGTH = 32 and requires recipientAddress.length == SUI_ADDRESS_LENGTH for Sui chain addresses
 *
 * Possible consequences: Invalid addresses could cause funds to be lost permanently on the destination chain or cause bridge operations to fail
 */
rule bridgeETH_invalid_recipient_address_length_33(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    uint256 recipientAddress_length_before = recipientAddress.length;

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress_length_before != 32) => bridgeETH_reverted);
}

/*
 * !committee.config().isChainSupported(destinationChainID) => revert
 *
 * What it means: The function must revert if the destination chain ID is not supported by the bridge configuration
 *
 * Why it should hold: The onlySupportedChain modifier requires committee.config().isChainSupported(destinationChainID) to be true
 *
 * Possible consequences: Funds could be locked in the bridge if sent to unsupported chains that cannot process the bridge messages
 */
rule bridgeETH_unsupported_destination_chain_34(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(committee_config_e__isChainSupported_e__destinationChainID__before) => bridgeETH_reverted);
}

/*
 * msg.value == 0 => revert
 *
 * What it means: The function must revert when msg.value is zero, preventing meaningless operations
 *
 * Why it should hold: Transferring 0 ETH serves no purpose and should be prevented as a no-op operation that wastes gas and creates unnecessary events
 *
 * Possible consequences: Gas waste, spam transactions, and potential DoS through flooding the bridge with meaningless operations
 */
rule bridgeETH_zero_value_transfer_35(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.value == 0) => bridgeETH_reverted);
}

/*
 * paused() => revert
 *
 * What it means: The function must revert when the contract is in a paused state
 *
 * Why it should hold: The whenNotPaused modifier requires the contract to not be paused for bridge operations to proceed
 *
 * Possible consequences: Bridge operations could continue during emergency situations when they should be halted
 */
rule bridgeETH_contract_paused_36(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (paused_e__before => bridgeETH_reverted);
}

/*
 * msg.value > 0 && recipientAddress.length == 32 && committee.config().isChainSupported(destinationChainID) && !paused() => nonces[BridgeUtils.TOKEN_TRANSFER]@after == nonces[BridgeUtils.TOKEN_TRANSFER]@before + 1
 *
 * What it means: When all conditions are met for a successful bridge operation, the TOKEN_TRANSFER nonce must increment by exactly 1
 *
 * Why it should hold: The contract increments nonces[BridgeUtils.TOKEN_TRANSFER]++ at the end of successful bridgeERC20 operations, and bridgeETH should behave similarly
 *
 * Possible consequences: Nonce tracking corruption could lead to message replay attacks or inability to process legitimate bridge messages
 */
rule bridgeETH_nonce_increments_on_success_37(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    uint256 recipientAddress_length_before = recipientAddress.length;
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    bool paused_e__before = paused(e);
    uint64 nonces_0__before = currentContract.nonces[0];

    // call function under test
    bridgeETH(e, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint64 nonces_0__after = currentContract.nonces[0];

    // verify integrity
    assert (((((e.msg.value > 0) && (recipientAddress_length_before == 32)) && committee_config_e__isChainSupported_e__destinationChainID__before) && !(paused_e__before)) => (nonces_0__after == nonces_0__before + 1));
}

/*
 * msg.value > 0 && recipientAddress.length == 32 && committee.config().isChainSupported(destinationChainID) && !paused() => address(vault).balance@after == address(vault).balance@before + msg.value
 *
 * What it means: When a successful ETH bridge operation occurs, the vault's ETH balance must increase by exactly the msg.value amount
 *
 * Why it should hold: The bridged ETH must be securely stored in the vault for later withdrawal operations, similar to how bridgeERC20 transfers tokens to the vault
 *
 * Possible consequences: ETH could be lost, stolen, or not properly accounted for in the bridge system
 */
rule bridgeETH_vault_receives_exact_eth_38(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    uint256 recipientAddress_length_before = recipientAddress.length;
    bool committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    bool paused_e__before = paused(e);
    address vault_before = currentContract.vault;
    uint256 vault_before_balance_before = nativeBalances[vault_before];

    // call function under test
    bridgeETH(e, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint256 vault_before_balance_after = nativeBalances[vault_before];

    // verify integrity
    assert (((((e.msg.value > 0) && (recipientAddress_length_before == 32)) && committee_config_e__isChainSupported_e__destinationChainID__before) && !(paused_e__before)) => (vault_before_balance_after == vault_before_balance_before + e.msg.value));
}


using BridgeUtils as BridgeUtils;

/*
 * _committee == address(0) || _vault == address(0) || _limiter == address(0) => revert
 *
 * What it means: The initialize function must revert if any of the three address parameters (_committee, _vault, or _limiter) is the zero address
 *
 * Why it should hold: Zero addresses are invalid for critical contract dependencies. The bridge relies on these contracts for core functionality - committee for signature verification, vault for token storage, and limiter for transfer limits. Setting any to zero address would break the bridge
 *
 * Possible consequences: Complete bridge failure, inability to process transfers, loss of access control, potential fund lock-up in vault
 */
rule initialize_c0c53b8b_zero_addresses_revert(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _vault, _limiter);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((((_committee == 0) || (_vault == 0)) || (_limiter == 0)) => initialize_reverted), "_committee == address(0) || _vault == address(0) || _limiter == address(0) => revert";
}

/*
 * _committee != address(0) && _vault != address(0) && _limiter != address(0) => committee@after == _committee
 *
 * What it means: When all three addresses are non-zero, the committee storage variable must be set to the _committee parameter value
 *
 * Why it should hold: The committee address is critical for signature verification in bridge operations. It must be properly set during initialization to enable the bridge to verify validator signatures for token transfers and emergency operations
 *
 * Possible consequences: Bridge operations fail, signature verification breaks, inability to process legitimate transfers
 */
rule initialize_c0c53b8b_sets_committee(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _vault, _limiter);

    // assign all the 'after' variables
    address currentContract_committee_after = currentContract.committee;

    // verify integrity
    assert ((((_committee != 0) && (_vault != 0)) && (_limiter != 0)) => (currentContract_committee_after == _committee)), "_committee != address(0) && _vault != address(0) && _limiter != address(0) => committee@after == _committee";
}

/*
 * _committee != address(0) && _vault != address(0) && _limiter != address(0) => vault@after == _vault
 *
 * What it means: When all three addresses are non-zero, the vault storage variable must be set to the _vault parameter value
 *
 * Why it should hold: The vault contract holds all bridged tokens and ETH. The bridge must know the correct vault address to transfer tokens to users during withdrawals and to deposit tokens during bridging operations
 *
 * Possible consequences: Inability to transfer tokens from vault, failed withdrawals, tokens sent to wrong address
 */
rule initialize_c0c53b8b_sets_vault(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _vault, _limiter);

    // assign all the 'after' variables
    address currentContract_vault_after = currentContract.vault;

    // verify integrity
    assert ((((_committee != 0) && (_vault != 0)) && (_limiter != 0)) => (currentContract_vault_after == _vault)), "_committee != address(0) && _vault != address(0) && _limiter != address(0) => vault@after == _vault";
}

/*
 * _committee != address(0) && _vault != address(0) && _limiter != address(0) => limiter@after == _limiter
 *
 * What it means: When all three addresses are non-zero, the limiter storage variable must be set to the _limiter parameter value
 *
 * Why it should hold: The limiter contract enforces daily transfer limits to prevent abuse and large-scale fund drainage. Without proper limiter setup, the bridge cannot enforce these critical security limits
 *
 * Possible consequences: No transfer limits enforced, potential for unlimited fund drainage, security bypass
 */
rule initialize_c0c53b8b_sets_limiter(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _vault, _limiter);

    // assign all the 'after' variables
    address currentContract_limiter_after = currentContract.limiter;

    // verify integrity
    assert ((((_committee != 0) && (_vault != 0)) && (_limiter != 0)) => (currentContract_limiter_after == _limiter)), "_committee != address(0) && _vault != address(0) && _limiter != address(0) => limiter@after == _limiter";
}

/*
 * committee@before != address(0) || vault@before != address(0) || limiter@before != address(0) => revert
 *
 * What it means: The initialize function must revert if the contract has already been initialized (any of committee, vault, or limiter is already set to non-zero)
 *
 * Why it should hold: This prevents re-initialization attacks where an attacker could change critical contract addresses after deployment. Initialize should only work once, following the initializer pattern for upgradeable contracts
 *
 * Possible consequences: Contract takeover, redirection of funds to attacker-controlled contracts, complete compromise of bridge security
 */
rule initialize_c0c53b8b_already_initialized_reverts(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables
    address currentContract_committee_before = currentContract.committee;
    address currentContract_vault_before = currentContract.vault;
    address currentContract_limiter_before = currentContract.limiter;

    // call function under test
    initialize@withrevert(e, _committee, _vault, _limiter);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((((currentContract_committee_before != 0) || (currentContract_vault_before != 0)) || (currentContract_limiter_before != 0)) => initialize_reverted), "committee@before != address(0) || vault@before != address(0) || limiter@before != address(0) => revert";
}

/*
 * _committee == _vault || _vault == _limiter || _committee == _limiter => committee@after == _committee && vault@after == _vault && limiter@after == _limiter
 *
 * What it means: The initialize function should allow the same address to be used for multiple parameters (committee, vault, limiter can be the same address) and still set all storage variables correctly
 *
 * Why it should hold: While not recommended, there may be valid deployment scenarios where the same contract implements multiple interfaces. The initialize function should handle this case without failing, as long as the address is not zero
 *
 * Possible consequences: Deployment failure in valid edge cases, inability to deploy bridge in certain configurations
 */
rule initialize_c0c53b8b_duplicate_addresses_allowed(env e) {
    address _committee;
    address _vault;
    address _limiter;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _vault, _limiter);

    // assign all the 'after' variables
    address currentContract_committee_after = currentContract.committee;
    address currentContract_vault_after = currentContract.vault;
    address currentContract_limiter_after = currentContract.limiter;

    // verify integrity
    assert ((((_committee == _vault) || (_vault == _limiter)) || (_committee == _limiter)) => (((currentContract_committee_after == _committee) && (currentContract_vault_after == _vault)) && (currentContract_limiter_after == _limiter))), "_committee == _vault || _vault == _limiter || _committee == _limiter => committee@after == _committee && vault@after == _vault && limiter@after == _limiter";
}

/*
 * isTransferProcessed[message.nonce]@before => revert
 *
 * What it means: If a transfer with a given nonce has already been processed, the function must revert
 *
 * Why it should hold: This prevents replay attacks where the same bridge message could be executed multiple times. The isTransferProcessed mapping tracks which nonces have been used to ensure each transfer happens only once
 *
 * Possible consequences: Double spending attacks, fund drainage, accounting inconsistencies where the same tokens are transferred multiple times from the vault
 */
rule transferBridgedTokensWithSignatures_beb0d55c_already_processed_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_message_nonce__before = currentContract.isTransferProcessed[message.nonce];

    // call function under test
    transferBridgedTokensWithSignatures@withrevert(e, signatures, message);
    bool transferBridgedTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (currentContract_isTransferProcessed_message_nonce__before => transferBridgedTokensWithSignatures_reverted), "isTransferProcessed[message.nonce]@before => revert";
}

/*
 * !isTransferProcessed[message.nonce]@before => isTransferProcessed[message.nonce]@after
 *
 * What it means: When a transfer with a previously unused nonce is processed, the nonce must be marked as processed in the mapping
 *
 * Why it should hold: This is the core mechanism that prevents replay attacks. Every successful transfer must update the isTransferProcessed mapping to record that this nonce has been used
 *
 * Possible consequences: Replay attack vulnerability where the same transfer can be executed multiple times since the system doesn't track processed nonces
 */
rule transferBridgedTokensWithSignatures_beb0d55c_marks_transfer_processed(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_message_nonce__before = currentContract.isTransferProcessed[message.nonce];

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_isTransferProcessed_message_nonce__after = currentContract.isTransferProcessed[message.nonce];

    // verify integrity
    assert (!(currentContract_isTransferProcessed_message_nonce__before) => currentContract_isTransferProcessed_message_nonce__after), "!isTransferProcessed[message.nonce]@before => isTransferProcessed[message.nonce]@after";
}

/*
 * isTransferProcessed[message.nonce]@before => isTransferProcessed[message.nonce]@after == isTransferProcessed[message.nonce]@before
 *
 * What it means: If a transfer was already processed before the function call, its processed status should remain unchanged (still true)
 *
 * Why it should hold: This ensures state consistency - once a transfer is marked as processed, it should never be unmarked. This property validates that the function doesn't corrupt existing processed transfer records
 *
 * Possible consequences: State corruption where previously processed transfers could be unmarked, potentially allowing replay attacks on old transactions
 */
rule transferBridgedTokensWithSignatures_beb0d55c_transfer_not_processed_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_message_nonce__before = currentContract.isTransferProcessed[message.nonce];

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_isTransferProcessed_message_nonce__after = currentContract.isTransferProcessed[message.nonce];

    // verify integrity
    assert (currentContract_isTransferProcessed_message_nonce__before => (currentContract_isTransferProcessed_message_nonce__after == currentContract_isTransferProcessed_message_nonce__before)), "isTransferProcessed[message.nonce]@before => isTransferProcessed[message.nonce]@after == isTransferProcessed[message.nonce]@before";
}

/*
 * n != message.nonce => isTransferProcessed[n]@after == isTransferProcessed[n]@before
 *
 * What it means: Processing a transfer with one nonce should not affect the processed status of any other nonces
 *
 * Why it should hold: This ensures surgical precision in state updates - only the specific nonce being processed should have its status changed, preventing unintended side effects on other transfers
 *
 * Possible consequences: State corruption where processing one transfer accidentally marks other nonces as processed or unprocessed, breaking the replay protection system
 */
rule transferBridgedTokensWithSignatures_beb0d55c_other_nonces_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint64 n;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_n__before = currentContract.isTransferProcessed[n];

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_isTransferProcessed_n__after = currentContract.isTransferProcessed[n];

    // verify integrity
    assert ((n != message.nonce) => (currentContract_isTransferProcessed_n__after == currentContract_isTransferProcessed_n__before)), "n != message.nonce => isTransferProcessed[n]@after == isTransferProcessed[n]@before";
}

/*
 * message.messageType != 1 => revert
 *
 * What it means: The function should only process messages with messageType equal to 1 (TOKEN_TRANSFER), rejecting all other message types
 *
 * Why it should hold: This function is specifically for token transfers and should not process other message types like emergency operations. The message type acts as a function selector in the bridge protocol
 *
 * Possible consequences: Function confusion attacks where emergency operation messages or other message types are processed as token transfers, leading to unauthorized operations
 */
rule transferBridgedTokensWithSignatures_beb0d55c_invalid_message_type_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    transferBridgedTokensWithSignatures@withrevert(e, signatures, message);
    bool transferBridgedTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.messageType != 1) => transferBridgedTokensWithSignatures_reverted), "message.messageType != 1 => revert";
}

/*
 * signatures.length == 0 => revert
 *
 * What it means: The function must reject calls with zero signatures provided
 *
 * Why it should hold: Bridge operations require committee signatures for authorization. An empty signature array indicates no authorization was provided, which should be rejected immediately
 *
 * Possible consequences: Unauthorized transfers without proper committee approval, bypassing the multi-signature security model
 */
rule transferBridgedTokensWithSignatures_beb0d55c_empty_signatures_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    transferBridgedTokensWithSignatures@withrevert(e, signatures, message);
    bool transferBridgedTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures.length == 0) => transferBridgedTokensWithSignatures_reverted), "signatures.length == 0 => revert";
}

/*
 * isTransferProcessed[message.nonce]@before => vault@after == vault@before
 *
 * What it means: When a transfer is rejected (because it was already processed), the vault address should remain unchanged
 *
 * Why it should hold: Failed operations should not modify critical system components. The vault address is a core infrastructure component that should only be changed through proper upgrade mechanisms
 *
 * Possible consequences: System corruption where failed transfers could accidentally modify the vault address, breaking all future operations
 */
rule transferBridgedTokensWithSignatures_beb0d55c_vault_unchanged_on_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_message_nonce__before = currentContract.isTransferProcessed[message.nonce];
    address currentContract_vault_before = currentContract.vault;

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_vault_after = currentContract.vault;

    // verify integrity
    assert (currentContract_isTransferProcessed_message_nonce__before => (currentContract_vault_after == currentContract_vault_before)), "isTransferProcessed[message.nonce]@before => vault@after == vault@before";
}

/*
 * isTransferProcessed[message.nonce]@before => limiter@after == limiter@before
 *
 * What it means: When a transfer is rejected (because it was already processed), the limiter address should remain unchanged
 *
 * Why it should hold: Failed operations should not modify system components. The limiter enforces withdrawal limits and its address should only be changed through proper governance
 *
 * Possible consequences: Security bypass where failed operations corrupt the limiter address, potentially removing withdrawal limits or redirecting to a malicious limiter
 */
rule transferBridgedTokensWithSignatures_beb0d55c_limiter_unchanged_on_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_message_nonce__before = currentContract.isTransferProcessed[message.nonce];
    address currentContract_limiter_before = currentContract.limiter;

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_limiter_after = currentContract.limiter;

    // verify integrity
    assert (currentContract_isTransferProcessed_message_nonce__before => (currentContract_limiter_after == currentContract_limiter_before)), "isTransferProcessed[message.nonce]@before => limiter@after == limiter@before";
}

/*
 * committee@after == committee@before
 *
 * What it means: The committee address should never change during execution of this function
 *
 * Why it should hold: The committee address is a critical system parameter that should only be modified through specific governance functions, not during regular transfer operations
 *
 * Possible consequences: Governance bypass where transfers could modify the committee address, potentially giving attackers control over bridge operations
 */
rule transferBridgedTokensWithSignatures_beb0d55c_committee_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address currentContract_committee_before = currentContract.committee;

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_committee_after = currentContract.committee;

    // verify integrity
    assert (currentContract_committee_after == currentContract_committee_before), "committee@after == committee@before";
}

/*
 * n1 != n2 => isTransferProcessed[n1]@after != isTransferProcessed[n2]@after || (!isTransferProcessed[n1]@after && !isTransferProcessed[n2]@after)
 *
 * What it means: Different nonces should have different processed states - if two nonces are different, they shouldn't both be processed unless they were both unprocessed before
 *
 * Why it should hold: This ensures that the nonce system maintains uniqueness and prevents nonce collision attacks where different transfers could interfere with each other's processed status
 *
 * Possible consequences: Nonce collision attacks where processing one transfer affects another transfer's status, potentially enabling replay attacks or preventing legitimate transfers
 */
rule transferBridgedTokensWithSignatures_beb0d55c_nonce_uniqueness_preserved(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint64 n1;
    uint64 n2;

    // assign all the 'before' variables

    // call function under test
    transferBridgedTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_isTransferProcessed_n1__after = currentContract.isTransferProcessed[n1];
    bool currentContract_isTransferProcessed_n2__after = currentContract.isTransferProcessed[n2];

    // verify integrity
    assert ((n1 != n2) => ((currentContract_isTransferProcessed_n1__after != currentContract_isTransferProcessed_n2__after) || (!(currentContract_isTransferProcessed_n1__after) && !(currentContract_isTransferProcessed_n2__after)))), "n1 != n2 => isTransferProcessed[n1]@after != isTransferProcessed[n2]@after || (!isTransferProcessed[n1]@after && !isTransferProcessed[n2]@after)";
}

/*
 * signatures.length == 0 => revert
 *
 * What it means: The function must revert if no signatures are provided in the signatures array
 *
 * Why it should hold: Emergency operations require cryptographic proof of authorization from committee members. An empty signatures array means no authorization was provided, which should never be allowed for critical emergency functions
 *
 * Possible consequences: Unauthorized emergency operations could be executed without any validation, leading to complete compromise of bridge security, unauthorized pausing/unpausing, or malicious state changes
 */
rule executeEmergencyOpWithSignatures_a6f740f6_empty_signatures_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures.length == 0) => executeEmergencyOpWithSignatures_reverted), "signatures.length == 0 => revert";
}

/*
 * message.messageType != BridgeUtils.EMERGENCY_OP => revert
 *
 * What it means: The function must revert if the message type is not BridgeUtils.EMERGENCY_OP
 *
 * Why it should hold: This function is specifically designed to handle emergency operations only. The verifyMessageAndSignatures modifier expects EMERGENCY_OP type, and processing other message types could bypass intended validation logic
 *
 * Possible consequences: Message type confusion could lead to processing of non-emergency messages through emergency pathways, potentially bypassing security checks designed for other message types
 */
rule executeEmergencyOpWithSignatures_a6f740f6_wrong_message_type_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.messageType != BridgeUtils.EMERGENCY_OP(e)) => executeEmergencyOpWithSignatures_reverted), "message.messageType != BridgeUtils.EMERGENCY_OP => revert";
}

/*
 * isTransferProcessed[message.nonce]@before => revert
 *
 * What it means: The function must revert if the message nonce has already been processed (marked as true in isTransferProcessed mapping)
 *
 * Why it should hold: Nonce replay protection is critical to prevent the same emergency operation from being executed multiple times. Each emergency message should only be processed once to maintain system integrity
 *
 * Possible consequences: Replay attacks where the same emergency operation is executed multiple times, leading to inconsistent state, multiple pausing/unpausing cycles, or repeated execution of critical operations
 */
rule executeEmergencyOpWithSignatures_a6f740f6_processed_nonce_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_message_nonce__before = currentContract.isTransferProcessed[message.nonce];

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (currentContract_isTransferProcessed_message_nonce__before => executeEmergencyOpWithSignatures_reverted), "isTransferProcessed[message.nonce]@before => revert";
}

/*
 * !isTransferProcessed[message.nonce]@before => isTransferProcessed[message.nonce]@after
 *
 * What it means: After successful execution, the function must mark the message nonce as processed by setting isTransferProcessed[nonce] to true
 *
 * Why it should hold: This implements replay protection by ensuring that once an emergency operation is executed, its nonce is marked as used, preventing future replay attacks with the same message
 *
 * Possible consequences: Without marking nonces as processed, the same emergency operation could be replayed indefinitely, leading to repeated execution of critical operations and potential system instability
 */
rule executeEmergencyOpWithSignatures_a6f740f6_marks_nonce_processed(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_isTransferProcessed_message_nonce__before = currentContract.isTransferProcessed[message.nonce];

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_isTransferProcessed_message_nonce__after = currentContract.isTransferProcessed[message.nonce];

    // verify integrity
    assert (!(currentContract_isTransferProcessed_message_nonce__before) => currentContract_isTransferProcessed_message_nonce__after), "!isTransferProcessed[message.nonce]@before => isTransferProcessed[message.nonce]@after";
}

/*
 * nonces[BridgeUtils.EMERGENCY_OP]@after == nonces[BridgeUtils.EMERGENCY_OP]@before + 1
 *
 * What it means: The function must increment the emergency operation nonce counter (nonces[BridgeUtils.EMERGENCY_OP]) by exactly 1
 *
 * Why it should hold: Nonce management ensures proper sequencing of emergency operations and prevents replay attacks. Each emergency operation should consume exactly one nonce to maintain the sequential ordering expected by the bridge protocol
 *
 * Possible consequences: Incorrect nonce management could lead to nonce gaps, replay vulnerabilities, or desynchronization with off-chain systems that track emergency operation sequences
 */
rule executeEmergencyOpWithSignatures_a6f740f6_increments_emergency_nonce(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 currentContract_nonces_BridgeUtils_EMERGENCY_OP_e___before = currentContract.nonces[BridgeUtils.EMERGENCY_OP(e)];

    // call function under test
    executeEmergencyOpWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_BridgeUtils_EMERGENCY_OP_e___after = currentContract.nonces[BridgeUtils.EMERGENCY_OP(e)];

    // verify integrity
    assert (currentContract_nonces_BridgeUtils_EMERGENCY_OP_e___after == currentContract_nonces_BridgeUtils_EMERGENCY_OP_e___before + 1), "nonces[BridgeUtils.EMERGENCY_OP]@after == nonces[BridgeUtils.EMERGENCY_OP]@before + 1";
}

/*
 * committee@before == address(0) => revert
 *
 * What it means: The function must revert if the committee address is set to the zero address (0x0)
 *
 * Why it should hold: The committee is essential for signature verification in emergency operations. A zero address indicates an uninitialized or corrupted state that would make signature verification impossible
 *
 * Possible consequences: Operations with zero committee address could bypass signature verification entirely or cause unexpected behavior in signature validation logic, potentially allowing unauthorized emergency operations
 */
rule executeEmergencyOpWithSignatures_a6f740f6_zero_committee_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address currentContract_committee_before = currentContract.committee;

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_committee_before == 0) => executeEmergencyOpWithSignatures_reverted), "committee@before == address(0) => revert";
}

/*
 * vault@before == address(0) => revert
 *
 * What it means: The function must revert if the vault address is set to the zero address (0x0)
 *
 * Why it should hold: The vault is critical infrastructure that holds bridge funds. Emergency operations might need to interact with the vault, and a zero address indicates a corrupted state that could lead to fund loss or system malfunction
 *
 * Possible consequences: Emergency operations that interact with a zero vault address could result in fund loss, failed transfers, or system instability during critical emergency scenarios
 */
rule executeEmergencyOpWithSignatures_a6f740f6_zero_vault_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address currentContract_vault_before = currentContract.vault;

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_vault_before == 0) => executeEmergencyOpWithSignatures_reverted), "vault@before == address(0) => revert";
}

/*
 * limiter@before == address(0) => revert
 *
 * What it means: The function must revert if the limiter address is set to the zero address (0x0)
 *
 * Why it should hold: The limiter enforces bridge transfer limits and is crucial for preventing abuse. Emergency operations might need to interact with or bypass limiter functions, and a zero address indicates system corruption
 *
 * Possible consequences: Emergency operations with zero limiter address could fail to properly manage transfer limits during emergency scenarios, potentially allowing unlimited withdrawals or causing system failures
 */
rule executeEmergencyOpWithSignatures_a6f740f6_zero_limiter_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address currentContract_limiter_before = currentContract.limiter;

    // call function under test
    executeEmergencyOpWithSignatures@withrevert(e, signatures, message);
    bool executeEmergencyOpWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_limiter_before == 0) => executeEmergencyOpWithSignatures_reverted), "limiter@before == address(0) => revert";
}

/*
 * amount == 0 => revert
 *
 * What it means: The function must revert when the amount parameter is zero
 *
 * Why it should hold: Zero-amount operations are meaningless no-ops that waste gas and could be used to spam the network or manipulate nonce counters without transferring actual value
 *
 * Possible consequences: DoS attacks through gas waste, nonce manipulation, event spam, and potential bypassing of rate limiting mechanisms
 */
rule bridgeERC20_212afaff_zero_amount_reverts(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount == 0) => bridgeERC20_reverted), "amount == 0 => revert";
}

/*
 * committee@before.config().tokenAddressOf(tokenID) == address(0) => revert
 *
 * What it means: The function must revert when the tokenID maps to address(0), indicating an unsupported token
 *
 * Why it should hold: Attempting to bridge unsupported tokens would result in undefined behavior and could lead to loss of funds or system corruption
 *
 * Possible consequences: Fund loss, system state corruption, and potential exploitation of undefined behavior in token handling
 */
rule bridgeERC20_212afaff_unsupported_token_reverts(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    address currentContract_committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_committee_config_e__tokenAddressOf_e__tokenID__before == 0) => bridgeERC20_reverted), "committee@before.config().tokenAddressOf(tokenID) == address(0) => revert";
}

/*
 * !committee@before.config().isChainSupported(destinationChainID) => revert
 *
 * What it means: The function must revert when the destinationChainID is not supported by the bridge configuration
 *
 * Why it should hold: Bridging to unsupported chains would result in tokens being sent to chains where they cannot be properly handled or retrieved
 *
 * Possible consequences: Permanent fund loss as tokens would be sent to chains without proper bridge infrastructure
 */
rule bridgeERC20_212afaff_unsupported_chain_reverts(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(currentContract_committee_config_e__isChainSupported_e__destinationChainID__before) => bridgeERC20_reverted), "!committee@before.config().isChainSupported(destinationChainID) => revert";
}

/*
 * recipientAddress.length != 32 => revert
 *
 * What it means: The function must revert when the recipientAddress byte array length is not exactly 32 bytes
 *
 * Why it should hold: Sui addresses must be exactly 32 bytes long, and invalid address formats would cause failures on the destination chain
 *
 * Possible consequences: Fund loss as tokens would be sent to invalid or unreachable addresses on the Sui chain
 */
rule bridgeERC20_212afaff_invalid_recipient_length_reverts(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress.length != 32) => bridgeERC20_reverted), "recipientAddress.length != 32 => revert";
}

/*
 * paused()@before => revert
 *
 * What it means: The function must revert when the contract is in a paused state
 *
 * Why it should hold: The pause mechanism is a critical safety feature that should halt all bridge operations during emergencies or maintenance
 *
 * Possible consequences: Bypassing emergency stops could allow continued operations during security incidents or system maintenance
 */
rule bridgeERC20_212afaff_paused_reverts(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (paused_e__before => bridgeERC20_reverted), "paused()@before => revert";
}

/*
 * IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before < amount => revert
 *
 * What it means: The function must revert when the caller has not approved sufficient tokens for the bridge contract to transfer
 *
 * Why it should hold: Without proper allowance, the transferFrom operation would fail, and the function should fail early rather than after partial execution
 *
 * Possible consequences: Inconsistent state where nonces increment but no tokens are transferred, leading to accounting mismatches
 */
rule bridgeERC20_212afaff_insufficient_allowance_reverts(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    address currentContract_committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.allowance(e, e.msg.sender, currentContract);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before < amount) => bridgeERC20_reverted), "IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before < amount => revert";
}

/*
 * IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before < amount => revert
 *
 * What it means: The function must revert when the caller does not have enough tokens to bridge the requested amount
 *
 * Why it should hold: Attempting to transfer more tokens than available would cause the ERC20 transfer to fail, and the function should validate this upfront
 *
 * Possible consequences: Transaction failures after partial execution, wasted gas, and potential state inconsistencies
 */
rule bridgeERC20_212afaff_insufficient_balance_reverts(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    address currentContract_committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);

    // call function under test
    bridgeERC20@withrevert(e, tokenID, amount, recipientAddress, destinationChainID);
    bool bridgeERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before < amount) => bridgeERC20_reverted), "IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before < amount => revert";
}

/*
 * !paused()@before && amount > 0 && committee@before.config().tokenAddressOf(tokenID) != address(0) && committee@before.config().isChainSupported(destinationChainID) && recipientAddress.length == 32 && IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before >= amount && IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before >= amount => nonces[1]@after == nonces[1]@before + 1
 *
 * What it means: When all conditions are valid, the TOKEN_TRANSFER nonce (index 1) must increment by exactly 1
 *
 * Why it should hold: Nonces ensure unique identification of bridge operations and prevent replay attacks; they must increment sequentially for each successful transfer
 *
 * Possible consequences: Nonce manipulation could enable replay attacks or cause message processing failures on the destination chain
 */
rule bridgeERC20_212afaff_nonce_increments(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    address currentContract_committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.allowance(e, e.msg.sender, currentContract);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);
    uint64 currentContract_nonces_1__before = currentContract.nonces[1];

    // call function under test
    bridgeERC20(e, tokenID, amount, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint64 currentContract_nonces_1__after = currentContract.nonces[1];

    // verify integrity
    assert (((((((!(paused_e__before) && (amount > 0)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before != 0)) && currentContract_committee_config_e__isChainSupported_e__destinationChainID__before) && (recipientAddress.length == 32)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before >= amount)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before >= amount)) => (currentContract_nonces_1__after == currentContract_nonces_1__before + 1)), "!paused()@before && amount > 0 && committee@before.config().tokenAddressOf(tokenID) != address(0) && committee@before.config().isChainSupported(destinationChainID) && recipientAddress.length == 32 && IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before >= amount && IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before >= amount => nonces[1]@after == nonces[1]@before + 1";
}

/*
 * !paused()@before && amount > 0 && committee@before.config().tokenAddressOf(tokenID) != address(0) && committee@before.config().isChainSupported(destinationChainID) && recipientAddress.length == 32 && IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before >= amount && IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before >= amount => IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(vault@before)@after == IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(vault@before)@before + amount
 *
 * What it means: When all conditions are valid, the vault's balance of the bridged token must increase by exactly the bridged amount
 *
 * Why it should hold: The vault must receive the exact amount of tokens being bridged to maintain proper custody and enable future withdrawals
 *
 * Possible consequences: Fund loss or theft if tokens don't reach the vault, or accounting errors leading to insolvency
 */
rule bridgeERC20_212afaff_vault_balance_increases(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    address currentContract_committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.allowance(e, e.msg.sender, currentContract);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);
    address currentContract_vault_before = currentContract.vault;
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__currentContract_vault_before__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, currentContract_vault_before);

    // call function under test
    bridgeERC20(e, tokenID, amount, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__currentContract_vault_before__after = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, currentContract_vault_before);

    // verify integrity
    assert (((((((!(paused_e__before) && (amount > 0)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before != 0)) && currentContract_committee_config_e__isChainSupported_e__destinationChainID__before) && (recipientAddress.length == 32)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before >= amount)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before >= amount)) => (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__currentContract_vault_before__after == currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__currentContract_vault_before__before + amount)), "!paused()@before && amount > 0 && committee@before.config().tokenAddressOf(tokenID) != address(0) && committee@before.config().isChainSupported(destinationChainID) && recipientAddress.length == 32 && IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before >= amount && IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before >= amount => IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(vault@before)@after == IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(vault@before)@before + amount";
}

/*
 * !paused()@before && amount > 0 && committee@before.config().tokenAddressOf(tokenID) != address(0) && committee@before.config().isChainSupported(destinationChainID) && recipientAddress.length == 32 && IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before >= amount && IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before >= amount => IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@after == IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before - amount
 *
 * What it means: When all conditions are valid, the caller's token balance must decrease by exactly the bridged amount
 *
 * Why it should hold: The caller must lose custody of the tokens they are bridging to prevent double-spending and maintain conservation of tokens
 *
 * Possible consequences: Double-spending attacks where users retain tokens locally while also receiving them on the destination chain
 */
rule bridgeERC20_212afaff_sender_balance_decreases(env e) {
    uint8 tokenID;
    uint256 amount;
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    address currentContract_committee_config_e__tokenAddressOf_e__tokenID__before = currentContract.committee.config(e).tokenAddressOf(e, tokenID);
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.allowance(e, e.msg.sender, currentContract);
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);

    // call function under test
    bridgeERC20(e, tokenID, amount, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint256 currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__after = currentContract_committee_config_e__tokenAddressOf_e__tokenID__before.balanceOf(e, e.msg.sender);

    // verify integrity
    assert (((((((!(paused_e__before) && (amount > 0)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before != 0)) && currentContract_committee_config_e__isChainSupported_e__destinationChainID__before) && (recipientAddress.length == 32)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_allowance_e__e_msg_sender__currentContract__before >= amount)) && (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before >= amount)) => (currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__after == currentContract_committee_config_e__tokenAddressOf_e__tokenID__before_balanceOf_e__e_msg_sender__before - amount)), "!paused()@before && amount > 0 && committee@before.config().tokenAddressOf(tokenID) != address(0) && committee@before.config().isChainSupported(destinationChainID) && recipientAddress.length == 32 && IERC20(committee@before.config().tokenAddressOf(tokenID)).allowance(msg.sender, address(this))@before >= amount && IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before >= amount => IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@after == IERC20(committee@before.config().tokenAddressOf(tokenID)).balanceOf(msg.sender)@before - amount";
}

/*
 * msg.value == 0 => revert
 *
 * What it means: The function must revert when called with zero ETH value (msg.value == 0)
 *
 * Why it should hold: Based on the NO-OP prevention pattern, bridging zero ETH is a meaningless operation that wastes gas and creates unnecessary events/state changes without transferring any value
 *
 * Possible consequences: DoS attacks through spam transactions, blockchain bloat from meaningless bridge events, wasted gas costs for users, and potential confusion in bridge monitoring systems
 */
rule bridgeETH_9449ebd2_zero_eth_reverts(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.value == 0) => bridgeETH_reverted), "msg.value == 0 => revert";
}

/*
 * recipientAddress.length != 32 => revert
 *
 * What it means: The function must revert when the recipient address length is not exactly 32 bytes (SUI_ADDRESS_LENGTH)
 *
 * Why it should hold: The contract defines SUI_ADDRESS_LENGTH = 32 and the bridgeERC20 function validates this same requirement, indicating Sui addresses must be exactly 32 bytes for proper cross-chain delivery
 *
 * Possible consequences: Fund loss due to invalid destination addresses, failed cross-chain transfers, and ETH locked in the bridge without proper recipient identification
 */
rule bridgeETH_9449ebd2_invalid_recipient_length_reverts(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress.length != 32) => bridgeETH_reverted), "recipientAddress.length != 32 => revert";
}

/*
 * !committee@before.config().isChainSupported(destinationChainID) => revert
 *
 * What it means: The function must revert when the destination chain ID is not supported by the bridge configuration
 *
 * Why it should hold: The onlySupportedChain modifier requires validation that the destination chain is configured and supported by the bridge system to ensure proper cross-chain delivery
 *
 * Possible consequences: Fund loss due to deposits to unsupported chains, ETH locked without recovery mechanism, and failed bridge operations
 */
rule bridgeETH_9449ebd2_unsupported_chain_reverts(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(currentContract_committee_config_e__isChainSupported_e__destinationChainID__before) => bridgeETH_reverted), "!committee@before.config().isChainSupported(destinationChainID) => revert";
}

/*
 * paused()@before => revert
 *
 * What it means: The function must revert when the bridge contract is in a paused state
 *
 * Why it should hold: The whenNotPaused modifier indicates that bridge operations should be disabled during emergency situations or maintenance periods to prevent further deposits during critical issues
 *
 * Possible consequences: Continued deposits during emergency situations, potential fund loss during security incidents, and inability to halt bridge operations when vulnerabilities are discovered
 */
rule bridgeETH_9449ebd2_paused_reverts(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);

    // call function under test
    bridgeETH@withrevert(e, recipientAddress, destinationChainID);
    bool bridgeETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (paused_e__before => bridgeETH_reverted), "paused()@before => revert";
}

/*
 * msg.value > 0 && recipientAddress.length == 32 && !paused()@before && committee@before.config().isChainSupported(destinationChainID) => nonces[0]@after == nonces[0]@before + 1
 *
 * What it means: When all conditions are met (positive ETH value, valid recipient length, not paused, supported chain), the TOKEN_TRANSFER nonce (nonces[0]) must increment by exactly 1
 *
 * Why it should hold: Based on bridgeERC20 incrementing nonces[BridgeUtils.TOKEN_TRANSFER]++, each successful bridge operation must have a unique nonce for proper cross-chain message ordering and replay protection
 *
 * Possible consequences: Nonce collision attacks, replay attacks, message ordering issues, and potential double-spending on the destination chain
 */
rule bridgeETH_9449ebd2_valid_transfer_increments_nonce(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    uint64 currentContract_nonces_0__before = currentContract.nonces[0];

    // call function under test
    bridgeETH(e, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint64 currentContract_nonces_0__after = currentContract.nonces[0];

    // verify integrity
    assert (((((e.msg.value > 0) && (recipientAddress.length == 32)) && !(paused_e__before)) && currentContract_committee_config_e__isChainSupported_e__destinationChainID__before) => (currentContract_nonces_0__after == currentContract_nonces_0__before + 1)), "msg.value > 0 && recipientAddress.length == 32 && !paused()@before && committee@before.config().isChainSupported(destinationChainID) => nonces[0]@after == nonces[0]@before + 1";
}

/*
 * msg.value > 0 && recipientAddress.length == 32 && !paused()@before && committee@before.config().isChainSupported(destinationChainID) => vault@after.balance == vault@before.balance + msg.value
 *
 * What it means: When a valid bridge operation occurs, the vault contract's ETH balance must increase by exactly the msg.value amount
 *
 * Why it should hold: The bridge architecture requires ETH to be stored in the vault contract for later withdrawal operations, as seen in _transferTokensFromVault calling vault.transferETH
 *
 * Possible consequences: Fund loss, accounting discrepancies, inability to fulfill withdrawal requests, and broken bridge economics
 */
rule bridgeETH_9449ebd2_vault_receives_eth(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    uint256 nativeBalances_currentContract_vault__before = nativeBalances[currentContract.vault];

    // call function under test
    bridgeETH(e, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint256 nativeBalances_currentContract_vault__after = nativeBalances[currentContract.vault];

    // verify integrity
    assert (((((e.msg.value > 0) && (recipientAddress.length == 32)) && !(paused_e__before)) && currentContract_committee_config_e__isChainSupported_e__destinationChainID__before) => (nativeBalances_currentContract_vault__after == nativeBalances_currentContract_vault__before + e.msg.value)), "msg.value > 0 && recipientAddress.length == 32 && !paused()@before && committee@before.config().isChainSupported(destinationChainID) => vault@after.balance == vault@before.balance + msg.value";
}

/*
 * msg.value == 0 || recipientAddress.length != 32 || paused()@before || !committee@before.config().isChainSupported(destinationChainID) => nonces[0]@after == nonces[0]@before
 *
 * What it means: When any validation fails (zero ETH, invalid recipient, paused state, or unsupported chain), the nonce must remain unchanged
 *
 * Why it should hold: Failed operations should not consume nonces to maintain proper message sequencing and prevent gaps in the nonce sequence that could complicate cross-chain message processing
 *
 * Possible consequences: Nonce sequence corruption, message processing issues, and potential synchronization problems between chains
 */
rule bridgeETH_9449ebd2_nonce_unchanged_on_revert(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    uint64 currentContract_nonces_0__before = currentContract.nonces[0];

    // call function under test
    bridgeETH(e, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint64 currentContract_nonces_0__after = currentContract.nonces[0];

    // verify integrity
    assert (((((e.msg.value == 0) || (recipientAddress.length != 32)) || paused_e__before) || !(currentContract_committee_config_e__isChainSupported_e__destinationChainID__before)) => (currentContract_nonces_0__after == currentContract_nonces_0__before)), "msg.value == 0 || recipientAddress.length != 32 || paused()@before || !committee@before.config().isChainSupported(destinationChainID) => nonces[0]@after == nonces[0]@before";
}

/*
 * msg.value == 0 || recipientAddress.length != 32 || paused()@before || !committee@before.config().isChainSupported(destinationChainID) => vault@after.balance == vault@before.balance
 *
 * What it means: When any validation fails, the vault's ETH balance must remain exactly the same as before the function call
 *
 * Why it should hold: Failed operations should not transfer any funds to maintain accounting integrity and ensure that only valid bridge operations affect the vault balance
 *
 * Possible consequences: Accounting corruption, fund leakage, and potential exploitation of failed transaction states
 */
rule bridgeETH_9449ebd2_vault_balance_unchanged_on_revert(env e) {
    bytes recipientAddress;
    uint8 destinationChainID;

    // assign all the 'before' variables
    bool paused_e__before = paused(e);
    bool currentContract_committee_config_e__isChainSupported_e__destinationChainID__before = currentContract.committee.config(e).isChainSupported(e, destinationChainID);
    uint256 nativeBalances_currentContract_vault__before = nativeBalances[currentContract.vault];

    // call function under test
    bridgeETH(e, recipientAddress, destinationChainID);

    // assign all the 'after' variables
    uint256 nativeBalances_currentContract_vault__after = nativeBalances[currentContract.vault];

    // verify integrity
    assert (((((e.msg.value == 0) || (recipientAddress.length != 32)) || paused_e__before) || !(currentContract_committee_config_e__isChainSupported_e__destinationChainID__before)) => (nativeBalances_currentContract_vault__after == nativeBalances_currentContract_vault__before)), "msg.value == 0 || recipientAddress.length != 32 || paused()@before || !committee@before.config().isChainSupported(destinationChainID) => vault@after.balance == vault@before.balance";
}