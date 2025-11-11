methods {
    function BridgeCommittee.verifySignatures(bytes[] signatures, BridgeUtils.Message message) external => CVL_verifySignatures(message); 
}

ghost bool verifySignaturesSuccessful;
ghost uint8 verifySignaturesMessageType;

function CVL_verifySignatures(BridgeUtils.Message message) {
    bool nondet;
    if (nondet) {
        revert();
    }
    verifySignaturesSuccessful = true;
    verifySignaturesMessageType = message.messageType;
}
