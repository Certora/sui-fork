import "dispatching_SuiBridge.spec";
import "snippet_uups.spec";

methods {
    function _.recordBridgeTransfers(uint8,uint8,uint256) external => NONDET;
    function BridgeUtils.decodeTokenTransferPayload(bytes memory _payload) internal returns (BridgeUtils.TokenTransferPayload memory)
        => CVL_decodedTokenTransferPayload();
}

function CVL_decodedTokenTransferPayload() returns BridgeUtils.TokenTransferPayload {
    BridgeUtils.TokenTransferPayload res;
    return res;
}

use builtin rule sanity filtered { f -> f.contract == currentContract }
