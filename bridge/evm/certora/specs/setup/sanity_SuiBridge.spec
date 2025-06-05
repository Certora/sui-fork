import "dispatching_SuiBridge.spec";
import "snippet_BridgeUtils.spec";
import "snippet_loopSummaries.spec";
import "snippet_uups.spec";

methods {
    function _.recordBridgeTransfers(uint8,uint8,uint256) external => NONDET;
}

use builtin rule sanity filtered { f -> f.contract == currentContract }
