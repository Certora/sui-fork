import "dispatching_BridgeCommittee.spec";
import "snippet_BridgeUtils.spec";
import "snippet_uups.spec";

use builtin rule sanity filtered { f ->
    f.contract == currentContract &&
    f.selector != sig:initializeConfig(address).selector
}
