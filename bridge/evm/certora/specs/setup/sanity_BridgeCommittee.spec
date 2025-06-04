import "dispatching_BridgeCommittee.spec";

methods {
    function _.splitSignature(bytes memory) internal => NONDET;
    function _.tryRecover(bytes32 hash, bytes memory signature) internal => NONDET;
}

use builtin rule sanity filtered { f ->
    f.contract == currentContract &&
    f.selector != sig:initializeConfig(address).selector
}
