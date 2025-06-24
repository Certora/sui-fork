import "dispatching_BridgeConfig.spec";
import "setup_BridgeConfig.spec";
import "snippet_uups.spec";

methods {
    function tokenPrices(uint8 tokenID) external returns (uint64) envfree;
    function supportedTokens(uint8 tokenID) external returns (address,uint8,bool) envfree;
}

use builtin rule sanity filtered { f -> f.contract == currentContract }

function getSupportedToken(uint8 tokenID) returns address {
    address res;
    (res,_,_) = supportedTokens(tokenID);
    return res;
}

invariant tokenPriceIsAlwaysPositive(uint8 tokenID)
    getSupportedToken(tokenID) != 0 => tokenPrices(tokenID) > 0;
