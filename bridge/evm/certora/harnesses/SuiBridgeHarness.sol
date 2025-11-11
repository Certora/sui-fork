import {SuiBridge} from "contracts/SuiBridge.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "contracts/interfaces/IBridgeVault.sol";
import "contracts/interfaces/IBridgeLimiter.sol";

contract SuiBridgeHarness is SuiBridge {
    constructor(address _committee, address _vault, address _limiter) {
        // revert disableInitializer
        InitializableStorage storage $ = _getInitializableStorage_();
        $._initializing = true;
        __CommitteeUpgradeable_init(_committee);
        __Pausable_init();
        vault = IBridgeVault(_vault);
        limiter = IBridgeLimiter(_limiter);
        $._initializing = false;
    }

    function _getInitializableStorage_() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00
        }
    }

}
