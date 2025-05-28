import {BridgeUtils} from "contracts/utils/BridgeUtils.sol";

contract BridgeUtilsHarness {
    
    uint8 public constant SUI = BridgeUtils.SUI;
    uint8 public constant BTC = BridgeUtils.BTC;
    uint8 public constant ETH = BridgeUtils.ETH;
    uint8 public constant USDC = BridgeUtils.USDC;
    uint8 public constant USDT = BridgeUtils.USDT;
}
