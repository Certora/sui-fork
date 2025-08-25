import {BridgeUtils} from "contracts/utils/BridgeUtils.sol";

contract BridgeUtilsHarness {
    
    uint8 public constant SUI = BridgeUtils.SUI;
    uint8 public constant BTC = BridgeUtils.BTC;
    uint8 public constant ETH = BridgeUtils.ETH;
    uint8 public constant USDC = BridgeUtils.USDC;
    uint8 public constant USDT = BridgeUtils.USDT;

    uint8 public constant TOKEN_TRANSFER = BridgeUtils.TOKEN_TRANSFER;
    uint8 public constant BLOCKLIST = BridgeUtils.BLOCKLIST;
    uint8 public constant EMERGENCY_OP = BridgeUtils.EMERGENCY_OP;
    uint8 public constant UPDATE_BRIDGE_LIMIT = BridgeUtils.UPDATE_BRIDGE_LIMIT;
    uint8 public constant UPDATE_TOKEN_PRICE = BridgeUtils.UPDATE_TOKEN_PRICE;
    uint8 public constant ADD_EVM_TOKENS = BridgeUtils.ADD_EVM_TOKENS;
}
