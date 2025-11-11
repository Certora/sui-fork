import {BridgeUtils} from "contracts/utils/BridgeUtils.sol";
import "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";

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

    function decodeTokenTransferPayloadWrapper(bytes memory _payload)
        external
        pure
        returns (BridgeUtils.TokenTransferPayload memory)
    {
        return BridgeUtils.decodeTokenTransferPayload(_payload);
    }

    function decodeEmergencyOpPayloadWrapper(bytes memory _payload) external pure returns (bool) {
        return BridgeUtils.decodeEmergencyOpPayload(_payload);
    }

    function decodeUpdateLimitPayloadWrapper(bytes memory _payload)
        external
        pure
        returns (uint8 senderChainID, uint64 newLimit)
    {
        return BridgeUtils.decodeUpdateLimitPayload(_payload);
    }


    function convertERC20ToSuiDecimalWrapper(uint8 erc20Decimal, uint8 suiDecimal, uint256 amount)
        external
        pure
        returns (uint64)
    {
        return BridgeUtils.convertERC20ToSuiDecimal(erc20Decimal, suiDecimal, amount);
    }

    function convertSuiToERC20DecimalWrapper(uint8 erc20Decimal, uint8 suiDecimal, uint64 amount)
        external
        pure
        returns (uint256)
    {
        return BridgeUtils.convertSuiToERC20Decimal(erc20Decimal, suiDecimal, amount);
    }
}
