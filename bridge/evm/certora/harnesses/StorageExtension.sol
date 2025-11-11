
contract StorageExtension {
    struct PausableStorage {
        bool _paused;
    }
    struct ReentrancyGuardStorage {
    uint256 _status;
    }


    /**
     * @custom:certoralink 0xcd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300
     */
    PausableStorage pausable;
    /**
     * @custom:certoralink 0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00
     */
    ReentrancyGuardStorage reentrancyGuard;
}
