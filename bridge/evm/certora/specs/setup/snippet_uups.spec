methods {
    function _.getImplementation() internal => CVL_getImplementation() expect address;
    function _._upgradeToAndCallUUPS(address newImplementation, bytes memory) internal => CVL_upgradeToAndCallUUPS(newImplementation) expect void;
}

ghost address UUPS_implementation;

function CVL_getImplementation() returns address {
    return UUPS_implementation;
}
function CVL_upgradeToAndCallUUPS(address newImplementation) {
    UUPS_implementation = newImplementation;
}
