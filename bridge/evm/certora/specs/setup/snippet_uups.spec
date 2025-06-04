methods {
    function _.getImplementation() internal => CVL_getImplementation() expect address;
    function _._upgradeToAndCallUUPS(address newImplementation, bytes memory) internal => CVL_upgradeToAndCallUUPS(newImplementation) expect void;
}

ghost address implementation;

function CVL_getImplementation() returns address {
    return implementation;
}
function CVL_upgradeToAndCallUUPS(address newImplementation) {
    implementation = newImplementation;
}
