// summarizes loops that are too long
// Should become obsolete with https://certora.atlassian.net/browse/CERT-8747
methods {
    function _.calculateWindowAmount(uint8) external => NONDET;
    function _.calculateWindowAmount(uint8) internal => NONDET;
}