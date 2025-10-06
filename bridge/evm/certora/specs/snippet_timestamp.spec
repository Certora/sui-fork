// Timestamp reasoning.
//
// We use a ghost variable lastTimestamp to keep track of the last timestamp recorded in the contract.
// This is used to ensure that timestamps are always increasing.  We also ensure that the timestamp
// does not exceed the uint40 range, which is sufficient for our use case (up to year 36812).

definition hour() returns mathint = 3600;

ghost mathint lastTimestamp {
    init_state axiom lastTimestamp >= 24*hour(); // prevent underflow in hour calculation. Contract is not deployed in 1970 
}

hook TIMESTAMP uint256 time {
    require(to_mathint(time) < 2^32 * hour(), "timestamp hour must fit in 32 bit");
    require(to_mathint(time) >= lastTimestamp, "timestamp must be increasing");
    lastTimestamp = time;
}

