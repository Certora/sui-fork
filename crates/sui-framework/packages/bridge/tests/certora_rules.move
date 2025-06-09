#[test_only]
module bridge::certora_rules;

use bridge::bridge_env::{
    create_bridge,
    create_env,
};
use bridge::chain_ids;


native fun CVT_assert(cond: bool);
native fun CVT_satisfy(cond: bool);
// fun assert_eq<T: drop>(t1: T, t2: T) {
//     CVT_assert(t1 == t2);
// }


public fun bridge_create() {
    let mut env = create_env(chain_ids::sui_testnet());
    env.create_bridge(@0x0);

    let bridge = env.bridge(@0x0);
    bridge.return_bridge();

    env.destroy_env();

    CVT_assert(false);
}
