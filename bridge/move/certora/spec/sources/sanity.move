#[test_only]
module spec::sanity;

use cvlm::manifest::module_sanity;

public fun cvlm_manifest() {
    module_sanity(@bridge, b"bridge");
    module_sanity(@bridge, b"committee");
}
