import "dispatching_BridgeConfig.spec";
import "snippet_uups.spec";

use builtin rule sanity filtered { f -> f.contract == currentContract }
