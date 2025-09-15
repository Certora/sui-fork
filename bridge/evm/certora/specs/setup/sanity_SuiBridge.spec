import "dispatching_SuiBridge.spec";
import "setup_BridgeConfig.spec";
import "snippet_BridgeUtils.spec";
import "snippet_loopSummaries.spec";
import "snippet_uups.spec";

use builtin rule sanity filtered { f -> f.contract == currentContract }
