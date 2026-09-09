# Mainnet code changes

1. In `src/cryptonote_core/lineage_audit_policy.h`, change
   `SALVIUM_LINEAGE_AUDIT_MAINNET_HEIGHT` from `0` to the agreed future
   activation height. Keep these values:

   ```cpp
   #define SALVIUM_LINEAGE_AUDIT_MAINNET_OPENING_HEIGHT 154749
   #define SALVIUM_LINEAGE_AUDIT_DURATION_BLOCKS 10080
   constexpr uint8_t fork_version = 14;
   ```

2. In `src/hardforks/hardforks.cpp`, update the fourth field of the existing
   mainnet audit entry to the finalized fork timestamp. Keep its
   `lineage_policy::fork_version` and `lineage_policy::mainnet_height`
   references and its zero voting threshold.
