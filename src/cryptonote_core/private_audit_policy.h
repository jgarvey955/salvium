#pragma once

#include <cstdint>
#include "lineage_audit_policy.h"

// The main developer selects the activation heights during release review.
// These are consensus settings, never wallet options or production RPC input.
#define SALVIUM_PRIVATE_AUDIT_MAINNET_HEIGHT 0
#define SALVIUM_PRIVATE_AUDIT_TESTNET_HEIGHT 0
#define SALVIUM_PRIVATE_AUDIT_STAGENET_HEIGHT 0

namespace cryptonote { namespace private_audit_policy {
constexpr uint8_t fork_version = 14;
constexpr uint64_t mainnet_height = SALVIUM_PRIVATE_AUDIT_MAINNET_HEIGHT;
constexpr uint64_t testnet_height = SALVIUM_PRIVATE_AUDIT_TESTNET_HEIGHT;
constexpr uint64_t stagenet_height = SALVIUM_PRIVATE_AUDIT_STAGENET_HEIGHT;
// A certificate confirmed in block H is usable in block H+1. Ordinary output
// maturity and stake locks remain independent requirements.
constexpr uint64_t confirmation_delay = 1;
static_assert(!(mainnet_height && lineage_policy::mainnet_height) &&
    !(testnet_height && lineage_policy::testnet_height) &&
    !(stagenet_height && lineage_policy::stagenet_height), "Do not activate the withdrawn v2 audit alongside v4");
static_assert(mainnet_height < UINT64_MAX - 21661 && testnet_height < UINT64_MAX - 21661 &&
    stagenet_height < UINT64_MAX - 21661, "Private audit activation overflow");
static_assert(!mainnet_height || mainnet_height > 521425, "Private audit must follow mainnet HF13");
static_assert(!testnet_height || testnet_height > 1400, "Private audit must follow testnet HF13");
} }
