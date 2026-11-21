#pragma once

namespace cryptonote { namespace audit_review_authority {
// The main developer supplies these public keys during PR/release review.
// Empty means no result-signing authority is designated: fail closed.
// Never put a private signing key here. Wallet owners cannot override these
// keys through RPC, CLI options, wallet attributes or a result's signer field.
constexpr const char* mainnet = "";
constexpr const char* testnet = "";
constexpr const char* stagenet = "";
} }
