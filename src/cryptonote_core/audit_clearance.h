#pragma once

#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/lineage_audit_limits.h"
#include "private_audit_policy.h"

namespace cryptonote
{
class BlockchainDB;

// Public authorization only. Amounts, owner identifiers, key images, private
// ownership proofs and economic evidence never belong in this wire format.
struct audit_clearance_certificate
{
  uint8_t version = 4;
  uint8_t network = 0;
  crypto::hash genesis = crypto::null_hash;
  uint64_t activation_height = 0;
  uint64_t snapshot_height = 0;
  crypto::hash snapshot_hash = crypto::null_hash;
  uint32_t policy_version = 0;
  uint64_t historical_cutoff_height = 0;
  crypto::hash policy_digest = crypto::null_hash;
  crypto::hash transaction = crypto::null_hash;
  uint32_t output_index = 0;
  bool stake = false;
  uint64_t revision = 1;
  // 1 finally authorizes spending; 2 records a developer denial of uncleared funds.
  uint8_t decision = 0;
  crypto::signature signature{};

  BEGIN_SERIALIZE_OBJECT()
    FIELD(version)
    if (version != 4) return false;
    FIELD(network)
    FIELD(genesis)
    VARINT_FIELD(activation_height)
    VARINT_FIELD(snapshot_height)
    FIELD(snapshot_hash)
    VARINT_FIELD(policy_version)
    VARINT_FIELD(historical_cutoff_height)
    FIELD(policy_digest)
    FIELD(transaction)
    VARINT_FIELD(output_index)
    FIELD(stake)
    VARINT_FIELD(revision)
    FIELD(decision)
    FIELD(signature)
  END_SERIALIZE()
};

struct audit_clearance_batch
{
  uint8_t version = 4;
  std::vector<audit_clearance_certificate> certificates;
  BEGIN_SERIALIZE_OBJECT()
    FIELD(version)
    if (version != 4) return false;
    CONTAINER_FIELD_CAPPED(certificates, lineage_limits::max_outputs)
    if (certificates.empty()) return false;
  END_SERIALIZE()
};

crypto::hash audit_clearance_message(const audit_clearance_certificate& certificate);
// Only compiled, developer-approved policies are signable on real networks.
// FAKECHAIN derives an isolated fixture binding from its activation height.
void bind_audit_clearance_policy(audit_clearance_certificate& certificate);
void sign_audit_clearance(audit_clearance_certificate& certificate, const crypto::secret_key& secret);
bool verify_audit_clearance(const audit_clearance_certificate& certificate, const crypto::public_key& authority);

class audit_clearance_registry
{
public:
  using identity = std::tuple<std::string, uint32_t, bool>;
  struct entry
  {
    audit_clearance_certificate certificate;
    uint64_t confirmed_height = 0;
  };
  struct eligible_output
  {
    uint64_t asset_index = 0, confirmed_height = 0;
    uint64_t height = 0;
    crypto::hash transaction = crypto::null_hash;
    uint32_t output_index = 0;
  };

  void configure(network_type network, uint64_t activation, const crypto::public_key& authority);
  uint64_t activation() const { return activation_; }
  bool active(uint64_t height) const { return activation_ && height >= activation_; }
  const crypto::public_key& authority() const { return authority_; }
  void sync(const BlockchainDB& db);
  bool validate_batch(const BlockchainDB& db, const audit_clearance_batch& batch,
      uint64_t candidate_height, std::string& reason, bool allow_confirmed = false) const;
  bool cleared(const crypto::hash& tx, uint32_t index, bool stake = false) const;
  bool validate_block(const BlockchainDB& db, const block& candidate, std::string& reason);
  bool check_spend(const BlockchainDB& db, const transaction& tx, std::string& reason);
  bool output_spendable(const BlockchainDB& db, uint64_t global_id, uint64_t candidate_height) const;
  std::vector<eligible_output> eligible_outputs(const BlockchainDB& db,
      const std::string& asset, uint64_t from_index, size_t limit, bool& more) const;
  const entry* find(const crypto::hash& transaction, uint32_t index, bool stake = false) const;

private:
  network_type network_ = UNDEFINED;
  uint64_t activation_ = 0, next_height_ = 0;
  crypto::public_key authority_ = crypto::null_pkey;
  uint32_t policy_version_ = 0;
  uint64_t historical_cutoff_ = 0;
  crypto::hash policy_digest_ = crypto::null_hash;
  crypto::hash tip_ = crypto::null_hash;
  std::map<identity, entry> entries_;
  std::set<identity> finalized_;
  struct catalog_entry
  {
    eligible_output output;
    uint64_t spendable_height = 0;
  };
  std::map<std::string, std::map<uint64_t, catalog_entry>> eligible_;
  std::map<uint64_t, std::vector<std::pair<identity, uint64_t>>> due_;
  std::map<uint64_t, std::vector<std::pair<crypto::hash, uint32_t>>> automatic_due_;
  void inherit_block(const BlockchainDB& db, const block& b, uint64_t height);
  void add_automatic(const BlockchainDB& db, const crypto::hash& tx, uint32_t index, uint64_t height);
  void reset();
  void apply(const BlockchainDB& db, const audit_clearance_batch& batch, uint64_t height);
  void update_eligible(const BlockchainDB& db, const identity& id, uint64_t candidate_height);
  void advance(const BlockchainDB& db, uint64_t candidate_height);
};
}
