#pragma once

#include <string>
#include <vector>
#include "lineage_audit.h"
#include "serialization/keyvalue_serialization.h"
#include "storages/portable_storage_template_helper.h"

namespace cryptonote
{
constexpr size_t max_audit_file_bytes = 256 * 1024 * 1024;
template<class T> bool load_audit_json(T& value, const std::string& text)
{
  if (text.size() > max_audit_file_bytes) return false;
  const epee::serialization::portable_storage::limits_t limits{1000000, 6000000, 4000000};
  return epee::serialization::load_t_from_json(value, text, &limits);
}
// Private, off-chain evidence. This domain must never be accepted as enrollment.
struct audit_review_package
{
  uint32_t version = 3;
  uint8_t network = 0;
  std::string genesis, snapshot_hash, nonce;
  uint64_t snapshot_height = 0;
  std::vector<std::string> proofs;
  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(version)
    KV_SERIALIZE(network)
    KV_SERIALIZE(genesis)
    KV_SERIALIZE(snapshot_height)
    KV_SERIALIZE(snapshot_hash)
    KV_SERIALIZE(nonce)
    KV_SERIALIZE(proofs)
  END_KV_SERIALIZE_MAP()
};

struct audit_review_request
{
  uint32_t version = 3;
  std::vector<audit_review_package> packages;
  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(version)
    KV_SERIALIZE(packages)
  END_KV_SERIALIZE_MAP()
};

struct audit_review_item
{
  std::string package_id, transaction, asset_type;
  uint32_t output_index = 0;
  uint64_t amount = 0;
  uint64_t canonical_height = UINT64_MAX;
  bool stake = false;
  bool spent = false;
  std::string state = "REVIEW_REQUIRED", recommendation = "DENY", reason;
  std::vector<std::string> missing_inputs;
  // Developer disposition is separate from the automatic finding.
  std::string decision, decision_reason;
  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(package_id)
    KV_SERIALIZE(transaction)
    KV_SERIALIZE(output_index)
    KV_SERIALIZE(asset_type)
    KV_SERIALIZE(amount)
    KV_SERIALIZE_OPT(canonical_height, uint64_t(UINT64_MAX))
    KV_SERIALIZE(stake)
    KV_SERIALIZE(spent)
    KV_SERIALIZE(state)
    KV_SERIALIZE(recommendation)
    KV_SERIALIZE(reason)
    KV_SERIALIZE(missing_inputs)
    KV_SERIALIZE(decision)
    KV_SERIALIZE(decision_reason)
  END_KV_SERIALIZE_MAP()
};

struct audit_review_report
{
  uint32_t version = 3;
  uint64_t revision = 1;
  uint8_t network = 0;
  uint64_t snapshot_height = 0, opening_height = 0;
  uint64_t public_work_limit = 0, public_outputs_checked = 0;
  std::string genesis, snapshot_hash, evidence_hash;
  // Owner proofs establish individual outputs, not exhaustive wallet/supply coverage.
  std::string coverage = "SUBMITTED_OUTPUTS_ONLY";
  std::vector<audit_review_item> outputs;
  std::string signer, signature;
  // Independently signed public certificates; omitted by report-only tools.
  std::vector<std::string> clearances;
  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(version)
    KV_SERIALIZE(revision)
    KV_SERIALIZE(network)
    KV_SERIALIZE(genesis)
    KV_SERIALIZE(snapshot_height)
    KV_SERIALIZE(snapshot_hash)
    KV_SERIALIZE(opening_height)
    KV_SERIALIZE(public_work_limit)
    KV_SERIALIZE(public_outputs_checked)
    KV_SERIALIZE(evidence_hash)
    KV_SERIALIZE(coverage)
    KV_SERIALIZE(outputs)
    KV_SERIALIZE(signer)
    KV_SERIALIZE(signature)
    KV_SERIALIZE_OPT(clearances, std::vector<std::string>())
  END_KV_SERIALIZE_MAP()
};

crypto::hash audit_review_proof_message(const audit_review_package&, const lineage_output_proof&);
bool verify_audit_review_proof(const audit_review_package&, const lineage_output_proof&,
    const crypto::public_key&, const rct::key&);
std::string audit_review_package_id(const audit_review_package&);
crypto::hash audit_review_report_hash(const audit_review_report&);
void validate_audit_review_report(const audit_review_report&);
bool authorized_audit_review_signer(network_type, const crypto::public_key&);
void sign_audit_review_report(audit_review_report&, const crypto::secret_key&);
bool verify_audit_review_report(const audit_review_report&, const crypto::public_key&);
void write_private_audit_file(const std::string& path, const std::string& contents);
std::string read_audit_file(const std::string& path, size_t max_bytes = max_audit_file_bytes);

// Runs on a read-only canonical database. No miner, P2P, spend gate or payout is changed.
class audit_review_verifier
{
public:
  static audit_review_report verify(const BlockchainDB&, network_type,
      const std::vector<audit_review_package>&, uint64_t opening_height,
      size_t public_work_limit = 50000, uint64_t activation_height = 0,
      const crypto::public_key& authority = crypto::null_pkey);
};
}
