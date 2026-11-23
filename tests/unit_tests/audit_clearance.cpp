#include "cryptonote_core/audit_clearance.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "blockchain_db/testdb.h"
#include "string_tools.h"
#include <iostream>
#include <stdexcept>

using namespace cryptonote;
namespace {
void check(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
class clearance_db : public BaseTestDB {
public:
  uint64_t candidate = 101, epoch = 0;
  std::unordered_map<crypto::hash, std::pair<transaction, uint64_t>> transactions;
  std::vector<tx_out_index> outputs;
  std::map<uint64_t, block> blocks;
  crypto::hash add(uint64_t height) {
    transaction tx; tx.version = 1; tx.type = transaction_type::TRANSFER;
    tx.source_asset_type = tx.destination_asset_type = "SAL1";
    tx.vin.push_back(txin_to_key{});
    crypto::public_key key; crypto::secret_key secret; crypto::generate_keys(key, secret);
    tx.vout.push_back({1, txout_to_key{key, "SAL1", 10}});
    if (height >= 100) {
      tx.vout[0].amount = 0;
      auto& input = boost::get<txin_to_key>(tx.vin[0]); input.asset_type = "SAL1"; input.key_offsets = {0};
    }
    return add_transaction(tx, height);
  }
  crypto::hash add_transaction(const transaction& tx, uint64_t height) {
    check(tx.vout.size() == 1, "Fixture requires one output");
    const auto id = get_transaction_hash(tx);
    transactions.emplace(id, std::make_pair(tx, height)); outputs.push_back({id, 0});
    if (tx.type == transaction_type::PROTOCOL) blocks[height].protocol_tx = tx;
    else blocks[height].tx_hashes.push_back(id);
    return id;
  }
  uint64_t height() const override { return candidate; }
  transaction get_tx(const crypto::hash& id) const override { return transactions.at(id).first; }
  transaction get_pruned_tx(const crypto::hash& id) const override { return get_tx(id); }
  uint64_t get_tx_block_height(const crypto::hash& id) const override { return transactions.at(id).second; }
  bool tx_exists(const crypto::hash& id) const override { return transactions.count(id); }
  bool tx_exists(const crypto::hash& id, uint64_t& index) const override {
    for (index = 0; index < outputs.size(); ++index) if (outputs[index].first == id) return true;
    return false;
  }
  block get_block_from_height(const uint64_t& h) const override {
    const auto found = blocks.find(h); return found == blocks.end() ? block{} : found->second;
  }
  crypto::hash get_block_hash_from_height(const uint64_t& h) const override {
    const auto text = std::to_string(h) + ":" + std::to_string(epoch);
    return crypto::cn_fast_hash(text.data(), text.size());
  }
  std::vector<std::vector<std::pair<uint64_t, uint64_t>>> get_tx_amount_output_indices(uint64_t id, size_t n = 1) const override {
    check(n == 1 && id < outputs.size(), "Invalid fixture index"); return {{{id, id}}};
  }
  uint64_t get_output_id_by_asset_index(const std::string& asset, uint64_t index) const override {
    check(asset == "SAL1" && index < outputs.size(), "Invalid fixture asset index"); return index;
  }
  tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const override { return outputs.at(index); }
  output_record_t get_output_record_by_id(uint64_t index) const override {
    output_record_t result{}; result.tx_hash = outputs.at(index).first;
    result.od.asset_type = asset_id_from_type("SAL1"); return result;
  }
  void carrier(uint64_t height, const audit_clearance_batch& batch) {
    const auto data = t_serializable_object_to_blob(tx_extra_field{tx_extra_audit_clearance{t_serializable_object_to_blob(batch)}});
    blocks[height].miner_tx.extra.assign(data.begin(), data.end());
  }
};
}
int main() {
  try {
    clearance_db db;
    const auto good = db.add(10), uncleared = db.add(11);
    crypto::public_key authority, other; crypto::secret_key secret, other_secret;
    crypto::generate_keys(authority, secret); crypto::generate_keys(other, other_secret);
    audit_clearance_registry registry; registry.configure(FAKECHAIN, 100, authority);
    db.candidate = 99;
    block historical; historical.miner_tx.extra = {0xff}; std::string historical_reason;
    check(registry.validate_block(db, historical, historical_reason), "Audit changed pre-activation extra rules");
    db.candidate = 101;
    audit_clearance_certificate c;
    c.network = FAKECHAIN; c.genesis = db.get_block_hash_from_height(0);
    c.activation_height = 100; c.snapshot_height = 100; c.snapshot_hash = db.get_block_hash_from_height(100);
    c.transaction = good; c.decision = 1; bind_audit_clearance_policy(c); sign_audit_clearance(c, secret);
    check(verify_audit_clearance(c, authority) && !verify_audit_clearance(c, other), "Authority binding failed");
    audit_clearance_batch batch; batch.certificates.push_back(c); std::string reason;
    check(registry.validate_batch(db, batch, 101, reason), "Valid certificate rejected");
    auto forged = batch; forged.certificates[0].decision = 2;
    check(!registry.validate_batch(db, forged, 101, reason), "Altered decision accepted");
    for (unsigned field = 0; field < 3; ++field) {
      auto wrong_policy = batch;
      auto& cert = wrong_policy.certificates.front();
      if (field == 0) ++cert.policy_version;
      else if (field == 1) --cert.historical_cutoff_height;
      else cert.policy_digest = crypto::cn_fast_hash("other policy", 12);
      crypto::generate_signature(audit_clearance_message(cert), authority, secret, cert.signature);
      check(!registry.validate_batch(db, wrong_policy, 101, reason), "Different signed historical policy accepted");
    }
    auto noncanonical = batch;
    reinterpret_cast<unsigned char*>(&noncanonical.certificates[0].signature)[sizeof(crypto::signature) - 1] = 1;
    check(!verify_audit_clearance(noncanonical.certificates[0], authority) &&
        !registry.validate_batch(db, noncanonical, 101, reason), "Noncanonical signature extension accepted");
    auto duplicate = batch; duplicate.certificates.push_back(c);
    check(!registry.validate_batch(db, duplicate, 101, reason), "Duplicate certificate accepted");
    auto excessive = batch; excessive.certificates.resize(lineage_limits::max_outputs + 1, c);
    check(!registry.validate_batch(db, excessive, 101, reason), "Certificate work limit bypassed");
    auto wrong = batch; --wrong.certificates[0].activation_height;
    bind_audit_clearance_policy(wrong.certificates[0]); sign_audit_clearance(wrong.certificates[0], secret);
    check(!registry.validate_batch(db, wrong, 101, reason), "Wrong epoch accepted");
    transaction spend; spend.type = transaction_type::TRANSFER; spend.source_asset_type = "SAL1";
    txin_to_key input; input.asset_type = "SAL1"; input.key_offsets = {0}; spend.vin.push_back(input);
    check(!registry.check_spend(db, spend, reason), "Uncleared source spent");
    db.carrier(101, batch);
    check(registry.validate_block(db, db.blocks[101], reason), "Valid clearance block rejected");
    auto doubled = db.blocks[101];
    const auto extra = doubled.miner_tx.extra;
    doubled.miner_tx.extra.insert(doubled.miner_tx.extra.end(), extra.begin(), extra.end());
    check(!registry.validate_block(db, doubled, reason), "Duplicate carrier across block batches accepted");
    check(!registry.check_spend(db, spend, reason), "Unconfirmed certificate spent");
    db.candidate = 102;
    check(registry.check_spend(db, spend, reason), "H+1 clearance imposed an extra delay");
    boost::get<txin_to_key>(spend.vin[0]).key_offsets = {0, 1};
    check(!registry.check_spend(db, spend, reason), "Cleared decoy authorized uncleared source");
    boost::get<txin_to_key>(spend.vin[0]).key_offsets = {0};
    bool more = false;
    check(registry.eligible_outputs(db, "SAL1", 0, 1, more).size() == 1 && !more, "Eligible population mismatch");
    check(!registry.validate_batch(db, batch, 102, reason), "Confirmed revision replay accepted");
    check(registry.validate_batch(db, batch, 102, reason, true), "Idempotent publication retry rejected");
    // A later valid transfer inherits clearance only after ordinary maturity.
    db.add(102); db.candidate = 112; registry.sync(db);
    check(registry.output_spendable(db, 2, 112), "Valid transfer did not inherit clearance");
    c.decision = 2; c.revision = 2; c.snapshot_height = 111; c.snapshot_hash = db.get_block_hash_from_height(111);
    sign_audit_clearance(c, secret); batch.certificates = {c};
    check(!registry.validate_batch(db, batch, 112, reason), "Final clearance could be altered");
    c.transaction = uncleared; c.revision = 1; sign_audit_clearance(c, secret); batch.certificates = {c};
    db.carrier(112, batch); db.candidate = 113; registry.sync(db);
    check(!registry.output_spendable(db, 1, 113), "Denied output became spendable");
    c.decision = 1; c.revision = 2; sign_audit_clearance(c, secret); batch.certificates = {c};
    check(registry.validate_batch(db, batch, 113, reason), "Developer could not clear an unresolved denial");
    db.carrier(113, batch); db.candidate = 114; registry.sync(db);
    check(registry.output_spendable(db, 1, 114), "Final clearance did not resolve denial at H+1");
    // Reorg replay removes both certificates and inherited descendants.
    db.blocks.erase(101); db.blocks.erase(112); db.blocks.erase(113); ++db.epoch; db.candidate = 101;
    check(!registry.check_spend(db, spend, reason), "Orphaned authorization survived reorg");
    c.decision = 1; sign_audit_clearance(c, secret); batch.certificates = {c};
    check(!registry.validate_batch(db, batch, 113, reason), "Orphaned snapshot accepted");
    // Late principal clearance finally authorizes an existing unique payout,
    // while the payout's ordinary 60-block maturity remains in force.
    clearance_db stakes;
    transaction principal = stakes.get_tx(stakes.add(1));
    stakes.transactions.clear(); stakes.outputs.clear(); stakes.blocks.clear();
    principal.type = transaction_type::STAKE; principal.amount_burnt = 12;
    crypto::public_key return_key; crypto::secret_key return_secret;
    crypto::generate_keys(return_key, return_secret); principal.return_address = return_key;
    principal.invalidate_hashes();
    const auto principal_id = stakes.add_transaction(principal, 10);
    const uint64_t payout_height = 10 + get_config(FAKECHAIN).STAKE_LOCK_PERIOD + 1;
    transaction payout; payout.version = 1; payout.type = transaction_type::PROTOCOL;
    payout.vin.push_back(txin_gen{payout_height});
    payout.vout.push_back({12, txout_to_key{return_key, "SAL1", 60}});
    const auto payout_id = stakes.add_transaction(payout, payout_height);
    c.transaction = principal_id; c.stake = true; c.revision = 1; c.decision = 1;
    c.activation_height = 90; c.snapshot_height = payout_height;
    bind_audit_clearance_policy(c);
    c.genesis = stakes.get_block_hash_from_height(0); c.snapshot_hash = stakes.get_block_hash_from_height(payout_height);
    sign_audit_clearance(c, secret); batch.certificates = {c};
    stakes.carrier(payout_height + 1, batch); stakes.candidate = payout_height + 2;
    audit_clearance_registry stake_registry; stake_registry.configure(FAKECHAIN, 90, authority); stake_registry.sync(stakes);
    check(stake_registry.cleared(payout_id, 0) && !stake_registry.output_spendable(stakes, 1, stakes.candidate),
        "Late principal clearance lost finality or bypassed payout maturity");
    check(stake_registry.eligible_outputs(stakes, "SAL1", 0, 1000, more).empty(), "Immature payout entered public decoy population");
    c.transaction = payout_id; c.stake = false; c.decision = 2;
    sign_audit_clearance(c, secret); batch.certificates = {c};
    check(!stake_registry.validate_batch(stakes, batch, stakes.candidate, reason), "Inherited final payout could be denied while maturing");
    stakes.candidate = payout_height + 60; stake_registry.sync(stakes);
    check(stake_registry.output_spendable(stakes, 1, stakes.candidate), "Payout required a second audit after normal maturity");
    clearance_db malformed_db;
    const transaction template_tx = malformed_db.get_tx(malformed_db.add(10));
    audit_clearance_registry malformed_registry;
    malformed_registry.configure(FAKECHAIN, 100, authority);
    for (unsigned variant = 0; variant < 3; ++variant) {
      auto tx = template_tx;
      tx.extra = {static_cast<uint8_t>(variant + 1)};
      if (variant == 0) tx.source_asset_type = "salOTHER";
      else tx.version = 2; // A confidential transaction retaining a public amount.
      if (variant == 2) { tx.type = transaction_type::STAKE; tx.amount_burnt = 12; }
      tx.invalidate_hashes();
      audit_clearance_certificate cert;
      cert.network = FAKECHAIN; cert.activation_height = 100;
      cert.snapshot_height = 100; cert.snapshot_hash = malformed_db.get_block_hash_from_height(100);
      cert.genesis = malformed_db.get_block_hash_from_height(0);
      cert.transaction = malformed_db.add_transaction(tx, 10); cert.stake = variant == 2;
      cert.decision = 1; bind_audit_clearance_policy(cert); sign_audit_clearance(cert, secret);
      audit_clearance_batch malformed_batch; malformed_batch.certificates = {cert};
      check(!malformed_registry.validate_batch(malformed_db, malformed_batch, 101, reason) &&
          reason.find("malformed") != std::string::npos, "Signed clearance accepted an intrinsically malformed origin");
      cert.decision = 2; sign_audit_clearance(cert, secret); malformed_batch.certificates = {cert};
      check(malformed_registry.validate_batch(malformed_db, malformed_batch, 101, reason),
          "Malformed origin could not receive an explicit denial");
    }
    std::cout << "AUDIT_CLEARANCE_PASS authority, tamper, epoch, duplicates, activation, H+1, mixed rings, inheritance, immutable clearance, denial resolution, replay, reorg, malformed-origin denial\n";
    return 0;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
