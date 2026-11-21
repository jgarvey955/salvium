#include "cryptonote_core/audit_review.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "blockchain_db/testdb.h"
#include "ringct/rctSigs.h"
#include "device/device.hpp"
#include "cryptonote_config.h"
#include "serialization/binary_utils.h"
#include "string_tools.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace cryptonote;
namespace {
void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
template<class F> void rejected(F f) {
  bool failed = false;
  try { f(); } catch (const std::exception&) { failed = true; }
  check(failed, "Invalid private audit evidence was accepted");
}
template<class T> std::string hex(const T& t) { return epee::string_tools::pod_to_hex(t); }
class review_db : public BaseTestDB {
public:
  std::unordered_map<crypto::hash, std::pair<transaction, uint64_t>> txs;
  uint64_t epoch = 0;
  uint64_t height() const override { return 201; }
  int get_yield_block_info(uint64_t, yield_block_info& info) const override {
    info = {}; return 0;
  }
  bool tx_exists(const crypto::hash& id) const override { return txs.count(id); }
  transaction get_tx(const crypto::hash& id) const override { return txs.at(id).first; }
  uint64_t get_tx_block_height(const crypto::hash& id) const override { return txs.at(id).second; }
  block get_block_from_height(const uint64_t& h) const override {
    block b;
    b.major_version = HF_VERSION_CARROT;
    for (const auto& item : txs) if (item.second.second == h) {
      if (item.second.first.type == transaction_type::MINER) b.miner_tx = item.second.first;
      else if (item.second.first.type == transaction_type::PROTOCOL) b.protocol_tx = item.second.first;
      else b.tx_hashes.push_back(item.first);
    }
    return b;
  }
  crypto::hash get_block_hash_from_height(const uint64_t& h) const override {
    crypto::hash hash{};
    std::memcpy(&hash, &h, sizeof(h));
    std::memcpy(reinterpret_cast<char*>(&hash) + sizeof(h), &epoch, sizeof(epoch));
    return hash;
  }
  std::vector<tx_out_index> indices;
  uint64_t get_output_id_by_asset_index(const std::string& asset, uint64_t index) const override {
    check(asset == "SAL1" && index < indices.size(), "Bad fixture ring index"); return index;
  }
  uint64_t get_legacy_output_id_by_asset_index(const std::string& asset, uint64_t index) const override {
    return get_output_id_by_asset_index(asset, index);
  }
  tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const override { return indices.at(index); }
};
audit_review_package context(const review_db& db) {
  audit_review_package p;
  p.network = uint8_t(FAKECHAIN); p.genesis = hex(db.get_block_hash_from_height(0));
  p.snapshot_height = db.height() - 1; p.snapshot_hash = hex(db.get_block_hash_from_height(p.snapshot_height));
  p.nonce = hex(crypto::rand<crypto::hash>());
  return p;
}
lineage_output_proof prove(const audit_review_package& p, const transaction& tx, size_t index,
    const rct::key& secret, const rct::key& mask, uint64_t amount, bool public_amount = false,
    bool stake_return = false) {
  lineage_output_proof proof;
  proof.transaction = get_transaction_hash(tx); proof.output_index = index; proof.amount = amount;
  proof.stake_return = stake_return;
  proof.offset_mask = mask == rct::zero() ? 1 : 0;
  const auto offset = proof.offset_mask ? rct::identity() : rct::zero();
  crypto::public_key key;
  check(get_output_public_key(tx.vout.at(index), key), "Missing fixture output key");
  crypto::generate_key_image(key, rct::rct2sk(secret), proof.image);
  const auto commitment = public_amount ? rct::commit(amount, rct::identity()) : tx.rct_signatures.outPk.at(index).mask;
  proof.signature = rct::proveRctTCLSAGSimple(rct::hash2rct(audit_review_proof_message(p, proof)),
      {{rct::pk2rct(key), commitment}}, secret, rct::zero(), mask, offset,
      rct::commit(amount, offset), 0, hw::get_device("default"));
  check(verify_audit_review_proof(p, proof, key, commitment), "Invalid fixture ownership proof");
  return proof;
}
void append(audit_review_package& p, const lineage_output_proof& proof) {
  p.proofs.push_back(epee::string_tools::buff_to_hex_nodelimer(t_serializable_object_to_blob(proof)));
}
struct owned_output { transaction tx; size_t index; rct::key secret, mask; uint64_t amount; };
owned_output transfer(review_db& db, const owned_output& parent, uint64_t height,
    const std::vector<size_t>& ring, size_t real_member) {
  const auto secret = rct::skGen(), dest = rct::scalarmultBase(secret);
  transaction tx;
  tx.version = 2; tx.type = transaction_type::TRANSFER;
  tx.source_asset_type = tx.destination_asset_type = "SAL1";
  crypto::public_key parent_key;
  check(get_output_public_key(parent.tx.vout[parent.index], parent_key), "Parent key missing");
  txin_to_key input{};
  input.asset_type = "SAL1";
  crypto::generate_key_image(parent_key, rct::rct2sk(parent.secret), input.k_image);
  for (size_t i = 0; i < ring.size(); ++i) input.key_offsets.push_back(i ? ring[i] - ring[i-1] : ring[i]);
  tx.vin.push_back(input);
  tx.vout.push_back({0, txout_to_key{rct::rct2pk(dest), "SAL1", 10}});
  rct::ctkeyV sources{{parent.secret, parent.mask}};
  rct::ctkeyM rings(1);
  for (const auto index : ring) {
    const auto reference = db.indices.at(index);
    const auto previous = db.get_tx(reference.first);
    const auto& out = previous.vout.at(reference.second);
    crypto::public_key key;
    get_output_public_key(out, key);
    rings[0].push_back({rct::pk2rct(key), previous.type == transaction_type::MINER || previous.type == transaction_type::PROTOCOL ?
        rct::zeroCommit(out.amount) : previous.rct_signatures.outPk.at(reference.second).mask});
  }
  rct::ctkeyV out_secrets;
  rct::RCTConfig config{rct::RangeProofPaddedBulletproof, 4};
  rct::salvium_data_t data{};
  tx.rct_signatures = rct::genRctSimple(rct::hash2rct(get_transaction_prefix_hash(tx)),
      sources, {dest}, tx.type, "SAL1", {"SAL1"}, {parent.amount}, {parent.amount}, 0,
      rings, {rct::skGen()}, {static_cast<unsigned>(real_member)}, out_secrets, config,
      hw::get_device("default"), data);
  tx.invalidate_hashes();
  db.txs[get_transaction_hash(tx)] = {tx, height};
  db.indices.emplace_back(get_transaction_hash(tx), 0);
  return {tx, 0, secret, out_secrets.at(0).mask, parent.amount};
}
}

int main(int argc, char** argv) {
  try {
    check(argc == 2, "Pass tests/data/sal1-bad-origin-465074.hex");
    std::ifstream in(argv[1]); std::string text, blob; in >> text;
    transaction historical;
    check(epee::string_tools::parse_hexstr_to_binbuff(text, blob) && parse_and_validate_tx_from_blob(blob, historical) &&
        hex(get_transaction_hash(historical)) == "9353dd3288e20618596085228ea6faf5bf2a9d01cd98c36ea5ceeef2c2d4eb1e",
        "Historical salYAHU fixture changed");
    review_db db;
    auto p = context(db);
    auto rekeyed = historical;
    std::vector<rct::key> keys, masks;
    for (size_t i = 0; i < rekeyed.vout.size(); ++i) {
      keys.push_back(rct::skGen()); masks.push_back(rct::skGen());
      boost::get<txout_to_carrot_v1>(rekeyed.vout[i].target).key = rct::rct2pk(rct::scalarmultBase(keys.back()));
      rekeyed.rct_signatures.outPk[i].mask = rct::commit(2000000000000000, masks.back());
    }
    rekeyed.invalidate_hashes();
    db.txs[get_transaction_hash(rekeyed)] = {rekeyed, 80};
    for (size_t i = 0; i < rekeyed.vout.size(); ++i) db.indices.emplace_back(get_transaction_hash(rekeyed), i);
    for (size_t i = 0; i < rekeyed.vout.size(); ++i)
      append(p, prove(p, rekeyed, i, keys[i], masks[i], 2000000000000000));
    auto bad = audit_review_verifier::verify(db, FAKECHAIN, {p}, 2);
    check(bad.outputs.size() == 2, "Lost malformed-origin outputs");
    for (const auto& item : bad.outputs)
      check(item.state == "REVIEW_REQUIRED" && item.recommendation == "DENY" &&
          item.reason == "CONFIRMED_MALFORMED_ORIGIN", "salYAHU origin was cleared or mislabeled");

    transaction reward;
    reward.version = 5; reward.type = transaction_type::MINER;
    reward.vin.push_back(txin_gen{1});
    const auto secret = rct::skGen();
    reward.vout.push_back({100, txout_to_carrot_v1{rct::rct2pk(rct::scalarmultBase(secret)), "SAL1", {}, {}}});
    db.txs[get_transaction_hash(reward)] = {reward, 1};
    db.indices.emplace_back(get_transaction_hash(reward), 0);
    auto roots = context(db);
    append(roots, prove(roots, reward, 0, secret, rct::identity(), 100, true));
    auto result = audit_review_verifier::verify(db, FAKECHAIN, {p, roots}, 2);
    check(result.outputs.back().state == "CLEARED" && result.outputs.back().reason == "ACCEPTED_OPENING",
        "Verified accepted root did not clear beside malformed funds");
    auto duplicate = audit_review_verifier::verify(db, FAKECHAIN, {p, roots, p}, 2);
    check(duplicate.outputs.size() == result.outputs.size(), "Duplicate package double counted outputs");
    const owned_output illicit{rekeyed, 0, keys[0], masks[0], 2000000000000000};
    const auto illicit_child = transfer(db, illicit, 100, {0}, 0);
    const auto illicit_grandchild = transfer(db, illicit_child, 120, {3}, 0);
    const owned_output legitimate{reward, 0, secret, rct::identity(), 100};
    const auto decoy_only = transfer(db, legitimate, 140, {0, 2}, 1);
    auto peers = context(db);
    for (const auto* out : {&illicit_child, &illicit_grandchild, &decoy_only})
      append(peers, prove(peers, out->tx, 0, out->secret, out->mask, out->amount));
    const auto missing = audit_review_verifier::verify(db, FAKECHAIN, {peers}, 2);
    for (const auto& item : missing.outputs)
      check(item.state == "REVIEW_REQUIRED", "Missing upstream owner silently cleared");
    check(missing.outputs[0].reason == "PROVEN_ILLICIT_FUNDING_REQUIRES_REVIEW" &&
        missing.outputs[1].reason == "PROVEN_ILLICIT_FUNDING_REQUIRES_REVIEW",
        "Conclusive public ring sets failed to identify illicit transfers without owner cooperation");
    const auto paths = audit_review_verifier::verify(db, FAKECHAIN, {peers, roots, p}, 2);
    check(paths.outputs[0].reason == "PROVEN_ILLICIT_FUNDING_REQUIRES_REVIEW" &&
        paths.outputs[1].reason == "PROVEN_ILLICIT_FUNDING_REQUIRES_REVIEW",
        "Illicit transfer across two independent owners escaped review");
    check(paths.outputs[2].state == "CLEARED", "An illicit decoy contaminated a proven legitimate spend");
    transaction accepted = reward;
    accepted.type = transaction_type::PROTOCOL;
    const auto accepted_secret = rct::skGen();
    boost::get<txout_to_carrot_v1>(accepted.vout[0].target).key = rct::rct2pk(rct::scalarmultBase(accepted_secret));
    accepted.invalidate_hashes();
    db.txs[get_transaction_hash(accepted)] = {accepted, 2};
    db.indices.emplace_back(get_transaction_hash(accepted), 0);
    const owned_output independent{accepted, 0, accepted_secret, rct::identity(), 100};
    const auto public_child = transfer(db, independent, 160, {6}, 0);
    auto alone = context(db);
    append(alone, prove(alone, public_child.tx, 0, public_child.secret, public_child.mask, public_child.amount));
    const auto automatic = audit_review_verifier::verify(db, FAKECHAIN, {alone}, 2);
    check(automatic.outputs.front().state == "CLEARED" &&
        automatic.outputs.front().reason == "ALL_RING_CANDIDATES_VERIFIED",
        "Publicly provable funding unnecessarily required the earlier owner");
    const auto bounded = audit_review_verifier::verify(db, FAKECHAIN, {alone}, 2, 0);
    check(bounded.outputs.front().state == "REVIEW_REQUIRED", "Work limit approved unchecked ancestry");
    auto locked_decoy = accepted;
    boost::get<txout_to_carrot_v1>(locked_decoy.vout[0].target).key = rct::rct2pk(rct::pkGen());
    // A valid accepted root can still be an immature candidate in a later ring.
    // Carrot has no per-output lock field, so put this accepted root near the spend.
    locked_decoy.invalidate_hashes();
    db.txs[get_transaction_hash(locked_decoy)] = {locked_decoy, 150};
    db.indices.emplace_back(get_transaction_hash(locked_decoy), 0);
    db.txs.erase(get_transaction_hash(public_child.tx));
    const auto mixed_maturity = transfer(db, independent, 160, {6, 8}, 0);
    auto maturity_request = context(db);
    append(maturity_request, prove(maturity_request, mixed_maturity.tx, 0,
        mixed_maturity.secret, mixed_maturity.mask, mixed_maturity.amount));
    // Opening 150 accepts both roots; only the exact real source establishes maturity.
    const auto maturity_public = audit_review_verifier::verify(db, FAKECHAIN, {maturity_request}, 150);
    check(maturity_public.outputs[0].state == "REVIEW_REQUIRED",
        "A public ring with an immature possible source cleared without an exact funding proof");
    auto maturity_parent = context(db);
    append(maturity_parent, prove(maturity_parent, accepted, 0, accepted_secret, rct::identity(), 100, true));
    const auto maturity_exact = audit_review_verifier::verify(db, FAKECHAIN, {maturity_request, maturity_parent}, 150);
    check(maturity_exact.outputs[0].state == "CLEARED",
        "An immature decoy prevented clearance of an exact mature real source");
    db.txs.erase(get_transaction_hash(mixed_maturity.tx));
    db.txs[get_transaction_hash(public_child.tx)] = {public_child.tx, 160};
    const auto opening_root = audit_review_verifier::verify(db, FAKECHAIN, {alone}, 170, 0);
    check(opening_root.outputs.front().state == "CLEARED" &&
        opening_root.outputs.front().reason == "ACCEPTED_OPENING",
        "Accepted opening unnecessarily required private ancestry before the boundary");
    // A funding defect must not count returned principal again beside its payout.
    review_db stake_db;
    stake_db.txs[get_transaction_hash(accepted)] = {accepted, 2};
    stake_db.indices.emplace_back(get_transaction_hash(accepted), 0);
    const auto stake_owner = transfer(stake_db, independent, 10, {0}, 0);
    stake_db.txs.erase(get_transaction_hash(stake_owner.tx));
    auto defective_stake = stake_owner.tx;
    defective_stake.type = transaction_type::STAKE;
    defective_stake.amount_burnt = 50; // Original transfer proof cannot authorize this extra burn.
    get_output_public_key(defective_stake.vout[0], defective_stake.return_address);
    defective_stake.return_pubkey = rct::rct2pk(rct::pkGen());
    defective_stake.invalidate_hashes();
    stake_db.txs[get_transaction_hash(defective_stake)] = {defective_stake, 10};
    transaction returned;
    returned.version = 2; returned.type = transaction_type::PROTOCOL;
    returned.vin.push_back(txin_gen{31});
    returned.vout.push_back({50, txout_to_key{defective_stake.return_address, "SAL1", 60}});
    add_additional_tx_pub_keys_to_extra(returned.extra, {defective_stake.return_pubkey});
    stake_db.txs[get_transaction_hash(returned)] = {returned, 31};
    auto stake_request = context(stake_db); stake_request.network = uint8_t(TESTNET);
    append(stake_request, prove(stake_request, defective_stake, 0, stake_owner.secret, rct::identity(), 50, true, true));
    append(stake_request, prove(stake_request, returned, 0, stake_owner.secret, rct::identity(), 50, true));
    const auto paid_defect = audit_review_verifier::verify(stake_db, TESTNET, {stake_request}, 2, 0);
    check(paid_defect.outputs[0].spent && !paid_defect.outputs[1].spent,
        "Returned defective stake principal inflated unspent custody");
    for (const auto& item : paid_defect.outputs)
      check(item.state == "REVIEW_REQUIRED" && item.recommendation == "DENY",
          "Recognizing a canonical payout cleared defective funding");
    auto wrong = p; wrong.snapshot_hash = hex(crypto::rand<crypto::hash>());
    rejected([&] { audit_review_verifier::verify(db, FAKECHAIN, {wrong}, 2); });
    wrong = p; wrong.network = uint8_t(MAINNET);
    rejected([&] { audit_review_verifier::verify(db, FAKECHAIN, {wrong}, 2); });
    wrong = p; wrong.nonce = hex(crypto::rand<crypto::hash>());
    rejected([&] { audit_review_verifier::verify(db, FAKECHAIN, {wrong}, 2); });
    wrong = p; wrong.proofs[0].back() = wrong.proofs[0].back() == '0' ? '1' : '0';
    rejected([&] { audit_review_verifier::verify(db, FAKECHAIN, {wrong}, 2); });
    ++db.epoch;
    rejected([&] { audit_review_verifier::verify(db, FAKECHAIN, {p}, 2); });
    --db.epoch;
    crypto::public_key developer, other; crypto::secret_key signing, other_secret;
    crypto::generate_keys(developer, signing); crypto::generate_keys(other, other_secret);
    check(!authorized_audit_review_signer(MAINNET, developer), "Owner substituted a mainnet audit signing authority");
    auto unauthorized = result; unauthorized.network = uint8_t(MAINNET);
    rejected([&] { sign_audit_review_report(unauthorized, signing); });
    sign_audit_review_report(result, signing);
    check(verify_audit_review_report(result, developer), "Developer result failed verification");
    check(!verify_audit_review_report(result, other), "Untrusted developer key accepted");
    auto changed = result; changed.outputs[0].state = "CLEARED";
    check(!verify_audit_review_report(changed, developer), "Forged clearance accepted");
    changed = result; ++changed.revision;
    check(!verify_audit_review_report(changed, developer), "Unsigned result revision accepted");
    changed = result; changed.outputs[0].decision = "CLEAR"; changed.outputs[0].decision_reason = "Verified innocent exchange purchase";
    sign_audit_review_report(changed, signing);
    check(verify_audit_review_report(changed, developer), "Explicit developer decision was lost");
    changed.outputs[0].decision_reason.clear(); sign_audit_review_report(changed, signing);
    check(!verify_audit_review_report(changed, developer), "Unexplained developer override accepted");
    const auto path = (boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("salvium-review-%%%%-%%%%")).string();
    write_private_audit_file(path, "private test\n");
    check(read_audit_file(path) == "private test\n", "Private export did not persist");
    rejected([&] { write_private_audit_file(path, "overwrite"); });
    check((boost::filesystem::status(path).permissions() & (boost::filesystem::group_all | boost::filesystem::others_all)) == 0,
        "Audit evidence is readable by other users");
    boost::filesystem::remove(path);
    std::cout << "AUDIT_PRIVATE_REVIEW_PASS: authentic finite proofs, rekeyed historical salYAHU origin, accepted root, duplicate package, context/forgery/reorg rejection, signed developer decisions and private files\n";
    return 0;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
