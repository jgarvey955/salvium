#include "audit_clearance.h"
#include "audit_review.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "carrot_impl/format_utils.h"
#include "serialization/binary_utils.h"
#include "string_tools.h"
#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

namespace cryptonote
{
namespace
{
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
audit_clearance_registry::identity certificate_identity(const audit_clearance_certificate& c)
{ return {epee::string_tools::pod_to_hex(c.transaction), c.output_index, c.stake}; }
bool valid_fields(const audit_clearance_certificate& c)
{
  return c.version == 4 && c.network <= uint8_t(FAKECHAIN) && c.genesis != crypto::null_hash &&
      c.activation_height && c.snapshot_height >= c.activation_height &&
      c.snapshot_height < UINT64_MAX - 1 && c.snapshot_hash != crypto::null_hash &&
      c.transaction != crypto::null_hash && c.revision && (c.decision == 1 || c.decision == 2) &&
      (!c.stake || c.output_index == 0);
}
transaction canonical_tx(const BlockchainDB& db, const crypto::hash& id)
{
  // Consensus clearance uses public transaction bases and retained prunable
  // hashes, so an otherwise valid pruned node does not need private witnesses.
  auto tx = db.get_pruned_tx(id);
  if (tx.version == 1) return db.get_tx(id);
  crypto::hash prunable = crypto::null_hash;
  require(tx.rct_signatures.type == rct::RCTTypeNull || db.get_prunable_tx_hash(id, prunable),
      "Missing canonical prunable transaction hash");
  require(get_pruned_transaction_hash(tx, prunable) == id, "Canonical transaction base/hash mismatch");
  return tx;
}
std::vector<audit_clearance_batch> batches(const block& b)
{
  std::vector<tx_extra_field> fields;
  require(parse_tx_extra(b.miner_tx.extra, fields), "Malformed miner extra");
  std::vector<audit_clearance_batch> result;
  size_t bytes = 0, count = 0;
  for (const auto& field : fields) if (const auto* envelope = boost::get<tx_extra_audit_clearance>(&field)) {
    const auto size = t_serializable_object_to_blob(field).size();
    require(size <= lineage_limits::max_bytes - bytes, "Audit clearance block carrier exceeds byte limit");
    bytes += size;
    audit_clearance_batch batch;
    require(serialization::parse_binary(envelope->data, batch) &&
        t_serializable_object_to_blob(batch) == envelope->data,
        "Invalid or noncanonical audit clearance batch");
    require(batch.certificates.size() <= lineage_limits::max_outputs - count,
        "Audit clearance block carrier exceeds certificate limit");
    count += batch.certificates.size();
    result.push_back(std::move(batch));
  }
  return result;
}
uint64_t normal_release(const transaction& tx, uint32_t index, uint64_t height)
{
  uint64_t age = 0;
  require(index < tx.vout.size() && get_output_unlock_time(tx.vout[index], age), "Invalid output lock");
  if (!age) age = tx.type == transaction_type::MINER || tx.type == transaction_type::PROTOCOL ?
      CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW : CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
  age = std::max<uint64_t>(age, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
  require(age < CRYPTONOTE_MAX_BLOCK_NUMBER && height <= UINT64_MAX - age, "Invalid output maturity");
  return height + age;
}
}

crypto::hash audit_clearance_message(const audit_clearance_certificate& c)
{
  std::string message = "Salvium public audit clearance v4";
  const auto field = [&](const std::string& s) { message += std::to_string(s.size()) + ":" + s; };
  field(std::to_string(c.version)); field(std::to_string(c.network));
  field(epee::string_tools::pod_to_hex(c.genesis)); field(std::to_string(c.activation_height));
  field(std::to_string(c.snapshot_height)); field(epee::string_tools::pod_to_hex(c.snapshot_hash));
  field(epee::string_tools::pod_to_hex(c.transaction)); field(std::to_string(c.output_index));
  field(c.stake ? "1" : "0"); field(std::to_string(c.revision)); field(std::to_string(c.decision));
  return crypto::cn_fast_hash(message.data(), message.size());
}
void sign_audit_clearance(audit_clearance_certificate& c, const crypto::secret_key& secret)
{
  crypto::public_key key;
  require(valid_fields(c) && crypto::secret_key_to_public_key(secret, key) &&
      authorized_audit_review_signer(static_cast<network_type>(c.network), key),
      "Invalid certificate or undesignated audit authority");
  crypto::generate_signature(audit_clearance_message(c), key, secret, c.signature);
}
bool verify_audit_clearance(const audit_clearance_certificate& c, const crypto::public_key& authority)
{
  return valid_fields(c) && crypto::check_key(authority) &&
      !(rct::pk2rct(authority) == rct::identity()) && rct::isInMainSubgroup(rct::pk2rct(authority)) &&
      crypto::check_signature(audit_clearance_message(c), authority, c.signature);
}

void audit_clearance_registry::configure(network_type net, uint64_t activation, const crypto::public_key& key)
{
  require(net <= FAKECHAIN && (!activation || (crypto::check_key(key) &&
      !(rct::pk2rct(key) == rct::identity()) && rct::isInMainSubgroup(rct::pk2rct(key)) &&
      authorized_audit_review_signer(net, key))), "Activation requires the designated audit authority");
  network_ = net; activation_ = activation; authority_ = key;
  reset();
}
void audit_clearance_registry::reset()
{
  entries_.clear(); finalized_.clear(); eligible_.clear(); due_.clear(); automatic_due_.clear();
  next_height_ = activation_; tip_ = crypto::null_hash;
}
const audit_clearance_registry::entry* audit_clearance_registry::find(
    const crypto::hash& transaction, uint32_t index, bool stake) const
{
  const auto found = entries_.find({epee::string_tools::pod_to_hex(transaction), index, stake});
  return found == entries_.end() ? nullptr : &found->second;
}
bool audit_clearance_registry::validate_batch(const BlockchainDB& db, const audit_clearance_batch& batch,
    uint64_t height, std::string& reason, bool allow_confirmed) const
{
  try {
    require(active(height), "Private audit clearance is not active");
    require(batch.version == 4 && !batch.certificates.empty() &&
        batch.certificates.size() <= lineage_limits::max_outputs, "Invalid certificate count");
    std::set<identity> seen;
    for (const auto& c : batch.certificates) {
      require(c.network == uint8_t(network_) && c.activation_height == activation_ &&
          c.genesis == db.get_block_hash_from_height(0) && c.snapshot_height < height &&
          c.snapshot_height < db.height() && c.snapshot_hash == db.get_block_hash_from_height(c.snapshot_height),
          "Certificate belongs to another epoch, network or orphaned snapshot");
      require(seen.insert(certificate_identity(c)).second, "Duplicate certified output");
      require(verify_audit_clearance(c, authority_), "Invalid developer clearance signature");
      require(db.tx_exists(c.transaction) && db.get_tx_block_height(c.transaction) <= c.snapshot_height,
          "Certificate output is not canonical at its snapshot");
      const auto tx = canonical_tx(db, c.transaction);
      require(get_transaction_hash(tx) == c.transaction, "Certificate transaction hash mismatch");
      if (c.stake) {
        require(tx.type == transaction_type::STAKE && tx.source_asset_type == "SAL1" &&
            tx.amount_burnt > 0 && c.output_index == 0, "Invalid stake clearance identity");
      } else {
        std::string asset;
        require(c.output_index < tx.vout.size() && get_output_asset_type(tx.vout[c.output_index], asset) &&
            is_lineage_audit_asset(asset), "Invalid certified output or asset");
        normal_release(tx, c.output_index, db.get_tx_block_height(c.transaction));
      }
      const auto* previous = find(c.transaction, c.output_index, c.stake);
      if (allow_confirmed && finalized_.count(certificate_identity(c)) && c.decision == 1) continue;
      if (allow_confirmed && previous && t_serializable_object_to_blob(previous->certificate) == t_serializable_object_to_blob(c)) continue;
      require(!finalized_.count(certificate_identity(c)), "Confirmed clearance is final and cannot be altered");
      require(!previous || c.revision > previous->certificate.revision,
          "Certificate revision is stale or already confirmed");
    }
    return true;
  } catch (const std::exception& e) { reason = e.what(); return false; }
}
bool audit_clearance_registry::cleared(const crypto::hash& tx, uint32_t index, bool stake) const
{
  return finalized_.count({epee::string_tools::pod_to_hex(tx), index, stake}) != 0;
}
bool audit_clearance_registry::validate_block(const BlockchainDB& db, const block& candidate, std::string& reason)
{
  try {
    sync(db);
    const auto carriers = batches(candidate);
    require(active(db.height()) || carriers.empty(), "Audit clearance carrier precedes activation");
    std::set<identity> seen;
    for (const auto& batch : carriers) {
      if (!validate_batch(db, batch, db.height(), reason)) return false;
      for (const auto& c : batch.certificates)
        require(seen.insert(certificate_identity(c)).second, "Duplicate certificate across block batches");
    }
    return true;
  } catch (const std::exception& e) { reason = e.what(); return false; }
}
void audit_clearance_registry::apply(const BlockchainDB& db, const audit_clearance_batch& batch, uint64_t height)
{
  for (const auto& c : batch.certificates) {
    const auto id = certificate_identity(c);
    entries_[id] = {c, height};
    if (c.decision == 1) finalized_.insert(id);
    const auto tx = canonical_tx(db, c.transaction);
    const uint64_t origin = db.get_tx_block_height(c.transaction);
    uint64_t release = height + private_audit_policy::confirmation_delay;
    if (c.stake) {
      const uint64_t term = get_config(network_).STAKE_LOCK_PERIOD + 1;
      require(origin <= UINT64_MAX - term - CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
          "Stake clearance maturity overflow");
      release = std::max(release, origin + term + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
    } else {
      release = std::max(release, normal_release(tx, c.output_index, origin));
    }
    if (c.decision == 1) {
      due_[release].push_back({id, c.revision});
      // A payout that already exists becomes finally authorized with its
      // principal, even while its ordinary maturity is still pending.
      if (c.stake) update_eligible(db, id, release);
    }
  }
}
void audit_clearance_registry::update_eligible(const BlockchainDB& db, const identity& id, uint64_t height)
{
  const auto& authorization = entries_.at(id);
  const auto& c = authorization.certificate;
  if (c.decision != 1 || height <= authorization.confirmed_height) return;
  const auto add = [&](const transaction& tx, const crypto::hash& tx_hash, uint32_t index) {
    const uint64_t origin = db.get_tx_block_height(tx_hash);
    if (height < normal_release(tx, index, origin)) return;
    const auto* direct = find(tx_hash, index);
    if (direct && (certificate_identity(direct->certificate) != id || direct->certificate.decision != 1)) return;
    uint64_t tx_id = 0;
    require(db.tx_exists(tx_hash, tx_id), "Missing eligible transaction");
    const auto indices = db.get_tx_amount_output_indices(tx_id);
    std::string asset;
    require(indices.size() == 1 && index < indices[0].size() &&
        get_output_asset_type(tx.vout[index], asset) && is_lineage_audit_asset(asset),
        "Missing eligible output asset/index");
    const uint64_t asset_index = indices[0][index].second;
    const auto canonical = db.get_output_tx_and_index_from_global(db.get_output_id_by_asset_index(asset, asset_index));
    require(canonical.first == tx_hash && canonical.second == index, "Noncanonical eligible output index");
    finalized_.insert({epee::string_tools::pod_to_hex(tx_hash), index, false});
    eligible_[asset][asset_index] = {{asset_index, authorization.confirmed_height, origin, tx_hash, index},
        std::max(authorization.confirmed_height + 1, normal_release(tx, index, origin))};
  };
  const auto source = canonical_tx(db, c.transaction);
  if (!c.stake) { add(source, c.transaction, c.output_index); return; }
  const uint64_t origin = db.get_tx_block_height(c.transaction);
  const uint64_t payout_height = origin + get_config(network_).STAKE_LOCK_PERIOD + 1;
  if (payout_height >= db.height()) return;
  const auto key = carrot::is_carrot_transaction_v1(source) ? source.protocol_tx_data.return_address : source.return_address;
  size_t sources = 0;
  for (const auto& tx_hash : db.get_block_from_height(origin).tx_hashes) {
    const auto stake = canonical_tx(db, tx_hash);
    if (stake.type == transaction_type::STAKE && stake.source_asset_type == "SAL1" &&
        (carrot::is_carrot_transaction_v1(stake) ? stake.protocol_tx_data.return_address : stake.return_address) == key) ++sources;
  }
  if (sources != 1) return; // Ambiguous ancestry requires direct payout review.
  const auto payout = db.get_block_from_height(payout_height).protocol_tx;
  const auto payout_id = get_transaction_hash(payout);
  std::vector<uint32_t> matched;
  for (uint32_t index = 0; index < payout.vout.size(); ++index) {
    crypto::public_key actual;
    if (get_output_public_key(payout.vout[index], actual) && actual == key) matched.push_back(index);
  }
  if (matched.size() == 1) add(payout, payout_id, matched.front());
}
void audit_clearance_registry::advance(const BlockchainDB& db, uint64_t height)
{
  while (!automatic_due_.empty() && automatic_due_.begin()->first <= height) {
    auto items = std::move(automatic_due_.begin()->second);
    automatic_due_.erase(automatic_due_.begin());
    for (const auto& item : items) add_automatic(db, item.first, item.second, height);
  }
  while (!due_.empty() && due_.begin()->first <= height) {
    auto items = std::move(due_.begin()->second);
    due_.erase(due_.begin());
    for (const auto& item : items) {
      const auto found = entries_.find(item.first);
      if (found != entries_.end() && found->second.certificate.revision == item.second)
        update_eligible(db, item.first, height);
    }
  }
}
void audit_clearance_registry::add_automatic(const BlockchainDB& db, const crypto::hash& hash,
    uint32_t index, uint64_t height)
{
  // An explicit disposition always takes precedence over inherited clearance.
  if (find(hash, index)) return;
  const auto tx = canonical_tx(db, hash);
  const auto origin = db.get_tx_block_height(hash);
  if (height < normal_release(tx, index, origin)) return;
  uint64_t tx_id = 0;
  require(db.tx_exists(hash, tx_id), "Missing inherited transaction");
  const auto indices = db.get_tx_amount_output_indices(tx_id);
  std::string asset;
  require(indices.size() == 1 && index < indices[0].size() &&
      get_output_asset_type(tx.vout[index], asset), "Missing inherited output index");
  if (!is_lineage_audit_asset(asset)) return;
  const auto asset_index = indices[0][index].second;
  eligible_[asset][asset_index] = {{asset_index, origin, origin, hash, index},
      normal_release(tx, index, origin)};
}
void audit_clearance_registry::inherit_block(const BlockchainDB& db, const block& b, uint64_t height)
{
  const auto schedule = [&](const transaction& tx, uint32_t index) {
    const identity id{epee::string_tools::pod_to_hex(get_transaction_hash(tx)), index, false};
    const auto* direct = find(get_transaction_hash(tx), index);
    if (direct && direct->certificate.decision == 2) return;
    finalized_.insert(id);
    automatic_due_[normal_release(tx, index, height)].push_back({get_transaction_hash(tx), index});
  };
  for (uint32_t i = 0; i < b.miner_tx.vout.size(); ++i) schedule(b.miner_tx, i);
  // These transactions were accepted only after every funding ring member
  // passed the gate. Subsequent owners need not audit the same funds again.
  for (const auto& hash : b.tx_hashes) {
    const auto tx = canonical_tx(db, hash);
    for (uint32_t i = 0; i < tx.vout.size(); ++i) schedule(tx, i);
  }
  // Protocol payouts can originate in a pre-activation obligation. Inherit
  // only a unique post-activation stake or same-block token registration.
  const uint64_t term = get_config(network_).STAKE_LOCK_PERIOD + 1;
  std::map<crypto::public_key, size_t> stake_keys;
  if (height >= term) {
    for (const auto& hash : db.get_block_from_height(height - term).tx_hashes) {
      const auto tx = canonical_tx(db, hash);
      const auto* approved = find(hash, 0, true);
      if (tx.type == transaction_type::STAKE && tx.source_asset_type == "SAL1" &&
          (height - term >= activation_ || (approved && approved->certificate.decision == 1)))
        ++stake_keys[carrot::is_carrot_transaction_v1(tx) ? tx.protocol_tx_data.return_address : tx.return_address];
    }
  }
  std::map<crypto::public_key, size_t> payout_keys;
  for (const auto& output : b.protocol_tx.vout) {
    crypto::public_key key;
    if (get_output_public_key(output, key)) ++payout_keys[key];
  }
  for (uint32_t i = 0; i < b.protocol_tx.vout.size(); ++i) {
    crypto::public_key key;
    std::string asset;
    if (!get_output_public_key(b.protocol_tx.vout[i], key) ||
        !get_output_asset_type(b.protocol_tx.vout[i], asset) || payout_keys[key] != 1) continue;
    bool authorized = asset == "SAL1" && stake_keys[key] == 1;
    if (is_asset_type_token(asset)) {
      size_t registrations = 0;
      for (const auto& hash : b.tx_hashes) {
        const auto tx = canonical_tx(db, hash);
        if (tx.type == transaction_type::CREATE_TOKEN && "sal" + tx.token_metadata.asset_type == asset &&
            tx.protocol_tx_data.return_address == key) ++registrations;
      }
      authorized = registrations == 1;
    }
    if (authorized) schedule(b.protocol_tx, i);
  }
}
void audit_clearance_registry::sync(const BlockchainDB& db)
{
  if (!activation_) return;
  if (next_height_ > db.height() || (tip_ != crypto::null_hash && next_height_ &&
      db.get_block_hash_from_height(next_height_ - 1) != tip_)) reset();
  if (db.height() < activation_) return;
  try {
    for (; next_height_ < db.height(); ++next_height_) {
      const auto b = db.get_block_from_height(next_height_);
      advance(db, next_height_);
      for (const auto& batch : batches(b)) {
        std::string reason;
        if (!validate_batch(db, batch, next_height_, reason)) throw std::runtime_error(reason);
        apply(db, batch, next_height_);
      }
      inherit_block(db, b, next_height_);
      tip_ = db.get_block_hash_from_height(next_height_);
    }
    advance(db, db.height());
  } catch (...) { reset(); throw; }
}
bool audit_clearance_registry::output_spendable(const BlockchainDB& db, uint64_t global_id, uint64_t height) const
{
  if (!active(height)) return true;
  const auto record = db.get_output_record_by_id(global_id);
  const auto asset = asset_type_from_id(record.od.asset_type);
  if (!is_lineage_audit_asset(asset)) return false;
  uint64_t tx_id = 0;
  require(db.tx_exists(record.tx_hash, tx_id), "Missing canonical output transaction");
  const auto indices = db.get_tx_amount_output_indices(tx_id);
  require(indices.size() == 1 && record.local_vout_index < indices[0].size(), "Missing canonical output index");
  const auto catalog = eligible_.find(asset);
  if (catalog == eligible_.end()) return false;
  const auto found = catalog->second.find(indices[0][record.local_vout_index].second);
  return found != catalog->second.end() && found->second.output.transaction == record.tx_hash &&
      found->second.output.output_index == record.local_vout_index && height >= found->second.spendable_height;
}
bool audit_clearance_registry::check_spend(const BlockchainDB& db, const transaction& tx, std::string& reason)
{
  if (!active(db.height())) return true;
  try {
    sync(db);
    require(!tx.vin.empty(), "Private audit requires spending inputs");
    for (const auto& output : tx.vout) {
      std::string asset;
      require(get_output_asset_type(output, asset) && asset == tx.source_asset_type && output.amount == 0,
          "Invalid cross-asset or cleartext issuance in ordinary transaction");
    }
    for (const auto& input : tx.vin) {
      const auto* key = boost::get<txin_to_key>(&input);
      require(key && is_lineage_audit_asset(key->asset_type) && !key->key_offsets.empty(),
          "Private audit requires supported key inputs");
      uint64_t index = 0;
      for (const auto offset : key->key_offsets) {
        require(offset <= UINT64_MAX - index, "Audit ring index overflow");
        index += offset;
        require(output_spendable(db, db.get_output_id_by_asset_index(key->asset_type, index), db.height()),
            "Spend ring contains an output without confirmed audit clearance or normal maturity");
      }
    }
    return true;
  } catch (const std::exception& e) { reason = e.what(); return false; }
}
std::vector<audit_clearance_registry::eligible_output> audit_clearance_registry::eligible_outputs(
    const BlockchainDB& db, const std::string& asset, uint64_t from, size_t limit, bool& more) const
{
  require(active(db.height()) && is_lineage_audit_asset(asset) && limit && limit <= 1000,
      "Invalid public audit output page");
  more = false;
  const auto found = eligible_.find(asset);
  if (found == eligible_.end()) return {};
  std::vector<eligible_output> result;
  auto item = found->second.lower_bound(from);
  while (item != found->second.end() && result.size() < limit) {
    if (item->second.spendable_height <= db.height()) result.push_back(item->second.output);
    ++item;
  }
  while (item != found->second.end() && item->second.spendable_height > db.height()) ++item;
  more = item != found->second.end();
  return result;
}
}
