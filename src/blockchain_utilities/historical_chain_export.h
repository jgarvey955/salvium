#pragma once
// Included by blockchain_verification.cpp after its historical ring-resolution
// helpers. This path is read-only and never signs or publishes authorizations.
#include "historical_audit_records.h"
#include "cryptonote_core/audit_clearance.h"
#include <chrono>
#include <boost/filesystem.hpp>
#include "hardforks/hardforks.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include <functional>
#include <future>
#include <atomic>

namespace {
void export_historical_chain(BlockchainLMDB& db, uint64_t audit_start, uint64_t end,
    network_type network, const std::string& path)
{
  using cryptonote::historical_audit::record;
  // Refuse accidental overwrite of completed or partial evidence.
  if (boost::filesystem::exists(path)) throw std::runtime_error("Historical evidence destination already exists");
  std::ofstream stream(path, std::ios::out | std::ios::binary);
  if (!stream) throw std::runtime_error("Cannot open historical evidence destination");
  db_rtxn_guard snapshot(&db);
  const auto began = std::chrono::steady_clock::now();
  const auto genesis = pod_to_hex_string(db.get_block_hash_from_height(0));
  const auto tip = pod_to_hex_string(db.get_block_hash_from_height(end));
  cryptonote::block expected_genesis;
  const auto& config = get_config(network);
  if (!generate_genesis_block(expected_genesis, config.GENESIS_TX, config.GENESIS_NONCE) ||
      pod_to_hex_string(get_block_hash(expected_genesis)) != genesis)
    throw std::runtime_error("Historical evidence network/genesis mismatch");
  record(&stream, "context").field("schema_version", uint64_t(1))
      .field("network", static_cast<uint64_t>(network)).field("genesis", genesis)
      .field("scan_start_height", audit_start).field("scan_end_height", end)
      .field("ending_block_hash", tip).field("inventory_start_height", uint64_t(0))
      .field("opening_height", audit_start ? audit_start - 1 : 0)
      .field("opening_block_hash", pod_to_hex_string(db.get_block_hash_from_height(audit_start ? audit_start - 1 : 0)))
      .field("build", MONERO_VERSION_FULL).field("certificates_issued", uint64_t(0))
      .field("coverage", "CANONICAL_PUBLIC_CHAIN_NO_POW_REPLAY");
  for (const auto& supply : db.get_circulating_supply())
    record(&stream, "stored_supply").field("asset", supply.first).field("amount_atomic", supply.second)
        .field("height", db.height() - 1).field("verification", "STORED_DB_TALLY_NOT_INDEPENDENTLY_RECONCILED");
  std::unordered_map<std::string, uint64_t> token_creations;
  const int asset_flow_result = run_asset_flow_forensic_scan(db, end, false, token_creations, audit_start);
  if (asset_flow_result != 0 && asset_flow_result != 2)
    throw std::runtime_error("Independent asset-flow validation failed");
  record(&stream, "verification_check").field("name", "independent_asset_flow")
      .field("start_height", audit_start).field("end_height", end)
      .field("status", asset_flow_result == 0 ? "PASS" : "FINDINGS_RECORDED_IN_NATIVE_LOG")
      .field("coverage", "ASSET_IDS_TOKEN_REGISTRATION_SUPPLY_PRICES_ROLLUP_FEE_AUTHORIZATION");
  // Compute issuance from serialized canonical history, including the accepted
  // opening's accounting context. This does not label that context re-audited.
  if (run_independent_chain_forensics(db, end, network, false, 0,
        lineage_policy::duration_blocks, 0, &stream))
    throw std::runtime_error("Independent historical accounting failed");

  std::unordered_set<std::string> known_tokens;
  std::unordered_set<crypto::key_image> spent_images;
  uint64_t transactions = 0, outputs = 0, cryptographic_failures = 0;
  uint64_t output_id = 0;
  cryptonote::tx_consensus::blockchain_tx_state_view state(db);
  struct cached_block {
    block value;
    std::vector<transaction> transactions;
    std::vector<uint8_t> proofs;
  };
  constexpr uint64_t batch_blocks = 256;
  std::vector<cached_block> cache;
  for (uint64_t height = 0; height <= end; ++height) {
    // Only proof arithmetic runs concurrently. Inventory order, token state,
    // key-image history, accounting and decisions remain serial/deterministic.
    // Each worker owns its LMDB read transaction/cursors on the immutable copy.
    if (height % batch_blocks == 0) {
      cache.clear(); cache.resize(std::min<uint64_t>(batch_blocks, end - height + 1));
      std::vector<std::pair<size_t, size_t>> jobs;
      for (size_t b = 0; b < cache.size(); ++b) {
        auto& item = cache[b];
        item.value = db.get_block_from_height(height + b);
        item.transactions.push_back(item.value.miner_tx);
        if (!item.value.protocol_tx.vout.empty()) item.transactions.push_back(item.value.protocol_tx);
        for (const auto& id : item.value.tx_hashes) {
          auto tx = db.get_tx(id);
          if (get_transaction_hash(tx) != id) throw std::runtime_error("Canonical transaction hash mismatch");
          item.transactions.push_back(std::move(tx));
        }
        item.proofs.assign(item.transactions.size(), 1);
        for (size_t t = 0; t < item.transactions.size(); ++t) {
          const auto& tx = item.transactions[t];
          if (tx.type != MINER && tx.type != PROTOCOL && tx.version > 1) jobs.emplace_back(b, t);
        }
      }
      std::atomic<size_t> next{0};
      std::vector<std::future<void>> workers;
      for (size_t worker = 0; worker < std::min<size_t>(8, jobs.size()); ++worker)
        workers.push_back(std::async(std::launch::async, [&] {
          db_rtxn_guard reader(&db);
          for (size_t n; (n = next.fetch_add(1)) < jobs.size();) {
            const auto job = jobs[n]; auto& item = cache[job.first];
            item.proofs[job.second] = verify_resolved_ringct(db, item.transactions[job.second], item.value.major_version);
          }
        }));
      for (auto& worker : workers) worker.get();
    }
    const auto& cached = cache[height % batch_blocks];
    const auto& block = cached.value;
    const auto block_hash = pod_to_hex_string(get_block_hash(block));
    uint8_t expected_hf = 1;
    if (network == MAINNET) for (size_t i = 0; i < num_mainnet_hard_forks; ++i)
      if (height >= mainnet_hard_forks[i].height) expected_hf = mainnet_hard_forks[i].version;
    const bool fork_ok = network != MAINNET || block.major_version == expected_hf;
    txrules::block_state_overlay overlay;
    const auto& txs = cached.transactions;
    record(&stream, "block").field("height", height).field("block_hash", block_hash)
        .field("hard_fork", uint64_t(block.major_version)).field("schedule_status", fork_ok ? "PASS" : "REVIEW").field("transactions", uint64_t(txs.size()));
    for (size_t tx_index = 0; tx_index < txs.size(); ++tx_index) {
      const auto& tx = txs[tx_index];
      const auto hash = get_transaction_hash(tx);
      const auto id = pod_to_hex_string(hash);
      const bool issuance = tx.type == MINER || tx.type == PROTOCOL;
      const auto category = tx_type_to_string(tx.type);
      bool rules_ok = fork_ok;
      std::string rule_reason;
      if (!issuance) {
        txrules::validation_env env;
        env.hf = block.major_version; env.height = height;
        env.mode = txrules::validation_mode::block;
        env.token_state = make_token_state_view(known_tokens); env.block_overlay = &overlay;
        txrules::consensus_result result;
        rules_ok = rules_ok && txrules::check_tx_consensus(tx, env, &state, &result);
        rule_reason = result.reason;
      }
      bool crypto_ok = true, duplicate_spend = false, exact_inputs = !issuance && !tx.vin.empty();
      unsigned __int128 input_total = 0;
      std::vector<std::pair<size_t, output_record_t>> proven_inputs;
      if (!issuance) {
        if (tx.version > 1) crypto_ok = cached.proofs[tx_index] != 0;
        for (size_t i = 0; i < tx.vin.size(); ++i) {
          const auto* input = boost::get<txin_to_key>(&tx.vin[i]);
          if (!input) { crypto_ok = false; exact_inputs = false; continue; }
          duplicate_spend |= !spent_images.insert(input->k_image).second;
          if (tx.version > 1 && input->key_offsets.size() != 1) {
            // Full ring mapping/proof validation already ran above. Such a
            // ring cannot establish an individual parent or a public amount.
            exact_inputs = false;
            continue;
          }
          std::vector<std::pair<uint64_t, output_record_t>> members;
          std::string reason;
          if (!resolve_input_output_records(db, *input, members, reason, block.major_version)) {
            crypto_ok = false; exact_inputs = false; continue;
          }
          if (tx.version == 1) {
            std::vector<crypto::public_key> keys;
            for (const auto& m : members) keys.push_back(m.second.od.pubkey);
            std::vector<const crypto::public_key*> pointers;
            for (const auto& k : keys) pointers.push_back(&k);
            crypto_ok &= i < tx.signatures.size() && tx.signatures[i].size() == keys.size() &&
                !keys.empty() && crypto::check_ring_signature(get_transaction_prefix_hash(tx),
                    input->k_image, pointers.data(), pointers.size(), tx.signatures[i].data());
          }
          uint64_t amount = 0;
          if (members.size() == 1) proven_inputs.emplace_back(i, members.front().second);
          if (members.size() != 1 || !canonical_clear_amount(db, members.front().second, input->asset_type, amount))
            exact_inputs = false;
          else input_total += amount;
        }
      }
      if (!crypto_ok) ++cryptographic_failures;
      if (crypto_ok) for (const auto& parent : proven_inputs)
        record(&stream, "proven_input").field("transaction", id).field("input_index", uint64_t(parent.first))
            .field("source_transaction", pod_to_hex_string(parent.second.tx_hash))
            .field("source_output_index", parent.second.local_vout_index)
            .field("source_height", parent.second.od.height).field("height", height)
            .field("asset", asset_type_from_id(parent.second.od.asset_type))
            .field("verification", "ONE_MEMBER_RING_CRYPTOGRAPHICALLY_VERIFIED");
      std::set<std::string> invalid_assets;
      for (const auto& out : tx.vout) {
        std::string asset;
        if (!issuance && get_output_asset_type(out, asset) && asset != tx.source_asset_type)
          invalid_assets.insert(asset);
      }
      const bool cross_asset = !invalid_assets.empty();
      const bool separate_fee = block.major_version >= HF_VERSION_CARROT && tx.source_asset_type != "SAL1";
      const unsigned __int128 deductions = static_cast<unsigned __int128>(committed_burn_amount(tx)) +
          (separate_fee ? 0 : tx.rct_signatures.txnFee);
      const bool exact_invalid = crypto_ok && exact_inputs && cross_asset && invalid_assets.size() == 1 &&
          std::all_of(tx.vout.begin(), tx.vout.end(), [&](const tx_out& out) {
            std::string a; return get_output_asset_type(out, a) && invalid_assets.count(a);
          }) && input_total >= deductions;
      std::string key_images;
      for (const auto& in : tx.vin) if (const auto* key = boost::get<txin_to_key>(&in))
        key_images += pod_to_hex_string(key->k_image);
      record(&stream, "transaction").field("height", height).field("block_hash", block_hash)
          .field("transaction", id).field("version", uint64_t(tx.version))
          .field("hard_fork", uint64_t(block.major_version)).field("category", category)
          .field("inputs", uint64_t(tx.vin.size())).field("outputs", uint64_t(tx.vout.size()))
          .field("key_images", key_images)
          .field("source_asset", tx.source_asset_type).field("destination_asset", tx.destination_asset_type)
          .field("amount_burnt_atomic", tx.amount_burnt).field("fee_atomic", tx.rct_signatures.txnFee)
          .field("rules_status", rules_ok ? "PASS" : "REVIEW").field("rules_reason", rule_reason)
          .field("crypto_status", issuance ? "PUBLIC_AMOUNT" : crypto_ok ? "PASS" : "REVIEW")
          .field("duplicate_key_image", duplicate_spend ? "yes" : "no")
          .field("invalid_issuance_asset", exact_invalid ? *invalid_assets.begin() : "")
          .field("invalid_issuance_atomic", exact_invalid ? uint128_to_string(input_total - deductions) : "NOT VERIFIABLE")
          .field("cross_asset_origin", cross_asset ? "yes" : "no");
      for (uint32_t index = 0; index < tx.vout.size(); ++index, ++output_id) {
        const auto& out = tx.vout[index];
        std::string asset;
        crypto::public_key key{};
        const bool fields_ok = get_output_asset_type(out, asset) && get_output_public_key(out, key);
        bool mapping_ok = false;
        rct::key commitment = rct::zero();
        try {
          const auto rec = db.get_output_record_by_id(output_id);
          const auto indices = db.get_tx_amount_output_indices([&] {
            uint64_t n = 0; if (!db.tx_exists(hash, n)) throw std::runtime_error("Missing canonical transaction"); return n;
          }(), 1);
          const bool expected_commitment = out.amount ? rec.od.commitment == rct::zeroCommit(out.amount) :
              index < tx.rct_signatures.outPk.size() && rec.od.commitment == tx.rct_signatures.outPk[index].mask;
          commitment = rec.od.commitment;
          mapping_ok = fields_ok && rec.tx_hash == hash && rec.local_vout_index == index &&
              rec.od.height == height && rec.od.pubkey == key && rec.od.asset_type == asset_id_from_type(asset) &&
              expected_commitment && indices.size() == 1 && index < indices[0].size() &&
              db.get_output_id_by_asset_index(asset, indices[0][index].second) == output_id &&
              db.get_output_id_by_amount_index(rec.consensus_amount_bucket, indices[0][index].first) == output_id;
        } catch (const std::exception&) { mapping_ok = false; }
        const bool bad_origin = !issuance && fields_ok && asset != tx.source_asset_type;
        const bool malformed_cleartext = !issuance && tx.version > 1 && out.amount != 0;
        uint64_t lock = 0;
        const bool lock_ok = get_output_unlock_time(out, lock);
        if (!lock) lock = issuance ? CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW : CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
        lock = std::max<uint64_t>(lock, CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
        record(&stream, "output").field("height", height).field("block_hash", block_hash)
            .field("transaction", id).field("output_index", uint64_t(index)).field("global_output_id", output_id)
            .field("asset", asset).field("public_key", fields_ok ? pod_to_hex_string(key) : "")
            .field("commitment", pod_to_hex_string(commitment)).field("category", category)
            .field("mature_at_snapshot", lock_ok && lock < CRYPTONOTE_MAX_BLOCK_NUMBER && height <= end && lock <= end - height ? "yes" : "no")
            .field("public_amount_atomic", issuance || tx.version == 1 ? std::to_string(out.amount) : "NOT VERIFIABLE")
            .field("structural_status", mapping_ok && crypto::check_key(key) ? "PASS" : "REVIEW")
            .field("monetary_status", (bad_origin || malformed_cleartext || duplicate_spend) && crypto_ok ? "CONFIRMED_INVALID" :
                (crypto_ok && rules_ok && !duplicate_spend ? "PASS" : "REVIEW"))
            .field("protocol_violation", bad_origin ? "ORDINARY_OUTPUT_ASSET_DIFFERS_FROM_SOURCE" :
                malformed_cleartext ? "NONZERO_CONFIDENTIAL_OUTPUT_AMOUNT" : duplicate_spend ? "DUPLICATE_CANONICAL_KEY_IMAGE" : "")
            .field("provenance", issuance ? "PUBLIC_ISSUANCE_REQUIRES_AUTHORIZATION" :
                bad_origin ? "CONFIRMED_INVALID_ORIGIN" : height < audit_start ? "ACCEPTED_OPENING" : "UNKNOWN_PROVENANCE")
            .field("evidence_reference", id + ":" + std::to_string(index));
        ++outputs;
      }
      if (tx.type == CREATE_TOKEN) known_tokens.insert("sal" + tx.token_metadata.asset_type);
      ++transactions;
    }
    if (height % 1000 == 0) {
      stream.flush();
      std::cout << "HISTORICAL_EXPORT_PROGRESS height=" << height << " target=" << end
                << " transactions=" << transactions << " outputs=" << outputs << std::endl;
    }
  }
  if (pod_to_hex_string(db.get_block_hash_from_height(end)) != tip)
    throw std::runtime_error("Historical snapshot changed during export");
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - began).count();
  record(&stream, "complete").field("scan_end_height", end).field("ending_block_hash", tip)
      .field("transactions", transactions).field("outputs", outputs)
      .field("cryptographic_failures", cryptographic_failures).field("elapsed_ms", uint64_t(elapsed));
  stream.flush();
  if (!stream) throw std::runtime_error("Historical evidence write failed");
}
}
