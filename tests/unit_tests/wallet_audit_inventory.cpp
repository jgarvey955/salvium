// Native wallet inventory regression. The injected HTTP client performs no
// network I/O and no wallet/chain/ring database is opened or written.
#include "wallet/wallet2.h"
#include "wallet/output_distribution.h"
#include "carrot_impl/format_utils.h"
#include "carrot_impl/input_selection.h"
#include <thread>
#include "cryptonote_core/lineage_audit.h"
#include "cryptonote_basic/tx_extra.h"
#include "serialization/binary_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "net/http_base.h"
#include "serialization/keyvalue_serialization.h"
#include "rapidjson/document.h"
#include <iostream>
#include <stdexcept>
#include <limits>

namespace {
uint64_t rpc_candidate_height = 100;
uint64_t rpc_opening_height = 0;
uint64_t rpc_activation_height = 10;
uint64_t rpc_private_activation_height = 0;
bool rpc_public_eligible = false;
std::string rpc_tip_hash;
size_t rpc_key_image_queries = 0;
std::string rpc_nettype = "fakechain";
std::string rpc_supply = "1000000";
std::vector<cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry> rpc_tx_entries;
std::vector<cryptonote::COMMAND_RPC_GET_YIELD_INFO::yield_data_t> rpc_yield_data;
void check(bool condition, const char* message)
{
  if (!condition) throw std::runtime_error(message);
}

class audit_status_client final : public epee::net_utils::http::abstract_http_client
{
  epee::net_utils::http::http_response_info response_{};
public:
  void set_server(std::string, std::string, boost::optional<epee::net_utils::http::login>, epee::net_utils::ssl_options_t) override {}
  void set_auto_connect(bool) override {}
  bool connect(std::chrono::milliseconds) override { return true; }
  bool disconnect() override { return true; }
  bool is_connected(bool* ssl = nullptr) override { if (ssl) *ssl = false; return true; }
  uint64_t get_bytes_sent() const override { return 0; }
  uint64_t get_bytes_received() const override { return 0; }
  bool invoke(const boost::string_ref, const boost::string_ref, const boost::string_ref body,
      std::chrono::milliseconds, const epee::net_utils::http::http_response_info** output,
      const epee::net_utils::http::fields_list&) override
  {
    rapidjson::Document request;
    request.Parse(body.data(), body.size());
    check(!request.HasParseError() && request.IsObject(), "Invalid native RPC request");
    if (request.HasMember("txs_hashes")) {
      cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response txs{};
      txs.status = "OK"; txs.txs = rpc_tx_entries;
      response_.m_response_code = 200;
      response_.m_body = epee::serialization::store_t_to_json(txs);
      *output = &response_;
      return true;
    }
    check(request.HasMember("method"), "Invalid native RPC method");
    const std::string method = request["method"].GetString();
    std::string result;
    if (method == "get_info") {
      cryptonote::COMMAND_RPC_GET_INFO::response info{};
      info.status = "OK"; info.nettype = rpc_nettype; info.height = rpc_candidate_height;
      result = epee::serialization::store_t_to_json(info);
    } else if (method == "get_supply_info") {
      cryptonote::COMMAND_RPC_GET_SUPPLY_INFO::response supply{};
      supply.status = "OK";
      supply.supply_tally.emplace_back("SAL1", rpc_supply);
      result = epee::serialization::store_t_to_json(supply);
    } else if (method == "get_yield_info") {
      cryptonote::COMMAND_RPC_GET_YIELD_INFO::response yield{};
      yield.status = "OK";
      const auto& params = request["params"];
      const uint64_t from = params.HasMember("from_height") ? params["from_height"].GetUint64() : 0;
      const uint64_t to = params.HasMember("to_height") ? params["to_height"].GetUint64() : 0;
      bool duplicate = false;
      for (size_t i = 1; i < rpc_yield_data.size(); ++i)
        duplicate |= rpc_yield_data[i].block_height <= rpc_yield_data[i - 1].block_height;
      if (!rpc_yield_data.empty() && from && to && !duplicate) {
        check(to >= from && to - from < 1000, "Yield request exceeded page limit");
        for (uint64_t height = from; height <= to; ++height) {
          cryptonote::COMMAND_RPC_GET_YIELD_INFO::yield_data_t entry{};
          entry.block_height = height;
          for (const auto& value : rpc_yield_data)
            if (value.block_height == height) entry = value;
          yield.yield_data.push_back(entry);
        }
      } else yield.yield_data = rpc_yield_data;
      result = epee::serialization::store_t_to_json(yield);
    } else if (method == "get_lineage_audit_status" || method == "get_private_audit_status") {
      cryptonote::COMMAND_RPC_LINEAGE_AUDIT_STATUS::response status{};
      status.status = "OK"; status.activation_height = rpc_activation_height; status.candidate_height = rpc_candidate_height;
      status.opening_height = rpc_opening_height;
      if (method == "get_private_audit_status") status.activation_height = rpc_private_activation_height;
      const auto& params = request["params"];
      if (params.HasMember("key_images")) {
        rpc_key_image_queries += params["key_images"].Size();
        // Even an incorrect positive daemon response must not let incomplete
        // inventory disappear or become good in the wallet's report.
        for (rapidjson::SizeType i = 0; i < params["key_images"].Size(); ++i)
          status.entries.push_back({"AUDIT_PASSED", 20, 30});
      }
      result = epee::serialization::store_t_to_json(status);
    } else if (method == "get_private_audit_outputs") {
      cryptonote::COMMAND_RPC_LINEAGE_AUDIT_OUTPUTS::response page{};
      page.status = "OK"; page.activation_height = rpc_private_activation_height;
      page.candidate_height = rpc_candidate_height; page.tip_hash = rpc_tip_hash;
      page.asset_type = request["params"].HasMember("asset_type") ? request["params"]["asset_type"].GetString() : "SAL1";
      check(!request["params"].HasMember("key_images"), "Public population request exposed key images");
      if (rpc_public_eligible) for (uint64_t i = 0; i < 4; ++i) page.outputs.push_back({i, 1});
      result = epee::serialization::store_t_to_json(page);
    } else throw std::runtime_error("Unexpected native RPC: " + method);
    response_.m_response_code = 200;
    response_.m_body = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"result\":" + result + "}";
    *output = &response_;
    return true;
  }
  bool invoke_get(const boost::string_ref uri, std::chrono::milliseconds timeout, const std::string& body,
      const epee::net_utils::http::http_response_info** output, const epee::net_utils::http::fields_list& fields) override
  { return invoke(uri, "GET", body, timeout, output, fields); }
  bool invoke_post(const boost::string_ref uri, const std::string& body, std::chrono::milliseconds timeout,
      const epee::net_utils::http::http_response_info** output, const epee::net_utils::http::fields_list& fields) override
  { return invoke(uri, "POST", body, timeout, output, fields); }
};

class audit_status_factory final : public epee::net_utils::http::http_client_factory
{
public:
  std::unique_ptr<epee::net_utils::http::abstract_http_client> create() override
  { return std::unique_ptr<epee::net_utils::http::abstract_http_client>(new audit_status_client()); }
};
}

// wallet2 already grants this test accessor friendship.
class wallet_accessor_test
{
public:
  static void hostile_rpc_checks(tools::wallet2& wallet)
  {
    for (unsigned method = 0; method < 3; ++method) {
      bool rejected = false;
      try {
        if (method == 0) wallet.get_token_info("salTEST");
        if (method == 1) { std::vector<std::string> tokens; wallet.get_tokens("", tokens); }
        if (method == 2) { oracle::pricing_record price; wallet.get_pricing_record(price, 1); }
      } catch (const std::exception&) { rejected = true; }
      check(rejected, "Throwing RPC transport was unexpectedly accepted");
      bool unlocked = false;
      std::thread contender([&] {
        unlocked = wallet.m_daemon_rpc_mutex.try_lock();
        if (unlocked) wallet.m_daemon_rpc_mutex.unlock();
      });
      contender.join();
      check(unlocked, "RPC failure stranded the wallet mutex");
    }
    cryptonote::block genesis;
    const auto& config = cryptonote::get_config(cryptonote::MAINNET);
    check(cryptonote::generate_genesis_block(genesis, config.GENESIS_TX, config.GENESIS_NONCE),
        "Cannot create public transaction response fixture");
    const auto id = cryptonote::get_transaction_hash(genesis.miner_tx);
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry entry{};
    entry.tx_hash = epee::string_tools::pod_to_hex(id);
    entry.as_hex = epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(genesis.miner_tx));
    rpc_tx_entries = {entry};
    check(wallet.get_tx_entries({id}).tx_entries.size() == 1, "Matching daemon transaction rejected");
    bool rejected = false;
    try { wallet.get_tx_entries({crypto::rand<crypto::hash>()}); }
    catch (const std::exception&) { rejected = true; }
    check(rejected, "Daemon substituted an unrequested transaction");
    rpc_tx_entries.clear();
    std::vector<uint64_t> counts{2, 3};
    check(tools::accumulate_output_distribution(counts, 7, 4, 12) &&
        counts == std::vector<uint64_t>({9, 12}), "Distribution omitted its base");
    for (const auto& values : {std::vector<uint64_t>{}, {UINT64_MAX, 1}, {1, UINT64_MAX}}) {
      auto changed = values;
      check(!tools::accumulate_output_distribution(changed, 0, 0, 0) && changed == values,
          "Invalid distribution changed caller data");
    }
    bool no_recent_outputs = false;
    const std::vector<uint64_t> stagnant(86400 * 365 / DIFFICULTY_TARGET_V2 + 1, 1);
    try { tools::gamma_picker picker(stagnant); }
    catch (const std::exception&) { no_recent_outputs = true; }
    check(no_recent_outputs, "Decoy picker accepted an empty consideration window");
    counts = {1};
    check(!tools::accumulate_output_distribution(counts, UINT64_MAX, 0, 0) && counts[0] == 1,
        "Distribution base overflow accepted");
    check(!tools::accumulate_output_distribution(counts, 0, UINT64_MAX, 0) && counts[0] == 1,
        "Distribution height overflow accepted");
    check(!tools::accumulate_output_distribution(counts, 0, 0, 2) && counts[0] == 1,
        "Impossible spendable output count accepted");
  }
  static void subaddress_bounds(tools::wallet2& wallet)
  {
    const auto labels = wallet.m_subaddress_labels;
    const auto major = wallet.m_subaddress_lookahead_major;
    const auto minor = wallet.m_subaddress_lookahead_minor;
    wallet.m_subaddress_labels = {{"main"}};
    wallet.m_subaddress_lookahead_major = 2;
    wallet.m_subaddress_lookahead_minor = 3;
    check(wallet.should_expand({1, 2}), "Valid future-account lookahead rejected");
    check(!wallet.should_expand({1, 3}), "Future account exceeded minor lookahead");
    check(!wallet.should_expand({1, UINT32_MAX}), "Unbounded imported minor index accepted");
    check(!wallet.should_expand({3, 0}), "Account exceeded major lookahead");
    check(wallet.should_expand({0, 3}) && !wallet.should_expand({0, 4}),
        "Existing-account minor boundary is incorrect");
    wallet.m_subaddress_labels.clear();
    check(wallet.should_expand({1, 2}) && !wallet.should_expand({2, 0}),
        "Empty account catalog exceeded lookahead");
    wallet.m_subaddress_labels = labels;
    wallet.m_subaddress_lookahead_major = major;
    wallet.m_subaddress_lookahead_minor = minor;
  }
  static void yield_summary_checks(tools::wallet2& wallet)
  {
    const auto original = wallet.m_transfers;
    const auto original_height = rpc_candidate_height;
    rpc_candidate_height = 103;
    wallet.m_transfers.clear();
    tools::wallet2::transfer_details stake{};
    stake.m_tx.type = cryptonote::STAKE;
    stake.m_tx.amount_burnt = 1000;
    stake.m_block_height = 100;
    stake.m_txid = crypto::rand<crypto::hash>();
    stake.asset_type = "SAL1";
    wallet.m_transfers.push_back(stake);
    tools::wallet2::transfer_details payout{};
    payout.m_tx.type = cryptonote::PROTOCOL;
    payout.m_td_origin_idx = 0;
    payout.m_amount = 1010;
    wallet.m_transfers.push_back(payout);
    rpc_yield_data = {{100, 0, 0, 1000, 100}, {101, 7, 0, 1000, 100}};
    uint64_t burnt, supply, locked, accrued, per_stake, size;
    std::vector<tools::wallet2::yield_payout_t> payouts;
    const auto read = [&] {
      wallet.m_node_rpc_proxy.invalidate();
      return wallet.get_yield_summary_info(burnt, supply, locked, accrued, per_stake, size, payouts);
    };
    check(read() && payouts.size() == 1 && std::get<4>(payouts[0]) == 10,
        "Stake at wallet transfer index zero was omitted");
    wallet.m_transfers[1].m_td_origin_idx = std::numeric_limits<size_t>::max();
    rpc_candidate_height = 21701;
    rpc_yield_data = {{99, 0, 0, 1000, 100}, {100, 999, 0, 1000, 100},
        {101, 7, 0, 1000, 100}, {21700, 3, 0, 1000, 100}, {21701, 999, 0, 1000, 100}};
    check(read() && payouts.size() == 1 && std::get<4>(payouts[0]) == 10,
        "Yield included the deposit block or blocks after stake maturity");
    for (const std::string invalid : {"-1", "+1", "1x", "18446744073709551616"}) {
      rpc_supply = invalid;
      check(!read() && payouts.empty() && burnt == 0 && supply == 0 && locked == 0 &&
          accrued == 0 && per_stake == 0 && size == 0,
          "Invalid daemon supply published partial yield results");
    }
    rpc_supply = "1000000";
    rpc_yield_data = {{100, 0, 0, 1000, 100}, {100, 7, 0, 1000, 100}};
    check(!read() && payouts.empty(), "Duplicate daemon yield rows were accepted");
    rpc_candidate_height = 103;
    rpc_yield_data = {{99, 0, 0, 1, 100},
        {100, std::numeric_limits<uint64_t>::max(), 0, 1, 100}, {101, 1, 0, 1, 100}};
    check(!read() && accrued == 0 && payouts.empty(), "Daemon yield totals overflowed");
    rpc_yield_data.clear();
    check(!read() && payouts.empty(), "Empty daemon yield history was accepted");
    wallet.m_transfers = original;
    rpc_candidate_height = original_height;
    wallet.m_node_rpc_proxy.invalidate();
    std::cout << "WALLET_YIELD_PASS: first stake, origin bounds, accrual window, malformed supply and empty history\n";
  }
  static void inventory(tools::wallet2& wallet)
  {
    wallet.m_subaddress_labels = {{"legacy"}, {"Carrot"}};
    const uint64_t amounts[] = {400000000, 700000000, 900000000, 500000000};
    for (size_t i = 0; i < 4; ++i) {
      tools::wallet2::transfer_details td{};
      td.m_block_height = 1;
      td.m_asset_type_output_index = i;
      td.m_tx.version = i == 3 ? 5 : 2;
      td.m_tx.type = cryptonote::transaction_type::MINER;
      td.m_amount = amounts[i]; td.asset_type = "SAL1";
      td.m_subaddr_index = {i == 3 ? 1u : 0u, 0};
      td.m_spent = i == 2;
      td.m_key_image = crypto::rand<crypto::key_image>();
      td.m_key_image_known = true;
      const crypto::public_key key = rct::rct2pk(rct::pkGen());
      cryptonote::tx_out output{};
      output.amount = amounts[i];
      if (i == 3) output.target = cryptonote::txout_to_carrot_v1{key, "SAL1", {}, {}};
      else if (i == 1) output.target = cryptonote::txout_to_tagged_key{key, "SAL1", 60, {}};
      else output.target = cryptonote::txout_to_key{key, "SAL1", 60};
      td.m_tx.vout.push_back(output);
      wallet.m_transfers.push_back(td);
    }
  }
  static void incomplete(tools::wallet2& wallet)
  {
    wallet.m_transfers[0].m_key_image_known = false;
    wallet.m_transfers[1].m_key_image_partial = true;
    wallet.m_transfers[3].m_tx.type = cryptonote::transaction_type::STAKE;
    wallet.m_transfers[3].m_tx.amount_burnt = 1200000000;
    wallet.m_transfers[3].m_txid = crypto::rand<crypto::hash>();
  }
  static void long_lock(tools::wallet2& wallet)
  {
    boost::get<cryptonote::txout_to_key>(wallet.m_transfers[0].m_tx.vout[0].target).unlock_time = 1000;
  }
  static void spent_height(tools::wallet2& wallet, uint64_t height)
  {
    wallet.m_transfers[2].m_spent_height = height;
  }
  static void signing_mode(tools::wallet2& wallet, bool watch, bool multisig,
      hw::device::device_type device = hw::device::SOFTWARE)
  {
    wallet.m_watch_only = watch;
    wallet.m_multisig = multisig;
    wallet.m_key_device_type = device;
  }
  static void conversion_review(tools::wallet2& wallet)
  {
    wallet.m_transfers.clear();
    wallet.m_account.generate({}, false, false, carrot::AddressDeriveType::PreCarrot);
    wallet.m_subaddress_labels.clear();
    wallet.expand_subaddresses({1, 1});
    const auto& keys = wallet.m_account.get_keys();
    auto& device = wallet.m_account.get_device();
    // Exercise the legacy return opening at nonzero protocol output indices,
    // across the main address and exchange accounts/subaddresses. Original SAL
    // change records are scanning context and must not become enrolled proofs.
    for (const auto index : {cryptonote::subaddress_index{0, 0}, {0, 1}, {1, 1}}) {
      const auto tx_key = cryptonote::keypair::generate(device);
      crypto::key_derivation origin_derivation;
      check(crypto::generate_key_derivation(tx_key.pub, keys.m_view_secret_key, origin_derivation),
          "Conversion origin derivation failed");
      const auto address = device.get_subaddress(keys, index);
      crypto::public_key change;
      check(crypto::derive_public_key(origin_derivation, 0, address.m_spend_public_key, change),
          "Conversion change key failed");
      wallet.m_account.insert_subaddresses({{change,
          {{index.major, index.minor}, carrot::AddressDeriveType::PreCarrot, true}}});
      cryptonote::keypair change_opening;
      crypto::key_image unused_image;
      rct::salvium_input_data_t unused_data{};
      check(cryptonote::generate_key_image_helper_precomp(keys, change, origin_derivation, 0, index,
          change_opening, unused_image, device, false, {}, unused_data), "Conversion change opening failed");
      const auto return_secret = rct::skGen();
      const auto return_pub = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(change), return_secret));
      crypto::key_derivation return_derivation;
      crypto::public_key returned;
      crypto::secret_key returned_secret;
      check(crypto::generate_key_derivation(return_pub, keys.m_view_secret_key, return_derivation) &&
          crypto::derive_public_key(return_derivation, 0, change, returned), "Conversion return derivation failed");
      crypto::derive_secret_key(return_derivation, 0, change_opening.sec, returned_secret);
      cryptonote::transaction origin;
      origin.version = 2; origin.type = cryptonote::transaction_type::AUDIT;
      origin.source_asset_type = "SAL"; origin.destination_asset_type = "SAL1";
      origin.return_address = returned; origin.return_pubkey = return_pub;
      origin.vout.push_back({0, cryptonote::txout_to_key{change, "SAL", 0}});
      cryptonote::add_tx_pub_key_to_extra(origin, tx_key.pub);
      tools::wallet2::transfer_details context{};
      context.m_tx = origin; context.m_txid = crypto::rand<crypto::hash>();
      context.asset_type = "SAL"; context.m_subaddr_index = index;
      context.m_td_origin_idx = std::numeric_limits<uint64_t>::max();
      const auto origin_index = wallet.m_transfers.size();
      wallet.m_transfers.push_back(context);

      cryptonote::transaction payout;
      payout.version = 2; payout.type = cryptonote::transaction_type::PROTOCOL;
      payout.vin.push_back(cryptonote::txin_gen{2});
      payout.vout.push_back({1, cryptonote::txout_to_key{tx_key.pub, "SAL1", 60}});
      payout.vout.push_back({500000000, cryptonote::txout_to_key{returned, "SAL1", 60}});
      cryptonote::add_tx_pub_key_to_extra(payout, tx_key.pub);
      cryptonote::add_additional_tx_pub_keys_to_extra(payout.extra, {tx_key.pub, return_pub});
      tools::wallet2::transfer_details receipt{};
      receipt.m_tx = payout; receipt.m_txid = cryptonote::get_transaction_hash(payout);
      receipt.asset_type = "SAL1"; receipt.m_amount = 500000000;
      receipt.m_block_height = 2; receipt.m_internal_output_index = 1;
      receipt.m_td_origin_idx = origin_index; receipt.m_subaddr_index = index;
      receipt.m_mask = rct::identity(); receipt.m_key_image_known = true;
      crypto::generate_key_image(returned, returned_secret, receipt.m_key_image);
      wallet.m_transfers.push_back(receipt);
    }
    auto token = wallet.m_transfers.back();
    token.asset_type = "OTHER";
    wallet.m_transfers.push_back(token);
    const auto prepared = wallet.audit(true, true, 0, {}, true);
    check(prepared.state == "VERIFICATION_PENDING" && prepared.outputs.size() == 3 && prepared.proofs.empty(),
        "Private conversion review omitted receipts or created public ownership proofs");
    for (const auto& output : prepared.outputs)
      check(output.state == "VERIFICATION_PENDING" && output.key_image.empty(),
          "Private conversion review exported a key image or automatic verdict");
    check(prepared.outputs[1].subaddress == 1 && prepared.outputs[2].account == 1,
        "Conversion review scope lost exchange account/subaddress");
    std::cout << "WALLET_CONVERSION_REVIEW_PASS: three receipts, all accounts/subaddresses, no proofs or key images published\n";
  }
  static void token_inventory(tools::wallet2& wallet)
  {
    auto token = wallet.m_transfers.at(1);
    token.asset_type = "salYAHU";
    boost::get<cryptonote::txout_to_key>(token.m_tx.vout[1].target).asset_type = token.asset_type;
    token.m_txid = crypto::rand<crypto::hash>();
    token.m_key_image = crypto::rand<crypto::key_image>();
    token.m_key_image_known = false;
    token.m_amount = 1700000000;
    wallet.m_transfers.push_back(token);
    const auto pending = wallet.audit(false);
    check(pending.state == "VERIFICATION_PENDING" && pending.good == 0 && pending.unresolved == 1500000000 &&
        pending.outputs.size() == 4 && pending.balances.size() == 2,
        "Token inventory omitted, mixed into SAL1 units, or ignored by overall state");
    const auto& balance = pending.balances.back();
    check(balance.asset_type == "salYAHU" && balance.unresolved == token.m_amount && balance.unresolved_count == 1,
        "Token unresolved balance or asset identity lost");
    check(wallet.is_transfer_unlocked(wallet.m_transfers.back()), "Review-only token was isolated from spending");
    wallet.m_transfers.back().m_key_image_known = true;
    wallet.update_lineage_audit_status();
    check(wallet.is_transfer_unlocked(wallet.m_transfers.back()), "Cleared mature token remained locked");
    const auto good = wallet.audit(false);
    check(good.state == "VERIFICATION_PENDING" && good.unresolved == pending.unresolved &&
        good.balances.back().unresolved == token.m_amount && good.outputs.back().asset_type == "salYAHU" &&
        good.outputs.back().key_image.empty(), "Review-only token was not reported privately and separately from SAL1");
    rpc_candidate_height = 101;
    wallet.update_lineage_audit_status();
    check(!wallet.is_transfer_unlocked(wallet.m_transfers.back()), "Unverified daemon height bypassed the token gate");
    rpc_candidate_height = 100;
    std::cout << "WALLET_TOKEN_REVIEW_PASS: token scope, separate units, private review and no signing gate\n";
  }

};

int main()
{
  try {
    std::map<size_t, rct::xmr_amount> token_fees;
    for (size_t count = 1; count <= 64; ++count) token_fees[count] = 1000000 + count * 100;
    const std::vector<carrot::input_selection_policy_t> policies{&carrot::ispolicy::select_greedy_aging};
    for (const auto amount : {uint64_t(1), uint64_t(10000000000)}) {
      const std::vector<carrot::InputCandidate> candidates{
          {{0, crypto::rand<crypto::key_image>()}, false, true, 1},
          {{amount, crypto::rand<crypto::key_image>()}, false, true, 2}};
      for (unsigned round = 0; round < 128; ++round) {
        auto select = carrot::make_single_transfer_input_selector(epee::to_span(candidates), epee::to_span(policies),
            carrot::InputSelectionFlags::IS_TOKEN_TRANSFER |
            carrot::InputSelectionFlags::ALLOW_EXTERNAL_INPUTS_IN_NORMAL_TRANSFERS, nullptr);
        std::vector<carrot::CarrotSelectedInput> selected;
        select(amount, token_fees, 1, 1, selected);
        check(selected.size() == 1 && selected.front().amount == amount,
            "Zero change or SAL1 fee units prevented a funded token spend");
      }
    }
    {
      const std::vector<carrot::InputCandidate> candidates{
          {{10, crypto::rand<crypto::key_image>()}, false, true, 1},
          {{100, crypto::rand<crypto::key_image>()}, false, true, 10}};
      std::set<size_t> chosen;
      carrot::ispolicy::select_greedy_aging(epee::to_span(candidates), {0, 1}, 1, 5, chosen);
      check(chosen == std::set<size_t>{0}, "Input aging searched index numbers instead of sorted amounts");
      carrot::ispolicy::select_greedy_aging(epee::to_span(candidates), {0, 1}, 1, 20, chosen);
      check(chosen == std::set<size_t>{1}, "Input aging replaced a funded input with insufficient money");
    }
    // Only TRANSFER serializes per-output encrypted return keys. Fee rollups,
    // burns and protocol authorizations still have ordinary spendable change.
    cryptonote::transaction change;
    change.vin.push_back(cryptonote::txin_to_key{});
    change.vout.push_back({0, cryptonote::txout_to_carrot_v1{}});
    change.rct_signatures.ecdhInfo.resize(1);
    change.rct_signatures.outPk.resize(1);
    std::vector<mx25519_pubkey> ephemeral(1);
    carrot::CarrotEnoteV1 enote;
    for (const auto type : {cryptonote::transaction_type::STAKE, cryptonote::transaction_type::BURN,
                           cryptonote::transaction_type::CREATE_TOKEN, cryptonote::transaction_type::ROLLUP}) {
      change.type = type;
      check(carrot::try_load_carrot_enote_from_transaction_v1(change, epee::to_span(ephemeral), 0, enote),
          "A serialized authorization change output required an unavailable encrypted return key");
    }
    change.type = cryptonote::transaction_type::TRANSFER;
    check(!carrot::try_load_carrot_enote_from_transaction_v1(change, epee::to_span(ephemeral), 0, enote),
        "A malformed transfer without an encrypted return key was accepted");
    // Legacy watch-only accounts must leave key images unknown, including
    // CARROT-encoded returns sent to their pre-CARROT addresses.
    carrot::carrot_and_legacy_account watch_account;
    tools::wallet::enote_view_incoming_scan_info_t scan{};
    scan.subaddr_index = carrot::subaddress_index_extended{
        {0, 0}, carrot::AddressDeriveType::PreCarrot, false};
    check(!tools::wallet::try_derive_enote_key_image(scan, watch_account),
        "Watch-only legacy scan fabricated a key image");
    scan.is_carrot = true;
    scan.is_return = true;
    check(!tools::wallet::try_derive_enote_key_image(scan, watch_account),
        "Watch-only legacy return fabricated a key image");
    scan.subaddr_index->derive_type = carrot::AddressDeriveType::Carrot;
    watch_account.insert_return_output_info({{scan.return_address, carrot::return_output_info_t{}}});
    check(!tools::wallet::try_derive_enote_key_image(scan, watch_account),
        "Unknown return key image was marked known");
    tools::wallet2 wallet(cryptonote::MAINNET, 1, true,
        std::unique_ptr<epee::net_utils::http::http_client_factory>(new audit_status_factory()));
    wallet.set_ring_database("");
    wallet_accessor_test::subaddress_bounds(wallet);
    wallet_accessor_test::hostile_rpc_checks(wallet);
    wallet_accessor_test::yield_summary_checks(wallet);
    wallet.set_lineage_regtest_height(10);
    cryptonote::block genesis;
    const auto& config = cryptonote::get_config(cryptonote::MAINNET);
    cryptonote::generate_genesis_block(genesis, config.GENESIS_TX, config.GENESIS_NONCE);
    const auto genesis_hash = cryptonote::get_block_hash(genesis);
    rpc_tip_hash = epee::string_tools::pod_to_hex(genesis_hash);
    wallet.import_blockchain({0, genesis_hash, std::vector<crypto::hash>(100, genesis_hash)});
    wallet_accessor_test::inventory(wallet);
    check(wallet.is_transfer_unlocked(wallet.get_transfer_details(3)),
        "Review-only inventory was isolated before its first status refresh");
    const auto all = wallet.audit(false);
    check(all.state == "VERIFICATION_PENDING" && all.outputs.size() == 4, "Complete private inventory failed");
    check(all.good == 0 && all.unresolved == 1600000000 && all.unresolved_count == 3 && !all.bad_count,
        "Review inventory control failed");
    for (const auto& output : all.outputs) check(output.key_image.empty(), "Private inventory exported a key image");
    wallet.set_attribute("sal1-audit-v2", "withdrawn-public-proof-must-not-be-decoded\n");
    wallet.set_lineage_regtest_height(0);
    rpc_activation_height = 0;
    const auto unscheduled = wallet.audit(true, true, 0, {}, true);
    check(unscheduled.activation_height == 0 && unscheduled.state == "VERIFICATION_PENDING" &&
        unscheduled.proofs.empty(), "Local review incorrectly required an enrollment epoch or decoded a saved v2 proof");
    wallet.set_lineage_regtest_height(10);
    rpc_activation_height = 10;
    check(all.spent == 900000000 && all.spent_count == 1, "Spent legacy history double counted");
    rpc_opening_height = 5;
    const auto opening = wallet.audit(false);
    check(opening.opening_height == 5 && opening.outputs.size() == 3 && opening.spent_count == 0 &&
        opening.unresolved == all.unresolved,
        "Previous-audit spent history included or opening balance lost");
    wallet_accessor_test::spent_height(wallet, 6);
    check(wallet.audit(false).spent == 900000000, "Post-boundary spend excluded from ancestry inventory");
    wallet_accessor_test::spent_height(wallet, 0);
    rpc_opening_height = 0;
    const auto legacy = wallet.audit(false, false, 0, {0});
    check(legacy.unresolved == 1100000000 && legacy.good == 0 && legacy.outputs.size() == 3, "Legacy scope failed");
    const auto carrot = wallet.audit(false, false, 1, {0});
    check(carrot.state == "VERIFICATION_PENDING" && carrot.unresolved == 500000000 && carrot.good == 0 && carrot.outputs.size() == 1,
        "Supported account control failed");
    wallet.update_lineage_audit_status();
    check(wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Refreshed good output control remained locked");
    check(wallet.is_transfer_unlocked(wallet.get_transfer_details(0)), "Verified legacy output remained locked");
    rpc_candidate_height = 101;
    wallet.update_lineage_audit_status();
    check(!wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Unverified daemon height bypassed the wallet gate");
    rpc_candidate_height = 100;
    wallet.update_lineage_audit_status();
    check(wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Refreshed chain tip did not restore clearance");
    rpc_private_activation_height = 10;
    wallet.update_lineage_audit_status();
    check(!wallet.is_transfer_unlocked(wallet.get_transfer_details(0)) &&
        !wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Active audit allowed uncleared outputs");
    rpc_public_eligible = true;
    wallet.update_lineage_audit_status();
    check(wallet.is_transfer_unlocked(wallet.get_transfer_details(0)) &&
        wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Public clearance required an owner receipt import");
    rpc_candidate_height = 101;
    wallet.update_lineage_audit_status();
    check(!wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Stale public population failed open");
    rpc_candidate_height = 100;
    wallet.update_lineage_audit_status();
    check(wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Canonical public population failed to restore clearance");
    rpc_public_eligible = false;
    wallet.update_lineage_audit_status();
    check(!wallet.is_transfer_unlocked(wallet.get_transfer_details(3)), "Orphaned clearance remained spendable");
    rpc_private_activation_height = 0;
    wallet.update_lineage_audit_status();
    for (bool watch : {false, true}) {
      wallet_accessor_test::signing_mode(wallet, watch, !watch);
      check(wallet.audit(false).state == "VERIFICATION_PENDING", "Read-only wallet review unavailable");
      const auto prepared = wallet.audit(false, true, 0, {}, true);
      check(prepared.proofs.empty(), "Wallet without full signing keys created ownership proofs");
    }
    for (const auto device : {hw::device::LEDGER, hw::device::TREZOR}) {
      wallet_accessor_test::signing_mode(wallet, false, false, device);
      check(wallet.audit(false).state == "VERIFICATION_PENDING", "Hardware-mode inventory unavailable");
      bool rejected_export = false;
      try { wallet.export_audit_review(99); }
      catch (const std::exception& error) {
        rejected_export = std::string(error.what()).find("full software wallet") != std::string::npos;
      }
      check(rejected_export, "Hardware-mode ownership export fabricated an unsupported signature");
    }
    wallet_accessor_test::signing_mode(wallet, false, false);
    wallet_accessor_test::long_lock(wallet);
    const auto locked = wallet.audit(false);
    check(locked.state == "VERIFICATION_PENDING" && locked.immature == 400000000, "Custom output maturity was ignored");
    wallet_accessor_test::incomplete(wallet);
    const auto incomplete = wallet.audit(false);
    check(incomplete.state == "BAD_ORIGIN_FOUND" && incomplete.outputs.size() == 5, "Incomplete stake inventory disappeared");
    check(incomplete.unresolved == 1100000000 && incomplete.bad == 500000000 && incomplete.stake_bad == 1200000000,
        "Direct malformed stake origin was not kept distinct from review-only inventory");
    for (const auto& output : incomplete.outputs) check(output.key_image.empty(), "Incomplete inventory exported a key image");
    wallet.update_lineage_audit_status();
    check(wallet.is_transfer_unlocked(wallet.get_transfer_details(1)), "Partial key image triggered lineage isolation");
    wallet_accessor_test::conversion_review(wallet);
    wallet_accessor_test::token_inventory(wallet);
    check(rpc_key_image_queries == 0, "Wallet sent deterministic key images to the daemon");
    wallet.set_lineage_regtest_height(10);
    rpc_nettype = "mainnet";
    bool rejected_test_authority = false;
    try { wallet.import_audit_review("{}", ""); }
    catch (const std::exception& e) {
      rejected_test_authority = std::string(e.what()).find("Ephemeral audit test keys require an isolated fakechain daemon") != std::string::npos;
    }
    check(rejected_test_authority, "Regtest flag bypassed main developer authority on a mainnet daemon");
    std::cout << "WALLET_AUDIT_REVIEW_PASS: local inventory, direct-origin distinction, no public proofs or key-image queries, confirmed population gate without receipt import, stale/reorg fail closed\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
