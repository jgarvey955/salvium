#include "cryptonote_core/audit_review.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "serialization/keyvalue_serialization.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"
#include "memwipe.h"
#include "misc_language.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <algorithm>
#include <iostream>
#include <set>

namespace po = boost::program_options;
using namespace cryptonote;
namespace {
struct review_decision {
  std::string package_id, transaction, action, reason;
  std::string evidence_reason;
  uint32_t output_index = 0;
  bool stake = false;
  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(package_id)
    KV_SERIALIZE(transaction)
    KV_SERIALIZE(output_index)
    KV_SERIALIZE(stake)
    KV_SERIALIZE(action)
    KV_SERIALIZE(reason)
    KV_SERIALIZE_OPT(evidence_reason, std::string())
  END_KV_SERIALIZE_MAP()
};
struct review_decisions {
  std::string report_hash;
  std::vector<review_decision> decisions;
  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(report_hash)
    KV_SERIALIZE(decisions)
  END_KV_SERIALIZE_MAP()
};
template<class T> T load(const std::string& path) {
  T value;
  if (!load_audit_json(value, read_audit_file(path)))
    throw std::runtime_error("Invalid audit JSON: " + path);
  return value;
}
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
}

int main(int argc, char** argv)
{
  try {
    po::options_description options("Private Salvium audit review (never starts a daemon)");
    options.add_options()
      ("help", "Show usage")
      ("keygen", po::value<std::string>(), "Create a private review signing key; print its public key")
      ("data-dir", po::value<std::string>(), "Canonical blockchain directory containing lmdb")
      ("network", po::value<std::string>()->default_value("mainnet"), "mainnet, testnet, stagenet or fakechain")
      ("opening", po::value<uint64_t>(), "Accepted opening height (mainnet is pinned)")
      ("public-work-limit", po::value<size_t>()->default_value(50000), "Maximum public ancestor outputs; zero uses only private proofs")
      ("input", po::value<std::vector<std::string>>()->multitoken(), "Private wallet evidence files")
      ("report", po::value<std::string>(), "Existing case report for developer decisions")
      ("decisions", po::value<std::string>(), "CLEAR/DENY decisions bound to report_hash")
      ("sign-key", po::value<std::string>(), "Private review signing key file")
      ("revision", po::value<uint64_t>(), "Increasing result revision for an updated case")
      ("verify-key", po::value<std::string>(), "Verify report against this independent public key")
      ("outdir", po::value<std::string>(), "New private case directory with recipient-specific results");
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, options), vm); po::notify(vm);
    if (vm.count("help") || argc == 1) { std::cout << options << '\n'; return 0; }
    if (vm.count("keygen")) {
      crypto::public_key key; crypto::secret_key secret;
      crypto::generate_keys(key, secret);
      auto encoded = epee::string_tools::pod_to_hex(unwrap(unwrap(secret))) + "\n";
      auto wipe = epee::misc_utils::create_scope_leave_handler([&] { memwipe(encoded.data(), encoded.size()); });
      write_private_audit_file(vm["keygen"].as<std::string>(), encoded);
      std::cout << "Audit public key: " << epee::string_tools::pod_to_hex(key) << '\n';
      return 0;
    }
    audit_review_report report;
    if (vm.count("report")) {
      report = load<audit_review_report>(vm["report"].as<std::string>());
      validate_audit_review_report(report);
    }
    if (vm.count("verify-key")) {
      crypto::public_key key;
      require(epee::string_tools::hex_to_pod(vm["verify-key"].as<std::string>(), key) &&
          verify_audit_review_report(report, key), "Invalid developer signature");
      std::cout << "VERIFIED " << epee::string_tools::pod_to_hex(audit_review_report_hash(report)) << '\n';
      if (!vm.count("outdir")) return 0;
    }
    require(vm.count("outdir"), "Specify --outdir");
    if (!vm.count("report")) {
      require(vm.count("input") && vm.count("data-dir"), "Specify --input and --data-dir");
      const std::string name = vm["network"].as<std::string>();
      const network_type net = name == "mainnet" ? MAINNET : name == "testnet" ? TESTNET :
          name == "stagenet" ? STAGENET : name == "fakechain" ? FAKECHAIN : UNDEFINED;
      require(net != UNDEFINED, "Unknown audit network");
      std::vector<audit_review_package> packages;
      for (const auto& path : vm["input"].as<std::vector<std::string>>()) {
        auto request = load<audit_review_request>(path);
        require(request.version == 3, "Unsupported evidence version");
        packages.insert(packages.end(), request.packages.begin(), request.packages.end());
        require(packages.size() <= 4096, "Too many private audit packages");
      }
      BlockchainLMDB db;
      db.open((boost::filesystem::path(vm["data-dir"].as<std::string>()) / "lmdb").string(), DBF_RDONLY);
      {
        db_rtxn_guard snapshot(&db);
        report = audit_review_verifier::verify(db, net, packages, vm.count("opening") ?
            vm["opening"].as<uint64_t>() : net == MAINNET ? lineage_policy::mainnet_opening_height : 0,
            vm["public-work-limit"].as<size_t>());
      }
      db.close();
    }
    crypto::secret_key secret;
    const bool sign = vm.count("sign-key");
    if (sign) {
      auto text = read_audit_file(vm["sign-key"].as<std::string>(), 128);
      auto wipe = epee::misc_utils::create_scope_leave_handler([&] { memwipe(text.data(), text.size()); });
      const auto end = text.find_last_not_of("\r\n");
      require(end != std::string::npos && end + 1 == 64, "Invalid audit signing key file");
      require(epee::string_tools::hex_to_pod(boost::string_ref(text.data(), end + 1), unwrap(unwrap(secret))), "Invalid audit signing key file");
      if (vm.count("report")) {
        crypto::public_key key;
        require(crypto::secret_key_to_public_key(secret, key) && verify_audit_review_report(report, key),
            "Existing cases must carry a valid developer signature; reprocess unsigned evidence with --input");
      }
    } else if (vm.count("report")) {
      require(vm.count("verify-key"), "Authenticate an existing case with --verify-key or --sign-key");
    }
    if (vm.count("decisions")) {
      const auto changes = load<review_decisions>(vm["decisions"].as<std::string>());
      require(changes.report_hash == epee::string_tools::pod_to_hex(audit_review_report_hash(report)),
          "Developer decisions refer to different evidence or report");
      std::set<std::tuple<std::string, std::string, uint32_t, bool>> seen;
      for (const auto& change : changes.decisions) {
        require((change.action == "CLEAR" || change.action == "DENY") && !change.reason.empty() &&
            change.reason.size() <= 4096, "Developer decisions require CLEAR or DENY and a reason");
        require(seen.emplace(change.package_id, change.transaction, change.output_index, change.stake).second,
            "Duplicate developer decision");
        bool found = false;
        for (auto& item : report.outputs)
          if (item.package_id == change.package_id && item.transaction == change.transaction &&
              item.output_index == change.output_index && item.stake == change.stake) {
            item.decision = change.action; item.decision_reason = change.reason; found = true;
          }
        require(found, "Developer decision refers to an output outside this case");
      }
      require(report.revision < UINT64_MAX, "Audit revision overflow");
      ++report.revision;
    }
    if (vm.count("revision")) {
      const auto revision = vm["revision"].as<uint64_t>();
      require(revision >= report.revision && revision != 0, "Audit revision must increase");
      report.revision = revision;
    }
    const boost::filesystem::path out(vm["outdir"].as<std::string>());
    require(!boost::filesystem::exists(out), "Choose a new output directory; evidence is never overwritten");
    require(boost::filesystem::create_directory(out), "Cannot create case directory");
    boost::filesystem::permissions(out, boost::filesystem::owner_all);
    if (sign) {
      sign_audit_review_report(report, secret);
    } else { report.signer.clear(); report.signature.clear(); }
    write_private_audit_file((out / "case.json").string(), epee::serialization::store_t_to_json(report));
    std::set<std::string> recipients;
    size_t automatic = 0, pending = 0, manual = 0;
    for (const auto& item : report.outputs) {
      recipients.insert(item.package_id);
      if (!item.decision.empty()) ++manual;
      else if (item.state == "CLEARED") ++automatic;
      else ++pending;
    }
    review_decisions queue;
    queue.report_hash = epee::string_tools::pod_to_hex(audit_review_report_hash(report));
    for (const auto& item : report.outputs) if (item.state == "REVIEW_REQUIRED" && item.decision.empty())
      queue.decisions.push_back({item.package_id, item.transaction, item.recommendation,
          "", item.reason, item.output_index, item.stake});
    write_private_audit_file((out / "review-queue.json").string(), epee::serialization::store_t_to_json(queue));
    for (const auto& id : recipients) {
      auto receipt = report;
      receipt.outputs.erase(std::remove_if(receipt.outputs.begin(), receipt.outputs.end(),
          [&](const audit_review_item& item) { return item.package_id != id; }), receipt.outputs.end());
      if (sign) sign_audit_review_report(receipt, secret);
      write_private_audit_file((out / (id + ".json")).string(), epee::serialization::store_t_to_json(receipt));
    }
    std::cout << "AUTO_CLEARED=" << automatic << " DEVELOPER_REVIEW=" << pending << " MANUAL_DECISIONS=" << manual
        << " SIGNED=" << (sign ? "yes" : "no") << "\nCASE_HASH="
        << epee::string_tools::pod_to_hex(audit_review_report_hash(report)) << '\n';
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "Audit review failed: " << e.what() << '\n'; return 1;
  }
}
