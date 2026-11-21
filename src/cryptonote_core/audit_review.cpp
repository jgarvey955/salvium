#include "audit_review.h"
#include "audit_review_authority.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "carrot_impl/format_utils.h"
#include "serialization/binary_utils.h"
#include "ringct/rctSigs.h"
#include "string_tools.h"
#include "common/util.h"
#include <algorithm>
#include <fstream>
#include <set>
#include <stdexcept>
#include <limits>
#include <boost/filesystem.hpp>

namespace cryptonote
{
namespace
{
void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
template<class T> std::string hex(const T& x) { return epee::string_tools::pod_to_hex(x); }
// Length-prefixed UTF-8 fields, including decimal integers; independent of JSON order/whitespace.
void field(std::string& s, const std::string& v) { s += std::to_string(v.size()) + ":" + v; }
template<class T> void number(std::string& s, T n) { field(s, std::to_string(n)); }
std::string context(const audit_review_package& p)
{
  std::string s = "Salvium private audit evidence v3";
  number(s, p.version); number(s, unsigned(p.network)); field(s, p.genesis);
  number(s, p.snapshot_height); field(s, p.snapshot_hash); field(s, p.nonce);
  return s;
}
void valid_context(const audit_review_package& p)
{
  crypto::hash value;
  require(p.version == 3 && epee::string_tools::hex_to_pod(p.genesis, value) &&
      epee::string_tools::hex_to_pod(p.snapshot_hash, value) &&
      epee::string_tools::hex_to_pod(p.nonce, value) && value != crypto::null_hash,
      "Invalid private audit context");
  require(!p.proofs.empty() && p.proofs.size() <= 512, "Private audit package must contain 1 to 512 proofs");
}
}

crypto::hash audit_review_proof_message(const audit_review_package& p, const lineage_output_proof& proof)
{
  std::string s = context(p);
  field(s, hex(proof.transaction)); number(s, proof.output_index); number(s, proof.stake_return);
  number(s, proof.amount); number(s, unsigned(proof.offset_mask)); field(s, hex(proof.image));
  return crypto::cn_fast_hash(s.data(), s.size());
}
bool verify_audit_review_proof(const audit_review_package& p, const lineage_output_proof& proof,
    const crypto::public_key& key, const rct::key& commitment)
{
  if (proof.offset_mask > 1 || proof.signature.sx.size() != 1 || proof.signature.sy.size() != 1 ||
      rct::ki2rct(proof.image) == rct::identity() || rct::pk2rct(key) == rct::identity() ||
      !rct::isInMainSubgroup(rct::ki2rct(proof.image)) || !rct::isInMainSubgroup(rct::pk2rct(key))) return false;
  auto signature = proof.signature;
  signature.I = rct::ki2rct(proof.image);
  return rct::verRctTCLSAGSimple(rct::hash2rct(audit_review_proof_message(p, proof)), signature,
      {{rct::pk2rct(key), commitment}}, rct::commit(proof.amount, proof.offset_mask ? rct::identity() : rct::zero()));
}
std::string audit_review_package_id(const audit_review_package& p)
{
  std::string s = context(p);
  number(s, p.proofs.size());
  for (const auto& proof : p.proofs) field(s, proof);
  return hex(crypto::cn_fast_hash(s.data(), s.size()));
}
crypto::hash audit_review_report_hash(const audit_review_report& r)
{
  std::string s = "Salvium private audit result v3";
  number(s, r.version); number(s, r.revision); number(s, unsigned(r.network)); field(s, r.genesis);
  number(s, r.snapshot_height); field(s, r.snapshot_hash); number(s, r.opening_height);
  number(s, r.public_work_limit); number(s, r.public_outputs_checked);
  field(s, r.evidence_hash); field(s, r.coverage); number(s, r.outputs.size());
  for (const auto& o : r.outputs) {
    field(s, o.package_id); field(s, o.transaction); number(s, o.output_index);
    field(s, o.asset_type); number(s, o.amount); number(s, o.stake); number(s, o.spent);
    field(s, o.state); field(s, o.recommendation); field(s, o.reason);
    number(s, o.missing_inputs.size());
    for (const auto& image : o.missing_inputs) field(s, image);
    field(s, o.decision); field(s, o.decision_reason);
  }
  field(s, r.signer);
  return crypto::cn_fast_hash(s.data(), s.size());
}
bool authorized_audit_review_signer(network_type net, const crypto::public_key& key)
{
  if (!crypto::check_key(key) || rct::pk2rct(key) == rct::identity() ||
      !rct::isInMainSubgroup(rct::pk2rct(key))) return false;
  // Isolated fakechain fixtures use ephemeral test keys. Wallet callers must
  // verify their daemon really is fakechain before enabling that test mode.
  if (net == FAKECHAIN) return true;
  const char* configured = net == MAINNET ? audit_review_authority::mainnet :
      net == TESTNET ? audit_review_authority::testnet :
      net == STAGENET ? audit_review_authority::stagenet : "";
  crypto::public_key authority;
  return epee::string_tools::hex_to_pod(configured, authority) && authority == key;
}
void validate_audit_review_report(const audit_review_report& r)
{
  const auto canonical_hash = [](const std::string& text) {
    crypto::hash value;
    return epee::string_tools::hex_to_pod(text, value) && hex(value) == text;
  };
  require(r.version == 3 && r.revision && r.network <= uint8_t(FAKECHAIN) &&
      r.coverage == "SUBMITTED_OUTPUTS_ONLY" && r.opening_height < r.snapshot_height &&
      r.snapshot_height < UINT64_MAX - 11 && r.public_work_limit <= 500000 &&
      r.public_outputs_checked <= r.public_work_limit && canonical_hash(r.genesis) &&
      canonical_hash(r.snapshot_hash) && canonical_hash(r.evidence_hash), "Invalid private audit report context");
  require(!r.outputs.empty() && r.outputs.size() <= 250000, "Invalid private audit report output count");
  std::set<std::tuple<std::string, std::string, uint32_t, bool>> identities;
  size_t missing = 0;
  for (const auto& o : r.outputs) {
    require(canonical_hash(o.package_id) && canonical_hash(o.transaction) &&
        is_lineage_audit_asset(o.asset_type), "Invalid private audit output identity");
    require(identities.emplace(o.package_id, o.transaction, o.output_index, o.stake).second,
        "Duplicate output in private audit report");
    require((o.state == "CLEARED" || o.state == "REVIEW_REQUIRED") &&
        (o.recommendation == "CLEAR" || o.recommendation == "DENY") &&
        (o.state != "CLEARED" || o.recommendation == "CLEAR") &&
        (o.decision.empty() || o.decision == "CLEAR" || o.decision == "DENY") &&
        (o.decision.empty() ? o.decision_reason.empty() : !o.decision_reason.empty()) &&
        o.reason.size() <= 4096 && o.decision_reason.size() <= 4096,
        "Invalid private audit finding or developer decision");
    require(o.missing_inputs.size() <= 1000000 - missing, "Too many private audit funding references");
    missing += o.missing_inputs.size();
    for (const auto& image : o.missing_inputs)
      require(canonical_hash(image), "Invalid private audit funding reference");
  }
}
void sign_audit_review_report(audit_review_report& r, const crypto::secret_key& secret)
{
  validate_audit_review_report(r);
  crypto::public_key key;
  require(crypto::secret_key_to_public_key(secret, key) && crypto::check_key(key), "Invalid audit signing key");
  require(authorized_audit_review_signer(static_cast<network_type>(r.network), key),
      "Only the designated main developer can sign results; configure the public authority during private release review");
  r.signer = hex(key);
  crypto::signature signature{};
  crypto::generate_signature(audit_review_report_hash(r), key, secret, signature);
  r.signature = hex(signature);
}
bool verify_audit_review_report(const audit_review_report& r, const crypto::public_key& trusted)
{
  try { validate_audit_review_report(r); } catch (const std::exception&) { return false; }
  crypto::signature signature;
  if (r.version != 3 || !r.revision || r.coverage != "SUBMITTED_OUTPUTS_ONLY" || r.signer != hex(trusted) ||
      !authorized_audit_review_signer(static_cast<network_type>(r.network), trusted) ||
      !crypto::check_key(trusted) || rct::pk2rct(trusted) == rct::identity() ||
      !epee::string_tools::hex_to_pod(r.signature, signature)) return false;
  return crypto::check_signature(audit_review_report_hash(r), trusted, signature);
}
void write_private_audit_file(const std::string& path, const std::string& contents)
{
  require(contents.size() <= max_audit_file_bytes, "Audit file exceeds 256 MiB limit");
  const auto temporary = path + "." + hex(crypto::rand<crypto::hash>()) + ".tmp";
  auto file = tools::private_file::create(temporary);
  require(bool(file.handle()), "Cannot create private audit file (choose a new filename)");
  require(std::fwrite(contents.data(), 1, contents.size(), file.handle()) == contents.size() &&
      std::fflush(file.handle()) == 0, "Cannot write private audit file");
  // private_file removes its temporary on destruction. Copy without replacing
  // any existing destination, retaining owner-only permissions.
  boost::filesystem::copy_file(temporary, path);
}
std::string read_audit_file(const std::string& path, size_t max_bytes)
{
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  require(bool(f), "Cannot open audit file");
  const auto size = f.tellg();
  require(size >= 0 && uint64_t(size) <= max_bytes, "Audit file exceeds size limit");
  std::string s(static_cast<size_t>(size), '\0');
  f.seekg(0); f.read(&s[0], s.size());
  require(bool(f), "Cannot read audit file");
  return s;
}

audit_review_report audit_review_verifier::verify(const BlockchainDB& db, network_type net,
    const std::vector<audit_review_package>& packages, uint64_t opening, size_t public_work_limit)
{
  require(!packages.empty() && packages.size() <= 4096, "Audit requires 1 to 4096 packages");
  size_t total_proofs = 0;
  for (const auto& p : packages) {
    require(p.proofs.size() <= 250000 - total_proofs, "Split cases above 250000 output proofs");
    total_proofs += p.proofs.size();
  }
  const auto& anchor = packages.front();
  require(anchor.snapshot_height < db.height() && anchor.snapshot_height < UINT64_MAX - 11,
      "Audit snapshot is outside canonical history");
  require(opening < anchor.snapshot_height, "Accepted opening must precede snapshot");
  require(net != MAINNET || (opening == lineage_policy::mainnet_opening_height),
      "Mainnet review must preserve the accepted SAL-to-SAL1 boundary");
  lineage_audit lineage;
  lineage.configure(anchor.snapshot_height + 1, opening);
  audit_review_report report;
  report.network = uint8_t(net); report.genesis = hex(db.get_block_hash_from_height(0));
  report.snapshot_height = anchor.snapshot_height; report.snapshot_hash = hex(db.get_block_hash_from_height(anchor.snapshot_height));
  report.opening_height = opening;
  require(public_work_limit <= 500000, "Public ancestry verification limit exceeds 500000 outputs");
  report.public_work_limit = public_work_limit;
  std::set<std::string> package_ids;
  using record = lineage_audit::record;
  struct checked {
    record source; audit_review_item item; uint64_t funding_height = 0;
    bool root = false, invalid = false, missing_authorization = false;
  };
  std::vector<checked> outputs;
  std::map<crypto::key_image, std::vector<size_t>> by_image;
  std::unordered_map<crypto::hash, std::shared_ptr<const std::vector<lineage_audit::dependency>>> funding_cache;
  std::unordered_map<crypto::hash, bool> funding_invalid;
  const auto funding = [&](const transaction& tx, uint64_t h, bool& invalid) {
    const auto id = get_transaction_hash(tx);
    auto found = funding_cache.find(id);
    if (found == funding_cache.end()) {
      bool bad = lineage_audit::has_bad_asset_origin(tx) || tx_has_cleartext_confidential_amount(tx);
      auto deps = lineage.inspect_funding(db, tx, h, bad);
      found = funding_cache.emplace(id, std::move(deps)).first;
      funding_invalid[id] = bad;
    }
    invalid |= funding_invalid.at(id);
    return found->second;
  };
  const auto inspect_output = [&](const lineage_output_proof& proof, const audit_review_package* private_context) {
    require(db.tx_exists(proof.transaction), "Evidence refers to a noncanonical transaction");
    const auto tx = db.get_tx(proof.transaction);
    const auto h = db.get_tx_block_height(proof.transaction);
    require(h <= report.snapshot_height && get_transaction_hash(tx) == proof.transaction,
        "Evidence transaction is beyond snapshot or has incorrect hash");
    checked node;
    node.funding_height = h;
    auto& item = node.item;
    item.transaction = hex(proof.transaction);
    item.output_index = proof.output_index; item.stake = proof.stake_return; item.amount = proof.amount;
    auto& source = node.source;
    source.image = proof.image; source.origin = proof.transaction; source.output_height = h;
    source.output_index = proof.output_index; source.stake_return = proof.stake_return;
    source.inputs = std::make_shared<const std::vector<lineage_audit::dependency>>();
    crypto::public_key key;
    rct::key commitment;
    bool direct_bad = false;
    bool intrinsic_bad = false;
    if (proof.stake_return) {
      require(tx.type == transaction_type::STAKE && tx.source_asset_type == "SAL1" &&
          proof.output_index == 0 && proof.amount == tx.amount_burnt && proof.amount > 0,
          "Invalid stake ownership reference");
      source.asset = "SAL1";
      key = carrot::is_carrot_transaction_v1(tx) ? tx.protocol_tx_data.return_address : tx.return_address;
      commitment = rct::commit(proof.amount, rct::identity());
      const uint64_t term = get_config(net).STAKE_LOCK_PERIOD + 1;
      require(h <= UINT64_MAX - term, "Stake maturity overflow");
      source.output_height = h + term;
      source.payout_height = source.output_height;
      source.inputs = funding(tx, h, intrinsic_bad);
      if (source.payout_height <= report.snapshot_height)
        node.missing_authorization = !lineage.historical_stake_payout(db, net, tx, source.payout_height);
    } else {
      require(proof.output_index < tx.vout.size(), "Evidence output index is out of range");
      const auto& out = tx.vout[proof.output_index];
      require(get_output_public_key(out, key) && get_output_asset_type(out, source.asset) &&
          is_lineage_audit_asset(source.asset), "Unsupported audit output asset or format");
      if (tx.type == transaction_type::MINER || tx.type == transaction_type::PROTOCOL) {
        require(proof.amount == out.amount, "Public output amount mismatch");
        commitment = rct::commit(proof.amount, rct::identity());
        const auto block = db.get_block_from_height(h);
        require(get_transaction_hash(tx.type == transaction_type::MINER ? block.miner_tx : block.protocol_tx) == proof.transaction,
            "Issuance transaction is not canonical for its block");
        if (tx.type == transaction_type::MINER) {
          node.root = h <= opening || lineage.valid_miner_origin(db, net, h);
          intrinsic_bad = !node.root;
        } else if (h <= opening || lineage.accepted_conversion_payout(db, net, tx, proof.output_index, h)) {
          node.root = true;
        } else if (source.asset != "SAL1") {
          crypto::hash creation;
          if (lineage.token_issuance_payout(db, tx, proof.output_index, h, creation))
            source.inputs = funding(db.get_tx(creation), h, intrinsic_bad);
          else intrinsic_bad = true;
        } else {
          // Locate the scheduled stake authorization, independently of owners' submission order.
          const auto term = get_config(net).STAKE_LOCK_PERIOD + 1;
          bool matched = false;
          if (h >= term) for (const auto& id : db.get_block_from_height(h - term).tx_hashes) {
            const auto stake = db.get_tx(id);
            const auto return_key = carrot::is_carrot_transaction_v1(stake) ? stake.protocol_tx_data.return_address : stake.return_address;
            if (stake.type != transaction_type::STAKE || return_key != key) continue;
            require(!matched, "Ambiguous stake payout authorization");
            matched = true;
            node.funding_height = h - term;
            node.missing_authorization = !lineage.historical_stake_payout(db, net, stake, h);
            source.inputs = funding(stake, h - term, intrinsic_bad);
          }
          intrinsic_bad |= !matched;
        }
      } else {
        require(proof.output_index < tx.rct_signatures.outPk.size(), "Missing canonical commitment");
        commitment = tx.rct_signatures.outPk[proof.output_index].mask;
        direct_bad = source.asset != tx.source_asset_type || out.amount != 0;
        node.root = h <= opening && !direct_bad;
        source.inputs = funding(tx, h, intrinsic_bad);
      }
    }
    require(crypto::check_key(key) && !(rct::pk2rct(key) == rct::identity()) &&
        rct::isInMainSubgroup(rct::pk2rct(key)) &&
        (!private_context || verify_audit_review_proof(*private_context, proof, key, commitment)),
        "Invalid private output ownership or amount proof");
    source.output_key = key; item.asset_type = source.asset;
    node.invalid = intrinsic_bad || direct_bad;
    if (direct_bad) item.reason = "CONFIRMED_MALFORMED_ORIGIN";
    else if (intrinsic_bad) item.reason = "INVALID_ISSUANCE_OR_TRANSACTION";
    else if (node.missing_authorization) item.reason = "MISSING_PAYOUT_AUTHORIZATION_EVIDENCE";
    else if (node.root) item.reason = h <= opening ? "ACCEPTED_OPENING" : "VERIFIED_ISSUANCE";
    else item.reason = "MISSING_FUNDING_EVIDENCE";
    return node;
  };
  for (const auto& p : packages) {
    valid_context(p);
    require(p.network == report.network && p.genesis == report.genesis &&
        p.snapshot_height == report.snapshot_height && p.snapshot_hash == report.snapshot_hash,
        "Mixed network, snapshot or orphaned audit evidence");
    const auto package_id = audit_review_package_id(p);
    if (!package_ids.insert(package_id).second) continue;
    std::set<std::tuple<crypto::hash, uint32_t, bool>> package_outputs;
    for (const auto& raw : p.proofs) {
      std::string binary;
      lineage_output_proof proof;
      require(raw.size() < 4096 && epee::string_tools::parse_hexstr_to_binbuff(raw, binary) &&
          serialization::parse_binary(binary, proof) && t_serializable_object_to_blob(proof) == binary,
          "Invalid or noncanonical private ownership proof");
      require(package_outputs.emplace(proof.transaction, proof.output_index, proof.stake_return).second,
          "Duplicate output in private audit evidence package");
      auto node = inspect_output(proof, &p);
      auto& item = node.item;
      auto& source = node.source;
      item.package_id = package_id;
      const auto h = db.get_tx_block_height(proof.transaction);
      const auto tx = db.get_tx(proof.transaction);
      // Exact duplicate proofs may occur in multiple wallet packages. Conflicting images cannot substitute.
      for (const auto index : by_image[proof.image]) {
        const auto& prior = outputs[index].source;
        require(prior.output_key == source.output_key && prior.asset == source.asset &&
            ((prior.origin == source.origin && prior.output_index == source.output_index && prior.stake_return == source.stake_return) ||
             (prior.stake_return != source.stake_return &&
              (prior.stake_return ? (tx.type == transaction_type::PROTOCOL && prior.payout_height == h) :
               (db.get_tx(prior.origin).type == transaction_type::PROTOCOL && source.payout_height == prior.output_height)))),
            "Conflicting canonical identity for private key image");
      }
      by_image[proof.image].push_back(outputs.size()); outputs.push_back(std::move(node));
    }
  }
  std::string evidence = "Salvium private audit case v3";
  for (const auto& id : package_ids) field(evidence, id);
  report.evidence_hash = hex(crypto::cn_fast_hash(evidence.data(), evidence.size()));
  // A ring signature proves that one of its members was spent. If every member
  // has verified provenance, no ancestor owner needs to disclose which one.
  // Use an explicit stack so a long chain cannot exhaust the C++ call stack.
  using member = lineage_audit::ring_member;
  struct public_node { checked inspected; std::vector<member> parents; uint8_t state = 1; };
  std::unordered_map<std::string, public_node> public_nodes;
  bool public_limit_hit = false;
  const auto public_identity = [](const member& m) { return hex(m.transaction) + ":" + std::to_string(m.output); };
  const auto public_good = [&](const member& first) {
    std::vector<member> stack{first};
    while (!stack.empty()) {
      const auto ref = stack.back();
      const auto id = public_identity(ref);
      auto found = public_nodes.find(id);
      if (found == public_nodes.end()) {
        if (report.public_outputs_checked >= public_work_limit) { public_limit_hit = true; return false; }
        ++report.public_outputs_checked;
        public_node entry;
        try {
          lineage_output_proof placeholder;
          placeholder.transaction = ref.transaction;
          require(ref.output <= UINT32_MAX, "Public output index overflow");
          placeholder.output_index = ref.output;
          placeholder.amount = db.get_tx(ref.transaction).vout.at(ref.output).amount;
          entry.inspected = inspect_output(placeholder, nullptr);
          const auto& source = entry.inspected.source;
          require(source.output_key == ref.key && source.output_height == ref.height,
              "Public ancestry identity mismatch");
          if (entry.inspected.invalid) entry.state = 4;
          else if (entry.inspected.missing_authorization) entry.state = 3;
          else if (entry.inspected.root) entry.state = 2;
          else {
            if (source.inputs->empty()) entry.state = 3;
            for (const auto& dep : *source.inputs) {
              if (dep.ring.empty()) entry.state = 3;
              for (const auto& parent : dep.ring) {
                if (parent.height >= entry.inspected.funding_height ||
                    parent.unlock_height > entry.inspected.funding_height) entry.state = 3;
                entry.parents.push_back(parent);
              }
            }
          }
        } catch (const std::exception& error) {
          MDEBUG("Public audit ancestor " << id << ": " << error.what());
          entry.state = 3;
        }
        found = public_nodes.emplace(id, std::move(entry)).first;
      }
      if (found->second.state != 1) { stack.pop_back(); continue; }
      bool pending = false;
      for (const auto& parent : found->second.parents) {
        const auto previous = public_nodes.find(public_identity(parent));
        if (previous == public_nodes.end() || previous->second.state == 1) {
          stack.push_back(parent); pending = true; break;
        }
      }
      if (!pending) {
        bool all_good = true, proven_exposure = false;
        for (const auto& dependency : *found->second.inspected.source.inputs) {
          bool all_bad = !dependency.ring.empty();
          for (const auto& source : dependency.ring) {
            const auto state = public_nodes.at(public_identity(source)).state;
            all_good &= state == 2;
            all_bad &= state == 4;
          }
          proven_exposure |= all_bad;
        }
        found->second.state = proven_exposure ? 4 : all_good ? 2 : 3;
        stack.pop_back();
      }
    }
    return public_nodes.at(public_identity(first)).state == 2;
  };
  // Oldest first gives linear propagation through ordinary cross-wallet chains.
  std::vector<size_t> order;
  for (size_t i = 0; i < outputs.size(); ++i) order.push_back(i);
  std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
    return outputs[a].source.output_height < outputs[b].source.output_height;
  });
  for (const auto index : order) {
    auto& node = outputs[index];
    if (node.invalid) { node.source.verdict = 2; continue; }
    if (node.root && !node.missing_authorization) {
      node.source.verdict = 1;
      node.item.state = "CLEARED";
      node.item.recommendation = "CLEAR";
      continue;
    }
    bool complete = !node.missing_authorization && (node.root || !node.source.inputs->empty()), exposure = false;
    bool premature = false;
    bool public_path = false;
    for (const auto& dep : *node.source.inputs) {
      bool input_complete = false;
      const auto candidates = by_image.find(dep.image);
      if (candidates != by_image.end()) for (const auto parent_index : candidates->second) {
        const auto& parent = outputs[parent_index].source;
        if (parent.asset != dep.asset || parent.output_height >= node.funding_height) continue;
        bool matches = false, ambiguous = false;
        bool mature = false;
        for (const auto& member : dep.ring) if (member.key == parent.output_key) {
          matches |= lineage_audit::matches(parent, member);
          ambiguous |= !lineage_audit::matches(parent, member);
          mature |= lineage_audit::matches(parent, member) && member.unlock_height <= node.funding_height;
        }
        if (!matches || ambiguous) continue;
        if (!mature) {
          premature = true;
          node.item.reason = "PREMATURE_FUNDING";
          break;
        }
        input_complete = parent.verdict != 0 && mature;
        exposure |= parent.verdict == 2 || parent.verdict == 3;
        break;
      }
      if (!input_complete && !exposure && !premature && !dep.ring.empty()) {
        public_limit_hit = false;
        input_complete = true;
        bool all_bad = true;
        for (const auto& possible : dep.ring) {
          input_complete &= possible.unlock_height <= node.funding_height && public_good(possible);
          const auto found = public_nodes.find(public_identity(possible));
          all_bad &= found != public_nodes.end() && found->second.state == 4;
        }
        exposure |= all_bad;
        if (!input_complete && public_limit_hit && public_work_limit)
          node.item.reason = "PUBLIC_VERIFICATION_WORK_LIMIT";
        public_path |= input_complete;
      }
      complete &= input_complete;
      if (!input_complete) node.item.missing_inputs.push_back(hex(dep.image));
    }
    if (premature) { node.source.verdict = 2; node.item.reason = "PREMATURE_FUNDING"; }
    else if (exposure) { node.source.verdict = 3; node.item.reason = "PROVEN_ILLICIT_FUNDING_REQUIRES_REVIEW"; }
    else if (complete) {
      node.source.verdict = 1; node.item.state = "CLEARED"; node.item.recommendation = "CLEAR";
      if (!node.root) node.item.reason = public_path ? "ALL_RING_CANDIDATES_VERIFIED" : "ALL_FUNDING_VERIFIED";
    }
  }
  // Inspect canonical spends through the requested snapshot, not the database's
  // later tip. The same key image may appear only once, regardless of wallet.
  std::set<crypto::key_image> spent;
  std::set<crypto::key_image> checked_images;
  for (const auto& entry : by_image) checked_images.insert(entry.first);
  for (const auto& entry : funding_cache)
    for (const auto& dependency : *entry.second) checked_images.insert(dependency.image);
  // Include earlier spends too: a reused public key must not appear unspent
  // merely because its matching key image occurred before the new output.
  for (uint64_t h = 0; h <= report.snapshot_height; ++h)
    for (const auto& id : db.get_block_from_height(h).tx_hashes)
      for (const auto& in : db.get_tx(id).vin)
        if (const auto* key = boost::get<txin_to_key>(&in)) if (checked_images.count(key->k_image)) {
          require(spent.insert(key->k_image).second, "Duplicate canonical spend of an audited key image");
        }
  for (auto& node : outputs) {
    node.item.spent = node.source.stake_return ?
        (node.source.payout_height <= report.snapshot_height && !node.missing_authorization) :
        spent.count(node.source.image);
    report.outputs.push_back(std::move(node.item));
  }
  require(hex(db.get_block_hash_from_height(report.snapshot_height)) == report.snapshot_hash,
      "Canonical snapshot changed during private audit");
  return report;
}
}
