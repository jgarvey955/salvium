#include "ringct/rctSigs.h"
#include "ringct/proof_validation.h"
#include "carrot_core/sparc.h"
#include "crypto/generators.h"
#include "cryptonote_core/tx_rules_engine.h"
#include "cryptonote_core/audit_review.h"
#include "cryptonote_core/audit_clearance.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "string_tools.h"
#include "serialization/binary_utils.h"
#include "device/log.hpp"
#include "file_io_utils.h"
#include "storages/parserse_base_utils.h"
#include "rapidjson/document.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <limits>

namespace {
void require(bool result, const char* reason) { if (!result) throw std::runtime_error(reason); }
void parsing_and_file_checks() {
  std::string bytes;
  for (unsigned c = 0; c < 32; ++c) bytes.push_back(static_cast<char>(c));
  bytes += "\"\\";
  const auto encoded = "\"" + epee::misc_utils::parse::transform_to_escape_sequence(bytes) + "\"";
  rapidjson::Document decoded;
  decoded.Parse(encoded.data(), encoded.size());
  require(!decoded.HasParseError() && decoded.IsString() &&
      std::string(decoded.GetString(), decoded.GetStringLength()) == bytes,
      "Control characters were not encoded as valid JSON");
#ifndef _WIN32
  const auto directory = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("salvium-safe-file-%%%%-%%%%");
  boost::filesystem::create_directory(directory);
  struct Cleanup { boost::filesystem::path path; ~Cleanup() { boost::filesystem::remove_all(path); } } cleanup{directory};
  const auto target = directory / "secret", link = directory / "link";
  require(epee::file_io_utils::save_string_to_file(target.string(), "original"), "Private file write failed");
  boost::filesystem::create_symlink(target, link);
  require(!epee::file_io_utils::save_string_to_file(link.string(), "replacement"), "Private file write followed a link");
  boost::filesystem::remove(link);
  boost::filesystem::create_hard_link(target, link);
  require(!epee::file_io_utils::save_string_to_file(target.string(), "replacement"), "Private file write accepted shared storage");
  std::string contents;
  require(epee::file_io_utils::load_file_to_string(target.string(), contents) && contents == "original",
      "Rejected private file write modified the original");
#endif
}
void device_log_checks() {
  char text[7] = {'x'};
  hw::buffer_to_str(text, sizeof(text), nullptr, 0);
  require(text[0] == '\0', "Empty hardware log buffer was not terminated");
  const char bytes[] = {0, static_cast<char>(0x80), static_cast<char>(0xff)};
  hw::buffer_to_str(text, sizeof(text), bytes, sizeof(bytes));
  require(std::string(text) == "0080ff", "Hardware log hex conversion failed");
  for (unsigned variant = 0; variant < 4; ++variant) {
    bool rejected = false;
    try {
      if (variant == 0) hw::buffer_to_str(text, sizeof(text) - 1, bytes, sizeof(bytes));
      if (variant == 1) hw::buffer_to_str(text, sizeof(text), bytes, std::numeric_limits<size_t>::max());
      if (variant == 2) hw::buffer_to_str(text, sizeof(text), nullptr, 1);
      if (variant == 3) hw::buffer_to_str(nullptr, 0, bytes, 0);
    } catch (const std::exception&) { rejected = true; }
    require(rejected, "Invalid hardware log buffer accepted");
  }
}
void proof_checks() {
  using namespace rct;
  require(!canonical_spend_point(identity()), "Identity accepted as a spend point");
  key alternate_identity = identity();
  alternate_identity.bytes[31] |= 0x80;
  require(!canonical_spend_point(alternate_identity), "Noncanonical identity accepted as a spend point");
  for (const auto& bad_key : {identity(), alternate_identity, zero()}) {
    const auto authority = rct2pk(bad_key);
    require(!cryptonote::authorized_audit_review_signer(cryptonote::FAKECHAIN, authority),
        "Malformed audit authority accepted");
    cryptonote::audit_clearance_registry registry;
    bool rejected = false;
    try { registry.configure(cryptonote::FAKECHAIN, 1, authority); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, "Malformed audit activation key accepted");
  }
  for (unsigned i = 0; i < 128; ++i) {
    const key witness = skGen(), statement = scalarmultBase(witness);
    require(canonical_spend_point(statement), "Valid canonical spend point rejected");
    const auto valid = PRProof_Gen(witness);
    require(PRProof_Ver(statement, valid, true), "Valid PR proof rejected");
    auto changed = valid; changed.z2 = identity();
    require(!PRProof_Ver(statement, changed, true), "Unauthenticated PR proof field accepted");
    changed = valid; changed.z1 = curveOrder();
    require(!PRProof_Ver(statement, changed, true), "Noncanonical PR response accepted");
    require(!PRProof_Ver(zero(), valid, true), "Invalid PR statement accepted");
    require(!PRProof_Ver(zero(), valid), "Malformed legacy PR statement did not fail closed");
    key nonzero_commitment; genC(nonzero_commitment, witness, 1);
    require(!PRProof_Ver(nonzero_commitment, valid, true), "Nonzero value accepted by zero remainder proof");
    const key x = skGen(), y = skGen();
    key public_key; addKeys2(public_key, x, y, pk2rct(crypto::get_T()));
    const auto sa = SAProof_Gen(public_key, x, y);
    require(SAProof_Ver(sa, public_key), "Valid current spend authority proof rejected");
    auto invalid_sa = sa; invalid_sa.z2 = curveOrder();
    require(!SAProof_Ver(invalid_sa, public_key), "Noncanonical spend authority proof accepted");
    require(!SAProof_Ver(sa, zero()), "Malformed spend key did not fail closed");
    zk_proof legacy_sa{};
    carrot::make_sparc_spend_authority_proof(x, y, public_key, legacy_sa);
    require(carrot::verify_sparc_spend_authority_proof(legacy_sa, public_key), "Valid SPARC proof rejected");
    auto malformed = legacy_sa; malformed.z1 = curveOrder();
    require(!carrot::verify_sparc_spend_authority_proof(malformed, public_key), "Noncanonical SPARC response accepted");
    require(!carrot::verify_sparc_spend_authority_proof(legacy_sa, zero()), "Malformed SPARC key did not fail closed");
    bool rejected = false;
    try { carrot::make_sparc_spend_authority_proof(x, y, statement, malformed); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, "Invalid SPARC witness accepted in release build");
  }
  const auto zero_proof = PRProof_Gen(zero());
  require(PRProof_Ver(identity(), zero_proof, true), "Legitimate zero remainder rejected");
  for (uint8_t type : {uint8_t(RCTTypeFull), uint8_t(RCTTypeSimple), uint8_t(RCTTypeSalviumOne)}) {
    rctSig malformed{}; malformed.type = type;
    require(type == RCTTypeFull ? !verRct(malformed, false) :
        !verRctNonSemanticsSimple(malformed, cryptonote::TRANSFER), "Empty proof vectors accepted");
  }
}
void asset_checks(const char* fixture) {
  std::ifstream input(fixture);
  std::string text; input >> text;
  std::string blob; cryptonote::transaction tx;
  require(epee::string_tools::parse_hexstr_to_binbuff(text, blob) &&
      cryptonote::parse_and_validate_tx_from_blob(blob, tx), "Cannot parse historical fixture");
  using namespace cryptonote;
  txrules::validation_env env;
  env.hf = HF_VERSION_REJECT_POISONED_REFS; env.height = 521425;
  env.mode = txrules::validation_mode::block;
  env.token_state.asset_exists = [](const void*, const std::string&) { return true; };
  txrules::consensus_result result;
  require(!txrules::check_tx_consensus(tx, env, nullptr, &result), "Historical cross-asset issuance accepted by current rules");
  require(result.reason.find("funded source asset") != std::string::npos, "Cross-asset regression did not reach source binding check");
  env.height = 1;
  require(!txrules::check_tx_consensus(tx, env, nullptr, &result), "Historical-height bypass accepted under current fork");
  env.hf = 11; env.height = 465074; env.mode = txrules::validation_mode::mempool;
  require(!txrules::check_tx_consensus(tx, env, nullptr, &result), "Mempool accepted cross-asset issuance");

  tx.type = CREATE_TOKEN; tx.version = TRANSACTION_VERSION_ENABLE_TOKENS;
  tx.source_asset_type = tx.destination_asset_type = "SAL1";
  for (auto& v : tx.vin) boost::get<txin_to_key>(v).asset_type = "SAL1";
  tx.token_metadata = {1, "YAHU", sal_token_t{1, 1000, 0, "Security regression fixture", "", {}}};
  tx.protocol_tx_data.version = 1;
  tx.amount_burnt = get_token_creation_price("YAHU");
  env.hf = HF_VERSION_REJECT_POISONED_REFS; env.height = 521425;
  env.token_state.asset_exists = [](const void*, const std::string&) { return false; };
  require(txrules::check_tx_consensus(tx, env, nullptr, &result), result.reason.c_str());
  const auto valid_token = tx;
  for (unsigned field = 0; field < 4; ++field) {
    tx = valid_token;
    if (field == 0) tx.token_metadata.asset_type = "yahu";
    if (field == 1) tx.token_metadata.version = 0;
    if (field == 2) tx.protocol_tx_data.version = 0;
    if (field == 3) boost::get<sal_token_t>(tx.token_metadata.token).version = 0;
    require(!txrules::check_tx_consensus(tx, env, nullptr, &result), "Noncanonical token metadata accepted");
  }
  layer2_rollup_data_t rollup; rollup.version = 1; rollup.txs.resize(256);
  std::string encoded;
  require(serialization::dump_binary(rollup, encoded), "Valid rollup encoding rejected");
  layer2_rollup_data_t decoded;
  require(serialization::parse_binary(encoded, decoded) && decoded.txs.size() == 256, "Valid rollup roundtrip failed");
  rollup.txs.emplace_back();
  require(!serialization::dump_binary(rollup, encoded), "Oversized rollup serialization accepted");
}
}
int main(int argc, char** argv) {
  try {
    require(argc == 2, "Supply public historical transaction fixture");
    proof_checks(); asset_checks(argv[1]); device_log_checks(); parsing_and_file_checks();
    std::cout << "PASS: PR remainder, current/legacy SPARC, malformed proof vectors and historical mint rejection regressions\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL: " << error.what() << '\n'; return 1;
  }
}
