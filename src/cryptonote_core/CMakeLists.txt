# Copyright (c) 2014-2022, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(cryptonote_core_sources
  audit_clearance.cpp
  audit_review.cpp
  lineage_audit.cpp
  ../wallet/scanning_tools.cpp
  blockchain.cpp
  cryptonote_core.cpp
  tx_pool.cpp
  tx_sanity_check.cpp
  cryptonote_tx_utils.cpp
  tx_verification_utils.cpp
  tx_consensus_checks.cpp
  tx_rules_adapters.cpp
  tx_rules_analyze.cpp
  tx_rules_engine.cpp
  tx_rules_validate.cpp
)

set(cryptonote_core_headers)

monero_find_all_headers(cryptonote_core_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

monero_private_headers(cryptonote_core
  ${cryptonote_core_private_headers})
monero_add_library(cryptonote_core
  ${cryptonote_core_sources}
  ${cryptonote_core_headers}
  ${cryptonote_core_private_headers})
target_link_libraries(cryptonote_core
  PUBLIC
    version
    carrot_core
    carrot_impl
    common
    cncrypto
    blockchain_db
    ringct
    device
    oracle
    hardforks
    ${Boost_DATE_TIME_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_SERIALIZATION_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
  PRIVATE
    ${EXTRA_LIBRARIES})

option(SALVIUM_BUILD_LINEAGE_TESTS "Build isolated lineage state regression executable" OFF)
if(SALVIUM_BUILD_LINEAGE_TESTS)
  add_library(audit_test_gtest STATIC ../../tests/gtest/src/gtest-all.cc ../../tests/gtest/src/gtest_main.cc)
  target_include_directories(audit_test_gtest SYSTEM PUBLIC ../../tests/gtest/include PRIVATE ../../tests/gtest)
  target_link_libraries(audit_test_gtest PRIVATE ${CMAKE_THREAD_LIBS_INIT})
  monero_add_minimal_executable(audit_crypto_tests
    ../../tests/unit_tests/carrot_core.cpp ../../tests/unit_tests/carrot_impl.cpp
    ../../tests/unit_tests/carrot_legacy.cpp ../../tests/unit_tests/carrot_return_index.cpp
    ../../tests/unit_tests/carrot_sparc.cpp ../../tests/unit_tests/carrot_transcript_fixed.cpp
    ../../tests/unit_tests/carrot_tx_proof.cpp ../../tests/unit_tests/carrot_mock_helpers.cpp
    ../../tests/unit_tests/bulletproofs.cpp ../../tests/unit_tests/bulletproofs_plus.cpp
    ../../tests/unit_tests/ringct.cpp ../../tests/unit_tests/protocol_tx.cpp
    ../../tests/unit_tests/canonical_amounts.cpp ../../tests/unit_tests/epee_utils.cpp
    ../../tests/unit_tests/wallet_yield.cpp)
  target_link_libraries(audit_crypto_tests PRIVATE audit_test_gtest cryptonote_core net ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})
  monero_add_minimal_executable(audit_http_security_tests ../../tests/unit_tests/epee_http_server.cpp)
  target_compile_definitions(audit_http_security_tests PRIVATE SALVIUM_STANDALONE_HTTP_TEST=1)
  target_link_libraries(audit_http_security_tests PRIVATE cryptonote_core ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})
  monero_add_minimal_executable(audit_security_tests ../../tests/unit_tests/audit_security.cpp)
  target_link_libraries(audit_security_tests PRIVATE cryptonote_core ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})
  monero_add_minimal_executable(audit_clearance_tests ../../tests/unit_tests/audit_clearance.cpp)
  target_link_libraries(audit_clearance_tests PRIVATE cryptonote_core ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})
  monero_add_minimal_executable(audit_review_tests ../../tests/unit_tests/audit_review.cpp)
  target_link_libraries(audit_review_tests PRIVATE cryptonote_core ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})
  monero_add_minimal_executable(lineage_audit_tests ../../tests/unit_tests/lineage_audit.cpp)
  target_link_libraries(lineage_audit_tests PRIVATE cryptonote_core ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})
  monero_add_minimal_executable(audit_randomx_tests ../../tests/unit_tests/audit_randomx.cpp)
  target_include_directories(audit_randomx_tests PRIVATE ${RANDOMX_INCLUDE})
  target_link_libraries(audit_randomx_tests PRIVATE cncrypto ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})
endif()
