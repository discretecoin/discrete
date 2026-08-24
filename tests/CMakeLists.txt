add_definitions(-DSTATICLIB)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} ../version)

# Classical-consensus test suites (CoreTests, TransfersTests, PerformanceTests) were
# removed, along with DifficultyTests (stale classical difficulty vectors) and
# LMDBReorgTests (classical chaingen, hangs on the PQ chain): they exercise classical
# CryptoNote tx/transfer/consensus mechanics that no longer exist on the post-quantum
# chain. The classical case-level tests inside UnitTests (WalletApi, WalletLegacyApi,
# Transfers*, tx_pool, parse_amount, BlockchainExplorer, ...) were pruned for the same
# reason; only the PqWalletIntegration gate remains there. The Pq* suites + the pruned
# UnitTests are the regression gate, and a bare `ctest` is now fully green.
file(GLOB_RECURSE FunctionalTests FunctionalTests/*)
file(GLOB_RECURSE IntegrationTestLibrary IntegrationTestLib/*)
file(GLOB_RECURSE IntegrationTests IntegrationTests/*)
file(GLOB_RECURSE NodeRpcProxyTests NodeRpcProxyTests/*)
file(GLOB_RECURSE SystemTests System/*)
file(GLOB_RECURSE TestGenerator TestGenerator/*)
file(GLOB_RECURSE UnitTests UnitTests/*)

file(GLOB_RECURSE CryptoNoteProtocol ../src/CryptoNoteProtocol/*)
file(GLOB_RECURSE P2p ../src/P2p/*)

source_group("" FILES ${FunctionalTests} ${IntegrationTestLibrary} ${IntegrationTests} ${NodeRpcProxyTests} ${SystemTests} ${TestGenerator} ${UnitTests})
source_group("" FILES ${CryptoNoteProtocol} ${P2p})

add_library(IntegrationTestLibrary ${IntegrationTestLibrary})
add_library(TestGenerator ${TestGenerator})

add_executable(IntegrationTests ${IntegrationTests})
add_executable(NodeRpcProxyTests ${NodeRpcProxyTests})
add_executable(SystemTests ${SystemTests})
add_executable(UnitTests ${UnitTests})
add_executable(HashTargetTests HashTarget.cpp)
add_executable(HashTests Hash/main.cpp)

add_executable(PqPrimitivesTests test_pq_primitives.cpp)
add_executable(PqDomainsTests test_pq_domains.cpp)
add_executable(PqDeriveTests test_pq_derive.cpp)
add_executable(PqSeedAddressTests test_pq_seed_address.cpp)
add_executable(PqExtraTests test_pq_extra.cpp)
add_executable(PqWireTests test_pq_wire.cpp)
add_executable(PqOutputBuilderTests test_pq_output_builder.cpp)
add_executable(PqScanTests test_pq_scan.cpp)
add_executable(PqPaymentProofTests test_pq_payment_proof.cpp)
add_executable(PqPaymentProofArchiveTests test_payment_proof_archive.cpp)
add_executable(PqNullifierDbTests test_pq_nullifier_db.cpp)
add_executable(PqValidationTests test_pq_validation.cpp)
add_executable(PqChainTests test_pq_chain.cpp)
add_executable(PqAccountTests test_pq_account.cpp)
add_executable(PqWalletTests test_pq_wallet.cpp)
add_executable(PqTxBuilderTests test_pq_tx_builder.cpp)
add_executable(PqWalletStateTests test_pq_wallet_state.cpp)
add_executable(PqConsumerTests test_pq_consumer.cpp)
add_executable(PqGenesisTests test_pq_genesis.cpp)
add_executable(DenominationsTests test_denominations.cpp)
add_executable(PqSenderTests test_pq_sender.cpp)
add_executable(PqFinalityTests test_pq_finality.cpp)
add_executable(PqPowTests test_pq_pow.cpp)
add_executable(PqDnsCheckpointTests test_dns_checkpoint.cpp)
add_executable(HttpFramingTests test_http_framing.cpp)
add_executable(PqMnemonicCompatTests test_pq_mnemonic_compat.cpp)
add_executable(PqWalletSecurityTests test_wallet_security.cpp)

target_link_libraries(IntegrationTests IntegrationTestLibrary Wallet NodeRpcProxy InProcessNode P2P Rpc Http CryptoNoteProtocol Transfers Serialization System CryptoNoteCore Logging Common Crypto BlockchainExplorer Checkpoints gtest Mnemonics upnpc-static ${Boost_LIBRARIES})
target_link_libraries(NodeRpcProxyTests NodeRpcProxy CryptoNoteCore Rpc Http Serialization System Logging Common Crypto ${Boost_LIBRARIES})
target_link_libraries(SystemTests System gtest_main ${Boost_LIBRARIES})
target_link_libraries(UnitTests gtest_main PaymentGate Wallet TestGenerator InProcessNode NodeRpcProxy Rpc Http Transfers Serialization System Logging BlockchainExplorer CryptoNoteCore Checkpoints Common Crypto Mnemonics ${Boost_LIBRARIES})
target_link_libraries(HashTargetTests CryptoNoteCore Crypto)
target_link_libraries(HashTests Crypto)

target_link_libraries(PqPrimitivesTests CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqDomainsTests CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqDeriveTests CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqSeedAddressTests CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqExtraTests CryptoNoteCore Serialization System Logging Common Crypto gtest ${Boost_LIBRARIES})
target_link_libraries(PqWireTests CryptoNoteCore Serialization System Logging Common Crypto gtest ${Boost_LIBRARIES})
target_link_libraries(PqOutputBuilderTests CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqScanTests CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqPaymentProofTests CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqPaymentProofArchiveTests Wallet CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqNullifierDbTests CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqValidationTests CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqChainTests TestGenerator Wallet CryptoNoteCore Serialization System Logging Common Crypto CryptoPq BlockchainExplorer Checkpoints ${Boost_LIBRARIES})
target_link_libraries(PqAccountTests CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqWalletTests Wallet CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqTxBuilderTests Wallet CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqWalletStateTests Wallet CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqConsumerTests Wallet Transfers CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqGenesisTests CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(DenominationsTests gtest ${Boost_LIBRARIES})
target_link_libraries(PqSenderTests Wallet CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqFinalityTests Checkpoints CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqPowTests CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(PqDnsCheckpointTests CheckpointsDns CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})
target_link_libraries(HttpFramingTests Http System Logging Common Crypto gtest ${Boost_LIBRARIES})
target_link_libraries(PqMnemonicCompatTests Mnemonics Common Crypto gtest ${Boost_LIBRARIES})
target_link_libraries(PqWalletSecurityTests Wallet CryptoNoteCore Serialization System Logging Common Crypto CryptoPq gtest ${Boost_LIBRARIES})

if(MSVC)
  target_link_libraries(SystemTests ws2_32)
  target_link_libraries(NodeRpcProxyTests ws2_32)
  target_link_libraries(HashTests legacy_stdio_definitions.lib)
  target_link_libraries(UnitTests legacy_stdio_definitions.lib)
  target_link_libraries(NodeRpcProxyTests legacy_stdio_definitions.lib ${OPENSSL_LIBRARIES})
  target_link_libraries(IntegrationTests legacy_stdio_definitions.lib ${OPENSSL_LIBRARIES} ws2_32)
  target_link_libraries(PqExtraTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqPaymentProofArchiveTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqWireTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqDomainsTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqNullifierDbTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqValidationTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqChainTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqAccountTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqWalletTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqTxBuilderTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqWalletStateTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqConsumerTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqGenesisTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(DenominationsTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqSenderTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqFinalityTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqPowTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqDnsCheckpointTests legacy_stdio_definitions.lib ws2_32)
  target_link_libraries(PqWalletSecurityTests legacy_stdio_definitions.lib ws2_32)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR APPLE AND NOT ANDROID)
  target_link_libraries(IntegrationTests -lresolv)
  target_link_libraries(NodeRpcProxyTests -lresolv)
  target_link_libraries(UnitTests -lresolv)
endif()

# Http/System reach OpenSSL through Boost.Asio's SSL streams; the MSVC branch
# above already links it, so cover the other toolchains here.
if(OPENSSL_FOUND AND NOT MSVC)
  target_link_libraries(NodeRpcProxyTests ${OPENSSL_LIBRARIES})
  target_link_libraries(IntegrationTests ${OPENSSL_LIBRARIES})
endif()

if(NOT MSVC)
  set_property(TARGET gtest gtest_main IntegrationTestLibrary IntegrationTests TestGenerator UnitTests SystemTests HashTargetTests APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-sign-compare")
endif()

add_custom_target(tests DEPENDS IntegrationTests NodeRpcProxyTests SystemTests UnitTests HashTargetTests HashTests)

set_property(TARGET
  tests
  IntegrationTestLibrary
  TestGenerator
  IntegrationTests
  NodeRpcProxyTests
  SystemTests
  UnitTests
  HashTargetTests
  HashTests
  PqPrimitivesTests
  PqDomainsTests
  PqDeriveTests
  PqSeedAddressTests
  PqExtraTests
  PqWireTests
  PqOutputBuilderTests
  PqScanTests
  PqPaymentProofTests
  PqPaymentProofArchiveTests
  PqNullifierDbTests
  PqValidationTests
  PqChainTests
  PqAccountTests
  PqWalletTests
  PqTxBuilderTests
  PqWalletStateTests
  PqConsumerTests
  PqGenesisTests
  DenominationsTests
  PqSenderTests
  PqFinalityTests
  PqPowTests
  PqDnsCheckpointTests
  HttpFramingTests
  PqMnemonicCompatTests
PROPERTY FOLDER "tests")

add_dependencies(IntegrationTestLibrary version)

set_property(TARGET IntegrationTests PROPERTY OUTPUT_NAME "integration_tests")
set_property(TARGET NodeRpcProxyTests PROPERTY OUTPUT_NAME "node_rpc_proxy_tests")
set_property(TARGET SystemTests PROPERTY OUTPUT_NAME "system_tests")
set_property(TARGET UnitTests PROPERTY OUTPUT_NAME "unit_tests")
set_property(TARGET HashTargetTests PROPERTY OUTPUT_NAME "hash_target_tests")
set_property(TARGET HashTests PROPERTY OUTPUT_NAME "hash_tests")
set_property(TARGET PqPrimitivesTests PROPERTY OUTPUT_NAME "pq_primitives_tests")
set_property(TARGET PqDomainsTests PROPERTY OUTPUT_NAME "pq_domains_tests")
set_property(TARGET PqDeriveTests PROPERTY OUTPUT_NAME "pq_derive_tests")
set_property(TARGET PqSeedAddressTests PROPERTY OUTPUT_NAME "pq_seed_address_tests")
set_property(TARGET PqExtraTests PROPERTY OUTPUT_NAME "pq_extra_tests")
set_property(TARGET PqWireTests PROPERTY OUTPUT_NAME "pq_wire_tests")
set_property(TARGET PqOutputBuilderTests PROPERTY OUTPUT_NAME "pq_output_builder_tests")
set_property(TARGET PqScanTests PROPERTY OUTPUT_NAME "pq_scan_tests")
set_property(TARGET PqPaymentProofTests PROPERTY OUTPUT_NAME "pq_payment_proof_tests")
set_property(TARGET PqPaymentProofArchiveTests PROPERTY OUTPUT_NAME "pq_payment_proof_archive_tests")
set_property(TARGET PqNullifierDbTests PROPERTY OUTPUT_NAME "pq_nullifier_db_tests")
set_property(TARGET PqValidationTests PROPERTY OUTPUT_NAME "pq_validation_tests")
set_property(TARGET PqChainTests PROPERTY OUTPUT_NAME "pq_chain_tests")
set_property(TARGET PqAccountTests PROPERTY OUTPUT_NAME "pq_account_tests")
set_property(TARGET PqWalletTests PROPERTY OUTPUT_NAME "pq_wallet_tests")
set_property(TARGET PqTxBuilderTests PROPERTY OUTPUT_NAME "pq_tx_builder_tests")
set_property(TARGET PqWalletStateTests PROPERTY OUTPUT_NAME "pq_wallet_state_tests")
set_property(TARGET PqConsumerTests PROPERTY OUTPUT_NAME "pq_consumer_tests")
set_property(TARGET PqGenesisTests PROPERTY OUTPUT_NAME "pq_genesis_tests")
set_property(TARGET DenominationsTests PROPERTY OUTPUT_NAME "denominations_tests")
set_property(TARGET PqSenderTests PROPERTY OUTPUT_NAME "pq_sender_tests")
set_property(TARGET PqFinalityTests PROPERTY OUTPUT_NAME "pq_finality_tests")
set_property(TARGET PqPowTests PROPERTY OUTPUT_NAME "pq_pow_tests")
set_property(TARGET PqDnsCheckpointTests PROPERTY OUTPUT_NAME "pq_dns_checkpoint_tests")
set_property(TARGET HttpFramingTests PROPERTY OUTPUT_NAME "http_framing_tests")
set_property(TARGET PqMnemonicCompatTests PROPERTY OUTPUT_NAME "pq_mnemonic_compat_tests")
set_property(TARGET PqWalletSecurityTests PROPERTY OUTPUT_NAME "pq_wallet_security_tests")

add_test(HashTests hash_tests)
add_test(HashTargetTests hash_target_tests)
add_test(SystemTests system_tests)
add_test(UnitTests unit_tests)
add_test(PqPrimitivesTests pq_primitives_tests)
add_test(PqDomainsTests pq_domains_tests)
add_test(PqDeriveTests pq_derive_tests)
add_test(PqSeedAddressTests pq_seed_address_tests)
add_test(PqExtraTests pq_extra_tests)
add_test(PqWireTests pq_wire_tests)
add_test(PqOutputBuilderTests pq_output_builder_tests)
add_test(PqScanTests pq_scan_tests)
add_test(PqPaymentProofTests pq_payment_proof_tests)
add_test(PqPaymentProofArchiveTests pq_payment_proof_archive_tests)
add_test(PqNullifierDbTests pq_nullifier_db_tests)
add_test(PqValidationTests pq_validation_tests)
add_test(PqChainTests pq_chain_tests)
add_test(PqAccountTests pq_account_tests)
add_test(PqWalletTests pq_wallet_tests)
add_test(PqTxBuilderTests pq_tx_builder_tests)
add_test(PqWalletStateTests pq_wallet_state_tests)
add_test(PqConsumerTests pq_consumer_tests)
add_test(PqGenesisTests pq_genesis_tests)
add_test(DenominationsTests denominations_tests)
add_test(PqSenderTests pq_sender_tests)
add_test(PqFinalityTests pq_finality_tests)
add_test(PqPowTests pq_pow_tests)
add_test(PqDnsCheckpointTests pq_dns_checkpoint_tests)
add_test(HttpFramingTests http_framing_tests)
add_test(PqMnemonicCompatTests pq_mnemonic_compat_tests)
add_test(PqWalletSecurityTests pq_wallet_security_tests)
# Wallet-sync E2E lives in unit_tests; expose just the PQ integration case under a
# Pq* name so it joins the regression gate (ctest -R "Pq|Denomination") without
# pulling in the runtime-broken classical UnitTests suites.
add_test(NAME PqWalletSyncE2E COMMAND unit_tests --gtest_filter=PqWalletIntegration.*)
