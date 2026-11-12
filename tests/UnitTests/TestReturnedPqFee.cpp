// Copyright (c) 2026, The Discrete developers
// Pool policy tests use controlled validators to count work and isolate ordering.
// These transactions are not chain-valid; the funded Core fixture tests crypto,
// actual input resolution, reorganization, persistence and miner-template admission.

#include "gtest/gtest.h"
#include "ICoreStub.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Logging/ConsoleLogger.h"

#include <map>

using namespace CryptoNote;
namespace {
struct FeeState {
  bool ready = false, resolvable = true, spent = false;
  uint64_t fee = 50;
  size_t validations = 0, resolutions = 0;
};
struct FeeCore : ICoreStub {
  uint32_t height = 10;
  uint8_t fork = 0;
  std::map<uint8_t, FeeState> state;
  uint32_t getCurrentBlockchainHeight() override { return height; }
  Crypto::Hash getBlockIdByHeight(uint32_t h) override {
    Crypto::Hash hash{}; hash.data[0] = static_cast<uint8_t>(h + 1);
    hash.data[1] = h + 1 == height ? fork : 0;
    return hash;
  }
  bool getPqTransactionFee(const Transaction& tx, uint64_t& fee) override {
    auto& entry = state.at(tx.extra.at(0));
    ++entry.resolutions;
    fee = entry.fee;
    return entry.resolvable;
  }
  bool check_tx_fee(const Transaction&, const Crypto::Hash&, size_t,
                    tx_verification_context&, uint32_t) override { return true; }
};
struct FeeValidator : ITransactionValidator {
  FeeCore& core;
  explicit FeeValidator(FeeCore& value) : core(value) {}
  bool checkTransactionInputs(const Transaction& tx, BlockInfo& used) override {
    const auto& entry = core.state.at(tx.extra.at(0));
    if (!entry.ready || entry.spent) return false;
    used.height = 1; used.id = core.getBlockIdByHeight(1);
    return true;
  }
  bool checkTransactionInputs(const Transaction& tx, BlockInfo& used, BlockInfo& failed) override {
    // Model the existing validator's negative-cache shortcut. The pool repair
    // must discard it when the failed tip becomes an ancestor or changes hash.
    if (!failed.empty() && core.height > failed.height && core.getBlockIdByHeight(failed.height) == failed.id)
      return false;
    auto& entry = core.state.at(tx.extra.at(0));
    ++entry.validations;
    if (checkTransactionInputs(tx, used)) return true;
    failed.height = core.height - 1; failed.id = core.getBlockIdByHeight(failed.height);
    return false;
  }
  bool haveSpentKeyImages(const Transaction& tx) override { return core.state.at(tx.extra.at(0)).spent; }
  bool checkTransactionSize(size_t) override { return true; }
};
struct FeeTime : ITimeProvider { time_t now() override { return 1000; } };

class ReturnedPqFee : public ::testing::Test {
protected:
  Logging::ConsoleLogger logger{Logging::ERROR};
  Currency currency = CurrencyBuilder(logger).testnet(true).minerTxBlobReservedSize(0).currency();
  FeeCore core;
  FeeValidator validator{core};
  FeeTime time;
  tx_memory_pool pool{currency, validator, core, time, logger};
  std::map<uint8_t, Crypto::Hash> ids;

  void add(uint8_t key, size_t size, bool kept = true, uint8_t type = TX_PQ, bool conflictingInput = false) {
    Transaction tx{}; tx.version = TRANSACTION_VERSION_1; tx.txType = type; tx.extra = {key};
    if (conflictingInput) {
      PqInput input{}; input.prevTxid.data[0] = 42;
      input.authPub.assign(PQ_AUTH_PUB_SIZE, 7); input.rhoReveal.assign(PQ_RHO_SIZE, 8);
      tx.inputs.push_back(input);
    }
    const auto id = getObjectHash(tx);
    tx_verification_context result{};
    ASSERT_TRUE(pool.add_tx(tx, id, size, result, kept));
    ASSERT_TRUE(result.m_added_to_pool);
    ids[key] = id;
  }
  void expectTemplate(const std::vector<uint8_t>& keys, size_t median, size_t maximum,
                      size_t expectedBytes, uint64_t expectedFee) {
    Block block{}; size_t bytes = 0; uint64_t fee = 0;
    ASSERT_TRUE(pool.fill_block_template(block, median, maximum, 0, bytes, fee));
    std::vector<Crypto::Hash> expected;
    for (auto key : keys) expected.push_back(ids.at(key));
    EXPECT_EQ(block.transactionHashes, expected);
    EXPECT_EQ(bytes, expectedBytes);
    EXPECT_EQ(fee, expectedFee);
  }
  void TearDown() override {
    for (const auto& entry : ids) {
      Transaction tx{}; size_t bytes = 0; uint64_t fee = 0;
      EXPECT_TRUE(pool.take_tx(entry.second, tx, bytes, fee));
    }
  }
};

TEST_F(ReturnedPqFee, RepairsBeforePriorityAndPaidSizeLimitWithoutRepeatedValidation) {
  core.state[1].fee = 100; add(1, 120);
  core.state[2].ready = true; core.state[2].fee = 2; add(2, 100, false);
  core.state[1].ready = true;
  // Zero-fee size policy would exclude 120 bytes at median 100. Once repaired,
  // this transaction also outranks the already-cached positive-fee entry.
  for (unsigned request = 0; request < 10; ++request) expectTemplate({1}, 100, 1000, 120, 100);
  EXPECT_EQ(core.state[1].validations, 1u);
  EXPECT_EQ(core.state[1].resolutions, 1u);
  expectTemplate({2}, 100, 119, 100, 2);
  expectTemplate({}, 100, 99, 0, 0);
}

TEST_F(ReturnedPqFee, MissingAndPartialInputsRecheckOnlyWhenTheCanonicalTipChanges) {
  core.state[1].fee = 123; add(1, 100); // A fee lookup alone could produce a partial sum.
  core.state[2].resolvable = false; add(2, 100);
  for (unsigned request = 0; request < 10; ++request) expectTemplate({}, 1000, 2000, 0, 0);
  EXPECT_EQ(core.state[1].validations, 1u); EXPECT_EQ(core.state[2].validations, 1u);
  EXPECT_EQ(core.state[1].resolutions, 0u); EXPECT_EQ(core.state[2].resolutions, 0u);
  ++core.height;
  expectTemplate({}, 1000, 2000, 0, 0);
  EXPECT_EQ(core.state[1].validations, 2u); EXPECT_EQ(core.state[2].validations, 2u);
  ++core.height; core.state[1].ready = true;
  expectTemplate({1}, 1000, 2000, 100, 123);
  EXPECT_EQ(core.state[1].validations, 3u);
  ++core.fork; core.state[2].ready = true; core.state[2].resolvable = true;
  core.state[1].spent = true;
  pool.on_blockchain_dec(core.height, core.getBlockIdByHeight(core.height - 1));
  expectTemplate({2}, 1000, 2000, 100, 50);
  EXPECT_EQ(core.state[2].validations, 4u);
  EXPECT_EQ(pool.get_transactions_count(), 2u);
}

TEST_F(ReturnedPqFee, ConflictingKeptInputsStillSelectOnlyTheHigherFeeTransaction) {
  core.state[1].fee = 60; add(1, 100, true, TX_PQ, true);
  core.state[2].fee = 80; add(2, 100, true, TX_PQ, true);
  core.state[1].ready = true; core.state[2].ready = true;
  expectTemplate({2}, 1000, 2000, 100, 80);
  EXPECT_EQ(pool.get_transactions_count(), 2u);
}

TEST_F(ReturnedPqFee, ZeroFeeRegistrationsKeepTheirExistingSizePolicy) {
  core.state[1].ready = true; add(1, 110, false, TX_FREE_REG);
  expectTemplate({}, 100, 1000, 0, 0);
  expectTemplate({1}, 120, 1000, 110, 0);
  EXPECT_EQ(core.state[1].resolutions, 0u);
}

TEST_F(ReturnedPqFee, FailedOrZeroFeeResolutionNeverBuildsAZeroFeeTransfer) {
  core.state[1].resolvable = false; add(1, 100);
  core.state[2].fee = 0; add(2, 100);
  core.state[1].ready = true; core.state[2].ready = true;
  expectTemplate({}, 1000, 2000, 0, 0);
  EXPECT_EQ(pool.get_transactions_count(), 2u);
}
} // namespace
