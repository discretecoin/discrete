// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// End-to-end integration test through the real Core/Blockchain:
//   * drives a synthetic chain across the v6 (PQ) activation using the V5+
//     yespower PoW harness (first real exercise of getBlockLongHash in tests);
//   * confirms a v2 TX_PQ routes through the live consensus dispatch
//     (Core::check_tx_semantic -> Blockchain::checkPqInputs) and is rejected
//     when it spends a non-existent output.
//
// NOTE: the funded happy-path lifecycle (bridge a coinbase -> spend via TX_PQ ->
// double-spend reject -> reorg-reinsert) additionally needs a ring-signed
// TX_BRIDGE builder (overlaps the wallet spend path); the PQ consensus crypto
// for it is already covered by PqValidationTests / PqNullifierDbTests.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/PqValidation.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "System/Context.h"
#include "TestGenerator/TestGenerator.h"

#include "PqTxType.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqWalletState.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqScan.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <list>
#include <string>
#include <vector>

namespace {

bool expect(bool cond, const std::string& msg) {
  if (!cond) { std::cerr << "[FAIL] " << msg << std::endl; }
  return cond;
}

template <std::size_t N> std::array<uint8_t, N> pat(uint8_t a, uint8_t b) {
  std::array<uint8_t, N> r;
  for (std::size_t i = 0; i < N; ++i) r[i] = static_cast<uint8_t>(i * a + b);
  return r;
}
template <std::size_t N> std::vector<uint8_t> toVec(const std::array<uint8_t, N>& a) {
  return std::vector<uint8_t>(a.begin(), a.end());
}

// Mine one main-chain block at the major version expected for its height.
bool mineBlock(CryptoNote::Core& core, const CryptoNote::Currency& currency,
               test_generator& gen, const CryptoNote::AccountBase& miner,
               uint64_t timestamp) {
  uint32_t height = core.getCurrentBlockchainHeight();
  Crypto::Hash tail = core.get_tail_id();
  uint64_t generated = 0;
  if (!core.getAlreadyGeneratedCoins(tail, generated)) return false;
  std::vector<size_t> sizes;
  if (!core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow())) return false;

  // Block version must match what consensus expects at this height.
  gen.defaultMajorVersion = core.getBlockMajorVersionForHeight(height);

  CryptoNote::Block blk;
  std::list<CryptoNote::Transaction> txs;
  if (!gen.constructBlock(blk, height, tail, miner, timestamp, generated, sizes, txs)) return false;

  CryptoNote::Difficulty diff = core.getNextBlockDifficulty();
  if (diff > 1) {
    // Discrete PoW commits to SHA3(ML-DSA signature), so the block must be
    // re-signed after every nonce change. Use the signing fillNonce overload.
    fillNonce(blk, diff, &core.get_blockchain_storage(), miner);
  }
  gen.addBlock(blk, 0, 0, sizes, generated);

  CryptoNote::block_verification_context bvc{};
  core.handle_incoming_block(blk, bvc, false, false);
  return bvc.m_added_to_main_chain && !bvc.m_verification_failed;
}

// Mine a block that includes the given transactions (test_generator accounts
// their fees via get_tx_fee — works for bridge KeyInputs which carry amounts).
bool mineBlockWithTxs(CryptoNote::Core& core, const CryptoNote::Currency& currency,
                      test_generator& gen, const CryptoNote::AccountBase& miner,
                      uint64_t timestamp, const std::list<CryptoNote::Transaction>& txs) {
  uint32_t height = core.getCurrentBlockchainHeight();
  Crypto::Hash tail = core.get_tail_id();
  uint64_t generated = 0;
  if (!core.getAlreadyGeneratedCoins(tail, generated)) return false;
  std::vector<size_t> sizes;
  if (!core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow())) return false;

  gen.defaultMajorVersion = core.getBlockMajorVersionForHeight(height);

  CryptoNote::Block blk;
  if (!gen.constructBlock(blk, height, tail, miner, timestamp, generated, sizes, txs)) return false;

  CryptoNote::Difficulty diff = core.getNextBlockDifficulty();
  if (diff > 1) {
    fillNonce(blk, diff, &core.get_blockchain_storage(), miner);
  }
  gen.addBlock(blk, 0, 0, sizes, generated);

  CryptoNote::block_verification_context bvc{};
  core.handle_incoming_block(blk, bvc, false, false);
  return bvc.m_added_to_main_chain && !bvc.m_verification_failed;
}

// An unfunded, well-formed, ML-DSA-signed TX_PQ that references a non-existent
// output (so it must be rejected at input resolution, not at shape).
CryptoNote::Transaction makeUnfundedPqTx() {
  using namespace CryptoNote;
  CryptoPQ::SeedMaster ms = pat<32>(2, 7);
  auto spend = CryptoPQ::deriveSpendKeys(ms);
  auto recipV = CryptoPQ::deriveViewKeys(pat<32>(3, 9));
  auto recipS = CryptoPQ::deriveSpendKeys(pat<32>(3, 9));

  PqInput in;
  in.prevTxid = Crypto::Hash{};                 // nonexistent outpoint
  for (size_t i = 0; i < 32; ++i) in.prevTxid.data[i] = static_cast<uint8_t>(i + 1);
  in.prevOutIndex = 0;
  in.authPub = toVec(spend.first);
  in.rhoReveal = toVec(pat<32>(3, 9));

  std::vector<CryptoPQ::InputRef> refs(1);
  std::memcpy(refs[0].prevTxid.data(), in.prevTxid.data, 32);
  refs[0].prevOutIndex = in.prevOutIndex;
  CryptoPQ::Hash256 ih = CryptoPQ::inputsHash(refs);

  CryptoPQ::PqBuiltOutput built = CryptoPQ::buildPqOutput(recipV.first, recipS.first, ih, 0, 500000);
  PqOutput po;
  po.kemCt = toVec(built.kemCt);
  po.encPayload = built.encPayload;
  std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);
  TransactionOutput out; out.amount = 500000; out.target = po;

  Transaction tx;
  tx.version = TRANSACTION_VERSION_PQ;
  tx.txType = TX_PQ;
  tx.unlockTime = 0;
  tx.inputs.push_back(in);
  tx.outputs.push_back(out);

  // Sign: fee = 0 (input is unresolved, but digest must still be consistent).
  uint64_t fee = 0;
  CryptoPQ::Hash256 d = pqSigningDigest(tx, fee);
  CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(spend.second, d.data(), d.size());
  tx.pqSignatures.assign(1, toVec(sig));
  return tx;
}

bool run() {
  Logging::ConsoleLogger logger(Logging::ERROR);
  // Jump v1 -> v6 cleanly: all upgrade heights equal, so heights <= 5 are v1 and
  // heights >= 6 are v6 (the PQ activation version).
  // The v5+ PoW (getBlockLongHash) samples prior blocks up to
  // (height - 1 - minedMoneyUnlockWindow). With the default window (10) that is
  // only valid once height >= 12, so the first v5/v6 block must sit at height
  // >= 12 (we cannot shrink the unlock window — genesis bakes in window=10).
  const CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)  // skips the mainnet-only V5 difficulty reset that spikes diff at low heights
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(11).upgradeHeightV6(12)
      .currency();

  std::filesystem::path dataDir("pq_chain_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  CryptoNote::Core core(currency, nullptr, logger, dispatcher, 0, false);
  CryptoNote::CoreConfig coreConfig;
  coreConfig.configFolder = dataDir.string();
  CryptoNote::MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());  // enables v5+ yespower PoW

  CryptoNote::AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  CryptoNote::Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "load genesis")) { core.deinit(); return false; }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  // Mine to height 13 (v6 active at 13). v5 lands at height 12, v6 at 13 — both
  // >= 12, so getBlockLongHash's prior-block sampling is valid. Wide block
  // spacing keeps difficulty at the floor (single hash per block, no search).
  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  const uint64_t step = currency.difficultyTarget() * 10;
  for (int i = 0; i < 13; ++i) {
    if (!expect(mineBlock(core, currency, gen, miner, ts), "mine block " + std::to_string(i + 1))) {
      core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
    }
    ts += step;
  }

  bool ok = true;
  uint32_t top = core.getCurrentBlockchainHeight() - 1;
  ok &= expect(core.getCurrentBlockchainHeight() == 14, "chain height == 14 (genesis + 13)");
  ok &= expect(core.getBlockMajorVersionForHeight(top) == CryptoNote::BLOCK_MAJOR_VERSION_6,
               "top block is v6 (PQ era active)");

  // v2 PQ dispatch through the live Core: an unfunded TX_PQ must be rejected.
  CryptoNote::Transaction pqTx = makeUnfundedPqTx();
  Crypto::Hash txHash = CryptoNote::getObjectHash(pqTx);
  CryptoNote::BinaryArray blob = CryptoNote::toBinaryArray(pqTx);
  CryptoNote::tx_verification_context tvc{};
  core.handleIncomingTransaction(pqTx, txHash, blob.size(), tvc, false,
                                 core.getCurrentBlockchainHeight());
  ok &= expect(!tvc.m_added_to_pool, "unfunded PQ tx not added to pool");
  ok &= expect(tvc.m_verification_failed, "unfunded PQ tx verification failed (dispatch fired)");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

CryptoNote::PqWalletKeys pqKeysFromPattern(uint8_t a, uint8_t b) {
  Crypto::SecretKey s;
  for (std::size_t i = 0; i < sizeof(s.data); ++i) s.data[i] = static_cast<uint8_t>(i * a + b);
  return CryptoNote::derivePqWalletKeys(s);
}

// Funded happy-path lifecycle through the LIVE Core:
//   mine PQ coinbase -> mature -> scan with miner PQ keys -> spend via TX_PQ
//   (accepted by consensus); a second spend of the same output (same nullifier)
//   is rejected. Discrete has no legacy chain or bridge, so the coinbase PqOutput
//   is the sole funds source (spendable once matured).
bool runFunded() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);
  // getBlockLongHash sampling needs height - 1 - unlockWindow(10) >= 1, so v5/v6
  // sit at height >= 12. Default unlock window (10) is kept, so the block-1
  // coinbase matures at height 11.
  const Currency currency = CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(11).upgradeHeightV6(12)
      .currency();

  std::filesystem::path dataDir("pq_funded_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher, 0, false);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "funded: core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());
  AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "funded: load genesis")) { core.deinit(); return false; }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  const uint64_t step = currency.difficultyTarget() * 10;  // hold difficulty at floor
  // Mine to height 13 (v6 active). The block-1 coinbase matured at height 11, so
  // by the tip (height 14) it is spendable.
  for (int i = 0; i < 13; ++i) {
    if (!expect(mineBlock(core, currency, gen, miner, ts), "funded: mine " + std::to_string(i + 1))) {
      core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
    }
    ts += step;
  }

  bool ok = true;

  // Pull block-1's coinbase: a single PqOutput addressed to the miner's PQ keys.
  Block blk1;
  ok &= expect(core.getBlockByHash(core.getBlockIdByHeight(1), blk1), "funded: load block 1");
  const Transaction& cb = blk1.baseTransaction;
  Crypto::Hash cbHash = getObjectHash(cb);
  ok &= expect(cb.outputs.size() == 1, "funded: coinbase has one PQ output");
  ok &= expect(cb.outputs[0].target.type() == typeid(PqOutput), "funded: coinbase output is PqOutput");
  if (!ok) { core.deinit(); std::filesystem::remove_all(dataDir, ec); return false; }

  uint64_t inAmount = cb.outputs[0].amount;
  const PqOutput& cbOut = boost::get<PqOutput>(cb.outputs[0].target);

  // Scan the coinbase with the miner's PQ scan keys (viewSk decapsulates, spendPub
  // recomputes the ownership commitment). inputsHash is zeros for a coinbase.
  CryptoPQ::PqScanKeys scan{miner.pqViewSk(), miner.pqSpendPk()};
  CryptoPQ::Hash256 cbIh = pqTransactionInputsHash(cb);
  CryptoPQ::PqScanOutput so;
  so.outputIndex = 0;
  so.amount = inAmount;
  std::memcpy(so.kemCt.data(), cbOut.kemCt.data(), so.kemCt.size());
  so.encPayload = cbOut.encPayload;
  std::memcpy(so.spendCommit.data(), cbOut.spendCommit.data, 32);
  auto owned = CryptoPQ::scanPqOutput(scan, cbIh, so);
  ok &= expect(static_cast<bool>(owned), "funded: miner scans its own coinbase PQ output");
  ok &= expect(owned && owned->amount == inAmount, "funded: scanned amount matches coinbase reward");
  if (!ok) { core.deinit(); std::filesystem::remove_all(dataDir, ec); return false; }

  // Build the spendable input descriptor from the scanned record.
  std::vector<PqSpendInput> spendIns(1);
  spendIns[0].prevTxid = cbHash;
  spendIns[0].prevOutIndex = 0;
  spendIns[0].amount = inAmount;
  spendIns[0].rho = owned->rho;

  // Spend the matured coinbase PQ output via TX_PQ through the live consensus
  // dispatch. The spender is the miner (its long-term ML-DSA spend keypair).
  PqWalletKeys recip2 = pqKeysFromPattern(9, 2);
  uint64_t pqFee = 1000000;
  Transaction spend = buildPqTransaction(
      spendIns, {PqSendOutput{recip2.viewPub, recip2.spendPub, inAmount - pqFee}},
      miner.pqSpendPk(), miner.pqSpendSk());

  Crypto::Hash spendHash = getObjectHash(spend);
  BinaryArray spendBlob = toBinaryArray(spend);
  tx_verification_context tvc{};
  core.handleIncomingTransaction(spend, spendHash, spendBlob.size(), tvc, false,
                                 core.getCurrentBlockchainHeight());
  ok &= expect(tvc.m_added_to_pool && !tvc.m_verification_failed,
               "funded: TX_PQ spending the matured coinbase accepted by consensus");
  ok &= expect(tvc.m_should_be_relayed, "funded: TX_PQ marked for relay");

  bool foundSpendInPool = false;
  uint64_t storedPqFee = 0;
  for (const auto& txd : core.getMemoryPool()) {
    if (std::memcmp(txd.id.data, spendHash.data, sizeof(spendHash.data)) == 0) {
      foundSpendInPool = true;
      storedPqFee = txd.fee;
      break;
    }
  }
  ok &= expect(foundSpendInPool && storedPqFee == pqFee,
               "funded: TX_PQ stored in mempool with actual fee");

  // Double-spend: a second TX_PQ over the same output (same nullifier) rejected.
  PqWalletKeys recip3 = pqKeysFromPattern(4, 4);
  Transaction spend2 = buildPqTransaction(
      spendIns, {PqSendOutput{recip3.viewPub, recip3.spendPub, inAmount - pqFee}},
      miner.pqSpendPk(), miner.pqSpendSk());
  Crypto::Hash spend2Hash = getObjectHash(spend2);
  BinaryArray spend2Blob = toBinaryArray(spend2);
  tx_verification_context tvc2{};
  core.handleIncomingTransaction(spend2, spend2Hash, spend2Blob.size(), tvc2, false,
                                 core.getCurrentBlockchainHeight());
  ok &= expect(!tvc2.m_added_to_pool, "funded: double-spend of PQ output rejected");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

// Regression guard for the daemon crash on incoming PQ transactions: ML-DSA-65
// verification (checkPqTransactionInputs -> CryptoPQ::dsa_verify) runs on a
// System::Dispatcher coroutine, whose Boost default stack is only 64 KB. A
// single ML-DSA-65 sign/verify frame needs far more than that, so on the
// default stack this overflowed and crashed the node with an access violation
// on ANY incoming PQ tx (a remote DoS). Run the heaviest PQ crypto on a
// coroutine here; on an undersized stack this aborts the process, so reaching
// the assertions at all proves the dispatcher stack is large enough.
bool runCoroutineStack() {
  using namespace CryptoNote;
  System::Dispatcher dispatcher;

  bool finished = false;
  bool verified = false;
  System::Context<> ctx(dispatcher, [&]() {
    CryptoPQ::DsaKeypairSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i * 7 + 1);
    auto kp = CryptoPQ::dsa_keygen_from_seed(seed);

    const std::array<uint8_t, 32> msg{};
    CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(kp.second, msg.data(), msg.size());
    verified = CryptoPQ::dsa_verify(kp.first, msg.data(), msg.size(), sig);
    finished = true;
  });
  dispatcher.yield();

  bool ok = true;
  ok &= expect(finished, "PQ crypto ran to completion on a dispatcher coroutine");
  ok &= expect(verified, "ML-DSA-65 sign+verify succeeded on a coroutine stack");
  return ok;
}

}  // namespace

int main() {
  if (!runCoroutineStack()) {
    std::cerr << "[FAIL] PQ dispatcher-coroutine stack test" << std::endl;
    return 1;
  }
  if (!run()) {
    std::cerr << "[FAIL] PQ chain integration test" << std::endl;
    return 1;
  }
  if (!runFunded()) {
    std::cerr << "[FAIL] PQ funded lifecycle test" << std::endl;
    return 1;
  }
  std::cout << "[PASS] PQ chain integration test" << std::endl;
  return 0;
}
