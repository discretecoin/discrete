// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// End-to-end integration test through the real Core/Blockchain:
//   * drives a synthetic chain across the v6 (PQ) activation using the V5+
//     yespower PoW harness (first real exercise of getBlockLongHash in tests);
//   * confirms a v2 TX_PQ routes through the live consensus dispatch
//     (Core::check_tx_semantic -> Blockchain::checkPqInputs) and is rejected
//     when it spends a non-existent output.
//
// NOTE: the funded happy-path lifecycle (mine a coinbase -> spend via TX_PQ ->
// double-spend reject -> reorg-reinsert) is exercised by runFunded() below; the
// PQ consensus crypto is also covered by PqValidationTests / PqNullifierDbTests.

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
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/WalletLedger.h"
#include "crypto_pq/PqOutputBuilder.h"
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

bool signBlockForTest(CryptoNote::Block& blk, const CryptoNote::AccountBase& miner) {
  std::array<uint8_t, 64> H{};
  if (!CryptoNote::get_block_pow_header_hash(blk, H)) {
    return false;
  }
  std::array<uint8_t, 64> m = CryptoNote::discrete_power_sign_message(H);
  CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(miner.pqSpendSk(), m.data(), m.size());
  blk.signature.assign(sig.begin(), sig.end());
  return true;
}

bool refreshBlockProofForTest(CryptoNote::Core& core, CryptoNote::Block& blk,
                              const CryptoNote::AccountBase& miner) {
  CryptoNote::Difficulty diff = core.getNextBlockDifficulty();
  if (diff > 1) {
    fillNonce(blk, diff, &core.get_blockchain_storage(), miner);
    return true;
  }
  return signBlockForTest(blk, miner);
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
    // DiscretePower binds PoW to the ML-DSA signature, so the block must be
    // re-signed after every nonce change. Use the signing fillNonce overload.
    fillNonce(blk, diff, &core.get_blockchain_storage(), miner);
  }
  gen.addBlock(blk, 0, 0, sizes, generated);

  CryptoNote::block_verification_context bvc{};
  core.handle_incoming_block(blk, bvc, false, false);
  return bvc.m_added_to_main_chain && !bvc.m_verification_failed;
}

// Mine a block that includes the given transactions (test_generator accounts
// their fees via get_tx_fee).
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

// Build a TX_FREE_REG with trivial PoW (any nonce passes a UINT64_MAX target).
// Different `seed` values produce different viewPub/spendPub so registrations
// are distinct and do not trigger the first-reg-wins duplicate check. Holding the
// seed and varying `nonce` gives the opposite: two distinct transactions that
// claim the same account, i.e. competitors for the same registration.
CryptoNote::Transaction makeFastFreeRegTx(const Crypto::Hash& refBlockHash, uint8_t seed,
                                          uint64_t nonce = 0) {
  using namespace CryptoNote;
  Transaction tx;
  tx.version = TRANSACTION_VERSION_1;
  tx.txType = TX_FREE_REG;
  tx.unlockHeight = 0;

  std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> vp;
  for (size_t i = 0; i < vp.size(); ++i) vp[i] = static_cast<uint8_t>(i * seed + 1);
  std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> sp;
  for (size_t i = 0; i < sp.size(); ++i) sp[i] = static_cast<uint8_t>(i * seed + 2);

  addPqAccountRegistrationToExtra(tx.extra, vp, sp);
  TransactionExtraPow pow{};
  pow.refBlockHash = refBlockHash;
  pow.nonce = nonce;  // trivially passes with UINT64_MAX powTarget in the test currency
  appendPowTagToExtra(tx.extra, pow);
  return tx;
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
  tx.version = TRANSACTION_VERSION_1;
  tx.txType = TX_PQ;
  tx.unlockHeight = 0;
  tx.inputs.push_back(in);
  tx.outputs.push_back(out);

  // Sign: fee = 0 (input is unresolved, but digest must still be consistent).
  uint64_t fee = 0;
  CryptoPQ::Hash256 d = pqSigningDigest(tx, fee);
  CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(spend.second, d.data(), d.size());
  tx.pqSignatures.assign(1, sig);
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
  CryptoNote::Core core(currency, nullptr, logger, dispatcher);
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
//   is rejected. Discrete has no legacy chain, so the coinbase CoinbaseOutput is
//   the sole funds source (spendable once matured).
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
  Core core(currency, nullptr, logger, dispatcher);
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

  // Pull block-1's coinbase: a single CoinbaseOutput addressed to the miner's PQ keys.
  Block blk1;
  ok &= expect(core.getBlockByHash(core.getBlockIdByHeight(1), blk1), "funded: load block 1");
  const Transaction& cb = blk1.baseTransaction;
  Crypto::Hash cbHash = getObjectHash(cb);
  ok &= expect(cb.outputs.size() == 1, "funded: coinbase has one CoinbaseOutput");
  ok &= expect(cb.outputs[0].target.type() == typeid(CoinbaseOutput),
               "funded: coinbase output is CoinbaseOutput");
  if (!ok) { core.deinit(); std::filesystem::remove_all(dataDir, ec); return false; }

  uint64_t inAmount = cb.outputs[0].amount;
  const CoinbaseOutput& cbOut = boost::get<CoinbaseOutput>(cb.outputs[0].target);

  // Scan the CoinbaseOutput via coinbaseRho (no KEM): recompute the commitment
  // and compare. The miner's spendPub + the block height determine ownership.
  CryptoPQ::DsaPublicKey minerSpendPub1 = miner.pqSpendPk();
  CryptoPQ::Rho cbRho = CryptoPQ::coinbaseRho(minerSpendPub1, /*height=*/1, /*outputIndex=*/0);
  CryptoPQ::Hash256 expectedSc = CryptoPQ::spendCommit(minerSpendPub1, cbRho);
  bool coinbaseOwned = (std::memcmp(expectedSc.data(), cbOut.spendCommit.data, 32) == 0);
  ok &= expect(coinbaseOwned, "funded: miner scans its own coinbase CoinbaseOutput");
  ok &= expect(inAmount > 0, "funded: coinbase reward non-zero");
  if (!ok) { core.deinit(); std::filesystem::remove_all(dataDir, ec); return false; }

  // Build the spendable input descriptor.
  std::vector<PqSpendInput> spendIns(1);
  spendIns[0].prevTxid = cbHash;
  spendIns[0].prevOutIndex = 0;
  spendIns[0].amount = inAmount;
  spendIns[0].rho = cbRho;

  // Spend the matured coinbase PQ output via TX_PQ through the live consensus
  // dispatch. The spender is the miner (its long-term ML-DSA spend keypair).
  PqWalletKeys recip2 = pqKeysFromPattern(9, 2);
  // Fee must sit above the per-4000-bytes floor (~2 atoms for a ~6.5 KB 1-in/1-out
  // TX_PQ) yet well below the coinbase reward.
  uint64_t pqFee = 50;
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

  // Tamper 1 — wrong tx: spend block-1's coinbase but point the input at a
  // DIFFERENT existing output (block-2's coinbase), revealing block-1's (spendPub,
  // rho). The referenced output's spend_commit won't match the revealed values
  // (block-2's coinbase rho differs), so consensus rejects. This proves the
  // outpoint cannot be swapped to a wrong output to forge/relocate a spend.
  {
    Block blk2;
    ok &= expect(core.getBlockByHash(core.getBlockIdByHeight(2), blk2), "tamper: load block 2");
    Crypto::Hash cb2Hash = getObjectHash(blk2.baseTransaction);
    std::vector<PqSpendInput> tamperIns(1);
    tamperIns[0].prevTxid = cb2Hash;     // wrong outpoint (different real output)
    tamperIns[0].prevOutIndex = 0;
    tamperIns[0].amount = inAmount;
    tamperIns[0].rho = cbRho;             // but reveal block-1's rho
    PqWalletKeys recip4 = pqKeysFromPattern(6, 6);
    Transaction tamper = buildPqTransaction(
        tamperIns, {PqSendOutput{recip4.viewPub, recip4.spendPub, inAmount - pqFee}},
        miner.pqSpendPk(), miner.pqSpendSk());  // validly signed over the tampered outpoint
    Crypto::Hash tHash = getObjectHash(tamper);
    BinaryArray tBlob = toBinaryArray(tamper);
    tx_verification_context tvc3{};
    core.handleIncomingTransaction(tamper, tHash, tBlob.size(), tvc3, false,
                                   core.getCurrentBlockchainHeight());
    ok &= expect(!tvc3.m_added_to_pool && tvc3.m_verification_failed,
                 "tamper: input pointing at a wrong tx rejected (spend_commit mismatch)");
  }

  // Tamper 2 — wrong index: point at block-1's coinbase with an out-of-range
  // output index. The output does not exist, so the spend is rejected.
  {
    std::vector<PqSpendInput> tamperIns(1);
    tamperIns[0].prevTxid = cbHash;      // real coinbase tx
    tamperIns[0].prevOutIndex = 1;       // but it has only output 0
    tamperIns[0].amount = inAmount;
    tamperIns[0].rho = cbRho;
    PqWalletKeys recip5 = pqKeysFromPattern(7, 7);
    Transaction tamper = buildPqTransaction(
        tamperIns, {PqSendOutput{recip5.viewPub, recip5.spendPub, inAmount - pqFee}},
        miner.pqSpendPk(), miner.pqSpendSk());
    Crypto::Hash tHash = getObjectHash(tamper);
    BinaryArray tBlob = toBinaryArray(tamper);
    tx_verification_context tvc4{};
    core.handleIncomingTransaction(tamper, tHash, tBlob.size(), tvc4, false,
                                   core.getCurrentBlockchainHeight());
    ok &= expect(!tvc4.m_added_to_pool && tvc4.m_verification_failed,
                 "tamper: input pointing at a wrong output index rejected (no such output)");
  }

  // Block level: mine the (mempool-accepted) TX_PQ into a real block. The test
  // registers the fee since a TX_PQ carries no inline input amounts; the coinbase
  // reward (base + fee) must match what consensus recomputes, or the block is
  // rejected — so a successful add also proves the PQ fee accounting is correct.
  uint32_t heightBefore = core.getCurrentBlockchainHeight();
  gen.setTxFee(spendHash, pqFee);
  ok &= expect(mineBlockWithTxs(core, currency, gen, miner, ts, {spend}),
               "funded: TX_PQ mined into a block (accepted by block validation)");
  ts += step;
  ok &= expect(core.getCurrentBlockchainHeight() == heightBefore + 1,
               "funded: chain advanced by the block carrying the TX_PQ");

  // Block-level double-spend: a block carrying a second spend of the same coinbase
  // output (same nullifier, now recorded on-chain) must be rejected by block
  // validation — not just at the mempool.
  PqWalletKeys recip6 = pqKeysFromPattern(8, 8);
  Transaction spend3 = buildPqTransaction(
      spendIns, {PqSendOutput{recip6.viewPub, recip6.spendPub, inAmount - pqFee}},
      miner.pqSpendPk(), miner.pqSpendSk());
  gen.setTxFee(getObjectHash(spend3), pqFee);
  bool blockRejected = !mineBlockWithTxs(core, currency, gen, miner, ts, {spend3});
  ok &= expect(blockRejected,
               "funded: block double-spending the now-spent coinbase rejected at block level");

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
  bool ok = true;
  bool finished = false;
  bool verified = false;

  System::Dispatcher dispatcher;
  {
    // Run a full ML-DSA-65 keygen + sign + verify ON the dispatcher coroutine.
    // This is the heaviest single PQ-crypto frame the daemon executes off the
    // main thread; on Boost's 64 KB default coroutine stack it overflowed and
    // crashed the node, so reaching the assertions proves the stack is sized.
    System::Context<> ctx(dispatcher, [&finished, &verified]() {
      auto kp = CryptoPQ::dsa_keygen();
      std::array<uint8_t, 32> msg = pat<32>(7, 1);
      CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(kp.second, msg.data(), msg.size());
      verified = CryptoPQ::dsa_verify(kp.first, msg.data(), msg.size(), sig);
      finished = true;
    });
    dispatcher.yield();
  }
  ok &= expect(finished, "coroutine ML-DSA: ran to completion on the dispatcher stack");
  ok &= expect(verified, "coroutine ML-DSA: signature verified");
  return ok;
}

// Free-reg per-block cap: verifies that a block is rejected when it carries more
// than freeRegPerBlock(2) TX_FREE_REG transactions.
bool runFreeRegCap() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);

  // Two key overrides: cap = 2 (vs production 100) and trivial PoW target so
  // nonce=0 always passes — no cn_slow_hash grinding needed.
  const Currency currency = CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(11).upgradeHeightV6(12)
      .freeRegPerBlock(2)
      .freeRegPowTarget(UINT64_MAX)
      .currency();

  std::filesystem::path dataDir("pq_freereg_cap_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "cap: core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());
  AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "cap: load genesis")) {
    core.deinit(); return false;
  }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  const uint64_t step = currency.difficultyTarget() * 10;
  for (int i = 0; i < 13; ++i) {
    if (!expect(mineBlock(core, currency, gen, miner, ts), "cap: mine " + std::to_string(i + 1))) {
      core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
    }
    ts += step;
  }

  bool ok = true;
  ok &= expect(core.getBlockMajorVersionForHeight(core.getCurrentBlockchainHeight() - 1) ==
               BLOCK_MAJOR_VERSION_6, "cap: v6 active");

  // Use the current tip as refBlockHash: on the main chain, within FREE_REG_REF_WINDOW.
  Crypto::Hash refHash = core.get_tail_id();

  // Build 3 distinct free-reg txs. Each gets a different seed → distinct identity
  // so first-reg-wins doesn't eliminate any of them.
  Transaction tx1 = makeFastFreeRegTx(refHash, 11);
  Transaction tx2 = makeFastFreeRegTx(refHash, 22);
  Transaction tx3 = makeFastFreeRegTx(refHash, 33);

  // Submit all 3 to the pool. The pool's static cap is FREE_REG_PER_BLOCK=100
  // (not the currency override), so all 3 should be accepted.
  auto submitFreeReg = [&](const Transaction& tx, const std::string& lbl) -> bool {
    Crypto::Hash txHash = getObjectHash(tx);
    BinaryArray blob = toBinaryArray(tx);
    tx_verification_context tvc{};
    core.handleIncomingTransaction(tx, txHash, blob.size(), tvc, false,
                                   core.getCurrentBlockchainHeight());
    return expect(tvc.m_added_to_pool && !tvc.m_verification_failed,
                  "cap: " + lbl + " pool-accepted");
  };
  ok &= submitFreeReg(tx1, "tx1");
  ok &= submitFreeReg(tx2, "tx2");
  ok &= submitFreeReg(tx3, "tx3");
  if (!ok) { core.deinit(); std::filesystem::remove_all(dataDir, ec); return false; }

  // A block carrying all 3 must be rejected: freeRegCount=3 > freeRegPerBlock()=2.
  std::list<Transaction> all3 = {tx1, tx2, tx3};
  bool rejectedAll3 = !mineBlockWithTxs(core, currency, gen, miner, ts, all3);
  ok &= expect(rejectedAll3, "cap: block with 3 free-reg txs rejected");
  ts += step;  // advance timestamp even for the failed block

  // A block carrying 2 is accepted.
  std::list<Transaction> first2 = {tx1, tx2};
  ok &= expect(mineBlockWithTxs(core, currency, gen, miner, ts, first2),
               "cap: block with 2 free-reg txs accepted");
  ts += step;

  // A subsequent block carrying the remaining 1 is also accepted.
  std::list<Transaction> third = {tx3};
  ok &= expect(mineBlockWithTxs(core, currency, gen, miner, ts, third),
               "cap: block with 3rd free-reg tx accepted alone");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

// First-registration-wins vs. the block template: a registration sitting in the
// pool must not be handed to a miner once another block has claimed the same
// account. Such a block is rejected at push time, so the whole proof-of-work is
// wasted. The pool's validated-tx cache makes this a real hazard — the stale tx
// is never re-validated on the cached path — so the template consults the chain
// registry directly.
bool runStaleRegTemplate() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);

  const Currency currency = CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(11).upgradeHeightV6(12)
      .freeRegPowTarget(UINT64_MAX)
      .currency();

  std::filesystem::path dataDir("pq_stale_reg_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "stale-reg: core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());
  AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "stale-reg: load genesis")) {
    core.deinit(); return false;
  }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  const uint64_t step = currency.difficultyTarget() * 10;
  for (int i = 0; i < 13; ++i) {
    if (!expect(mineBlock(core, currency, gen, miner, ts), "stale-reg: mine " + std::to_string(i + 1))) {
      core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
    }
    ts += step;
  }

  bool ok = true;
  const Crypto::Hash refHash = core.get_tail_id();

  // Two competing registrations of the SAME account (same seed, different PoW
  // nonce → different tx hashes).
  Transaction pooled  = makeFastFreeRegTx(refHash, 44, 1);
  Transaction winner  = makeFastFreeRegTx(refHash, 44, 2);

  auto submit = [&](const Transaction& tx, bool keptByBlock) {
    Crypto::Hash txHash = getObjectHash(tx);
    BinaryArray blob = toBinaryArray(tx);
    tx_verification_context tvc{};
    core.handleIncomingTransaction(tx, txHash, blob.size(), tvc, keptByBlock,
                                   core.getCurrentBlockchainHeight());
    return tvc;
  };

  tx_verification_context pooledTvc = submit(pooled, false);
  ok &= expect(pooledTvc.m_added_to_pool && !pooledTvc.m_verification_failed,
               "stale-reg: registration accepted into the pool");

  // Build a template while it is still valid — this is what seeds the pool's
  // validated-tx cache with the (soon to be stale) registration.
  auto buildTemplate = [&](Block& b) {
    Difficulty diff = 0;
    uint32_t height = 0;
    return core.get_block_template_pq(b, miner.pqViewPk(), miner.pqSpendPk(), diff, height,
                                      BinaryArray());
  };
  Block beforeTemplate;
  ok &= expect(buildTemplate(beforeTemplate), "stale-reg: template built");
  ok &= expect(beforeTemplate.transactionHashes.size() == 1 &&
               beforeTemplate.transactionHashes[0] == getObjectHash(pooled),
               "stale-reg: valid registration is included in the template");

  // The competitor wins the race. keptByBlock admits it alongside the pending
  // duplicate, exactly as the reorg re-insert path (saveTransactions) does.
  tx_verification_context winnerTvc = submit(winner, true);
  ok &= expect(winnerTvc.m_added_to_pool, "stale-reg: competitor admitted (kept by block)");
  std::list<Transaction> winnerOnly = {winner};
  ok &= expect(mineBlockWithTxs(core, currency, gen, miner, ts, winnerOnly),
               "stale-reg: block carrying the competitor accepted");
  ts += step;

  TransactionExtraPqAccountRegistration reg{};
  ok &= expect(getPqAccountRegistrationFromExtra(winner.extra, reg), "stale-reg: read registration");
  uint32_t regHeight = 0, regTxIndex = 0;
  ok &= expect(core.getPqAccountNumber(getPqAccountIdentityHash(reg), regHeight, regTxIndex),
               "stale-reg: account is registered on chain");

  // The pooled registration is now unminable. It must not reach the miner.
  Block afterTemplate;
  ok &= expect(buildTemplate(afterTemplate), "stale-reg: template rebuilt");
  ok &= expect(afterTemplate.transactionHashes.empty(),
               "stale-reg: already-registered registration excluded from the block template");

  // ... and it is dropped from the pool rather than relayed until it expires.
  core.on_idle();
  ok &= expect(core.getPoolTransactionsCount() == 0,
               "stale-reg: already-registered registration purged from the pool");

  // A fresh submission for the same account never gets in at all.
  Transaction latecomer = makeFastFreeRegTx(core.get_tail_id(), 44, 3);
  tx_verification_context lateTvc = submit(latecomer, false);
  ok &= expect(!lateTvc.m_added_to_pool && lateTvc.m_verification_failed,
               "stale-reg: registration for a registered account rejected at pool admission");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

// Mining policy must not create a template whose timestamp predates its direct
// parent. This is deliberately not a consensus rule: received blocks continue
// to use the existing future-time and median-time-past validation.
bool runTimestampTemplateHardening() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);

  const Currency currency = CurrencyBuilder(logger)
      .testnet(true)
      .currency();

  std::filesystem::path dataDir("pq_timestamp_template_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "timestamp-template: core.init")) {
    return false;
  }

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());
  AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "timestamp-template: load genesis")) {
    core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
  }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  const uint64_t parentTimestamp = static_cast<uint64_t>(std::time(nullptr)) + 120;
  if (!expect(mineBlock(core, currency, gen, miner, parentTimestamp),
              "timestamp-template: mine future-dated parent")) {
    core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
  }

  Block blockTemplate;
  Difficulty difficulty = 0;
  uint32_t height = 0;
  bool ok = expect(core.get_block_template_pq(blockTemplate, miner.pqViewPk(), miner.pqSpendPk(),
                                               difficulty, height, BinaryArray()),
                   "timestamp-template: build child template");
  ok &= expect(blockTemplate.previousBlockHash == core.get_tail_id(),
               "timestamp-template: template extends the current parent");
  ok &= expect(blockTemplate.timestamp >= parentTimestamp,
               "timestamp-template: child timestamp does not predate parent");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

// registered_account_numbers_count (RPC getinfo field) is served by
// Core::getCanonicalAccountRegistrationsCount(), which is a thin pass-through to
// Blockchain::getCanonicalAccountRegistrationsCount() -> pq_acct_reg's mdb_stat
// count. This drives that exact call path through a live Core: the count must
// reflect a freshly mined registration immediately, and must drop immediately
// (no cache lag) when the block carrying it is rolled back — the same
// popTransaction() path a real reorg takes.
bool runAccountRegCountRollback() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);

  const Currency currency = CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(11).upgradeHeightV6(12)
      .freeRegPowTarget(UINT64_MAX)
      .currency();

  std::filesystem::path dataDir("pq_acctreg_count_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "acctreg-count: core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());
  AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "acctreg-count: load genesis")) {
    core.deinit(); return false;
  }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  const uint64_t step = currency.difficultyTarget() * 10;
  for (int i = 0; i < 13; ++i) {
    if (!expect(mineBlock(core, currency, gen, miner, ts), "acctreg-count: mine " + std::to_string(i + 1))) {
      core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
    }
    ts += step;
  }

  bool ok = true;
  uint64_t count = 999;
  ok &= expect(core.getCanonicalAccountRegistrationsCount(count),
               "acctreg-count: initial count query (getinfo path)");
  ok &= expect(count == 0, "acctreg-count: no registrations before any tx");

  const uint32_t heightBeforeReg = core.getCurrentBlockchainHeight();
  const Crypto::Hash refHash = core.get_tail_id();

  Transaction reg = makeFastFreeRegTx(refHash, 77);
  Crypto::Hash txHash = getObjectHash(reg);
  BinaryArray blob = toBinaryArray(reg);
  tx_verification_context tvc{};
  core.handleIncomingTransaction(reg, txHash, blob.size(), tvc, false,
                                 core.getCurrentBlockchainHeight());
  ok &= expect(tvc.m_added_to_pool && !tvc.m_verification_failed,
               "acctreg-count: registration accepted into pool");

  std::list<Transaction> regTxs = {reg};
  ok &= expect(mineBlockWithTxs(core, currency, gen, miner, ts, regTxs),
               "acctreg-count: block carrying registration accepted");
  ts += step;

  ok &= expect(core.getCanonicalAccountRegistrationsCount(count),
               "acctreg-count: count query after registration (getinfo path)");
  ok &= expect(count == 1,
               "acctreg-count: registered_account_numbers_count reflects the new registration");

  // Reorg rollback: pop the block carrying the registration via the same
  // popTransaction() path a real reorg takes. The count must drop immediately.
  core.get_blockchain_storage().rollbackBlockchainTo(heightBeforeReg - 1);
  ok &= expect(core.getCurrentBlockchainHeight() == heightBeforeReg,
               "acctreg-count: chain rolled back to height before the registration block");

  ok &= expect(core.getCanonicalAccountRegistrationsCount(count),
               "acctreg-count: count query after rollback (getinfo path)");
  ok &= expect(count == 0,
               "acctreg-count: count decreases immediately after reorg rollback");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

// Emission curve sanity check + coinbase maturity boundary.
// Uses minedMoneyUnlockWindow=3 so the first PQ coinbase (block 6) matures at
// height 9, while v6 activates at height 6. This lets us confirm a spend is
// rejected at height 8 and accepted at height 9.
bool runEmission() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);

  // minedMoneyUnlockWindow=3: getBlockLongHash look-back = 3, so v5 is safe at
  // height 5 (samples block at index 5-1-3=1 which exists).
  const Currency currency = CurrencyBuilder(logger)
      .testnet(true)
      .minedMoneyUnlockWindow(3)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(5).upgradeHeightV6(6)
      .currency();

  std::filesystem::path dataDir("pq_emission_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "emission: core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());
  AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "emission: load genesis")) {
    core.deinit(); return false;
  }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  bool ok = true;
  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  const uint64_t step = currency.difficultyTarget() * 10;

  // Mine 7 blocks (heights 1-5 legacy, heights 6-7 v6) and verify the reward for
  // each matches currency.calculateReward(alreadyGeneratedBefore).
  for (int i = 0; i < 7; ++i) {
    uint64_t genBefore = 0;
    core.getAlreadyGeneratedCoins(core.get_tail_id(), genBefore);

    if (!expect(mineBlock(core, currency, gen, miner, ts),
                "emission: mine block " + std::to_string(i + 1))) {
      core.deinit(); std::filesystem::remove_all(dataDir, ec); return false;
    }
    ts += step;

    uint64_t genAfter = 0;
    core.getAlreadyGeneratedCoins(core.get_tail_id(), genAfter);
    uint64_t actualReward = genAfter - genBefore;
    uint64_t expectedReward = currency.calculateReward(genBefore);
    ok &= expect(actualReward == expectedReward,
                 "emission: block " + std::to_string(i + 1) +
                 " reward " + std::to_string(actualReward) +
                 " == expected " + std::to_string(expectedReward));
  }
  // After 7 blocks: getCurrentBlockchainHeight() == 8.

  // Scan block-6's PQ coinbase (height 6, unlockHeight = 6+3 = 9).
  Block blk6;
  ok &= expect(core.getBlockByHash(core.getBlockIdByHeight(6), blk6), "emission: load block 6");
  const Transaction& cb6 = blk6.baseTransaction;
  Crypto::Hash cb6Hash = getObjectHash(cb6);
  ok &= expect(!cb6.outputs.empty() && cb6.outputs[0].target.type() == typeid(CoinbaseOutput),
               "emission: block-6 coinbase has CoinbaseOutput");
  if (!ok) { core.deinit(); std::filesystem::remove_all(dataDir, ec); return false; }

  uint64_t inAmount = cb6.outputs[0].amount;
  const CoinbaseOutput& cbOut6 = boost::get<CoinbaseOutput>(cb6.outputs[0].target);

  CryptoPQ::DsaPublicKey minerSpendPub6 = miner.pqSpendPk();
  CryptoPQ::Rho cbRho6 = CryptoPQ::coinbaseRho(minerSpendPub6, /*height=*/6, /*outputIndex=*/0);
  CryptoPQ::Hash256 expectedSc6 = CryptoPQ::spendCommit(minerSpendPub6, cbRho6);
  bool coinbaseOwned6 = (std::memcmp(expectedSc6.data(), cbOut6.spendCommit.data, 32) == 0);
  ok &= expect(coinbaseOwned6, "emission: miner scans block-6 coinbase");
  if (!ok) { core.deinit(); std::filesystem::remove_all(dataDir, ec); return false; }

  std::vector<PqSpendInput> spendIns(1);
  spendIns[0].prevTxid = cb6Hash;
  spendIns[0].prevOutIndex = 0;
  spendIns[0].amount = inAmount;
  spendIns[0].rho = cbRho6;

  PqWalletKeys recip = pqKeysFromPattern(7, 3);
  const uint64_t pqFee = 50;  // well above the per-4000-bytes floor
  Transaction spend = buildPqTransaction(
      spendIns, {PqSendOutput{recip.viewPub, recip.spendPub, inAmount - pqFee}},
      miner.pqSpendPk(), miner.pqSpendSk());

  // Maturity boundary is exercised through the pool path. Mining a TX_PQ into a
  // block isn't supported by the test harness: TestGenerator::constructBlock
  // prices each tx via get_tx_fee, which can't value PqInputs (they carry no
  // inline amount, unlike legacy KeyInputs). The pool path resolves the
  // referenced coinbase and applies the same maturity gate
  // (is_tx_spendheight_unlocked, currentHeight >= unlockHeight given
  // lockedTxAllowedDeltaBlocks == 1).
  auto submitSpend = [&](const Transaction& tx) -> tx_verification_context {
    Crypto::Hash h = getObjectHash(tx);
    BinaryArray b = toBinaryArray(tx);
    tx_verification_context v{};
    core.handleIncomingTransaction(tx, h, b.size(), v, false, core.getCurrentBlockchainHeight());
    return v;
  };

  // Height 8: unlockHeight=9, currentHeight=8 → 8 >= 9 false → immature → rejected.
  ok &= expect(core.getCurrentBlockchainHeight() == 8, "emission: height is 8 before maturity test");
  tx_verification_context tvcImmature = submitSpend(spend);
  ok &= expect(!tvcImmature.m_added_to_pool,
               "emission: spend of immature coinbase rejected at height 8");

  // Mine an empty block so currentHeight advances to 9.
  ok &= expect(mineBlock(core, currency, gen, miner, ts), "emission: mine empty block to height 9");
  ts += step;
  ok &= expect(core.getCurrentBlockchainHeight() == 9, "emission: height is 9 at maturity");

  // Height 9: unlockHeight=9, currentHeight=9 → 9 >= 9 → matured → accepted.
  tx_verification_context tvcMature = submitSpend(spend);
  ok &= expect(tvcMature.m_added_to_pool && !tvcMature.m_verification_failed,
               "emission: spend of matured coinbase accepted at height 9");

  // Double-spend: a second TX_PQ over the same output (same nullifier) rejected.
  PqWalletKeys recip2 = pqKeysFromPattern(8, 4);
  Transaction spend2 = buildPqTransaction(
      spendIns, {PqSendOutput{recip2.viewPub, recip2.spendPub, inAmount - pqFee}},
      miner.pqSpendPk(), miner.pqSpendSk());
  tx_verification_context tvc2 = submitSpend(spend2);
  ok &= expect(!tvc2.m_added_to_pool, "emission: double-spend of matured coinbase rejected");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

// Identity-bound mining (anti-pool/botnet): the coinbase reward recipient MUST
// be the block signer. A block whose coinbase pays one identity but is signed by
// a different identity must be rejected by validate_block_signature.
bool runMinerBinding() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);
  const Currency currency = CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(11).upgradeHeightV6(12)
      .currency();

  std::filesystem::path dataDir("pq_binding_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "binding: core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());

  AccountBase miner;    miner.generate();
  AccountBase attacker; attacker.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "binding: load genesis")) { core.deinit(); return false; }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  uint64_t ts = static_cast<uint64_t>(std::time(nullptr)) - 24 * 60 * 60;
  const uint64_t step = currency.difficultyTarget() * 10;
  for (int i = 0; i < 3; ++i) {
    if (!expect(mineBlock(core, currency, gen, miner, ts), "binding: warmup mine")) { core.deinit(); return false; }
    ts += step;
  }

  // Construct a normal (valid) block paying `attacker`, signed by `attacker`.
  uint32_t height = core.getCurrentBlockchainHeight();
  Crypto::Hash tail = core.get_tail_id();
  uint64_t generated = 0; core.getAlreadyGeneratedCoins(tail, generated);
  std::vector<size_t> sizes; core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow());
  gen.defaultMajorVersion = core.getBlockMajorVersionForHeight(height);
  Block good; std::list<Transaction> txs;
  if (!expect(gen.constructBlock(good, height, tail, attacker, ts, generated, sizes, txs), "binding: construct")) { core.deinit(); return false; }

  bool ok = true;

  // Tamper only the miner tx subtype, then refresh the signature/PoW so the
  // rejection must come from coinbase prevalidation rather than stale proof data.
  Block wrongType = good;
  wrongType.baseTransaction.txType = TX_PQ;
  if (!expect(refreshBlockProofForTest(core, wrongType, attacker), "binding: wrong txType proof")) { core.deinit(); return false; }
  block_verification_context bvcWrongType{};
  core.handle_incoming_block(wrongType, bvcWrongType, false, false);
  ok &= expect(bvcWrongType.m_verification_failed && !bvcWrongType.m_added_to_main_chain,
               "binding: coinbase wrong txType REJECTED");

  // Tamper a copy: keep the coinbase paying `attacker` but re-point the producer
  // identity to `miner` and re-sign with miner's key. Now recipient != signer.
  Block bad = good;
  bad.baseTransaction.extra.clear();
  std::array<uint8_t, PQ_AUTH_PUB_SIZE> minerPub{};
  std::copy(miner.pqSpendPk().begin(), miner.pqSpendPk().end(), minerPub.begin());
  addPqMinerSpendPubToExtra(bad.baseTransaction.extra, minerPub);
  if (!expect(refreshBlockProofForTest(core, bad, miner), "binding: bad proof")) { core.deinit(); return false; }

  block_verification_context bvcBad{};
  core.handle_incoming_block(bad, bvcBad, false, false);
  ok &= expect(bvcBad.m_verification_failed && !bvcBad.m_added_to_main_chain,
               "binding: coinbase-recipient != signer REJECTED");

  // The untampered block (recipient == signer == attacker) is accepted, proving
  // the rejection above is due to the binding rule, not PoW/structure.
  block_verification_context bvcGood{};
  core.handle_incoming_block(good, bvcGood, false, false);
  ok &= expect(bvcGood.m_added_to_main_chain && !bvcGood.m_verification_failed,
               "binding: coinbase-recipient == signer ACCEPTED");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
  return ok;
}

// Regression for randomized ML-DSA block proofs. Two signatures over the same
// unsigned candidate must have different block IDs, and admitting one proof must
// not make a second proof hit the already-exists path. An invalid third witness
// must still reach signature verification and fail independently.
bool runBlockWitnessIsolation() {
  using namespace CryptoNote;
  Logging::ConsoleLogger logger(Logging::ERROR);
  const Currency currency = CurrencyBuilder(logger).testnet(true).currency();

  std::filesystem::path dataDir("pq_block_witness_test_data");
  std::error_code ec;
  std::filesystem::remove_all(dataDir, ec);
  std::filesystem::create_directories(dataDir, ec);

  System::Dispatcher dispatcher;
  Core core(currency, nullptr, logger, dispatcher);
  CoreConfig coreConfig; coreConfig.configFolder = dataDir.string();
  MinerConfig minerConfig;
  if (!expect(core.init(coreConfig, minerConfig, false), "witness: core.init")) return false;

  test_generator gen(currency);
  gen.setBlockchain(&core.get_blockchain_storage());
  AccountBase miner; miner.generate();

  Crypto::Hash genesisHash = core.getBlockIdByHeight(0);
  Block genesis;
  if (!expect(core.getBlockByHash(genesisHash, genesis), "witness: load genesis")) {
    core.deinit(); return false;
  }
  std::vector<size_t> emptySizes;
  gen.addBlock(genesis, 0, 0, emptySizes, 0);

  const uint32_t height = core.getCurrentBlockchainHeight();
  const Crypto::Hash tail = core.get_tail_id();
  uint64_t generated = 0;
  if (!expect(core.getAlreadyGeneratedCoins(tail, generated), "witness: generated coins")) {
    core.deinit(); return false;
  }
  std::vector<size_t> sizes;
  if (!expect(core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow()),
              "witness: block sizes")) {
    core.deinit(); return false;
  }

  gen.defaultMajorVersion = core.getBlockMajorVersionForHeight(height);
  Block first;
  std::list<Transaction> txs;
  const uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));
  if (!expect(gen.constructBlock(first, height, tail, miner, timestamp, generated, sizes, txs),
              "witness: construct candidate")) {
    core.deinit(); return false;
  }
  if (!expect(signBlockForTest(first, miner), "witness: sign first proof")) {
    core.deinit(); return false;
  }

  Block second = first;
  for (unsigned attempt = 0; attempt < 4 && second.signature == first.signature; ++attempt) {
    if (!expect(signBlockForTest(second, miner), "witness: sign alternate proof")) {
      core.deinit(); return false;
    }
  }

  bool ok = true;
  ok &= expect(first.signature != second.signature,
               "witness: randomized signatures over one candidate are distinct");
  BinaryArray firstBlob;
  BinaryArray secondBlob;
  ok &= expect(get_block_hashing_blob(first, firstBlob) &&
               get_block_hashing_blob(second, secondBlob) && firstBlob == secondBlob,
               "witness: alternate proofs share the unsigned candidate blob");

  const Crypto::Hash firstId = get_block_hash(first);
  const Crypto::Hash secondId = get_block_hash(second);
  ok &= expect(firstId != secondId,
               "witness: alternate valid signatures have distinct block IDs");

  PrevalidatedBlockProof firstProof{};
  ok &= expect(core.prevalidateBlockProofOfWork(first, firstProof),
               "witness: context-free proof prevalidation succeeds");
  ok &= expect(firstProof.blockHash == firstId,
               "witness: prevalidated proof is bound to the exact block ID");

  block_verification_context mismatchedBvc{};
  core.handle_incoming_block_prevalidated(second, firstProof, mismatchedBvc, false, false);
  ok &= expect(mismatchedBvc.m_verification_failed && !mismatchedBvc.m_added_to_main_chain,
               "witness: a prevalidated proof cannot be reused for another block");

  block_verification_context firstBvc{};
  core.handle_incoming_block_prevalidated(first, firstProof, firstBvc, false, false);
  ok &= expect(firstBvc.m_added_to_main_chain && !firstBvc.m_verification_failed,
               "witness: correctly bound prevalidated proof accepted on the main chain");

  block_verification_context secondBvc{};
  core.handle_incoming_block(second, secondBvc, false, false);
  ok &= expect(!secondBvc.m_already_exists && !secondBvc.m_verification_failed,
               "witness: second valid proof independently admitted as an alternative block");

  Block invalid = first;
  invalid.signature[0] ^= 0x01;
  const Crypto::Hash invalidId = get_block_hash(invalid);
  ok &= expect(invalidId != firstId && invalidId != secondId,
               "witness: invalid signature variant also has its own ID");
  block_verification_context invalidBvc{};
  core.handle_incoming_block(invalid, invalidBvc, false, false);
  ok &= expect(!invalidBvc.m_already_exists && invalidBvc.m_verification_failed,
               "witness: known candidate content cannot bypass validation for a new witness");

  core.deinit();
  std::filesystem::remove_all(dataDir, ec);
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
  if (!runFreeRegCap()) {
    std::cerr << "[FAIL] PQ free-reg per-block cap test" << std::endl;
    return 1;
  }
  if (!runStaleRegTemplate()) {
    std::cerr << "[FAIL] PQ stale account-registration block-template test" << std::endl;
    return 1;
  }
  if (!runTimestampTemplateHardening()) {
    std::cerr << "[FAIL] PQ timestamp-template hardening test" << std::endl;
    return 1;
  }
  if (!runAccountRegCountRollback()) {
    std::cerr << "[FAIL] PQ registered_account_numbers_count rollback test" << std::endl;
    return 1;
  }
  if (!runEmission()) {
    std::cerr << "[FAIL] PQ emission curve and maturity test" << std::endl;
    return 1;
  }
  if (!runMinerBinding()) {
    std::cerr << "[FAIL] PQ miner identity-binding test" << std::endl;
    return 1;
  }
  if (!runBlockWitnessIsolation()) {
    std::cerr << "[FAIL] PQ block-witness isolation test" << std::endl;
    return 1;
  }
  std::cout << "[PASS] PQ chain integration test" << std::endl;
  return 0;
}
