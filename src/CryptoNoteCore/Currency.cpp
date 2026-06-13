// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2018  zawy12
// Copyright (c) 2016-2026, The Karbowanec developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include "Currency.h"
#include <cctype>
#include <boost/algorithm/string/trim.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/lexical_cast.hpp>
#include "../Common/Base58.h"
#include "../Common/int-util.h"
#include "../Common/FormatTools.h"
#include "../Common/StringTools.h"
#include "Account.h"
#include "CryptoNoteBasicImpl.h"
#include "CryptoNoteFormatUtils.h"
#include "CryptoNoteTools.h"
#include "TransactionExtra.h"
#include "UpgradeDetector.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqHash.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqKem.h"
#include "PqTxType.h"

#undef ERROR

using namespace Logging;
using namespace Common;

constexpr auto RESET_WORK_FACTOR_V5 = 1000;

namespace CryptoNote {

  const std::vector<uint64_t> Currency::PRETTY_AMOUNTS = {
    1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 20, 30, 40, 50, 60, 70, 80, 90,
    100, 200, 300, 400, 500, 600, 700, 800, 900,
    1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000,
    10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000,
    100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000,
    1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000, 9000000,
    10000000, 20000000, 30000000, 40000000, 50000000, 60000000, 70000000, 80000000, 90000000,
    100000000, 200000000, 300000000, 400000000, 500000000, 600000000, 700000000, 800000000, 900000000,
    1000000000, 2000000000, 3000000000, 4000000000, 5000000000, 6000000000, 7000000000, 8000000000, 9000000000,
    10000000000, 20000000000, 30000000000, 40000000000, 50000000000, 60000000000, 70000000000, 80000000000, 90000000000,
    100000000000, 200000000000, 300000000000, 400000000000, 500000000000, 600000000000, 700000000000, 800000000000, 900000000000,
    1000000000000, 2000000000000, 3000000000000, 4000000000000, 5000000000000, 6000000000000, 7000000000000, 8000000000000, 9000000000000,
    10000000000000, 20000000000000, 30000000000000, 40000000000000, 50000000000000, 60000000000000, 70000000000000, 80000000000000, 90000000000000,
    100000000000000, 200000000000000, 300000000000000, 400000000000000, 500000000000000, 600000000000000, 700000000000000, 800000000000000, 900000000000000,
    1000000000000000, 2000000000000000, 3000000000000000, 4000000000000000, 5000000000000000, 6000000000000000, 7000000000000000, 8000000000000000, 9000000000000000,
    10000000000000000, 20000000000000000, 30000000000000000, 40000000000000000, 50000000000000000, 60000000000000000, 70000000000000000, 80000000000000000, 90000000000000000,
    100000000000000000, 200000000000000000, 300000000000000000, 400000000000000000, 500000000000000000, 600000000000000000, 700000000000000000, 800000000000000000, 900000000000000000,
    1000000000000000000, 2000000000000000000, 3000000000000000000, 4000000000000000000, 5000000000000000000, 6000000000000000000, 7000000000000000000, 8000000000000000000, 9000000000000000000,
    10000000000000000000ull
  };

  bool Currency::init() {
    if (!generateGenesisBlock()) {
      logger(ERROR, BRIGHT_RED) << "Failed to generate genesis block";
      return false;
    }

    if (!get_block_hash(m_genesisBlock, m_genesisBlockHash)) {
      logger(ERROR, BRIGHT_RED) << "Failed to get genesis block hash";
      return false;
    }

    if (isTestnet()) {
      if (m_upgradeHeightV2 == parameters::UPGRADE_HEIGHT_V2) {
        m_upgradeHeightV2 = 2;
      }
      if (m_upgradeHeightV3 == parameters::UPGRADE_HEIGHT_V3) {
        m_upgradeHeightV3 = 3;
      }
      if (m_upgradeHeightV4 == parameters::UPGRADE_HEIGHT_V4) {
        m_upgradeHeightV4 = 4;
      }
      if (m_upgradeHeightV5 == parameters::UPGRADE_HEIGHT_V5) {
        m_upgradeHeightV5 = 15;
      }
      if (m_upgradeHeightV6 == parameters::UPGRADE_HEIGHT_V6) {
        m_upgradeHeightV6 = 20;
      }
      m_blocksFileName = "testnet_" + m_blocksFileName;
      m_blocksCacheFileName = "testnet_" + m_blocksCacheFileName;
      m_blockIndexesFileName = "testnet_" + m_blockIndexesFileName;
      m_blockchainIndicesFileName = "testnet_" + m_blockchainIndicesFileName;
      m_txPoolFileName = "testnet_" + m_txPoolFileName;
    }

    return true;
  }

  bool Currency::generateGenesisBlock() {
    m_genesisBlock = boost::value_initialized<Block>();

    std::string genesisCoinbaseTxHex = GENESIS_COINBASE_TX_HEX;
    BinaryArray minerTxBlob;

    bool r =
      fromHex(genesisCoinbaseTxHex, minerTxBlob) &&
      fromBinaryArray(m_genesisBlock.baseTransaction, minerTxBlob);

    if (!r) {
      // No valid hex — generate a PQ genesis coinbase from a deterministic zero seed.
      // The genesis block signature is skipped at height 0 (validate_block_signature).
      CryptoPQ::DsaKeypairSeed dsaSeed{};
      CryptoPQ::KemKeypairSeed kemSeed{};
      auto [dPk, dSk] = CryptoPQ::dsa_keygen_from_seed(dsaSeed);
      auto [kPk, kSk] = CryptoPQ::kem_keygen_from_seed(kemSeed);
      (void)dSk; (void)kSk;
      if (!constructMinerTxPq(BLOCK_MAJOR_VERSION_1, 0, 0, 0, 0, 0, kPk, dPk,
                               m_genesisBlock.baseTransaction)) {
        logger(ERROR, BRIGHT_RED) << "Failed to create PQ genesis coinbase";
        return false;
      }
    }

    m_genesisBlock.majorVersion = BLOCK_MAJOR_VERSION_1;
    m_genesisBlock.minorVersion = BLOCK_MINOR_VERSION_0;
    m_genesisBlock.timestamp = 0;
    m_genesisBlock.nonce = 70;
    if (m_testnet) {
      ++m_genesisBlock.nonce;
    }
    // Genesis signature validation is skipped (height 0), but the wire format
    // requires exactly PQ_SIGNATURE_SIZE bytes. Fill with zeros.
    if (m_genesisBlock.signature.empty()) {
      m_genesisBlock.signature.assign(PQ_SIGNATURE_SIZE, 0);
    }

    return true;
  }

  size_t Currency::blockGrantedFullRewardZoneByBlockVersion(uint8_t blockMajorVersion) const {
    if (blockMajorVersion >= BLOCK_MAJOR_VERSION_3) {
      return m_blockGrantedFullRewardZone;
    }
    else if (blockMajorVersion == BLOCK_MAJOR_VERSION_2) {
      return CryptoNote::parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
    }
    else {
      return CryptoNote::parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
    }
  }

  uint32_t Currency::upgradeHeight(uint8_t majorVersion) const {
    if (majorVersion == BLOCK_MAJOR_VERSION_8) {
      return m_upgradeHeightV8;
    }
    else if (majorVersion == BLOCK_MAJOR_VERSION_7) {
      return m_upgradeHeightV7;
    }
    else if (majorVersion == BLOCK_MAJOR_VERSION_6) {
      return m_upgradeHeightV6;
    }
    else if (majorVersion == BLOCK_MAJOR_VERSION_5) {
      return m_upgradeHeightV5;
    }
    else if (majorVersion == BLOCK_MAJOR_VERSION_4) {
      return m_upgradeHeightV4;
    }
    else if (majorVersion == BLOCK_MAJOR_VERSION_2) {
      return m_upgradeHeightV2;
    }
    else if (majorVersion == BLOCK_MAJOR_VERSION_3) {
      return m_upgradeHeightV3;
    }
    else {
      return static_cast<uint32_t>(-1);
    }
  }

  uint64_t Currency::calculateReward(uint64_t alreadyGeneratedCoins) const {
    assert(m_emissionSpeedFactor > 0 && m_emissionSpeedFactor <= 8 * sizeof(uint64_t));
    // Initial exponential emission curve with fallback to flat rate tail emission
    uint64_t baseRewardInitial = alreadyGeneratedCoins < m_moneySupply ? (m_moneySupply - alreadyGeneratedCoins) >> m_emissionSpeedFactor : CryptoNote::parameters::TAIL_EMISSION_REWARD;
    // Friedman's k-percent rule, inflation 2% of total coins in circulation p.a.
    const uint64_t blocksInOneYear = expectedNumberOfBlocksPerDay() * 365;
    assert(blocksInOneYear > 0);
    uint64_t twoPercentOfEmission = alreadyGeneratedCoins / 100 * 2;
    uint64_t baseRewardTail = twoPercentOfEmission / blocksInOneYear;
    // Transition from exponential to tail emission (whichever reward is larger)
    return std::max(baseRewardInitial, baseRewardTail);
  }

  bool Currency::getBlockReward(uint8_t blockMajorVersion, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins,
    uint64_t fee, uint64_t& reward, int64_t& emissionChange) const {

    uint64_t baseReward = calculateReward(alreadyGeneratedCoins);

    size_t blockGrantedFullRewardZone = blockGrantedFullRewardZoneByBlockVersion(blockMajorVersion);
    medianSize = std::max(medianSize, blockGrantedFullRewardZone);
    if (currentBlockSize > UINT64_C(2) * medianSize) {
      logger(DEBUGGING) << "Block cumulative size is too big: " << currentBlockSize << ", expected less than " << 2 * medianSize;
      return false;
    }

    uint64_t penalizedBaseReward = getPenalizedAmount(baseReward, medianSize, currentBlockSize);
    uint64_t penalizedFee = blockMajorVersion >= BLOCK_MAJOR_VERSION_2 ? getPenalizedAmount(fee, medianSize, currentBlockSize) : fee;
    if (cryptonoteCoinVersion() == 1) {
      penalizedFee = getPenalizedAmount(fee, medianSize, currentBlockSize);
    }

    emissionChange = penalizedBaseReward - (fee - penalizedFee);
    reward = penalizedBaseReward + penalizedFee;

    return true;
  }

  size_t Currency::maxBlockCumulativeSize(uint64_t height) const {
    assert(height <= std::numeric_limits<uint64_t>::max() / m_maxBlockSizeGrowthSpeedNumerator);
    size_t maxSize = static_cast<size_t>(m_maxBlockSizeInitial +
      (height * m_maxBlockSizeGrowthSpeedNumerator) / m_maxBlockSizeGrowthSpeedDenominator);
    assert(maxSize >= m_maxBlockSizeInitial);
    return maxSize;
  }

  bool Currency::constructMinerTx(uint8_t blockMajorVersion, uint32_t height, size_t medianSize, uint64_t alreadyGeneratedCoins, size_t currentBlockSize,
    uint64_t fee, const AccountPublicAddress& /*minerAddress_ECC_unused*/, Transaction& tx, Crypto::SecretKey& /*txKey_unused*/, const BinaryArray& extraNonce/* = BinaryArray()*/, size_t /*maxOuts*/) const {
    // ECC miner address path is dead on Discrete. Caller must use the PqAddress overload.
    // This stub exists only so legacy callers (e.g. test harness) compile.
    logger(ERROR, BRIGHT_RED) << "constructMinerTx: ECC miner address not supported in Discrete; use the PqAddress overload";
    return false;
  }

  bool Currency::constructMinerTxPq(uint8_t blockMajorVersion, uint32_t height, size_t medianSize,
    uint64_t alreadyGeneratedCoins, size_t currentBlockSize, uint64_t fee,
    const CryptoPQ::KemPublicKey& minerViewPub,
    const CryptoPQ::DsaPublicKey& minerSpendPub,
    Transaction& tx,
    const BinaryArray& extraNonce) const {

    tx.inputs.clear();
    tx.outputs.clear();
    tx.extra.clear();
    tx.signatures.clear();

    tx.version   = TRANSACTION_VERSION_PQ;
    tx.txType    = TX_COINBASE;
    tx.unlockTime = height + minedMoneyUnlockWindow();

    // Coinbase input: block height.
    BaseInput in;
    in.blockIndex = height;
    tx.inputs.push_back(in);

    // Block reward calculation.
    uint64_t blockReward;
    int64_t emissionChange;
    if (!getBlockReward(blockMajorVersion, medianSize, currentBlockSize, alreadyGeneratedCoins, fee, blockReward, emissionChange)) {
      logger(INFO) << "Block is too big";
      return false;
    }

    // Single PQ output to the miner's address.
    // inputsHash = zeros (coinbase has no PQ inputs, no prior outpoints).
    CryptoPQ::Hash256 inputsHash{};
    CryptoPQ::PqBuiltOutput built = CryptoPQ::buildPqOutput(
        minerViewPub, minerSpendPub, inputsHash, /*outputIndex=*/0, blockReward);

    PqOutput po;
    po.kemCt.assign(built.kemCt.begin(), built.kemCt.end());
    po.encPayload = built.encPayload;
    std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);

    TransactionOutput out;
    out.amount = blockReward;
    out.target = std::move(po);
    tx.outputs.push_back(std::move(out));

    // Extra: miner ML-DSA spend pub key (used by validate_block_signature).
    addPqMinerSpendPubToExtra(tx.extra, minerSpendPub);

    if (!extraNonce.empty()) {
      addExtraNonceToTransactionExtra(tx.extra, extraNonce);
    }

    return true;
  }

  std::string Currency::accountAddressAsString(const AccountBase& account) const {
    return getAccountAddressAsStr(m_publicAddressBase58Prefix, account.getAccountKeys().address);
  }

  std::string Currency::accountAddressAsString(const AccountPublicAddress& accountPublicAddress) const {
    return getAccountAddressAsStr(m_publicAddressBase58Prefix, accountPublicAddress);
  }

  bool Currency::parseAccountAddressString(const std::string& str, AccountPublicAddress& addr) const {
    uint64_t prefix;
    if (!CryptoNote::parseAccountAddressString(prefix, addr, str)) {
      return false;
    }

    if (prefix != m_publicAddressBase58Prefix) {
      logger(DEBUGGING) << "Wrong address prefix: " << prefix << ", expected " << m_publicAddressBase58Prefix;
      return false;
    }

    return true;
  }

  std::string Currency::formatAmount(uint64_t amount) const {
    return Common::Format::formatAmount(amount);
  }

  std::string Currency::formatAmount(int64_t amount) const {
    return Common::Format::formatAmount(amount);
  }

  bool Currency::parseAmount(const std::string& str, uint64_t& amount) const {
    return Common::Format::parseAmount(str, amount);
  }

  uint64_t Currency::getMinimalFee(const uint32_t /*height*/) const {
    return CryptoNote::parameters::MINIMUM_FEE;
  }

  // All that exceeds 100 bytes is charged per byte,
  // the cost of one byte is 1/100 of minimal fee
  uint64_t Currency::getFeePerByte(const uint64_t txExtraSize, const uint64_t minFee) const {
    return txExtraSize > 100 ? minFee / 100 * (txExtraSize - 100) : 0;
  }

  Difficulty Currency::nextDifficulty(uint32_t height, uint8_t blockMajorVersion, std::vector<uint64_t> timestamps,
    std::vector<Difficulty> cumulativeDifficulties) const {
    // Discrete: LWMA-1 (V5) is the sole difficulty algorithm from genesis.
    (void)blockMajorVersion;
    return nextDifficultyV5(height, blockMajorVersion, timestamps, cumulativeDifficulties);
  }

  Difficulty Currency::nextDifficultyV5(
    uint32_t height,
    uint8_t blockMajorVersion,
    std::vector<std::uint64_t> timestamps,
    std::vector<Difficulty> cumulativeDifficulties) const {

    // LWMA-1 difficulty algorithm
    // Copyright (c) 2017-2018 Zawy, MIT License
    // See commented link below for required config file changes. Fix FTL and MTP.
    // https://github.com/zawy12/difficulty-algorithms/issues/3

    // begin reset difficulty for new epoch

    height--; // there's difference between karbo1 and karbo2 here (height vs top block index)

    const uint32_t upgradeHeightV5 = upgradeHeight(CryptoNote::BLOCK_MAJOR_VERSION_5);

    /*
      Mainnet: keep original V5 reset behavior for consensus compatibility.
      Testnet: skip this reset. On low-height testnet this can produce bad/zero
      difficulty or interact badly with the small available window.
    */
    if (!isTestnet() && height == upgradeHeightV5) {
      Difficulty resetDifficulty =
        cumulativeDifficulties[0] / height / RESET_WORK_FACTOR_V5;

      return std::max<Difficulty>(1, resetDifficulty);
    }

    uint32_t count =
      static_cast<uint32_t>(difficultyBlocksCountByBlockVersion(blockMajorVersion)) - 1;

    /*
      Mainnet: keep original post-upgrade window trimming.
      Testnet: skip this. At low testnet heights, offset can be larger than the
      available vectors and can break difficulty calculation/template generation.
    */
    if (!isTestnet() &&
      height > upgradeHeightV5 &&
      height < CryptoNote::parameters::UPGRADE_HEIGHT_V5 + count) {

      uint32_t offset = count - (height - upgradeHeightV5);

      /*
        Nasty bug guard only. This should not affect normal mainnet behavior,
        but prevents invalid erase if the available history is shorter than offset.
      */
      if (offset >= timestamps.size() || offset >= cumulativeDifficulties.size()) {
        return 1;
      }

      timestamps.erase(timestamps.begin(), timestamps.begin() + offset);
      cumulativeDifficulties.erase(cumulativeDifficulties.begin(), cumulativeDifficulties.begin() + offset);
    }

    // end reset difficulty for new epoch

    assert(timestamps.size() == cumulativeDifficulties.size());

    /*
      Testnet/mainnet safety guard. Original code assumes there are at least
      two cumulative difficulty entries. Without this, size_t underflow is possible:
      cumulativeDifficulties.size() - 1.
    */
    if (timestamps.size() <= 1 || cumulativeDifficulties.size() <= 1) {
      return 1;
    }

    const int64_t T = static_cast<int64_t>(m_difficultyTarget);

    /*
      Use the smaller available vector length. In normal mainnet operation they
      are equal, so this does not change mainnet behavior.
    */
    uint64_t available =
      std::min<uint64_t>(timestamps.size(), cumulativeDifficulties.size());

    uint64_t N =
      std::min<uint64_t>(difficultyBlocksCount4(), available - 1);

    if (N == 0) {
      return 1;
    }

    uint64_t L(0), avg_D, next_D, i, this_timestamp(0), previous_timestamp(0);

    previous_timestamp = timestamps[0] - T;

    for (i = 1; i <= N; i++) {
      // Safely prevent out-of-sequence timestamps
      if (timestamps[i] > previous_timestamp) {
        this_timestamp = timestamps[i];
      }
      else {
        this_timestamp = previous_timestamp + 1;
      }

      L += i * std::min<uint64_t>(6 * T, this_timestamp - previous_timestamp);
      previous_timestamp = this_timestamp;
    }

    if (L < N * N * T / 20) {
      L = N * N * T / 20;
    }

    if (L == 0) {
      return 1;
    }

    avg_D = (cumulativeDifficulties[N] - cumulativeDifficulties[0]) / N;

    /*
      If testnet cumulative difficulty barely moved, avg_D can become 0.
      Original mainnet is unlikely to hit this, but returning difficulty 0 is invalid.
    */
    if (avg_D == 0) {
      return 1;
    }

    // Prevent round off error for small D and overflow for large D.
    if (avg_D > 2000000 * N * N * T) {
      next_D = (avg_D / (200 * L)) * (N * (N + 1) * T * 99);
    }
    else {
      next_D = (avg_D * N * (N + 1) * T * 99) / (200 * L);
    }

    // Optional. Make all insignificant digits zero for easy reading.
    i = 1000000000;
    while (i > 1) {
      if (next_D > i * 100) {
        next_D = ((next_D + i / 2) / i) * i;
        break;
      }
      else {
        i /= 10;
      }
    }

    // minimum limit
    if (!isTestnet() && next_D < 100000) {
      next_D = 100000;
    }

    return std::max<Difficulty>(1, next_D);
  }

  bool Currency::checkProofOfWorkV1(Crypto::cn_context& context, const Block& block, Difficulty currentDiffic,
    Crypto::Hash& proofOfWork) const {
    if (BLOCK_MAJOR_VERSION_2 == block.majorVersion || BLOCK_MAJOR_VERSION_3 == block.majorVersion) {
      return false;
    }

    if (!get_block_longhash(context, block, proofOfWork)) {
      return false;
    }

    return check_hash(proofOfWork, currentDiffic);
  }

  bool Currency::checkProofOfWorkV2(Crypto::cn_context& context, const Block& block, Difficulty currentDiffic,
    Crypto::Hash& proofOfWork) const {
    if (block.majorVersion < BLOCK_MAJOR_VERSION_2) {
      return false;
    }

    if (!get_block_longhash(context, block, proofOfWork)) {
      return false;
    }

    if (!check_hash(proofOfWork, currentDiffic)) {
      return false;
    }

    TransactionExtraMergeMiningTag mmTag;
    if (!getMergeMiningTagFromExtra(block.parentBlock.baseTransaction.extra, mmTag)) {
      logger(ERROR) << "merge mining tag wasn't found in extra of the parent block miner transaction";
      return false;
    }

    if (8 * sizeof(m_genesisBlockHash) < block.parentBlock.blockchainBranch.size()) {
      return false;
    }

    Crypto::Hash auxBlockHeaderHash;
    if (!get_aux_block_header_hash(block, auxBlockHeaderHash)) {
      return false;
    }

    Crypto::Hash auxBlocksMerkleRoot;
    Crypto::tree_hash_from_branch(block.parentBlock.blockchainBranch.data(), block.parentBlock.blockchainBranch.size(),
      auxBlockHeaderHash, &m_genesisBlockHash, auxBlocksMerkleRoot);

    if (auxBlocksMerkleRoot != mmTag.merkleRoot) {
      logger(ERROR, BRIGHT_YELLOW) << "Aux block hash wasn't found in merkle tree";
      return false;
    }

    return true;
  }

  bool Currency::checkProofOfWork(Crypto::cn_context& context, const Block& block, Difficulty currentDiffic, Crypto::Hash& proofOfWork) const {
    // Discrete only has v6+ blocks; yespower (V1 PoW path reuses the yespower impl).
    return checkProofOfWorkV1(context, block, currentDiffic, proofOfWork);
  }

  size_t Currency::getApproximateMaximumInputCount(size_t transactionSize, size_t outputCount, size_t mixinCount) const {
    const size_t KEY_IMAGE_SIZE = sizeof(Crypto::KeyImage);
    const size_t OUTPUT_KEY_SIZE = sizeof(decltype(KeyOutput::key));
    const size_t AMOUNT_SIZE = sizeof(uint64_t) + 2; //varint
    const size_t GLOBAL_INDEXES_VECTOR_SIZE_SIZE = sizeof(uint8_t);//varint
    const size_t GLOBAL_INDEXES_INITIAL_VALUE_SIZE = sizeof(uint32_t);//varint
    const size_t GLOBAL_INDEXES_DIFFERENCE_SIZE = sizeof(uint32_t);//varint
    const size_t SIGNATURE_SIZE = sizeof(Crypto::Signature);
    const size_t EXTRA_TAG_SIZE = sizeof(uint8_t);
    const size_t INPUT_TAG_SIZE = sizeof(uint8_t);
    const size_t OUTPUT_TAG_SIZE = sizeof(uint8_t);
    const size_t PUBLIC_KEY_SIZE = sizeof(Crypto::PublicKey);
    const size_t TRANSACTION_VERSION_SIZE = sizeof(uint8_t);
    const size_t TRANSACTION_UNLOCK_TIME_SIZE = sizeof(uint64_t);

    const size_t outputsSize = outputCount * (OUTPUT_TAG_SIZE + OUTPUT_KEY_SIZE + AMOUNT_SIZE);
    const size_t headerSize = TRANSACTION_VERSION_SIZE + TRANSACTION_UNLOCK_TIME_SIZE + EXTRA_TAG_SIZE + PUBLIC_KEY_SIZE;
    const size_t inputSize = INPUT_TAG_SIZE + AMOUNT_SIZE + KEY_IMAGE_SIZE + SIGNATURE_SIZE + GLOBAL_INDEXES_VECTOR_SIZE_SIZE + GLOBAL_INDEXES_INITIAL_VALUE_SIZE +
      mixinCount * (GLOBAL_INDEXES_DIFFERENCE_SIZE + SIGNATURE_SIZE);

    return (transactionSize - headerSize - outputsSize) / inputSize;
  }

  CurrencyBuilder::CurrencyBuilder(Logging::ILogger& log) : m_currency(log) {
    maxBlockNumber(parameters::CRYPTONOTE_MAX_BLOCK_NUMBER);
    maxBlockBlobSize(parameters::CRYPTONOTE_MAX_BLOCK_BLOB_SIZE);
    maxTxSize(parameters::CRYPTONOTE_MAX_TX_SIZE);
    publicAddressBase58Prefix(parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
    minedMoneyUnlockWindow(parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
    transactionSpendableAge(parameters::CRYPTONOTE_TX_SPENDABLE_AGE);
    expectedNumberOfBlocksPerDay(parameters::EXPECTED_NUMBER_OF_BLOCKS_PER_DAY);

    timestampCheckWindow(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);
    timestampCheckWindow_v1(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1);
    blockFutureTimeLimit(parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT);
    blockFutureTimeLimit_v1(parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V1);

    moneySupply(parameters::MONEY_SUPPLY);
    emissionSpeedFactor(parameters::EMISSION_SPEED_FACTOR);
    cryptonoteCoinVersion(parameters::CRYPTONOTE_COIN_VERSION);

    rewardBlocksWindow(parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW);
    blockGrantedFullRewardZone(parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE);
    minerTxBlobReservedSize(parameters::CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE);
    maxTransactionSizeLimit(parameters::MAX_TRANSACTION_SIZE_LIMIT);

    minMixin(parameters::MIN_TX_MIXIN_SIZE);
    maxMixin(parameters::MAX_TX_MIXIN_SIZE);

    numberOfDecimalPlaces(parameters::CRYPTONOTE_DISPLAY_DECIMAL_POINT);

    minimumFee(parameters::MINIMUM_FEE);
    defaultDustThreshold(parameters::DEFAULT_DUST_THRESHOLD);

    difficultyTarget(parameters::DIFFICULTY_TARGET);
    difficultyWindow(parameters::DIFFICULTY_WINDOW);
    difficultyLag(parameters::DIFFICULTY_LAG);
    difficultyCut(parameters::DIFFICULTY_CUT);

    maxBlockSizeInitial(parameters::MAX_BLOCK_SIZE_INITIAL);
    maxBlockSizeGrowthSpeedNumerator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR);
    maxBlockSizeGrowthSpeedDenominator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR);

    lockedTxAllowedDeltaSeconds(parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS);
    lockedTxAllowedDeltaBlocks(parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS);

    mempoolTxLiveTime(parameters::CRYPTONOTE_MEMPOOL_TX_LIVETIME);
    mempoolTxFromAltBlockLiveTime(parameters::CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME);
    numberOfPeriodsToForgetTxDeletedFromPool(parameters::CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL);

    upgradeHeightV2(parameters::UPGRADE_HEIGHT_V2);
    upgradeHeightV3(parameters::UPGRADE_HEIGHT_V3);
    upgradeHeightV4(parameters::UPGRADE_HEIGHT_V4);
    upgradeHeightV5(parameters::UPGRADE_HEIGHT_V5);
    upgradeHeightV6(parameters::UPGRADE_HEIGHT_V6);
    upgradeHeightV7(parameters::UPGRADE_HEIGHT_V7);
    upgradeHeightV8(parameters::UPGRADE_HEIGHT_V8);
    upgradeVotingThreshold(parameters::UPGRADE_VOTING_THRESHOLD);
    upgradeVotingWindow(parameters::UPGRADE_VOTING_WINDOW);
    upgradeWindow(parameters::UPGRADE_WINDOW);

    blocksFileName(parameters::CRYPTONOTE_BLOCKS_FILENAME);
    blocksCacheFileName(parameters::CRYPTONOTE_BLOCKSCACHE_FILENAME);
    blockIndexesFileName(parameters::CRYPTONOTE_BLOCKINDEXES_FILENAME);
    blockchainIndicesFileName(parameters::CRYPTONOTE_BLOCKCHAIN_INDICES_FILENAME);
    txPoolFileName(parameters::CRYPTONOTE_POOLDATA_FILENAME);

    testnet(false);
  }

  Transaction CurrencyBuilder::generateGenesisTransaction() {
    CryptoNote::Transaction tx;
    Crypto::SecretKey txKey;
    CryptoNote::AccountPublicAddress ac = boost::value_initialized<CryptoNote::AccountPublicAddress>();
    m_currency.constructMinerTx(1, 0, 0, 0, 0, 0, ac, tx, txKey); // zero fee in genesis
    return tx;
  }
  CurrencyBuilder& CurrencyBuilder::emissionSpeedFactor(unsigned int val) {
    if (val <= 0 || val > 8 * sizeof(uint64_t)) {
      throw std::invalid_argument("val at emissionSpeedFactor()");
    }

    m_currency.m_emissionSpeedFactor = val;
    return *this;
  }

  CurrencyBuilder& CurrencyBuilder::numberOfDecimalPlaces(size_t val) {
    m_currency.m_numberOfDecimalPlaces = val;
    m_currency.m_coin = 1;
    for (size_t i = 0; i < m_currency.m_numberOfDecimalPlaces; ++i) {
      m_currency.m_coin *= 10;
    }

    return *this;
  }

  CurrencyBuilder& CurrencyBuilder::difficultyWindow(size_t val) {
    if (val < 2) {
      throw std::invalid_argument("val at difficultyWindow()");
    }
    m_currency.m_difficultyWindow = val;
    return *this;
  }

  CurrencyBuilder& CurrencyBuilder::upgradeVotingThreshold(unsigned int val) {
    if (val <= 0 || val > 100) {
      throw std::invalid_argument("val at upgradeVotingThreshold()");
    }

    m_currency.m_upgradeVotingThreshold = val;
    return *this;
  }

  CurrencyBuilder& CurrencyBuilder::upgradeWindow(size_t val) {
    if (val <= 0) {
      throw std::invalid_argument("val at upgradeWindow()");
    }

    m_currency.m_upgradeWindow = static_cast<uint32_t>(val);
    return *this;
  }

}
