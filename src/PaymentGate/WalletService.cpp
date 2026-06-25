// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Copyright (c) 2021-2023, The Talleo developers
// Copyright (c) 2016-2026, The Karbo developers
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

#include "WalletService.h"


#include <future>
#include <assert.h>
#include <sstream>
#include <unordered_set>

#include <boost/filesystem/operations.hpp>

#include <System/Timer.h>
#include <System/InterruptedException.h>
#include "Common/Util.h"

#include "crypto/crypto.h"
#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/Account.h"

#include <System/EventLock.h>

#include "PaymentServiceJsonRpcMessages.h"

#include "Wallet/WalletGreen.h"
#include "Wallet/PqRecipient.h"
#include "Wallet/PqSender.h"
#include "AccountNumber.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/WalletUtils.h"
#include "WalletServiceErrorCategory.h"
#include "ITransfersContainer.h"

#include "Mnemonics/electrum-words.cpp"

using namespace CryptoNote;

namespace PaymentService {

namespace {

bool checkPaymentId(const std::string& paymentId) {
  if (paymentId.size() != 64) {
    return false;
  }

  return std::all_of(paymentId.begin(), paymentId.end(), [] (const char c) {
    if (c >= '0' && c <= '9') {
      return true;
    }

    if (c >= 'a' && c <= 'f') {
      return true;
    }

    if (c >= 'A' && c <= 'F') {
      return true;
    }

    return false;
  });
}

Crypto::Hash parsePaymentId(const std::string& paymentIdStr) {
  if (!checkPaymentId(paymentIdStr)) {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
  }

  Crypto::Hash paymentId;
  bool r = Common::podFromHex(paymentIdStr, paymentId);
  if (!r) {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
  }

  return paymentId;
}

bool getPaymentIdFromExtra(const std::string& binaryString, Crypto::Hash& paymentId) {
  return CryptoNote::getPaymentIdFromTxExtra(Common::asBinaryArray(binaryString), paymentId);
}

std::string getPaymentIdStringFromExtra(const std::string& binaryString) {
  Crypto::Hash paymentId;

  if (!getPaymentIdFromExtra(binaryString, paymentId)) {
    return std::string();
  }

  return Common::podToHex(paymentId);
}

}

struct TransactionsInBlockInfoFilter {
  TransactionsInBlockInfoFilter(const std::vector<std::string>& addressesVec, const std::string& paymentIdStr) {
    addresses.insert(addressesVec.begin(), addressesVec.end());

    if (!paymentIdStr.empty()) {
      paymentId = parsePaymentId(paymentIdStr);
      havePaymentId = true;
    } else {
      havePaymentId = false;
    }
  }

  bool checkTransaction(const CryptoNote::WalletTransactionWithTransfers& transaction) const {
    if (havePaymentId) {
      Crypto::Hash transactionPaymentId;
      if (!getPaymentIdFromExtra(transaction.transaction.extra, transactionPaymentId)) {
        return false;
      }

      if (paymentId != transactionPaymentId) {
        return false;
      }
    }

    if (addresses.empty()) {
      return true;
    }

    bool haveAddress = false;
    for (const CryptoNote::WalletTransfer& transfer: transaction.transfers) {
      if (addresses.find(transfer.address) != addresses.end()) {
        haveAddress = true;
        break;
      }
    }

    return haveAddress;
  }

  std::unordered_set<std::string> addresses;
  bool havePaymentId = false;
  Crypto::Hash paymentId;
};

namespace {

void addPaymentIdToExtra(const std::string& paymentId, std::string& extra) {
  std::vector<uint8_t> extraVector;
  if (!CryptoNote::createTxExtraWithPaymentId(paymentId, extraVector)) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_PAYMENT_ID));
  }

  std::copy(extraVector.begin(), extraVector.end(), std::back_inserter(extra));
}

void validatePaymentId(const std::string& paymentId, Logging::LoggerRef logger) {
  if (!checkPaymentId(paymentId)) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't validate payment id: " << paymentId;
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_PAYMENT_ID_FORMAT));
  }
}

Crypto::Hash parseHash(const std::string& hashString, Logging::LoggerRef logger) {
  Crypto::Hash hash;

  if (!Common::podFromHex(hashString, hash)) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't parse hash string " << hashString;
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_HASH_FORMAT));
  }

  return hash;
}

std::vector<CryptoNote::TransactionsInBlockInfo> filterTransactions(
  const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks,
  const TransactionsInBlockInfoFilter& filter) {

  std::vector<CryptoNote::TransactionsInBlockInfo> result;

  for (const auto& block: blocks) {
    CryptoNote::TransactionsInBlockInfo item;
    item.blockHash = block.blockHash;

    for (const auto& transaction: block.transactions) {
      if (transaction.transaction.state != CryptoNote::WalletTransactionState::DELETED && filter.checkTransaction(transaction)) {
        item.transactions.push_back(transaction);
      }
    }

    if (!block.transactions.empty()) {
      result.push_back(std::move(item));
    }
  }

  return result;
}

PaymentService::TransactionRpcInfo convertTransactionWithTransfersToTransactionRpcInfo(
  const CryptoNote::WalletTransactionWithTransfers& transactionWithTransfers) {

  PaymentService::TransactionRpcInfo transactionInfo;

  transactionInfo.state = static_cast<uint8_t>(transactionWithTransfers.transaction.state);
  transactionInfo.transactionHash = Common::podToHex(transactionWithTransfers.transaction.hash);
  transactionInfo.blockIndex = transactionWithTransfers.transaction.blockHeight;
  transactionInfo.timestamp = transactionWithTransfers.transaction.timestamp;
  transactionInfo.isBase = transactionWithTransfers.transaction.isBase;
  transactionInfo.unlockHeight = transactionWithTransfers.transaction.unlockHeight;
  transactionInfo.amount = transactionWithTransfers.transaction.totalAmount;
  transactionInfo.fee = transactionWithTransfers.transaction.fee;
  transactionInfo.extra = Common::toHex(transactionWithTransfers.transaction.extra.data(), transactionWithTransfers.transaction.extra.size());
  transactionInfo.paymentId = getPaymentIdStringFromExtra(transactionWithTransfers.transaction.extra);

  for (const CryptoNote::WalletTransfer& transfer: transactionWithTransfers.transfers) {
    PaymentService::TransferRpcInfo rpcTransfer;
    rpcTransfer.address = transfer.address;
    rpcTransfer.amount = transfer.amount;
    rpcTransfer.type = static_cast<uint8_t>(transfer.type);

    transactionInfo.transfers.push_back(std::move(rpcTransfer));
  }

  return transactionInfo;
}

std::vector<PaymentService::TransactionsInBlockRpcInfo> convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(
  const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) {

  std::vector<PaymentService::TransactionsInBlockRpcInfo> rpcBlocks;
  rpcBlocks.reserve(blocks.size());
  for (const auto& block: blocks) {
    PaymentService::TransactionsInBlockRpcInfo rpcBlock;
    rpcBlock.blockHash = Common::podToHex(block.blockHash);

    for (const CryptoNote::WalletTransactionWithTransfers& transactionWithTransfers: block.transactions) {
      PaymentService::TransactionRpcInfo transactionInfo = convertTransactionWithTransfersToTransactionRpcInfo(transactionWithTransfers);
      rpcBlock.transactions.push_back(std::move(transactionInfo));
    }

    rpcBlocks.push_back(std::move(rpcBlock));
  }

  return rpcBlocks;
}

std::vector<PaymentService::TransactionHashesInBlockRpcInfo> convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(
    const std::vector<CryptoNote::TransactionsInBlockInfo>& blocks) {

  std::vector<PaymentService::TransactionHashesInBlockRpcInfo> transactionHashes;
  transactionHashes.reserve(blocks.size());
  for (const CryptoNote::TransactionsInBlockInfo& block: blocks) {
    PaymentService::TransactionHashesInBlockRpcInfo item;
    item.blockHash = Common::podToHex(block.blockHash);

    for (const CryptoNote::WalletTransactionWithTransfers& transaction: block.transactions) {
      item.transactionHashes.emplace_back(Common::podToHex(transaction.transaction.hash));
    }

    transactionHashes.push_back(std::move(item));
  }

  return transactionHashes;
}

void validateMixin(const uint16_t& mixin, const CryptoNote::Currency& currency, Logging::LoggerRef logger) {
    if (mixin < currency.minMixin() && mixin != 0) {
        logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Mixin must be equal to or bigger than " << currency.minMixin();
        throw std::system_error(make_error_code(CryptoNote::error::MIXIN_COUNT_TOO_SMALL));
    }
    if (mixin > currency.maxMixin()) {
        logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Mixin must be equal to or smaller than " << currency.maxMixin();
        throw std::system_error(make_error_code(CryptoNote::error::MIXIN_COUNT_TOO_LARGE));
    }
}

void validateAddresses(const std::vector<std::string>& addresses, const CryptoNote::Currency& currency, Logging::LoggerRef logger) {
  for (const auto& address: addresses) {
    if (!CryptoNote::validateAddress(address, currency)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't validate address " << address;
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
    }
  }
}

// Resolve an address-or-index selector to the wallet's canonical address string.
// A pure-decimal selector is an address INDEX (0 = the wallet's primary address,
// 1.. = deposit subaddress in issue order) and is mapped to wallet.getAddress(index);
// anything else (a PQ address, a classical address, or an H-I-C / H-I-T-C account
// number) passes through unchanged for the wallet / validateAddress to resolve. This
// is what lets every per-address RPC accept "address OR index" in the same field.
std::string canonicalizeAddressSelector(CryptoNote::IWallet& wallet, const std::string& selector) {
  if (selector.empty()) {
    return selector;
  }
  for (char c : selector) {
    if (c < '0' || c > '9') {
      return selector;  // not a pure-decimal index
    }
  }
  uint64_t index = 0;
  try {
    index = std::stoull(selector);
  } catch (const std::exception&) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS),
                            "address index out of range: " + selector);
  }
  if (index >= wallet.getAddressCount()) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS),
                            "address index out of range: " + selector);
  }
  return wallet.getAddress(static_cast<size_t>(index));
}

std::vector<std::string> canonicalizeAddressSelectors(CryptoNote::IWallet& wallet,
                                                      const std::vector<std::string>& selectors) {
  std::vector<std::string> out;
  out.reserve(selectors.size());
  for (const auto& s : selectors) {
    out.push_back(canonicalizeAddressSelector(wallet, s));
  }
  return out;
}

std::string getValidatedTransactionExtraString(const std::string& extraString) {
  std::vector<uint8_t> binary;
  if (!Common::fromHex(extraString, binary)) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_TRANSACTION_EXTRA));
  }

  return Common::asString(binary);
}

std::vector<std::string> collectDestinationAddresses(const std::vector<PaymentService::WalletRpcOrder>& orders) {
  std::vector<std::string> result;

  result.reserve(orders.size());
  for (const auto& order: orders) {
    result.push_back(order.address);
  }

  return result;
}

std::vector<CryptoNote::WalletOrder> convertWalletRpcOrdersToWalletOrders(const std::vector<PaymentService::WalletRpcOrder>& orders) {
  std::vector<CryptoNote::WalletOrder> result;
  result.reserve(orders.size());

  for (const auto& order: orders) {
    result.emplace_back(CryptoNote::WalletOrder {order.address, order.amount});
  }

  return result;
}

}

void generateNewWallet(const CryptoNote::Currency& currency, const WalletConfiguration& conf, Logging::ILogger& logger, System::Dispatcher& dispatcher, CryptoNote::INode& node, CryptoNote::PqDepositScheme depositScheme) {
  Logging::LoggerRef log(logger, "generateNewWallet");

  CryptoNote::IWallet* wallet = new CryptoNote::WalletGreen(dispatcher, currency, node, logger);
  std::unique_ptr<CryptoNote::IWallet> walletGuard(wallet);

  std::string address;

  // Mint a fresh PQ master seed, or import the given 32-byte seed, as the primary
  // address (record 0). The PQ wallet is single-identity; there is no classical
  // view key, HD batch, or independent-key mode.
  auto createPrimary = [&wallet, &conf](const Crypto::SecretKey* importSeed) -> std::string {
    if (importSeed != nullptr) {
      return conf.scanHeight != 0 ? wallet->createAddress(*importSeed, conf.scanHeight)
                                  : wallet->createAddress(*importSeed);
    }
    return conf.scanHeight != 0 ? wallet->createAddress(conf.scanHeight) : wallet->createAddress();
  };

  if (conf.secretSpendKey.empty() && conf.mnemonicSeed.empty())
  {
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "Generating new PQ wallet";
    wallet->initialize(conf.walletFile, conf.walletPassword);
    address = createPrimary(nullptr);
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "New PQ wallet generated. Address: " << address;
  }
  else if (!conf.mnemonicSeed.empty()) {
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "Importing PQ wallet from mnemonic seed";

    Crypto::SecretKey seed;
    std::string languageName;
    if (!Crypto::ElectrumWords::words_to_bytes(conf.mnemonicSeed, seed, languageName))
    {
      log(Logging::ERROR, Logging::BRIGHT_RED) << "Electrum-style word list failed verification.";
      return;
    }

    wallet->initialize(conf.walletFile, conf.walletPassword);
    address = createPrimary(&seed);
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "Imported PQ wallet from mnemonic. Address: " << address;
  }
  else {
    // Import from a raw 32-byte secret = the PQ master seed. Any view key argument is
    // ignored (PQ has no classical view key).
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "Importing PQ wallet from key";
    Crypto::Hash seed_hash;
    size_t size;
    if (!Common::fromHex(conf.secretSpendKey, &seed_hash, sizeof(seed_hash), size) || size != sizeof(seed_hash)) {
      log(Logging::ERROR, Logging::BRIGHT_RED) << "Invalid spend key (PQ master seed)";
      return;
    }
    Crypto::SecretKey seed = *(struct Crypto::SecretKey *) &seed_hash;
    wallet->initialize(conf.walletFile, conf.walletPassword);
    address = createPrimary(&seed);
    log(Logging::INFO, Logging::BRIGHT_WHITE) << "PQ wallet imported successfully. Address: " << address;
  }

  // Record the deposit-wallet scheme in the container (immutable after creation).
  // It lives in the PQ state blob, which is only serialized at SAVE_ALL, so a
  // freshly generated container is saved at SAVE_ALL (its tx/transfer collections
  // are empty, so this is just the keys + the deposit scheme).
  if (auto* greenWallet = dynamic_cast<CryptoNote::WalletGreen*>(wallet)) {
    if (greenWallet->pqEnabled()) {
      greenWallet->setPqDepositScheme(depositScheme);
      log(Logging::INFO, Logging::BRIGHT_WHITE) << "Deposit scheme: "
        << (depositScheme == CryptoNote::PqDepositScheme::SingleKeyIndex ? "single-key-index" : "aggregated-multikey");

      // Restore the deposit subaddresses. The seed derives every deposit key, but the
      // COUNT is not in the seed (it lives only in the wallet file), so the caller
      // supplies it via restore-address-count (total addresses incl. the primary).
      // This is REQUIRED to recover AggregatedMultikey deposit funds: each deposit
      // output commits to a distinct derived spend key, and the scanner only
      // recognizes an output whose key it has reserved/derived.
      for (uint32_t i = 1; i < conf.restoreAddressCount; ++i) {
        greenWallet->reservePqDepositIndex();
      }
      if (conf.restoreAddressCount > 1) {
        log(Logging::INFO, Logging::BRIGHT_WHITE)
          << "Restored " << (conf.restoreAddressCount - 1) << " deposit address(es) from the seed";
      }
    }
  }

  wallet->save(CryptoNote::WalletSaveLevel::SAVE_ALL);
  log(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet is saved";
}

void changePassword(const CryptoNote::Currency& currency, const WalletConfiguration& conf, Logging::ILogger& logger, System::Dispatcher& dispatcher, CryptoNote::INode& node, const std::string newPassword) {
  Logging::LoggerRef log(logger, "changePassword");
  log(Logging::INFO, Logging::BRIGHT_WHITE) << "Changing wallet password...";

  CryptoNote::IWallet* wallet = new CryptoNote::WalletGreen(dispatcher, currency, node, logger);
  std::unique_ptr<CryptoNote::IWallet> walletGuard(wallet);

  wallet->start();
  wallet->load(conf.walletFile, conf.walletPassword);
  wallet->changePassword(conf.walletPassword, newPassword);
  wallet->save();
}

WalletService::WalletService(const CryptoNote::Currency& currency, System::Dispatcher& sys, CryptoNote::INode& node,
  CryptoNote::IWallet& wallet, const WalletConfiguration& conf, Logging::ILogger& logger) :
    currency(currency),
    wallet(wallet),
    node(node),
    config(conf),
    inited(false),
    logger(logger, "WalletService"),
    dispatcher(sys),
    readyEvent(dispatcher),
    refreshContext(dispatcher)
{
  readyEvent.set();
}

WalletService::~WalletService() {
  if (inited) {
    wallet.stop();
    refreshContext.wait();
    wallet.shutdown();
  }
}

void WalletService::init() {
  loadWallet();
  loadTransactionIdIndex();

  refreshContext.spawn([this] { refresh(); });

  inited = true;
}

void WalletService::saveWallet() {
  wallet.save();
  logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet is saved";
}

void WalletService::loadWallet() {
  logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Loading wallet";
  wallet.load(config.walletFile, config.walletPassword);
  logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet loading is finished.";
}

void WalletService::loadTransactionIdIndex() {
  transactionIdIndex.clear();

  for (size_t i = 0; i < wallet.getTransactionCount(); ++i) {
    transactionIdIndex.emplace(Common::podToHex(wallet.getTransaction(i).hash), i);
  }
}

std::error_code WalletService::saveWalletNoThrow() {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Saving wallet...";

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Save impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    saveWallet();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while saving wallet: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while saving wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::resetWallet() {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Resetting wallet";

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Reset impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    reset();
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet has been reset";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while resetting wallet: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while resetting wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::resetWallet(const uint32_t scanHeight) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Resetting wallet";

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Reset impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    wallet.reset(scanHeight);
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Wallet has been reset starting scanning from height " << scanHeight;
  }
  catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while resetting wallet: " << x.what();
    return x.code();
  }
  catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while resetting wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::exportWallet(const std::string& fileName) {
  try {
    System::EventLock lk(readyEvent);

    if (!inited) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Export impossible: Wallet Service is not initialized";
      return make_error_code(CryptoNote::error::NOT_INITIALIZED);
    }

    boost::filesystem::path walletPath(config.walletFile);
    boost::filesystem::path exportPath = walletPath.parent_path() / fileName;

    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "Exporting wallet to " << exportPath.string();
    wallet.exportWallet(exportPath.string());
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while exporting wallet: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while exporting wallet: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::replaceWithNewWallet(const std::string& viewSecretKeyText) {
  try {
    System::EventLock lk(readyEvent);

    Crypto::SecretKey viewSecretKey;
    if (!Common::podFromHex(viewSecretKeyText, viewSecretKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Cannot restore view secret key: " << viewSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    Crypto::PublicKey viewPublicKey;
    if (!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Cannot derive view public key, wrong secret key: " << viewSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    replaceWithNewWallet(viewSecretKey);
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "The container has been replaced";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while replacing container: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while replacing container: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::replaceWithNewWallet(const std::string& viewSecretKeyText, const uint32_t scanHeight) {
  try {
    System::EventLock lk(readyEvent);

    Crypto::SecretKey viewSecretKey;
    if (!Common::podFromHex(viewSecretKeyText, viewSecretKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Cannot restore view secret key: " << viewSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    Crypto::PublicKey viewPublicKey;
    if (!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Cannot derive view public key, wrong secret key: " << viewSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    replaceWithNewWallet(viewSecretKey, scanHeight);
    logger(Logging::INFO, Logging::BRIGHT_WHITE) << "The container has been replaced";
  }
  catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while replacing container: " << x.what();
    return x.code();
  }
  catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while replacing container: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::createAddress(const std::string& spendSecretKeyText, bool reset, std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating address";

    Crypto::SecretKey secretKey;
    if (!Common::podFromHex(spendSecretKeyText, secretKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Wrong key format: " << spendSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = wallet.createAddress(secretKey, reset);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletService::createAddress(const std::string& spendSecretKeyText, const uint32_t scanHeight, std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating address";

    Crypto::SecretKey secretKey;
    if (!Common::podFromHex(spendSecretKeyText, secretKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Wrong key format: " << spendSecretKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = wallet.createAddress(secretKey, scanHeight);
  }
  catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletService::createAddress(std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating address";

    address = wallet.createAddress();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;

  return std::error_code();
}

std::error_code WalletService::createTrackingAddress(const std::string& spendPublicKeyText, std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating tracking address";

    Crypto::PublicKey publicKey;
    if (!Common::podFromHex(spendPublicKeyText, publicKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Wrong key format: " << spendPublicKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = wallet.createAddress(publicKey);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating tracking address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;
  return std::error_code();
}

std::error_code WalletService::createTrackingAddress(const std::string& spendPublicKeyText, const uint32_t scanHeight, std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Creating tracking address";

    Crypto::PublicKey publicKey;
    if (!Common::podFromHex(spendPublicKeyText, publicKey)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Wrong key format: " << spendPublicKeyText;
      return make_error_code(CryptoNote::error::WalletServiceErrorCode::WRONG_KEY_FORMAT);
    }

    address = wallet.createAddress(publicKey, scanHeight);
  }
  catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating tracking address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Created address " << address;
  return std::error_code();
}

std::error_code WalletService::deleteAddress(const std::string& address) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Delete address request came";
    wallet.deleteAddress(address);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while deleting address: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Address " << address << " successfully deleted";
  return std::error_code();
}

std::error_code WalletService::hasAddress(const std::string& address, bool& isOurs) {
  try {
    System::EventLock lk(readyEvent);

    logger(Logging::DEBUGGING) << "Has address request came";

    isOurs = wallet.isMyAddress(canonicalizeAddressSelector(wallet, address));
    if (!isOurs) {
      logger(Logging::DEBUGGING, Logging::BRIGHT_YELLOW) << "Address " << address << " doesn't exist in container";
      //return make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND);
    } else {
      logger(Logging::DEBUGGING) << "Address " << address << " exists in container";
    }
  }
  catch (std::system_error& x) {
    logger(Logging::DEBUGGING, Logging::BRIGHT_YELLOW) << "Error while checking if address exists in container: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getSpendkeys(const std::string& address, std::string& publicSpendKeyText, std::string& secretSpendKeyText) {
  try {
    System::EventLock lk(readyEvent);

    CryptoNote::KeyPair key = wallet.getAddressSpendKey(canonicalizeAddressSelector(wallet, address));

    publicSpendKeyText = Common::podToHex(key.publicKey);
    secretSpendKeyText = Common::podToHex(key.secretKey);

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting spend key: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getBalance(const std::string& address, uint64_t& availableBalance, uint64_t& lockedAmount) {
  try {
    System::EventLock lk(readyEvent);
    const std::string resolved = canonicalizeAddressSelector(wallet, address);
    logger(Logging::DEBUGGING) << "Getting balance for address " << resolved;

    availableBalance = wallet.getActualBalance(resolved);
    lockedAmount = wallet.getPendingBalance(resolved);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting balance: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << address << " actual balance: " << availableBalance << ", pending: " << lockedAmount;
  return std::error_code();
}

std::error_code WalletService::getBalance(uint64_t& availableBalance, uint64_t& lockedAmount) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Getting wallet balance";

    availableBalance = wallet.getActualBalance();
    lockedAmount = wallet.getPendingBalance();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting balance: " << x.what();
    return x.code();
  }

  logger(Logging::DEBUGGING) << "Wallet actual balance: " << availableBalance << ", pending: " << lockedAmount;
  return std::error_code();
}

std::error_code WalletService::getBlockHashes(uint32_t firstBlockIndex, uint32_t blockCount, std::vector<std::string>& blockHashes) {
  try {
    System::EventLock lk(readyEvent);
    std::vector<Crypto::Hash> hashes = wallet.getBlockHashes(firstBlockIndex, blockCount);

    blockHashes.reserve(hashes.size());
    for (const auto& hash: hashes) {
      blockHashes.push_back(Common::podToHex(hash));
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting block hashes: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getViewKey(std::string& viewSecretKey) {
  try {
    System::EventLock lk(readyEvent);
    CryptoNote::KeyPair viewKey = wallet.getViewKey();
    viewSecretKey = Common::podToHex(viewKey.secretKey);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting view key: " << x.what();
    return x.code();
  }

  return std::error_code();
}


std::error_code WalletService::getMnemonicSeed(const std::string& address, std::string& mnemonicSeed) {
  try {
    System::EventLock lk(readyEvent);

    // The PQ master seed IS the deterministic backup; encode it as Electrum words.
    // (PQ wallets are single-identity, so the address is irrelevant.)
    (void)address;
    Crypto::ElectrumWords::bytes_to_words(wallet.getDeterministicSeed(), mnemonicSeed, "English");
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting mnemonic seed: " << x.what();
    return x.code();
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionHashes(const std::vector<std::string>& addresses, const std::string& blockHashString,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes) {
  try {
    System::EventLock lk(readyEvent);
    const std::vector<std::string> resolvedAddresses = canonicalizeAddressSelectors(wallet, addresses);
    validateAddresses(resolvedAddresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(resolvedAddresses, paymentId);
    Crypto::Hash blockHash = parseHash(blockHashString, logger);

    transactionHashes = getRpcTransactionHashes(blockHash, blockCount, transactionFilter);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionHashes(const std::vector<std::string>& addresses, uint32_t firstBlockIndex,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes) {
  try {
    System::EventLock lk(readyEvent);
    const std::vector<std::string> resolvedAddresses = canonicalizeAddressSelectors(wallet, addresses);
    validateAddresses(resolvedAddresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(resolvedAddresses, paymentId);
    transactionHashes = getRpcTransactionHashes(firstBlockIndex, blockCount, transactionFilter);

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactions(const std::vector<std::string>& addresses, const std::string& blockHashString,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactions) {
  try {
    System::EventLock lk(readyEvent);
    const std::vector<std::string> resolvedAddresses = canonicalizeAddressSelectors(wallet, addresses);
    validateAddresses(resolvedAddresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(resolvedAddresses, paymentId);

    Crypto::Hash blockHash = parseHash(blockHashString, logger);

    std::vector<TransactionsInBlockRpcInfo> txs = getRpcTransactions(blockHash, blockCount, transactionFilter);
    for (TransactionsInBlockRpcInfo& b : txs){
      for (TransactionRpcInfo& t : b.transactions) {
        t.confirmations = (t.blockIndex != UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX ? wallet.getBlockCount() - t.blockIndex : 0);
      }
    }
    transactions = txs;
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactions(const std::vector<std::string>& addresses, uint32_t firstBlockIndex,
  uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactions) {
  try {
    System::EventLock lk(readyEvent);
    const std::vector<std::string> resolvedAddresses = canonicalizeAddressSelectors(wallet, addresses);
    validateAddresses(resolvedAddresses, currency, logger);

    if (!paymentId.empty()) {
      validatePaymentId(paymentId, logger);
    }

    TransactionsInBlockInfoFilter transactionFilter(resolvedAddresses, paymentId);

    std::vector<TransactionsInBlockRpcInfo> txs = getRpcTransactions(firstBlockIndex, blockCount, transactionFilter);
    for (TransactionsInBlockRpcInfo& b : txs){
      for (TransactionRpcInfo& t : b.transactions) {
        t.confirmations = (t.blockIndex != UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX ? wallet.getBlockCount() - t.blockIndex : 0);
      }
    }
    transactions = txs;
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transactions: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransaction(const std::string& transactionHash, TransactionRpcInfo& transaction) {
  try {
    System::EventLock lk(readyEvent);
    Crypto::Hash hash = parseHash(transactionHash, logger);

    CryptoNote::WalletTransactionWithTransfers transactionWithTransfers = wallet.getTransaction(hash);

    if (transactionWithTransfers.transaction.state == CryptoNote::WalletTransactionState::DELETED) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Transaction " << transactionHash << " is deleted";
      return make_error_code(CryptoNote::error::OBJECT_NOT_FOUND);
    }

    TransactionRpcInfo tempTrans = convertTransactionWithTransfersToTransactionRpcInfo(transactionWithTransfers);
    tempTrans.confirmations = (transactionWithTransfers.transaction.blockHeight != UNCONFIRMED_TRANSACTION_GLOBAL_OUTPUT_INDEX ? wallet.getBlockCount() - transactionWithTransfers.transaction.blockHeight : 0);
    transaction = tempTrans;

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionSecretKey(const std::string& transactionHash, std::string& transactionSecretKey) {
  try {
    System::EventLock lk(readyEvent);
    Crypto::Hash hash = parseHash(transactionHash, logger);

    Crypto::SecretKey txSecretKey = wallet.getTransactionSecretKey(hash);

    if (txSecretKey == CryptoNote::NULL_SECRET_KEY) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Transaction " << transactionHash << " secret key is not available";
      return make_error_code(CryptoNote::error::OBJECT_NOT_FOUND);
    }

    transactionSecretKey = Common::podToHex(txSecretKey);

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction secret key: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction secret key: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getTransactionProof(const std::string& transactionHash, const std::string& destinationAddress, const std::string& transactionSecretKey, std::string& transactionProof) {
  try {
    System::EventLock lk(readyEvent);
    Crypto::Hash hash = parseHash(transactionHash, logger);

    Crypto::SecretKey txSecretKey = wallet.getTransactionSecretKey(hash);

    if (!transactionSecretKey.empty()) {  
      Crypto::SecretKey txSecretKeyFromReq;
      Crypto::Hash tx_key_hash;
      size_t size;
      if (!Common::fromHex(transactionSecretKey, &tx_key_hash, sizeof(tx_key_hash), size) || size != sizeof(tx_key_hash)) {
        logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to parse tx secret key: " << transactionSecretKey;
        return make_error_code(CryptoNote::error::WRONG_TX_SECRET_KEY);
      }
      txSecretKeyFromReq = *(struct Crypto::SecretKey *) &tx_key_hash;

      if (txSecretKey != CryptoNote::NULL_SECRET_KEY && txSecretKey != txSecretKeyFromReq) {
        logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Transaction secret keys do not match";
        return make_error_code(CryptoNote::error::WRONG_TX_SECRET_KEY);
      }
      txSecretKey = txSecretKeyFromReq;
    }
    else if (txSecretKey == CryptoNote::NULL_SECRET_KEY) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Transaction secret key not found";
      return make_error_code(CryptoNote::error::WRONG_PARAMETERS);
    }

    CryptoNote::AccountPublicAddress destAddress;
    if (!currency.parseAccountAddressString(destinationAddress, destAddress)) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to parse address: " << destinationAddress;
      return make_error_code(CryptoNote::error::BAD_ADDRESS);
    }

    std::string sig_str;
    if (wallet.getTransactionProof(hash, destAddress, txSecretKey, sig_str)) {
      transactionProof = sig_str;
    }
    else {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to get transaction proof";
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }

  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction proof: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting transaction proof: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::signMessage(const std::string& message, const std::string& address, std::string& signature) {
  try {
    System::EventLock lk(readyEvent);

    // Accept an address index / account number / address as the signing selector
    // (empty = the primary identity).
    signature = wallet.signMessage(message, canonicalizeAddressSelector(wallet, address));
  }
  catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while signing message: " << x.what();
    return x.code();
  }
  catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while signing message: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }
  return std::error_code();
}

std::error_code WalletService::verifyMessage(const std::string& message, const std::string& signature, const std::string& address, bool& isValid) {
  try {
    System::EventLock lk(readyEvent);

    // A numeric index resolves to one of our addresses; any address / account number
    // passes through (you can verify against an external signer's address too).
    isValid = wallet.verifyMessage(message, canonicalizeAddressSelector(wallet, address), signature);
  }
  catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while verifying message: " << x.what();
    return x.code();
  }
  catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while verifying message: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }
  return std::error_code();
}

std::error_code WalletService::getAddresses(std::vector<std::string>& addresses) {
  try {
    System::EventLock lk(readyEvent);

    addresses.clear();
    addresses.reserve(wallet.getAddressCount());

    for (size_t i = 0; i < wallet.getAddressCount(); ++i) {
      addresses.push_back(wallet.getAddress(i));
    }
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Can't get addresses: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getAddressesCount(size_t& addressesCount) {
  try {
    System::EventLock lk(readyEvent);

    addressesCount = wallet.getAddressCount();
  }
  catch (std::exception& e) {
    logger(Logging::WARNING) << "Can't get addresses count : " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getPqAddress(std::string& pqAddress, bool& pqEnabled) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Getting address";

    // The PQ surface is concrete on WalletGreen, not on the IWallet interface.
    auto* greenWallet = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    if (greenWallet == nullptr) {
      pqEnabled = false;
      pqAddress.clear();
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }
    pqEnabled = greenWallet->pqEnabled();
    pqAddress = greenWallet->getPqAddress();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting address: " << x.what();
    return x.code();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting address: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getPqBalance(uint64_t& availableBalance, uint32_t& scannedHeight, bool& pqEnabled) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Getting balance";

    auto* greenWallet = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    if (greenWallet == nullptr) {
      pqEnabled = false;
      availableBalance = 0;
      scannedHeight = 0;
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }
    pqEnabled = greenWallet->pqEnabled();
    availableBalance = greenWallet->pqActualBalance();
    scannedHeight = greenWallet->pqSyncedHeight();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting balance: " << x.what();
    return x.code();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting balance: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  logger(Logging::DEBUGGING) << "Available balance: " << availableBalance << ", scanned height: " << scannedHeight;
  return std::error_code();
}

std::error_code WalletService::registerPqAccount(std::string& transactionHash) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Registering account number (free, anti-spam PoW)";

    auto* greenWallet = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    std::string viewHex, spendHex;
    if (greenWallet == nullptr || !greenWallet->pqEnabled() ||
        !greenWallet->getPqRegistrationKeysHex(viewHex, spendHex)) {
      logger(Logging::WARNING) << "Registration unavailable (no spend authority)";
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }

    // Reference a recent main-chain block (validated within FREE_REG_REF_WINDOW).
    Crypto::Hash refBlockHash = node.getLastLocalBlockHeaderInfo().hash;
    if (refBlockHash == Crypto::Hash{}) {
      logger(Logging::WARNING) << "Node has no known block to reference yet";
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }

    // Build (grind PoW) inside the wallet, then relay through the node. The node
    // proxy runs on its own dispatcher thread, so the future wait does not deadlock.
    CryptoNote::Transaction tx = greenWallet->buildPqFreeRegTransaction(refBlockHash);

    auto relayCompleted = std::promise<std::error_code>();
    auto relayFuture = relayCompleted.get_future();
    node.relayTransaction(tx, [&relayCompleted](std::error_code error) {
      auto detached = std::move(relayCompleted);
      detached.set_value(error);
    });
    std::error_code relayError = relayFuture.get();
    if (relayError) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to relay registration: " << relayError.message();
      return relayError;
    }

    transactionHash = Common::podToHex(CryptoNote::getObjectHash(tx));
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while registering account number: " << x.what();
    return x.code();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while registering account number: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  logger(Logging::DEBUGGING) << "Registration submitted, tx hash: " << transactionHash;
  return std::error_code();
}

std::error_code WalletService::registerPqAccountPaid(std::string& transactionHash) {
  try {
    System::EventLock lk(readyEvent);
    auto* gw = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    std::string viewHex, spendHex;
    if (gw == nullptr || !gw->pqEnabled() || !gw->getPqRegistrationKeysHex(viewHex, spendHex)) {
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }
    // A paid registration is a fee-paying TX_PQ carrying the registration tag.
    CryptoNote::PqSendResult r = gw->registerPqAccountPaid();
    transactionHash = Common::podToHex(CryptoNote::getObjectHash(r.tx));
    logger(Logging::DEBUGGING) << "Paid registration tx " << transactionHash << " has been sent";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error during paid registration: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error during paid registration: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }
  return std::error_code();
}

std::error_code WalletService::getPqAccountStatus(bool& registered, std::string& accountNumber,
                                                  uint32_t& blockHeight, uint32_t& txIndex) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Getting account status";

    registered = false;
    accountNumber.clear();
    blockHeight = 0;
    txIndex = 0;

    auto* greenWallet = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    if (greenWallet == nullptr) {
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }
    std::string viewHex, spendHex;
    if (!greenWallet->getPqRegistrationKeysHex(viewHex, spendHex)) {
      // No spend authority: account-number registration is not available.
      return std::error_code();
    }

    auto statusCompleted = std::promise<std::error_code>();
    auto statusFuture = statusCompleted.get_future();
    node.getPqAccount(viewHex, spendHex, registered, blockHeight, txIndex,
                      [&statusCompleted](std::error_code error) {
                        auto detached = std::move(statusCompleted);
                        detached.set_value(error);
                      });
    std::error_code statusError = statusFuture.get();
    if (statusError) {
      logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Failed to query account: " << statusError.message();
      return statusError;
    }

    if (registered) {
      accountNumber = CryptoNote::AccountNumber{blockHeight, txIndex}.toString();
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting account status: " << x.what();
    return x.code();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting account status: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

namespace {

const char* depositSchemeName(CryptoNote::PqDepositScheme s) {
  return s == CryptoNote::PqDepositScheme::SingleKeyIndex ? "single-key-index" : "aggregated-multikey";
}

// Resolve this wallet's OWN PQ account registration coords (H, I) via the node.
// `registered` is false (with H=I=0) when the wallet has no PQ identity or is unregistered.
std::error_code resolveOwnPqRegistration(CryptoNote::INode& node, CryptoNote::WalletGreen& gw,
                                         bool& registered, uint32_t& blockHeight, uint32_t& txIndex) {
  registered = false;
  blockHeight = 0;
  txIndex = 0;
  std::string viewHex, spendHex;
  if (!gw.getPqRegistrationKeysHex(viewHex, spendHex)) {
    return std::error_code();  // no spend authority: nothing registered
  }
  auto completed = std::promise<std::error_code>();
  auto fut = completed.get_future();
  node.getPqAccount(viewHex, spendHex, registered, blockHeight, txIndex,
                    [&completed](std::error_code e) {
                      auto detached = std::move(completed);
                      detached.set_value(e);
                    });
  return fut.get();
}

}  // namespace

std::error_code WalletService::getPqDepositScheme(std::string& scheme, uint32_t& depositCount) {
  try {
    System::EventLock lk(readyEvent);
    auto* gw = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    if (gw == nullptr) {
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }
    scheme = depositSchemeName(gw->getPqDepositScheme());
    depositCount = gw->getPqDepositCount();
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting deposit scheme: " << x.what();
    return x.code();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting deposit scheme: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }
  return std::error_code();
}

std::error_code WalletService::createPqDepositAddress(std::string& address, uint32_t& index) {
  try {
    System::EventLock lk(readyEvent);
    logger(Logging::DEBUGGING) << "Creating deposit address";

    auto* gw = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    if (gw == nullptr || !gw->pqEnabled()) {
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }

    // single-key-index deposit identities are H-I-T-C, which needs the account's
    // on-chain registration coords (H, I). Resolve them first; require registration.
    uint32_t regH = 0, regI = 0;
    if (gw->getPqDepositScheme() == CryptoNote::PqDepositScheme::SingleKeyIndex) {
      bool registered = false;
      std::error_code rc = resolveOwnPqRegistration(node, *gw, registered, regH, regI);
      if (rc) {
        return rc;
      }
      if (!registered) {
        logger(Logging::WARNING) << "single-key-index deposit address requested before the account is registered";
        return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
      }
    }

    index = gw->reservePqDepositIndex();
    address = gw->pqDepositAddress(index, regH, regI);
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating deposit address: " << x.what();
    return x.code();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while creating deposit address: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }
  return std::error_code();
}

std::error_code WalletService::listPqDepositAddresses(std::vector<std::string>& addresses,
                                                      std::vector<uint32_t>& indices) {
  try {
    System::EventLock lk(readyEvent);
    addresses.clear();
    indices.clear();

    auto* gw = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    if (gw == nullptr || !gw->pqEnabled()) {
      return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
    }

    uint32_t regH = 0, regI = 0;
    if (gw->getPqDepositScheme() == CryptoNote::PqDepositScheme::SingleKeyIndex) {
      bool registered = false;
      std::error_code rc = resolveOwnPqRegistration(node, *gw, registered, regH, regI);
      if (rc) {
        return rc;
      }
      // If unregistered we simply cannot render H-I-T-C; return the empty list.
      if (!registered) {
        return std::error_code();
      }
    }

    uint32_t count = gw->getPqDepositCount();
    addresses.reserve(count);
    indices.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
      addresses.push_back(gw->pqDepositAddress(i, regH, regI));
      indices.push_back(i);
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while listing deposit addresses: " << x.what();
    return x.code();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while listing deposit addresses: " << e.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }
  return std::error_code();
}

std::error_code WalletService::sendTransaction(const SendTransaction::Request& request, std::string& transactionHash, std::string& transactionSecretKey) {
  try {
    System::EventLock lk(readyEvent);

    // PQ-native path: destinations are PQ addresses / account numbers, the build +
    // relay go through the common sender, and ring/mixin params are not applicable.
    auto* gw = dynamic_cast<CryptoNote::WalletGreen*>(&wallet);
    if (gw != nullptr && gw->pqEnabled()) {
      std::vector<CryptoNote::PqSendOutput> recipients;
      recipients.reserve(request.transfers.size());
      for (const auto& t : request.transfers) {
        CryptoPQ::KemPublicKey viewPub;
        CryptoPQ::DsaPublicKey spendPub;
        uint64_t subaddrT = 0;
        const std::string recipient = canonicalizeAddressSelector(wallet, t.address);
        if (!CryptoNote::resolvePqRecipient(node, recipient, viewPub, spendPub, subaddrT)) {
          logger(Logging::WARNING) << "Invalid recipient: " << recipient;
          return make_error_code(CryptoNote::error::BAD_ADDRESS);
        }
        recipients.push_back(CryptoNote::PqSendOutput{viewPub, spendPub, t.amount, subaddrT});
      }
      // Restrict the spend to the requested source addresses (index / address /
      // account-number selectors all resolve to buckets inside the wallet).
      const std::vector<std::string> sourceAddresses =
          canonicalizeAddressSelectors(wallet, request.sourceAddresses);

      // Change destination — the original CryptoNote getChangeDestination /
      // validateChangeDestination rule: an explicit changeAddress (valid and ours),
      // else the wallet's sole address, else the sole source address; otherwise the
      // change destination is ambiguous and must be given.
      std::string changeAddress;
      if (!request.changeAddress.empty()) {
        changeAddress = canonicalizeAddressSelector(wallet, request.changeAddress);
        if (!CryptoNote::validateAddress(changeAddress, currency)) {
          logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Bad change address: " << changeAddress;
          return make_error_code(CryptoNote::error::BAD_ADDRESS);
        }
        if (!wallet.isMyAddress(changeAddress)) {
          logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Change address is not ours: " << changeAddress;
          return make_error_code(CryptoNote::error::CHANGE_ADDRESS_NOT_FOUND);
        }
      } else if (wallet.getAddressCount() == 1) {
        changeAddress.clear();  // the sole address; sendPqTransfer routes change to it
      } else if (sourceAddresses.size() == 1) {
        changeAddress = sourceAddresses[0];
      } else {
        logger(Logging::WARNING, Logging::BRIGHT_YELLOW)
            << "Change address is required when the wallet has deposits and the source is ambiguous";
        return make_error_code(CryptoNote::error::CHANGE_ADDRESS_REQUIRED);
      }

      CryptoNote::PqSendResult r = gw->sendPqTransfer(recipients, request.fee, request.unlockHeight,
                                                      std::vector<uint8_t>{}, sourceAddresses, changeAddress);
      transactionHash = Common::podToHex(CryptoNote::getObjectHash(r.tx));
      transactionSecretKey.clear();  // PQ transactions carry no per-tx secret key
      logger(Logging::DEBUGGING) << "Transaction " << transactionHash << " has been sent";
      return std::error_code();
    }

    validateAddresses(request.sourceAddresses, currency, logger);
    validateAddresses(collectDestinationAddresses(request.transfers), currency, logger);
    if (!request.changeAddress.empty()) {
      validateAddresses({ request.changeAddress }, currency, logger);
    }
    validateMixin(request.anonymity, currency, logger);

    CryptoNote::TransactionParameters sendParams;
    if (!request.paymentId.empty()) {
      addPaymentIdToExtra(request.paymentId, sendParams.extra);
    } else {
      sendParams.extra = getValidatedTransactionExtraString(request.extra);
    }

    sendParams.sourceAddresses = request.sourceAddresses;
    sendParams.destinations = convertWalletRpcOrdersToWalletOrders(request.transfers);
    sendParams.fee = request.fee;
    sendParams.mixIn = request.anonymity;
    sendParams.unlockHeightstamp = request.unlockHeight;
    sendParams.changeDestination = request.changeAddress;

    Crypto::SecretKey tx_key;
    size_t transactionId = wallet.transfer(sendParams, tx_key);
    transactionHash = Common::podToHex(wallet.getTransaction(transactionId).hash);
    transactionSecretKey = Common::podToHex(tx_key);

    logger(Logging::DEBUGGING) << "Transaction " << transactionHash << " has been sent";
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending transaction: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while sending transaction: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getUnconfirmedTransactionHashes(const std::vector<std::string>& addresses, std::vector<std::string>& transactionHashes) {
  try {
    System::EventLock lk(readyEvent);

    const std::vector<std::string> resolvedAddresses = canonicalizeAddressSelectors(wallet, addresses);
    validateAddresses(resolvedAddresses, currency, logger);

    std::vector<CryptoNote::WalletTransactionWithTransfers> transactions = wallet.getUnconfirmedTransactions();

    TransactionsInBlockInfoFilter transactionFilter(resolvedAddresses, "");

    for (const auto& transaction: transactions) {
      if (transactionFilter.checkTransaction(transaction)) {
        transactionHashes.emplace_back(Common::podToHex(transaction.transaction.hash));
      }
    }
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting unconfirmed transaction hashes: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting unconfirmed transaction hashes: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::getStatus(uint32_t& blockCount, uint32_t& knownBlockCount, uint32_t& localDaemonBlockCount, std::string& lastBlockHash, uint32_t& peerCount, uint64_t& minimalFee) {
  try {
    System::EventLock lk(readyEvent);

    knownBlockCount = node.getKnownBlockCount();
    peerCount = static_cast<uint32_t>(node.getPeerCount());
    blockCount = wallet.getBlockCount();
    localDaemonBlockCount = node.getLocalBlockCount();
    minimalFee = node.getMinimalFee();

    auto lastHashes = wallet.getBlockHashes(blockCount - 1, 1);
    lastBlockHash = Common::podToHex(lastHashes.back());
  } catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting status: " << x.what();
    return x.code();
  } catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while getting status: " << x.what();
    return make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR);
  }

  return std::error_code();
}

std::error_code WalletService::validateAddress(const std::string& address, bool& isValid, std::string& _address, std::string& spendPublicKey, std::string& viewPublicKey) {
  try {
    System::EventLock lk(readyEvent);

    // Accept any selector form: a numeric index resolves to one of our addresses,
    // then classical / PQ / H-I-C / H-I-T-C account number are all recognized.
    const std::string resolved = canonicalizeAddressSelector(wallet, address);

    CryptoNote::AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
    if (currency.parseAccountAddressString(resolved, acc)) {
      isValid = true;
      _address = currency.accountAddressAsString(acc);
      spendPublicKey = Common::podToHex(acc.spendPublicKey);
      viewPublicKey = Common::podToHex(acc.viewPublicKey);
    }
    else if (CryptoNote::validateAddress(resolved, currency)) {
      // A PQ address or an H-I-C / H-I-T-C account number: valid, but its spend/view
      // authority is not a classical 32-byte keypair (PQ keys are large; account-
      // number keys live on-chain), so only echo the normalized address.
      isValid = true;
      _address = resolved;
      spendPublicKey.clear();
      viewPublicKey.clear();
    }
    else {
      isValid = false;
    }
  }
  catch (std::system_error& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while validating address: " << x.what();
     return x.code();
  }
  catch (std::exception& x) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Error while validating address: " << x.what();
    return make_error_code(CryptoNote::error::BAD_ADDRESS);
  }

  return std::error_code();
}

void WalletService::refresh() {
  try {
    logger(Logging::DEBUGGING) << "Refresh is started";
    for (;;) {
      auto event = wallet.getEvent();
      if (event.type == CryptoNote::TRANSACTION_CREATED) {
        size_t transactionId = event.transactionCreated.transactionIndex;
        transactionIdIndex.emplace(Common::podToHex(wallet.getTransaction(transactionId).hash), transactionId);
      }
    }
  } catch (std::system_error& e) {
    logger(Logging::DEBUGGING) << "refresh is stopped: " << e.what();
  } catch (std::exception& e) {
    logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "exception thrown in refresh(): " << e.what();
  }
}

void WalletService::reset() {
  wallet.save(CryptoNote::WalletSaveLevel::SAVE_KEYS_ONLY);
  wallet.stop();
  wallet.shutdown();
  inited = false;
  refreshContext.wait();

  wallet.start();
  init();
}

void WalletService::replaceWithNewWallet(const Crypto::SecretKey& viewSecretKey, const uint32_t scanHeight) {
  wallet.stop();
  wallet.shutdown();
  inited = false;
  refreshContext.wait();

  transactionIdIndex.clear();

  size_t i = 0;
  for (;;) {
    boost::system::error_code ec;
    std::string backup = config.walletFile + ".backup";
    if (i != 0) {
      backup += "." + std::to_string(i);
    }

    if (!boost::filesystem::exists(backup)) {
      boost::filesystem::rename(config.walletFile, backup);
      logger(Logging::DEBUGGING) << "Walletd file '" << config.walletFile  << "' backed up to '" << backup << '\'';
      break;
    }
  }

  wallet.start();
  wallet.initializeWithViewKey(config.walletFile, config.walletPassword, viewSecretKey, scanHeight);
  inited = true;
}

void WalletService::replaceWithNewWallet(const Crypto::SecretKey& viewSecretKey) {
  wallet.stop();
  wallet.shutdown();
  inited = false;
  refreshContext.wait();

  transactionIdIndex.clear();

  size_t i = 0;
  for (;;) {
    boost::system::error_code ec;
    std::string backup = config.walletFile + ".backup";
    if (i != 0) {
      backup += "." + std::to_string(i);
    }

    if (!boost::filesystem::exists(backup)) {
      boost::filesystem::rename(config.walletFile, backup);
      logger(Logging::DEBUGGING) << "Walletd file '" << config.walletFile  << "' backed up to '" << backup << '\'';
      break;
    }
  }

  wallet.start();
  wallet.initializeWithViewKey(config.walletFile, config.walletPassword, viewSecretKey);
  inited = true;
}

std::vector<CryptoNote::TransactionsInBlockInfo> WalletService::getTransactions(const Crypto::Hash& blockHash, size_t blockCount) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> result = wallet.getTransactions(blockHash, blockCount);
  if (result.empty()) {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  return result;
}

std::vector<CryptoNote::TransactionsInBlockInfo> WalletService::getTransactions(uint32_t firstBlockIndex, size_t blockCount) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> result = wallet.getTransactions(firstBlockIndex, blockCount);
  if (result.empty()) {
    throw std::system_error(make_error_code(CryptoNote::error::WalletServiceErrorCode::OBJECT_NOT_FOUND));
  }

  return result;
}

std::vector<TransactionHashesInBlockRpcInfo> WalletService::getRpcTransactionHashes(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(blockHash, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionHashesInBlockRpcInfo> WalletService::getRpcTransactionHashes(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(firstBlockIndex, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionHashesInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionsInBlockRpcInfo> WalletService::getRpcTransactions(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(blockHash, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(filteredTransactions);
}

std::vector<TransactionsInBlockRpcInfo> WalletService::getRpcTransactions(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const {
  std::vector<CryptoNote::TransactionsInBlockInfo> allTransactions = getTransactions(firstBlockIndex, blockCount);
  std::vector<CryptoNote::TransactionsInBlockInfo> filteredTransactions = filterTransactions(allTransactions, filter);
  return convertTransactionsInBlockInfoToTransactionsInBlockRpcInfo(filteredTransactions);
}

} //namespace PaymentService
