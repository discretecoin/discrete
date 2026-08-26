// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019, The Cash2 developers
// Copyright (c) 2021-2023, The Talleo developers
// Copyright (c) 2016-2024, The Karbo developers
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

#pragma once

#include <System/ContextGroup.h>
#include <System/Dispatcher.h>
#include <System/Event.h>
#include "IWallet.h"
#include "INode.h"
#include "CryptoNoteCore/Currency.h"
#include "Wallet/PqWallet.h"  // CryptoNote::PqDepositScheme
#include "PaymentServiceJsonRpcMessages.h"
#ifdef _WIN32
#undef ERROR //TODO: workaround for windows build. fix it
#endif
#include "Logging/LoggerRef.h"

#include <fstream>
#include <memory>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/hashed_index.hpp>

namespace PaymentService {

struct WalletConfiguration {
  std::string walletFile;
  std::string walletPassword;
  std::string secretViewKey;
  std::string secretSpendKey;
  std::string mnemonicSeed;
  bool generateDeterministic = false;
  uint32_t scanHeight = 0;
  uint32_t restoreAddressCount = 1;
};

void generateNewWallet(const CryptoNote::Currency& currency, const WalletConfiguration& conf, Logging::ILogger& logger, System::Dispatcher& dispatcher, CryptoNote::INode& node, CryptoNote::PqDepositScheme depositScheme = CryptoNote::PqDepositScheme::AggregatedMultikey);
void changePassword(const CryptoNote::Currency& currency, const WalletConfiguration& conf, Logging::ILogger& logger, System::Dispatcher& dispatcher, CryptoNote::INode& node, const std::string newPassword);

struct TransactionsInBlockInfoFilter;

class WalletService {
public:
  WalletService(const CryptoNote::Currency& currency, System::Dispatcher& sys, CryptoNote::INode& node, CryptoNote::IWallet& wallet,
    const WalletConfiguration& conf, Logging::ILogger& logger);
  virtual ~WalletService();

  void init();
  void saveWallet();

  std::error_code saveWalletNoThrow();
  std::error_code rescanWallet();
  std::error_code rescanWallet(const uint32_t scanHeight);
  std::error_code resetWallet();
  std::error_code resetWallet(const uint32_t scanHeight);
  std::error_code exportWallet(const std::string& fileName);
  std::error_code replaceWithNewWallet(const std::string& viewSecretKey);
  std::error_code replaceWithNewWallet(const std::string& viewSecretKey, const uint32_t scanHeight);
  std::error_code createAddress(const std::string& spendSecretKeyText, bool reset, std::string& address);
  std::error_code createAddress(const std::string& spendSecretKeyText, const uint32_t scanHeight, std::string& address);
  std::error_code createAddress(std::string& address);
  std::error_code createTrackingAddress(const std::string& spendPublicKeyText, std::string& address);
  std::error_code createTrackingAddress(const std::string& spendPublicKeyText, const uint32_t scanHeight, std::string& address);
  std::error_code deleteAddress(const std::string& address);
  std::error_code hasAddress(const std::string& address, bool& isOurs);
  std::error_code getSpendkeys(const std::string& address, std::string& publicSpendKeyText, std::string& secretSpendKeyText);
  std::error_code getBalance(const std::string& address, uint64_t& availableBalance, uint64_t& lockedAmount);
  std::error_code getBalance(uint64_t& availableBalance, uint64_t& lockedAmount);
  std::error_code getBlockHashes(uint32_t firstBlockIndex, uint32_t blockCount, std::vector<std::string>& blockHashes);
  std::error_code getViewKey(std::string& viewSecretKey);
  // The `pqview1:` audit credential — scan authority, no spend authority. This is
  // what a view-only container is provisioned from; getSpendkeys/getMnemonicSeed
  // return the master seed and must never be used for that.
  std::error_code getTrackingKey(std::string& trackingKey);
  std::error_code getMnemonicSeed(const std::string& address, std::string& mnemonicSeed);
  std::error_code getTransactionHashes(const std::vector<std::string>& addresses, const std::string& blockHash,
    uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes);
  std::error_code getTransactionHashes(const std::vector<std::string>& addresses, uint32_t firstBlockIndex,
    uint32_t blockCount, const std::string& paymentId, std::vector<TransactionHashesInBlockRpcInfo>& transactionHashes);
  std::error_code getTransactions(const std::vector<std::string>& addresses, const std::string& blockHash,
    uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactionHashes);
  std::error_code getTransactions(const std::vector<std::string>& addresses, uint32_t firstBlockIndex,
    uint32_t blockCount, const std::string& paymentId, std::vector<TransactionsInBlockRpcInfo>& transactionHashes);
  std::error_code getTransaction(const std::string& transactionHash, TransactionRpcInfo& transaction);
  std::error_code getAddresses(std::vector<std::string>& addresses);
  std::error_code getAddressesCount(size_t& addressesCount);
  std::error_code getPqAddress(std::string& pqAddress, bool& pqEnabled);
  std::error_code getPqBalance(uint64_t& availableBalance, uint64_t& lockedAmount, uint32_t& scannedHeight, bool& pqEnabled);
  std::error_code getPqBalance(const std::string& address, uint64_t& availableBalance, uint64_t& lockedAmount, uint32_t& scannedHeight, bool& pqEnabled);
  std::error_code registerPqAccount(std::string& transactionHash);
  std::error_code registerPqAccountPaid(std::string& transactionHash);
  std::error_code getPqAccountStatus(bool& registered, std::string& accountNumber, uint32_t& blockHeight, uint32_t& txIndex);
  std::error_code getPqDepositScheme(std::string& scheme, uint32_t& depositCount);
  std::error_code createPqDepositAddress(std::string& address, uint32_t& index);
  std::error_code listPqDepositAddresses(std::vector<std::string>& addresses, std::vector<uint32_t>& indices);
  // Volatile SingleKeyIndex legacy-window extension. Normal scanning covers
  // the issued cursor automatically; use this before `reset` only to recover
  // beyond locally retained metadata. WalletGreen carries it through reset's
  // internal reload, but a new process starts at zero again.
  std::error_code enableLegacyDepositRescan(uint32_t maxT);
  std::error_code sendTransaction(const SendTransaction::Request& request, std::string& transactionHash,
                                  std::vector<std::string>& paymentProofs);
  std::error_code sendTransaction(const SendTransaction::Request& request, std::string& transactionHash) {
    std::vector<std::string> ignored;
    return sendTransaction(request, transactionHash, ignored);
  }
  std::error_code prepareTransaction(const SendTransaction::Request& request,
                                     std::string& transactionHash,
                                     std::string& transactionHex,
                                     std::vector<std::string>& paymentProofs);
  std::error_code getPaymentProofs(const std::string& transactionHash, std::vector<PaymentProofRpcEntry>& entries);
  std::error_code deletePaymentProof(const std::string& transactionHash, uint32_t recipientIndex,
                                     bool confirm, bool& deleted);
  std::error_code exportPaymentProof(const std::string& transactionHash, uint32_t recipientIndex, std::string& recordHex);
  std::error_code importPaymentProof(const std::string& recordHex, std::string& transactionHash);
  std::error_code getUnconfirmedTransactionHashes(const std::vector<std::string>& addresses, std::vector<std::string>& transactionHashes);
  std::error_code getStatus(uint32_t& blockCount, uint32_t& knownBlockCount, uint32_t& localDaemonBlockCount, std::string& lastBlockHash, uint32_t& peerCount, uint64_t& minimalFee);
  std::error_code validateAddress(const std::string& address, bool& isValid, std::string& _address, std::string& spendPublicKey, std::string& viewPublicKey);
  std::error_code signMessage(const std::string& message, const std::string& address, std::string& signature);
  std::error_code verifyMessage(const std::string& message, const std::string& signature, const std::string& address, bool& isValid);

private:
  std::error_code createTransaction(const SendTransaction::Request& request, bool relay,
                                    std::string& transactionHash,
                                    std::string& transactionHex,
                                    std::vector<std::string>& paymentProofs);
  void refresh();

  void loadWallet();
  void loadTransactionIdIndex();
  void recoverWalletAfterRebuildFailure();

  void replaceWithNewWallet(const Crypto::SecretKey& viewSecretKey);
  void replaceWithNewWallet(const Crypto::SecretKey& viewSecretKey, const uint32_t scanHeight);

  std::vector<CryptoNote::TransactionsInBlockInfo> getTransactions(const Crypto::Hash& blockHash, size_t blockCount) const;
  std::vector<CryptoNote::TransactionsInBlockInfo> getTransactions(uint32_t firstBlockIndex, size_t blockCount) const;

  std::vector<TransactionHashesInBlockRpcInfo> getRpcTransactionHashes(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;
  std::vector<TransactionHashesInBlockRpcInfo> getRpcTransactionHashes(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;

  std::vector<TransactionsInBlockRpcInfo> getRpcTransactions(const Crypto::Hash& blockHash, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;
  std::vector<TransactionsInBlockRpcInfo> getRpcTransactions(uint32_t firstBlockIndex, size_t blockCount, const TransactionsInBlockInfoFilter& filter) const;

  const CryptoNote::Currency& currency;
  CryptoNote::IWallet& wallet;
  CryptoNote::INode& node;
  const WalletConfiguration& config;
  bool inited;
  Logging::LoggerRef logger;
  System::Dispatcher& dispatcher;
  System::Event readyEvent;
  System::ContextGroup refreshContext;

  std::map<std::string, size_t> transactionIdIndex;
};

} //namespace PaymentService
