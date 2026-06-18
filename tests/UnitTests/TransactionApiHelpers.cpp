// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include "TransactionApiHelpers.h"
#include "CryptoNoteCore/TransactionApi.h"

using namespace CryptoNote;
using namespace Crypto;

TestTransactionBuilder::TestTransactionBuilder() {
  tx = createTransaction();
}

TestTransactionBuilder::TestTransactionBuilder(const BinaryArray& txTemplate, const Crypto::SecretKey& secretKey) {
  tx = createTransaction(txTemplate);
  tx->setTransactionSecretKey(secretKey);
}

PublicKey TestTransactionBuilder::getTransactionPublicKey() const {
  return tx->getTransactionPublicKey();
}

void TestTransactionBuilder::appendExtra(const BinaryArray& extraData) {
  tx->appendExtra(extraData);
}

void TestTransactionBuilder::setUnlockTime(uint64_t time) {
  tx->setUnlockTime(time);
}

size_t TestTransactionBuilder::addTestInput(uint64_t amount, const AccountKeys& senderKeys) {
  using namespace TransactionTypes;

  TransactionTypes::InputKeyInfo info;
  PublicKey targetKey;

  CryptoNote::KeyPair srcTxKeys = CryptoNote::generateKeyPair();
  derivePublicKey(senderKeys, srcTxKeys.publicKey, 5, targetKey);

  TransactionTypes::GlobalOutput gout = { targetKey, 0 };

  info.amount = amount;
  info.outputs.push_back(gout);

  info.realOutput.transactionIndex = 0;
  info.realOutput.outputInTransaction = 5;
  info.realOutput.transactionPublicKey = reinterpret_cast<const PublicKey&>(srcTxKeys.publicKey);

  KeyPair ephKeys;
  size_t idx = tx->addInput(senderKeys, info, ephKeys);
  keys[idx] = std::make_pair(info, ephKeys);
  return idx;
}

size_t TestTransactionBuilder::addTestInput(uint64_t amount, std::vector<uint32_t> gouts, const AccountKeys& senderKeys) {
  using namespace TransactionTypes;

  TransactionTypes::InputKeyInfo info;
  PublicKey targetKey;

  CryptoNote::KeyPair srcTxKeys = CryptoNote::generateKeyPair();
  derivePublicKey(senderKeys, srcTxKeys.publicKey, 5, targetKey);

  TransactionTypes::GlobalOutput gout = { targetKey, 0 };

  info.amount = amount;
  info.outputs.push_back(gout);
  PublicKey pk;
  SecretKey sk;
  for (auto out : gouts) {
    Crypto::generate_keys(pk, sk);
    info.outputs.push_back(TransactionTypes::GlobalOutput{ pk, out });
  }

  info.realOutput.transactionIndex = 0;
  info.realOutput.outputInTransaction = 5;
  info.realOutput.transactionPublicKey = reinterpret_cast<const PublicKey&>(srcTxKeys.publicKey);

  KeyPair ephKeys;
  size_t idx = tx->addInput(senderKeys, info, ephKeys);
  keys[idx] = std::make_pair(info, ephKeys);
  return idx;
}

void TestTransactionBuilder::addInput(const AccountKeys& senderKeys, const TransactionOutputInformation& t) {
  TransactionTypes::InputKeyInfo info;
  info.amount = t.amount;

  TransactionTypes::GlobalOutput globalOut;
  globalOut.outputIndex = t.globalOutputIndex;
  globalOut.targetKey = t.outputKey;
  info.outputs.push_back(globalOut);

  info.realOutput.outputInTransaction = t.outputInTransaction;
  info.realOutput.transactionIndex = 0;
  info.realOutput.transactionPublicKey = t.transactionPublicKey;

  KeyPair ephKeys;
  size_t idx = tx->addInput(senderKeys, info, ephKeys);
  keys[idx] = std::make_pair(info, ephKeys);
}

TransactionOutputInformationIn TestTransactionBuilder::addTestKeyOutput(uint64_t amount, uint32_t globalOutputIndex, const AccountKeys& senderKeys) {
  uint32_t index = static_cast<uint32_t>(tx->addOutput(amount, senderKeys.address));

  uint64_t amount_;
  KeyOutput output;
  tx->getOutput(index, output, amount_);

  TransactionOutputInformationIn outputInfo;
  outputInfo.type = TransactionTypes::OutputType::Key;
  outputInfo.amount = amount_;
  outputInfo.globalOutputIndex = globalOutputIndex;
  outputInfo.outputInTransaction = index;
  outputInfo.transactionPublicKey = tx->getTransactionPublicKey();
  outputInfo.outputKey = output.key;
  outputInfo.keyImage = generateKeyImage(senderKeys, index, tx->getTransactionPublicKey());

  return outputInfo;
}

size_t TestTransactionBuilder::addOutput(uint64_t amount, const AccountPublicAddress& to) {
  return tx->addOutput(amount, to);
}

size_t TestTransactionBuilder::addOutput(uint64_t amount, const KeyOutput& out) {
  return tx->addOutput(amount, out);
}

std::unique_ptr<ITransactionReader> TestTransactionBuilder::build() {
  for (const auto& kv : keys) {
    tx->signInputKey(kv.first, kv.second.first, kv.second.second);
  }

  transactionHash = tx->getTransactionHash();

  keys.clear();
  return std::move(tx);
}

Crypto::Hash TestTransactionBuilder::getTransactionHash() const {
  return transactionHash;
}

// FusionTransactionBuilder removed: Discrete has no fusion transactions.
