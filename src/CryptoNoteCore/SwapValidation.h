// Copyright (c) 2026, The Discrete developers. LGPL-3.0-or-later.
#pragma once
#include "PqValidation.h"
#include "PqTxType.h"

namespace CryptoNote {
inline bool isSwapTransaction(const TransactionPrefix& tx) {
  return tx.txType == TX_SWAP_FUND || tx.txType == TX_SWAP_SPEND;
}
struct SwapResolvedInput {
  bool exists = false;
  TransactionOutput output{};
};
bool swapInputReference(const TransactionInput& input, Crypto::Hash& txid, uint32_t& index);
Crypto::KeyImage swapSpendTag(const SwapInput& input, const Crypto::Hash& chain);
bool transactionSpendTag(const TransactionInput& input, const Crypto::Hash& chain, Crypto::KeyImage& tag);
Crypto::Hash swapHashlock(const std::vector<uint8_t>& secret);
bool checkSwapTransactionSemantic(const Transaction& tx, std::string* error);
bool swapResolvedFee(const Transaction& tx, const std::vector<SwapResolvedInput>& resolved,
                     uint64_t& fee, std::string* error);
CryptoPQ::Hash256 swapSigningDigest(const Transaction& tx, const std::vector<SwapResolvedInput>& resolved,
                                   const Crypto::Hash& chain, uint32_t inputIndex);
bool checkSwapTransactionInputs(const Transaction& tx, const std::vector<SwapResolvedInput>& resolved,
                               const Crypto::Hash& chain, uint32_t height,
                               std::vector<Crypto::KeyImage>* tags, uint64_t* fee, std::string* error);
}
