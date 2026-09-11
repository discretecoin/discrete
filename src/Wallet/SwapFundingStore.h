// Copyright (c) 2026, The Discrete developers. LGPL-3.0-or-later.
#pragma once
#include <memory>
#include <optional>
#include <string>
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "crypto_pq/PqHash.h"

namespace CryptoNote {
// Private immutable sidecar records, not a wallet-file or consensus format.
// Holds an exclusive process lock for its lifetime. Existing/corrupt records
// are never replaced, deleted, pruned or interpreted as an absent operation.
class SwapFundingStore {
public:
  static constexpr size_t MAX_OPERATIONS = 128;
  static constexpr size_t MAX_RECORD_BYTES = 262144;
  static constexpr size_t MAX_WIRE_BYTES = 65536;
  enum Stage : uint8_t { Identity = 0, Draft = 1, Prepared = 2 };
  SwapFundingStore(const std::string& path, const CryptoPQ::Hash256& key,
                   const Crypto::Hash& wallet, const Crypto::Hash& genesis, bool create);
  ~SwapFundingStore();
  SwapFundingStore(const SwapFundingStore&) = delete;
  SwapFundingStore& operator=(const SwapFundingStore&) = delete;
  bool available() const;
  std::optional<BinaryArray> read(const Crypto::Hash& operation, Stage stage) const;
  void publish(const Crypto::Hash& operation, Stage stage, const BinaryArray& bytes);
private:
  struct Impl;
  std::unique_ptr<Impl> impl;
};
}
