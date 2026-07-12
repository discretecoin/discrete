// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <string>
#include <vector>

#include "SentPaymentsStore.h"

namespace CryptoNote {

// Crash-safe write-ahead archive for SentPaymentsStore. Files contain the same
// ordered SentPaymentEntry records (including the existing opaque proof field),
// not a parallel witness schema. The encrypted wallet cache mirrors this store.
class PaymentProofArchive {
public:
  enum class Fault { None, Create, Write, Flush, Rename };

  void configure(const std::string& walletFile, const Crypto::Hash& genesisId,
                 SentPaymentsStore& store, std::vector<std::string>* warnings = nullptr);
  bool configured() const { return !m_directory.empty(); }
  const std::string& directory() const { return m_directory; }

  // Synchronously write, flush, atomically rename, read back, and validate.
  // Existing byte-identical content is idempotent; a conflict throws.
  void persist(const Crypto::Hash& txid, const SentPaymentRecord& record);
  void erase(const Crypto::Hash& txid);
  void replaceAfterExplicitDeletion(const Crypto::Hash& txid, const SentPaymentRecord& record);
  void exportRecord(const Crypto::Hash& txid, const SentPaymentRecord& record,
                    const std::string& path);

  static std::string readExternalFile(const std::string& path) { return readFile(path); }

  void setFaultForTests(Fault fault) { m_fault = fault; }

  static std::string encodeRecord(const Crypto::Hash& genesisId,
                                  const Crypto::Hash& txid,
                                  const SentPaymentRecord& record);
  static bool decodeRecord(const std::string& bytes, Crypto::Hash& genesisId,
                           Crypto::Hash& txid, SentPaymentRecord& record,
                           std::string* error = nullptr);

private:
  std::string pathFor(const Crypto::Hash& txid) const;
  static std::string readFile(const std::string& path);
  void durableReplace(const std::string& finalPath, const std::string& bytes);

  std::string m_directory;
  Crypto::Hash m_genesisId{};
  Fault m_fault = Fault::None;
};

}  // namespace CryptoNote
