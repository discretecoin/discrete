// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <string>

#include "SentPaymentsStore.h"

namespace CryptoNote {

// Serialization codec for a single transaction's SentPaymentRecord (its ordered
// recipient labels + opaque payment proofs). These records are ordinary wallet
// metadata: the wallet keeps them in its own encrypted cache via
// SentPaymentsStore and saves/loads them with the wallet file — there is no
// separate store to configure. This codec only (de)serializes the standalone
// files a user explicitly exports/imports and the walletd RPC blob; it holds no
// state.
class PaymentProofArchive {
public:
  static std::string encodeRecord(const Crypto::Hash& genesisId,
                                  const Crypto::Hash& txid,
                                  const SentPaymentRecord& record);
  static bool decodeRecord(const std::string& bytes, Crypto::Hash& genesisId,
                           Crypto::Hash& txid, SentPaymentRecord& record,
                           std::string* error = nullptr);

  // Read a standalone export file the user pointed us at.
  static std::string readExternalFile(const std::string& path);
  // Atomically write an encoded record to a user-chosen external path
  // (owner-only permissions, crash-safe temp+rename).
  static void exportRecord(const Crypto::Hash& genesisId, const Crypto::Hash& txid,
                           const SentPaymentRecord& record, const std::string& path);
};

}  // namespace CryptoNote
