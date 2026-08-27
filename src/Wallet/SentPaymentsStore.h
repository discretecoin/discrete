// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Discrete is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Discrete.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <cstdint>
#include <istream>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <cstring>

#include "crypto/hash.h"  // Crypto::Hash + its std::hash specialization (CRYPTO_MAKE_HASHABLE)

// Payer-side record of who we paid, captured at send time.
//
// PQ owned-output scanning (WalletLedger) can only reconstruct the wallet's OWN net
// effect of a transaction — the counterparty address is never on chain and cannot be
// recovered by scanning, nor regenerated from the mnemonic. In the classical
// CryptoNote/Karbo wallet this was solved by the WalletUserTransactionsCache, which
// stored the destination transfers you supplied at send time and serialized them into
// the wallet file (and, being local-only, was lost on a wallet reset). That cache is
// gone in the PQ transition, which is why the History view lost the recipient column.
//
// This store re-introduces exactly that: a txid-keyed, send-time capture of the
// external recipients, serialized into the wallet's encrypted cache section. It is
// deliberately shaped to also carry the off-chain payment proof (https://docs.discrete.cash/#/reference/payment-proof)
// per recipient, since both are the same payer-side, send-time, txid-keyed data — see
// SentPaymentEntry::proof.

namespace CryptoNote {

// One external recipient of an outgoing payment, captured when this wallet built and
// relayed the transaction. Change back to self is never recorded — only who we paid.
struct SentPaymentEntry {
  std::string address;    // the account number / address string the user paid
  uint64_t    amount = 0; // atomic units sent to this recipient

  // Canonical encoded off-chain payer proof. Kept as the existing opaque,
  // length-prefixed blob; the proof archive stores this same field rather than a
  // parallel witness schema.
  std::string proof;
};

// All external recipients of one outgoing transaction.
struct SentPaymentRecord {
  std::vector<SentPaymentEntry> recipients;
};

// txid -> the recipients we paid. Serialized into the wallet's encrypted cache.
class SentPaymentsStore {
public:
  struct HashEqual {
    bool operator()(const Crypto::Hash& a, const Crypto::Hash& b) const noexcept {
      return std::memcmp(a.data, b.data, sizeof(a.data)) == 0;
    }
  };
  using Records = std::unordered_map<Crypto::Hash, SentPaymentRecord,
                                     std::hash<Crypto::Hash>, HashEqual>;
  // Legacy cache helper. Evidence-bearing paths use recordChecked() below.
  void record(const Crypto::Hash& txid, SentPaymentRecord record) {
    auto existing = m_records.find(txid);
    uint64_t oldRecipients = 0;
    uint64_t oldStringBytes = 0;
    if (existing != m_records.end()) {
      measure(existing->second, oldRecipients, oldStringBytes);
    }
    uint64_t newRecipients = 0;
    uint64_t newStringBytes = 0;
    if ((existing == m_records.end() && m_records.size() >= kMaxRecords) ||
        !measure(record, newRecipients, newStringBytes) ||
        newRecipients > kMaxTotalRecipients - (m_totalRecipients - oldRecipients) ||
        newStringBytes > kMaxTotalStringBytes - (m_totalStringBytes - oldStringBytes)) {
      throw std::runtime_error("sent-payment record exceeds persistence limits");
    }
    m_totalRecipients = m_totalRecipients - oldRecipients + newRecipients;
    m_totalStringBytes = m_totalStringBytes - oldStringBytes + newStringBytes;
    m_records[txid] = std::move(record);
  }

  // Insert without silently replacing evidentiary data. Returns true for a new
  // or byte-identical record and false for a conflicting existing txid.
  bool recordChecked(const Crypto::Hash& txid, const SentPaymentRecord& record) {
    auto it = m_records.find(txid);
    if (it == m_records.end()) {
      uint64_t recipients = 0;
      uint64_t stringBytes = 0;
      if (m_records.size() >= kMaxRecords ||
          !measure(record, recipients, stringBytes) ||
          recipients > kMaxTotalRecipients - m_totalRecipients ||
          stringBytes > kMaxTotalStringBytes - m_totalStringBytes) {
        return false;
      }
      m_records.emplace(txid, record);
      m_totalRecipients += recipients;
      m_totalStringBytes += stringBytes;
      return true;
    }
    return equal(it->second, record);
  }

  bool remove(const Crypto::Hash& txid) {
    auto it = m_records.find(txid);
    if (it == m_records.end()) return false;
    uint64_t recipients = 0;
    uint64_t stringBytes = 0;
    measure(it->second, recipients, stringBytes);
    m_totalRecipients -= recipients;
    m_totalStringBytes -= stringBytes;
    m_records.erase(it);
    return true;
  }
  const Records& records() const { return m_records; }

  // The recipients we recorded for txid, or nullptr if none (incoming tx or a send
  // made before this feature existed).
  const SentPaymentRecord* find(const Crypto::Hash& txid) const {
    auto it = m_records.find(txid);
    return it == m_records.end() ? nullptr : &it->second;
  }

  bool empty() const { return m_records.empty(); }
  std::size_t size() const { return m_records.size(); }
  void clear() {
    m_records.clear();
    m_totalRecipients = 0;
    m_totalStringBytes = 0;
  }

  // Versioned binary form for the wallet's encrypted cache section. The caller frames
  // the blob (length-prefixed), so no magic is needed here.
  void save(std::ostream& os) const {
    const uint8_t version = kVersion;
    if (m_records.size() > kMaxRecords ||
        m_totalRecipients > kMaxTotalRecipients ||
        m_totalStringBytes > kMaxTotalStringBytes) {
      throw std::runtime_error("sent-payments store exceeds persistence limits");
    }
    os.write(reinterpret_cast<const char*>(&version), sizeof(version));
    const uint64_t count = m_records.size();
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& kv : m_records) {
      os.write(reinterpret_cast<const char*>(kv.first.data), sizeof(kv.first.data));
      const uint32_t n = static_cast<uint32_t>(kv.second.recipients.size());
      os.write(reinterpret_cast<const char*>(&n), sizeof(n));
      for (const auto& e : kv.second.recipients) {
        writeString(os, e.address);
        os.write(reinterpret_cast<const char*>(&e.amount), sizeof(e.amount));
        writeString(os, e.proof);
      }
    }
  }

  // Restore from a section written by save(). Parsing is transactional: malformed,
  // oversized, duplicate, or trailing input is rejected without changing the
  // existing evidence store. The caller decides whether a rejected cache section
  // should abort the wallet load or be logged and skipped.
  bool load(std::istream& is, std::string* error = nullptr) {
    auto fail = [error](const char* message) {
      if (error != nullptr) *error = message;
      return false;
    };

    uint8_t version = 0;
    is.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (!is || version == 0 || version > kVersion) {
      return fail("unsupported or missing sent-payments version");
    }
    uint64_t count = 0;
    is.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!is) return fail("truncated sent-payments record count");
    if (count > kMaxRecords) return fail("sent-payments record count exceeds limit");

    Records decoded;
    uint64_t totalRecipients = 0;
    uint64_t totalStringBytes = 0;
    for (uint64_t i = 0; i < count; ++i) {
      Crypto::Hash txid{};
      is.read(reinterpret_cast<char*>(txid.data), sizeof(txid.data));
      uint32_t n = 0;
      is.read(reinterpret_cast<char*>(&n), sizeof(n));
      if (!is) return fail("truncated sent-payments record header");
      if (n > kMaxRecipientsPerRecord ||
          totalRecipients > kMaxTotalRecipients - n) {
        return fail("sent-payments recipient count exceeds limit");
      }
      totalRecipients += n;

      SentPaymentRecord rec;
      rec.recipients.reserve(n);
      for (uint32_t j = 0; j < n; ++j) {
        SentPaymentEntry e;
        if (!readString(is, e.address, kMaxAddressBytes, totalStringBytes)) {
          return fail("invalid sent-payments address");
        }
        is.read(reinterpret_cast<char*>(&e.amount), sizeof(e.amount));
        if (!is) return fail("truncated sent-payments amount");
        if (!readString(is, e.proof, kMaxProofBytes, totalStringBytes)) {
          return fail("invalid sent-payments proof");
        }
        rec.recipients.push_back(std::move(e));
      }
      if (!decoded.emplace(txid, std::move(rec)).second) {
        return fail("duplicate sent-payments transaction id");
      }
    }
    if (is.peek() != std::char_traits<char>::eof()) {
      return fail("trailing sent-payments data");
    }

    m_records.swap(decoded);
    m_totalRecipients = totalRecipients;
    m_totalStringBytes = totalStringBytes;
    if (error != nullptr) error->clear();
    return true;
  }

private:
  static constexpr uint8_t kVersion = 1;
  static constexpr uint64_t kMaxRecords = 100000;
  static constexpr uint32_t kMaxRecipientsPerRecord = 64;
  static constexpr uint64_t kMaxTotalRecipients = 1000000;
  static constexpr uint64_t kMaxAddressBytes = 16 * 1024;
  static constexpr uint64_t kMaxProofBytes = 1024 * 1024;
  static constexpr uint64_t kMaxTotalStringBytes = 64 * 1024 * 1024;

  static void writeString(std::ostream& os, const std::string& s) {
    const uint64_t len = s.size();
    os.write(reinterpret_cast<const char*>(&len), sizeof(len));
    if (len) os.write(s.data(), static_cast<std::streamsize>(len));
  }

  static bool readString(std::istream& is, std::string& s, uint64_t maxBytes,
                         uint64_t& totalStringBytes) {
    uint64_t len = 0;
    is.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!is) return false;
    if (len > maxBytes || len > kMaxTotalStringBytes - totalStringBytes ||
        len > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
      return false;
    }
    s.resize(static_cast<std::size_t>(len));
    if (len) is.read(&s[0], static_cast<std::streamsize>(len));
    if (!is) return false;
    totalStringBytes += len;
    return true;
  }

  static bool equal(const SentPaymentRecord& a, const SentPaymentRecord& b) {
    if (a.recipients.size() != b.recipients.size()) return false;
    for (std::size_t i = 0; i < a.recipients.size(); ++i) {
      const auto& x = a.recipients[i];
      const auto& y = b.recipients[i];
      if (x.address != y.address || x.amount != y.amount || x.proof != y.proof) return false;
    }
    return true;
  }

  static bool measure(const SentPaymentRecord& record, uint64_t& recipients,
                      uint64_t& stringBytes) {
    recipients = record.recipients.size();
    stringBytes = 0;
    if (recipients > kMaxRecipientsPerRecord) {
      return false;
    }
    for (const auto& entry : record.recipients) {
      if (entry.address.size() > kMaxAddressBytes ||
          entry.proof.size() > kMaxProofBytes ||
          entry.address.size() > kMaxTotalStringBytes - stringBytes) {
        return false;
      }
      stringBytes += entry.address.size();
      if (entry.proof.size() > kMaxTotalStringBytes - stringBytes) {
        return false;
      }
      stringBytes += entry.proof.size();
    }
    return true;
  }

  Records m_records;
  uint64_t m_totalRecipients = 0;
  uint64_t m_totalStringBytes = 0;
};

}  // namespace CryptoNote
