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

#include "WalletUtils.h"

#include "CryptoNote.h"
#include "crypto/crypto.h"
#include "AccountNumber.h"
#include "PqAddress.h"
#include "Wallet/WalletErrors.h"

namespace CryptoNote {

bool validateAddress(const std::string& address, const CryptoNote::Currency& currency) {
  // Discrete is PQ-only: the classical base58 ECC address form is never issued and
  // can't be spent to, so it is NOT accepted here. Valid forms are a bech32m PQ
  // address or an H-I-A-C / H-I-A-T-C account number.
  //
  // PQ addresses (what the wallet actually issues) — restrict to THIS network's
  // HRP: mainnet and testnet share the same numeric networkPrefix, so the bech32m
  // HRP is the only thing that tells a "disc…" mainnet address apart from a
  // "tdisc…" testnet one.
  CryptoNote::PqAddress pq;
  if (CryptoNote::decodePqAddress(address, currency.isTestnet(), pq)) {
    return true;
  }
  // H-I-A-T-C deposit subaddress (SingleKeyIndex scheme) or its H-I-A-C base account.
  // Both are self-validating (Luhn mod-36 check char), so accept either form so the
  // per-index RPCs can filter/select by account number, not just by raw address.
  CryptoNote::AccountNumber acct;
  uint32_t subaddrIndex = 0;
  return CryptoNote::AccountNumber::fromStringWithIndex(address, acct, subaddrIndex) ||
         CryptoNote::AccountNumber::fromString(address, acct);
}

std::ostream& operator<<(std::ostream& os, CryptoNote::WalletTransactionState state) {
  switch (state) {
  case CryptoNote::WalletTransactionState::SUCCEEDED:
    os << "SUCCEEDED";
    break;
  case CryptoNote::WalletTransactionState::FAILED:
    os << "FAILED";
    break;
  case CryptoNote::WalletTransactionState::CANCELLED:
    os << "CANCELLED";
    break;
  case CryptoNote::WalletTransactionState::CREATED:
    os << "CREATED";
    break;
  case CryptoNote::WalletTransactionState::DELETED:
    os << "DELETED";
    break;
  default:
    os << "<UNKNOWN>";
  }

  return os << " (" << static_cast<int>(state) << ')';
}

std::ostream& operator<<(std::ostream& os, CryptoNote::WalletTransferType type) {
  switch (type) {
  case CryptoNote::WalletTransferType::USUAL:
    os << "USUAL";
    break;
  case CryptoNote::WalletTransferType::DONATION:
    os << "DONATION";
    break;
  case CryptoNote::WalletTransferType::CHANGE:
    os << "CHANGE";
    break;
  default:
    os << "<UNKNOWN>";
  }

  return os << " (" << static_cast<int>(type) << ')';
}

std::ostream& operator<<(std::ostream& os, CryptoNote::WalletGreen::WalletState state) {
  switch (state) {
  case CryptoNote::WalletGreen::WalletState::INITIALIZED:
    os << "INITIALIZED";
    break;
  case CryptoNote::WalletGreen::WalletState::NOT_INITIALIZED:
    os << "NOT_INITIALIZED";
    break;
  default:
    os << "<UNKNOWN>";
  }

  return os << " (" << static_cast<int>(state) << ')';
}

std::ostream& operator<<(std::ostream& os, CryptoNote::WalletGreen::WalletTrackingMode mode) {
  switch (mode) {
  case CryptoNote::WalletGreen::WalletTrackingMode::TRACKING:
    os << "TRACKING";
    break;
  case CryptoNote::WalletGreen::WalletTrackingMode::NOT_TRACKING:
    os << "NOT_TRACKING";
    break;
  case CryptoNote::WalletGreen::WalletTrackingMode::NO_ADDRESSES:
    os << "NO_ADDRESSES";
    break;
  default:
    os << "<UNKNOWN>";
  }

  return os << " (" << static_cast<int>(mode) << ')';
}

WalletOrderListFormatter::WalletOrderListFormatter(const CryptoNote::Currency& currency, const std::vector<CryptoNote::WalletOrder>& walletOrderList) :
  m_currency(currency),
  m_walletOrderList(walletOrderList) {
}

void WalletOrderListFormatter::print(std::ostream& os) const {
  os << '{';

  if (!m_walletOrderList.empty()) {
    os << '<' << m_currency.formatAmount(m_walletOrderList.front().amount) << ", " << m_walletOrderList.front().address << '>';

    for (auto it = std::next(m_walletOrderList.begin()); it != m_walletOrderList.end(); ++it) {
      os << '<' << m_currency.formatAmount(it->amount) << ", " << it->address << '>';
    }
  }

  os << '}';
}

std::ostream& operator<<(std::ostream& os, const WalletOrderListFormatter& formatter) {
  formatter.print(os);
  return os;
}

}
