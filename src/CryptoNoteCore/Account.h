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

#pragma once

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "crypto/crypto.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqKem.h"

namespace CryptoNote {

  class ISerializer;

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class AccountBase {
  public:
    AccountBase();
    void generate();
    void generateDeterministic();

    static void generateViewFromSpend(const Crypto::SecretKey&, Crypto::SecretKey&, Crypto::PublicKey&);
    static void generateViewFromSpend(const Crypto::SecretKey&, Crypto::SecretKey&);

    const AccountKeys& getAccountKeys() const;
    void setAccountKeys(const AccountKeys& keys);
    uint64_t get_createtime() const { return m_creation_timestamp; }
    void set_createtime(uint64_t val) { m_creation_timestamp = val; }
    void serialize(ISerializer& s);

    // PQ keypair — native Discrete keys used for block signing and coinbase outputs.
    const CryptoPQ::DsaPublicKey& pqSpendPk() const { return m_pqSpendPk; }
    const CryptoPQ::DsaSecretKey& pqSpendSk() const { return m_pqSpendSk; }
    const CryptoPQ::KemPublicKey& pqViewPk()  const { return m_pqViewPk;  }
    const CryptoPQ::KemSecretKey& pqViewSk()  const { return m_pqViewSk;  }

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int /*ver*/) {
      a & m_keys;
      a & m_creation_timestamp;
    }

  private:
    void setNull();
    AccountKeys m_keys;
    uint64_t m_creation_timestamp;
    CryptoPQ::DsaPublicKey m_pqSpendPk{};
    CryptoPQ::DsaSecretKey m_pqSpendSk{};
    CryptoPQ::KemPublicKey m_pqViewPk{};
    CryptoPQ::KemSecretKey m_pqViewSk{};
  };
}
