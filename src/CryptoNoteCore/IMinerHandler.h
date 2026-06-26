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
#include "CryptoNoteCore/Difficulty.h"
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"

namespace CryptoNote {
  struct IMinerHandler {
    virtual bool handle_block_found(Block& b) = 0;
    // PQ block template: the coinbase reward goes to (viewPub, spendPub) AND the
    // coinbase extra carries spendPub — the miner signs the block with the matching
    // spend secret, so the reward recipient IS the block signer (identity-bound
    // mining; you cannot mine to a key you do not hold).
    virtual bool get_block_template_pq(Block& b, const CryptoPQ::KemPublicKey& viewPub, const CryptoPQ::DsaPublicKey& spendPub, Difficulty& diffic, uint32_t& height, const BinaryArray& ex_nonce) = 0;
    virtual bool getBlockLongHash(Crypto::cn_context &context, const Block& b, Crypto::Hash& res) = 0;

  protected:
    ~IMinerHandler(){};
  };
}
