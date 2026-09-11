// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2016, The Monero Project
// Copyright (c) 2016-2026, Karbo developers
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
#include "CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "crypto/hash.h"
#include "Rpc/CoreRpcServerCommandsDefinitions.h"
#include "WalletRpcServerErrorCodes.h"
#include "../CryptoNoteConfig.h"

namespace Tools {
namespace wallet_rpc {

using CryptoNote::ISerializer;

#define WALLET_RPC_STATUS_OK      "OK"
#define WALLET_RPC_STATUS_BUSY    "BUSY"

  // Lab-only prepare endpoints return signed bytes; the coordinator must durably
  // record the intent/exposure before any external relay. They never relay here.
  struct COMMAND_RPC_SWAP_ROLE {
    struct request { std::string rho; void serialize(ISerializer& s) { KV_MEMBER(rho) } };
    struct response {
      std::string commitment, address, genesis_hash;
      void serialize(ISerializer& s) { KV_MEMBER(commitment) KV_MEMBER(address) KV_MEMBER(genesis_hash) }
    };
  };
  struct SwapPreparedResponse {
    std::string tx_hash, tx_as_hex;
    uint64_t fee_atoms = 0, principal_atoms = 0;
    void serialize(ISerializer& s) { KV_MEMBER(tx_hash) KV_MEMBER(tx_as_hex) KV_MEMBER(fee_atoms) KV_MEMBER(principal_atoms) }
  };
  struct COMMAND_RPC_SWAP_PREPARE_FUNDING {
    struct request {
      uint64_t principal_atoms = 0;
      uint32_t refund_height = 0;
      std::string hashlock, nonce, claim_commitment, refund_rho, genesis_hash;
      void serialize(ISerializer& s) {
        KV_MEMBER(principal_atoms) KV_MEMBER(refund_height) KV_MEMBER(hashlock) KV_MEMBER(nonce)
        KV_MEMBER(claim_commitment) KV_MEMBER(refund_rho) KV_MEMBER(genesis_hash)
      }
    };
    using response = SwapPreparedResponse;
  };
  struct COMMAND_RPC_SWAP_PREPARE_SPEND {
    struct request {
      std::string funding_txid, rho, secret, genesis_hash;
      uint32_t output_index = 0, branch = 0;
      void serialize(ISerializer& s) {
        KV_MEMBER(funding_txid) KV_MEMBER(output_index) KV_MEMBER(branch)
        KV_MEMBER(rho) KV_MEMBER(secret) KV_MEMBER(genesis_hash)
      }
    };
    using response = SwapPreparedResponse;
  };
  struct COMMAND_RPC_SWAP_FUNDING_CAPABILITIES {
    using request = CryptoNote::EMPTY_STRUCT;
    struct response {
      uint32_t version=1,max_operations=128,max_wire_bytes=65536;
      bool durable_prepare=true,lookup=true;
      void serialize(ISerializer& s) {
        KV_MEMBER(version) KV_MEMBER(durable_prepare) KV_MEMBER(lookup) KV_MEMBER(max_operations) KV_MEMBER(max_wire_bytes)
      }
    };
  };
  struct SwapFundingPreparationResponse : SwapPreparedResponse {
    std::string status,operation_id,request_hash,draft_hash;
    void serialize(ISerializer& s) {
      KV_MEMBER(status) KV_MEMBER(operation_id) KV_MEMBER(request_hash) KV_MEMBER(draft_hash)
      SwapPreparedResponse::serialize(s);
    }
  };
  struct COMMAND_RPC_SWAP_PREPARE_FUNDING_ONCE {
    struct request : COMMAND_RPC_SWAP_PREPARE_FUNDING::request {
      std::string operation_id;
      void serialize(ISerializer& s) { KV_MEMBER(operation_id) COMMAND_RPC_SWAP_PREPARE_FUNDING::request::serialize(s); }
    };
    using response = SwapFundingPreparationResponse;
  };
  struct COMMAND_RPC_SWAP_GET_FUNDING_PREPARATION {
    struct request { std::string operation_id; void serialize(ISerializer& s) { KV_MEMBER(operation_id) } };
    using response = SwapFundingPreparationResponse;
  };

  /* Command: get_balance */
  struct COMMAND_RPC_GET_BALANCE
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    struct response
    {
      uint64_t locked_amount;
      uint64_t available_balance;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(locked_amount)
        KV_MEMBER(available_balance)
      }
    };
  };

  /* Command: transfer */ 
  struct transfer_destination
  {
    uint64_t amount;
    std::string address;

    void serialize(ISerializer& s)
    {
      KV_MEMBER(amount)
      KV_MEMBER(address)
    }
  };

  struct COMMAND_RPC_TRANSFER
  {
    struct request
    {
      std::list<transfer_destination> destinations;
      uint64_t fee = CryptoNote::parameters::MINIMUM_FEE;
      uint64_t unlock_height = 0;
      std::string payment_id;
      std::string extra;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(destinations)
        KV_MEMBER(fee)
        KV_MEMBER(unlock_height)
        KV_MEMBER(payment_id)
        KV_MEMBER(extra)
      }
    };
    struct response
    {
      std::string tx_hash;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(tx_hash)
      }
    };
  };

  /* Command: store */
  struct COMMAND_RPC_STORE
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    struct response
    {
      bool stored;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(stored)
      }
    };
  };

  /* Command: stop_wallet */
  struct COMMAND_RPC_STOP
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    typedef CryptoNote::EMPTY_STRUCT response;
  };

  /* Command: get_payments */
  struct payment_details
  {
    std::string tx_hash;
    uint64_t amount;
    uint64_t block_height;
    uint64_t unlock_height;

    void serialize(ISerializer& s)
    {
      KV_MEMBER(tx_hash)
      KV_MEMBER(amount)
      KV_MEMBER(block_height)
      KV_MEMBER(unlock_height)
    }
  };

  struct COMMAND_RPC_GET_PAYMENTS
  {
    struct request
    {
      std::string payment_id;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(payment_id)
      }
    };
    struct response
    {
      std::list<payment_details> payments;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(payments)
      }
    };
  };

  /* Command: get_transfers */
  struct Transfer
  {
    uint64_t time;
    bool output;
    std::string transactionHash;
    uint64_t amount;
    uint64_t fee;
    std::string paymentId;
    std::string address;
    uint64_t blockIndex;
    uint64_t unlockHeight;
    uint64_t confirmations;
    std::string txKey;

    void serialize(ISerializer& s)
    {
      KV_MEMBER(time)
      KV_MEMBER(output)
      KV_MEMBER(transactionHash)
      KV_MEMBER(amount)
      KV_MEMBER(fee)
      KV_MEMBER(paymentId)
      KV_MEMBER(address)
      KV_MEMBER(blockIndex)
      KV_MEMBER(unlockHeight)
      KV_MEMBER(confirmations)
      KV_MEMBER(txKey)
    }
  };

  struct COMMAND_RPC_GET_TRANSFERS
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    struct response
    {
      std::list<Transfer> transfers;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(transfers)
      }
    };
  };

  struct COMMAND_RPC_GET_LAST_TRANSFERS
  {
    struct request
    {
      size_t count = 1000;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(count)
      }
    };
    struct response
    {
      std::list<Transfer> transfers;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(transfers)
      }
    };
  };

  /* Command: get_transaction */
  struct COMMAND_RPC_GET_TRANSACTION
  {
    struct request
    {
      std::string tx_hash;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(tx_hash)
      }
    };
    struct response
    {
      Transfer transaction_details;
      std::list<transfer_destination> destinations;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(transaction_details)
        KV_MEMBER(destinations)
      }
    };
  };

  struct COMMAND_RPC_GET_HEIGHT
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    struct response
    {
      uint64_t height;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(height)
      }
    };
  };

  /* Command: reset */
  /* Command: reset
   *
   * Rescans the chain AND deletes the recipient addresses and payment proofs
   * held in this wallet. Those are local: neither the chain nor the seed can
   * supply them again. Because a caller cannot be prompted over RPC, the
   * deletion has to be asked for in the request itself -- the same contract
   * walletd uses (Reset::Request::confirmDestructive).
   *
   * Callers that only want to re-scan should call `rescan`.
   */
  struct COMMAND_RPC_RESET
  {
    struct request
    {
      bool confirm_destructive = false;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(confirm_destructive)
      }
    };

    typedef CryptoNote::EMPTY_STRUCT response;
  };

  /* Command: rescan
   *
   * Rebuilds blockchain-derived state from scratch. Everything the chain cannot
   * supply -- recipient addresses, payment proofs, keys, deposit configuration
   * -- is kept. Safe to call unprompted.
   */
  struct COMMAND_RPC_RESCAN
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    typedef CryptoNote::EMPTY_STRUCT response;
  }; 

  /* Command: query_key */
  struct COMMAND_RPC_QUERY_KEY
  {
    struct request
    {
      std::string key_type;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(key_type)
      }
    };
    struct response
    {
      std::string key;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(key)
      }
    };
  };

  /* Command: get_address */
  struct COMMAND_RPC_GET_ADDRESS
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    struct response
    {
      std::string address;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(address)
      }
    };
  };

  /* Command: paymentid */
  struct COMMAND_RPC_GEN_PAYMENT_ID
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    struct response
    {
      std::string payment_id;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(payment_id)
      }
    };
  };

  struct COMMAND_RPC_SIGN_MESSAGE
  {
    struct request
    {
      std::string message;
 
      void serialize(ISerializer& s)
      {
        KV_MEMBER(message);
      }
    };

    struct response
    {
      std::string signature;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(signature);
      }
    };
  };

  struct COMMAND_RPC_VERIFY_MESSAGE
  {
    struct request
    {
      std::string message;
      std::string address;
      std::string signature;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(message);
        KV_MEMBER(address);
        KV_MEMBER(signature);
      }
    };

    struct response
    {
      bool good;
 
      void serialize(ISerializer& s)
      {
        KV_MEMBER(good);
      }
    };
  };

  struct COMMAND_RPC_CHANGE_PASSWORD
  {
    struct request
    {
      std::string old_password;
      std::string new_password;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(old_password);
        KV_MEMBER(new_password);
      }
    };

    struct response
    {
      bool password_changed;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(password_changed);
      }
    };
  };

  struct COMMAND_RPC_GET_OUTPUTS
    {
      typedef CryptoNote::EMPTY_STRUCT request;

      struct response
      {
        size_t unlocked_outputs_count;

        void serialize(ISerializer& s) {
          KV_MEMBER(unlocked_outputs_count)
        }
      };
    };

  struct COMMAND_RPC_VALIDATE_ADDRESS {
    struct request {
      std::string address;

      void serialize(ISerializer &s) {
        KV_MEMBER(address)
      }
    };

    struct response {
      bool is_valid;
      std::string address;
      std::string spend_public_key;
      std::string view_public_key;
      std::string status;

      void serialize(ISerializer &s) {
        KV_MEMBER(is_valid)
        KV_MEMBER(address)
        KV_MEMBER(spend_public_key)
        KV_MEMBER(view_public_key)
        KV_MEMBER(status)
      }
    };
  };

  /* Command: register_pq_account */
  struct COMMAND_RPC_REGISTER_PQ_ACCOUNT
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    struct response
    {
      std::string tx_hash;

      void serialize(ISerializer& s)
      {
        KV_MEMBER(tx_hash)
      }
    };
  };

}} //Tools::wallet_rpc
