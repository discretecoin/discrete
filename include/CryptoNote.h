// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
// Copyright (c) 2026, The Discrete developers
//
// Discrete — post-quantum-only cryptocurrency.
// ECC-based types (KeyInput, KeyOutput, AccountPublicAddress with ECC keys)
// have been removed. Only PQ wire types remain.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <boost/variant.hpp>
#include "android.h"
#include "CryptoTypes.h"
#include "PqAddress.h"

namespace CryptoNote {

// ---------------------------------------------------------------------------
// Block coinbase input (genesis / miner reward)
// ---------------------------------------------------------------------------
struct BaseInput {
  uint32_t blockIndex;
};

// Legacy ECC ring-sig input — kept as a stub for compilation.
// MUST NOT appear in any valid Discrete transaction; the consensus layer
// rejects transactions that contain KeyInput at the semantic-check stage.
struct KeyInput {
  uint64_t amount;
  std::vector<uint32_t> outputIndexes;
  Crypto::KeyImage keyImage;
};

// Legacy ECC stealth output — stub for compilation only.
struct KeyOutput {
  Crypto::PublicKey key;
};

// ---------------------------------------------------------------------------
// PQ wire types (the only transaction input/output types in Discrete)
// ---------------------------------------------------------------------------
// Fixed-size blob sizes (consensus-enforced).
constexpr size_t PQ_KEM_CIPHERTEXT_SIZE = 1088;  // ML-KEM-768 ciphertext
constexpr size_t PQ_ENC_PAYLOAD_SIZE    = 48;    // ChaCha20-Poly1305(rho): 32 ct + 16 tag
constexpr size_t PQ_AUTH_PUB_SIZE       = 1952;  // ML-DSA-65 public spend key
constexpr size_t PQ_RHO_SIZE            = 32;
constexpr size_t PQ_SIGNATURE_SIZE      = 3309;  // ML-DSA-65 signature

// One PQ input. The ML-DSA signature is embedded here (not in Transaction.signatures).
struct PqInput {
  Crypto::Hash         prevTxid;
  uint32_t             prevOutIndex;
  std::vector<uint8_t> authPub;     // PQ_AUTH_PUB_SIZE bytes
  std::vector<uint8_t> rhoReveal;   // PQ_RHO_SIZE bytes
  std::vector<uint8_t> signature;   // PQ_SIGNATURE_SIZE bytes
};

// One PQ output target. Amount is plain (in TransactionOutput.amount).
struct PqOutput {
  std::vector<uint8_t> kemCt;       // PQ_KEM_CIPHERTEXT_SIZE bytes
  std::vector<uint8_t> encPayload;  // PQ_ENC_PAYLOAD_SIZE bytes
  Crypto::Hash         spendCommit; // SHA3-256(spend_pub || rho)
};

// ---------------------------------------------------------------------------
// Coinbase output (miner reward to a PQ address).
// For v6+ coinbase: BaseInput + one or more CoinbaseOutput (= PqOutput with
// the miner's kemCt/encPayload/spendCommit constructed from their PQ address).
// We alias PqOutput here for clarity; the serializer treats them identically.
// ---------------------------------------------------------------------------
using CoinbaseOutput = PqOutput;

// ---------------------------------------------------------------------------
// Transaction input/output variant types.
// KeyInput is removed — the consensus layer rejects any transaction carrying it.
// KeyOutput is kept in the variant so existing visitor code compiles, but the
// serializer throws if it encounters tag 0x2 (KeyOutput) on the wire, and
// Blockchain::checkTransactionInputs rejects any tx whose outputs aren't PqOutput.
// ---------------------------------------------------------------------------
typedef boost::variant<BaseInput, PqInput> TransactionInput;
typedef boost::variant<KeyOutput, PqOutput> TransactionOutputTarget;

struct TransactionOutput {
  uint64_t amount;
  TransactionOutputTarget target;
};

using TransactionInputs = std::vector<TransactionInput>;

struct TransactionPrefix {
  uint8_t  version;
  uint8_t  txType = 0;   // PQ sub-type (TX_PQ / TX_FREE_REG); 0 for coinbase
  uint64_t unlockTime;
  TransactionInputs inputs;
  std::vector<TransactionOutput> outputs;
  std::vector<uint8_t> extra;
};

struct Transaction : public TransactionPrefix {
  // No legacy ring-signature vector. PQ signatures live inside PqInput.
  // The field is kept (always empty) for ABI compat with serialization paths
  // that still reference Transaction::signatures.
  std::vector<std::vector<Crypto::Signature>> signatures;
};

constexpr size_t PQ_VIEW_PUB_SIZE = 1184;  // ML-KEM-768 encapsulation key

// Legacy ECC address type — kept as a stub for code that references it but
// must never appear in any valid Discrete transaction or wallet.
struct AccountPublicAddress {
  Crypto::PublicKey spendPublicKey;
  Crypto::PublicKey viewPublicKey;
};

struct ParentBlock {
  uint8_t  majorVersion;
  uint8_t  minorVersion;
  Crypto::Hash previousBlockHash;
  uint16_t transactionCount;
  std::vector<Crypto::Hash> baseTransactionBranch;
  Transaction baseTransaction;
  std::vector<Crypto::Hash> blockchainBranch;
};

struct BlockHeader {
  uint8_t  majorVersion;
  uint8_t  minorVersion;
  uint32_t nonce;
  uint64_t timestamp;
  Crypto::Hash previousBlockHash;
};

struct Block : public BlockHeader {
  ParentBlock parentBlock;
  Transaction baseTransaction;
  // PQ block signature: ML-DSA-65 signature (3309 bytes).
  // The miner signs SHA3-256(get_block_hashing_blob) with their spend secret key.
  std::vector<uint8_t> signature;
  std::vector<Crypto::Hash> transactionHashes;
};

// ECC account keys — stub only; Discrete wallets use PqWallet.
struct AccountKeys {
  AccountPublicAddress address;
  Crypto::SecretKey spendSecretKey;
  Crypto::SecretKey viewSecretKey;
};

struct KeyPair {
  Crypto::PublicKey publicKey;
  Crypto::SecretKey secretKey;
};

using BinaryArray = std::vector<uint8_t>;

}  // namespace CryptoNote
