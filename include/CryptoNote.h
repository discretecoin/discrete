// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
// Copyright (c) 2026, The Discrete developers
//
// Discrete — post-quantum-only cryptocurrency.
// ECC-based types (KeyInput, KeyOutput, AccountPublicAddress with ECC keys)
// have been removed. Only PQ wire types remain.

#pragma once

#include <array>
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
constexpr size_t PQ_ENC_PAYLOAD_SIZE    = 56;    // ChaCha20-Poly1305(rho||LE64(T)): 40 ct + 16 tag
constexpr size_t PQ_AUTH_PUB_SIZE       = 1952;  // ML-DSA-65 public spend key
constexpr size_t PQ_RHO_SIZE            = 32;
constexpr size_t PQ_SIGNATURE_SIZE      = 3309;  // ML-DSA-65 signature

// PqInput::keyRef value meaning "this input carries its own spend key".
constexpr uint32_t PQ_NO_KEY_REF = 0xFFFFFFFFu;

// One PQ input (no embedded signature — ML-DSA signatures live in Transaction.pqSignatures).
//
// Two wire forms share this one in-memory type:
//
//   key-carrying (tag 0x10)   prevTxid, prevOutIndex, authPub, rhoReveal
//   key-reference (tag 0x13)  prevTxid, prevOutIndex, keyRef,  rhoReveal
//
// A key-reference input is authorized by the same ML-DSA key as an EARLIER
// key-carrying input of the same transaction, named by its index. It carries no
// key and no signature of its own: the one signature of the input it references
// covers the whole transaction body, which includes this input's outpoint and
// rho. That turns the marginal cost of spending another output of the same key
// from ~5.3 KB (key + signature) into ~70 bytes.
//
// `authPub` is ALWAYS populated in memory, whichever form the input has on the
// wire — the deserializer copies it from the referenced input — so ownership,
// nullifier and scanning code never has to distinguish the two forms. Only the
// serializer, the signature count and the consensus structure checks read keyRef.
//
// Key references are a consensus change that is implemented but not scheduled:
// see parameters::PQ_GROUPED_AUTH_HEIGHT. Grouping is optional; the signer picks
// the form, and every signature binds it.
struct PqInput {
  Crypto::Hash         prevTxid;
  uint32_t             prevOutIndex;
  std::vector<uint8_t> authPub;     // PQ_AUTH_PUB_SIZE bytes
  std::vector<uint8_t> rhoReveal;   // PQ_RHO_SIZE bytes
  uint32_t             keyRef = PQ_NO_KEY_REF;  // index of the input carrying this key
};

// One PQ output target. Amount is plain (in TransactionOutput.amount).
struct PqOutput {
  std::vector<uint8_t> kemCt;       // PQ_KEM_CIPHERTEXT_SIZE bytes
  std::vector<uint8_t> encPayload;  // PQ_ENC_PAYLOAD_SIZE bytes
  Crypto::Hash         spendCommit; // SHA3-256(spend_pub || rho)
};

// ---------------------------------------------------------------------------
// Coinbase output (miner reward / genesis Treasury Reserve batch).
// Stripped form: only the spend commitment, no KEM ciphertext or AEAD payload.
// The rho is publicly derivable as coinbaseRho(spendPub, height, outputIndex),
// so the recipient doesn't need an encrypted delivery — they recompute it.
// Wire tag: 0x11 (distinct from PqOutput 0x10).
// ---------------------------------------------------------------------------
struct CoinbaseOutput {
  Crypto::Hash spendCommit;  // SHA3-256(kDomainSpendCommit || spendPub || rho)
};

// ---------------------------------------------------------------------------
// Transaction input/output variant types.
// KeyInput is removed — the consensus layer rejects any transaction carrying it.
// KeyOutput is kept in the variant so existing visitor code compiles, but the
// serializer throws if it encounters tag 0x2 (KeyOutput) on the wire, and
// Blockchain::checkTransactionInputs rejects any tx whose outputs aren't PqOutput.
// ---------------------------------------------------------------------------
// Experimental conditional-output profile. Not activated on mainnet.
struct SwapOutput {
  uint8_t version = 1, hashScheme = 1, authScheme = 1, amountScheme = 1;
  Crypto::Hash nonce{}, hashlock{}, claimCommit{}, refundCommit{};
  uint32_t refundHeight = 0;
};
struct SwapInput {
  Crypto::Hash prevTxid{};
  uint32_t prevOutIndex = 0;
  uint8_t branch = 1; // 1 = claimant + preimage; 2 = timed refund owner.
  std::vector<uint8_t> authPub, rhoReveal, secret;
};
typedef boost::variant<BaseInput, PqInput, SwapInput> TransactionInput;
typedef boost::variant<KeyOutput, PqOutput, CoinbaseOutput, SwapOutput> TransactionOutputTarget;

struct TransactionOutput {
  uint64_t amount;
  // Per-output spend lock: the output is unspendable until the chain reaches
  // this block height. 0 = no lock (immediately spendable once mature). This is
  // a consensus field, distinct from the per-tx TransactionPrefix.unlockHeight:
  // it lets one transaction time-lock some outputs (e.g. a vesting payment or a
  // genesis Treasury Reserve batch) while leaving others (e.g. change) spendable.
  uint64_t unlockHeight = 0;
  TransactionOutputTarget target;
};

using TransactionInputs = std::vector<TransactionInput>;

struct TransactionPrefix {
  uint8_t  version;
  uint8_t  txType = 0;   // PQ sub-type (TX_PQ / TX_FREE_REG); 0 for coinbase
  uint64_t unlockHeight;
  TransactionInputs inputs;
  std::vector<TransactionOutput> outputs;
  std::vector<uint8_t> extra;
};

struct Transaction : public TransactionPrefix {
  // ML-DSA-65 signatures: one fixed-size array per KEY-CARRYING input (PqInput
  // with keyRef == PQ_NO_KEY_REF, or SwapInput), in input order. Key-reference
  // inputs have none. Analogous to CN's ring-sig vector; size enforced at
  // compile time. Empty for coinbase (BaseInput only) and TX_FREE_REG (no inputs).
  std::vector<std::array<uint8_t, PQ_SIGNATURE_SIZE>> pqSignatures;
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
  // DiscretePower PoW signature: exactly one ML-DSA-65 signature (DISCRETE_POWER_SIG_LEN =
  // 3309 bytes), serialized OUTSIDE the hashing blob. The block-v1 ID commits to
  // it through a 32-byte SHAKE-256 witness, while admission independently verifies
  // the signature-bound PoW for every new proof-bearing ID. The miner signs
  // m = SHAKE256("DiscretePower/v2/sign" || H) every attempt;
  // this same signature is the tape injected into yespower-discrete AND the reward
  // binding (there is no separate reward signature). See
  // https://docs.discrete.cash/#/consensus/pow.
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
