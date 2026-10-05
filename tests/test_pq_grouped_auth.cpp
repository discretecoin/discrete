// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Grouped input authorization (parameters::PQ_GROUPED_AUTH_HEIGHT, unscheduled).
//
// Before it, every input of a transfer carries its own 1952-byte ML-DSA key and
// its own 3309-byte signature, even when all of them are signed by one key. From
// it, an input may be a key reference (wire tag 0x13) to an earlier input that
// carries the same key; the referenced input's one signature, made over a body
// that lists every input, authorizes it.
//
// These tests pin: the wire form and its parser, the semantic caps, the height
// gate, that grouping is optional, that a third party cannot re-encode inputs
// under existing signatures, that a reference cannot be used to spend another
// key's output, the batched digest, and the builder and sender behaviour on both
// sides of activation.

#include "gtest/gtest.h"

#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/PqValidation.h"
#include "Serialization/SerializationTools.h"
#include "Wallet/PqSender.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqWallet.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqSeed.h"
#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "PqTxType.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

using namespace CryptoNote;
namespace P = CryptoNote::parameters;

namespace {

CryptoPQ::SeedMaster seedBytes(uint8_t a, uint8_t b) {
  CryptoPQ::SeedMaster out{};
  for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<uint8_t>(i * a + b);
  return out;
}

struct Owner {
  CryptoPQ::DsaPublicKey pub;
  CryptoPQ::DsaSecretKey sk;
};

Owner ownerOf(uint8_t a, uint8_t b) {
  auto keys = CryptoPQ::deriveSpendKeys(seedBytes(a, b));
  return Owner{keys.first, keys.second};
}

// An output owned by `owner`: the spend input a wallet would use plus the view a
// node resolves for it. `n` makes the outpoint and rho distinct.
struct Funded {
  PqSpendInput input;
  PqResolvedInput resolved;
};

Funded fundedBy(const Owner& owner, uint64_t amount, uint32_t n) {
  Funded f;
  for (std::size_t j = 0; j < 32; ++j) f.input.prevTxid.data[j] = static_cast<uint8_t>(j * 5 + 3);
  std::memcpy(f.input.prevTxid.data, &n, sizeof(n));
  f.input.prevOutIndex = n % 3;
  f.input.amount = amount;
  for (std::size_t j = 0; j < f.input.rho.size(); ++j) f.input.rho[j] = static_cast<uint8_t>(j * 11 + 7);
  std::memcpy(f.input.rho.data(), &n, sizeof(n));

  const CryptoPQ::Hash256 sc = CryptoPQ::spendCommit(owner.pub, f.input.rho);
  std::memcpy(f.resolved.spendCommit.data, sc.data(), 32);
  f.resolved.amount = amount;
  f.resolved.exists = true;
  f.resolved.isPqOutput = true;
  return f;
}

PqSendOutput payee(uint64_t amount) {
  return PqSendOutput{CryptoPQ::deriveViewKeys(seedBytes(61, 2)).first,
                      CryptoPQ::deriveSpendKeys(seedBytes(61, 2)).first, amount};
}

CryptoPQ::Hash256 chainId() {
  const char label[] = "grouped-auth test chain";
  return CryptoPQ::sha3_256(label, sizeof(label) - 1);
}

PqSigningContext v1Context() { return PqSigningContext{}; }

PqSigningContext v2Context() {
  PqSigningContext c;
  c.useV2 = true;
  c.chainId = chainId();
  return c;
}

PqSigningContext groupedContext() {
  PqSigningContext c = v2Context();
  c.groupedAuth = true;
  return c;
}

// A built transaction together with the resolved views in input order.
struct Built {
  Transaction tx;
  std::vector<PqResolvedInput> resolved;
};

// Spend `funded[i]` with `owners[i]`'s key, paying everything but a 1-unit fee.
Built build(const std::vector<Funded>& funded, const std::vector<const Owner*>& owners,
            const PqSigningContext& signing) {
  std::vector<PqSpendInput> inputs;
  std::vector<PqInputAuth> auth(funded.size());
  Built b;
  uint64_t total = 0;
  for (std::size_t i = 0; i < funded.size(); ++i) {
    inputs.push_back(funded[i].input);
    b.resolved.push_back(funded[i].resolved);
    auth[i].spendPub = owners[i]->pub;
    auth[i].spendSk = owners[i]->sk;
    total += funded[i].input.amount;
  }
  b.tx = buildPqTransaction(inputs, {payee(total - 1)}, auth, 0, {}, signing);
  return b;
}

bool accepted(const Transaction& tx, const std::vector<PqResolvedInput>& resolved,
              const PqSigningContext& signing, std::string* why = nullptr) {
  std::string err;
  if (!checkPqTransactionSemantic(tx, &err)) {
    if (why) *why = "semantic: " + err;
    return false;
  }
  std::vector<Crypto::Hash> nullifiers;
  if (!checkPqTransactionInputs(tx, resolved, 0, &nullifiers, &err, signing)) {
    if (why) *why = err;
    return false;
  }
  return true;
}

const PqInput& pqIn(const Transaction& tx, std::size_t i) {
  return boost::get<PqInput>(tx.inputs[i]);
}

// Three outputs of key A and one of key B, interleaved: A, A, B, A.
struct MixedSpend {
  Owner a = ownerOf(3, 1);
  Owner b = ownerOf(4, 9);
  std::vector<Funded> funded;
  std::vector<const Owner*> owners;
  MixedSpend() {
    funded = {fundedBy(a, 1000, 1), fundedBy(a, 2000, 2), fundedBy(b, 3000, 3), fundedBy(a, 4000, 4)};
    owners = {&a, &a, &b, &a};
  }
};

}  // namespace

// --- Wire form ----------------------------------------------------------------

TEST(PqGroupedAuthWire, ReferencesTravelWithoutTheKeyAndParseBackPopulated) {
  MixedSpend s;
  Built grouped = build(s.funded, s.owners, groupedContext());
  Built plain = build(s.funded, s.owners, v2Context());

  // Inputs 1 and 3 reuse A (carried by input 0); input 2 carries B.
  ASSERT_EQ(grouped.tx.inputs.size(), 4u);
  EXPECT_EQ(pqIn(grouped.tx, 0).keyRef, PQ_NO_KEY_REF);
  EXPECT_EQ(pqIn(grouped.tx, 1).keyRef, 0u);
  EXPECT_EQ(pqIn(grouped.tx, 2).keyRef, PQ_NO_KEY_REF);
  EXPECT_EQ(pqIn(grouped.tx, 3).keyRef, 0u);
  EXPECT_EQ(grouped.tx.pqSignatures.size(), 2u);  // one per distinct key
  EXPECT_EQ(plain.tx.pqSignatures.size(), 4u);

  const BinaryArray blob = toBinaryArray(grouped.tx);
  // Two references save two keys and two signatures.
  EXPECT_EQ(toBinaryArray(plain.tx).size() - blob.size(),
            2 * (PQ_AUTH_PUB_SIZE + PQ_SIGNATURE_SIZE) - 2 /* two 1-byte key_ref varints */);

  Transaction parsed;
  ASSERT_TRUE(fromBinaryArray(parsed, blob));
  ASSERT_EQ(parsed.inputs.size(), 4u);
  for (std::size_t i = 0; i < 4; ++i) {
    EXPECT_EQ(pqIn(parsed, i).keyRef, pqIn(grouped.tx, i).keyRef);
    // The parser restores every reference's key from the input it names, so all
    // ownership and nullifier code sees a populated input.
    EXPECT_EQ(pqIn(parsed, i).authPub, pqIn(grouped.tx, i).authPub) << "input " << i;
  }
  EXPECT_EQ(toBinaryArray(parsed), blob);
  EXPECT_EQ(getObjectHash(parsed), getObjectHash(grouped.tx));
  EXPECT_TRUE(accepted(parsed, grouped.resolved, groupedContext()));

  // The JSON the daemon serves (and the web wallet parses): type "13", the
  // referenced index as key_ref, and no auth_pub.
  const Common::JsonValue json = storeToJsonValue(grouped.tx);
  const Common::JsonValue& vin = json("vin");
  ASSERT_EQ(vin.size(), 4u);
  EXPECT_EQ(vin[0]("type").getString(), "10");
  EXPECT_TRUE(vin[0]("value").contains("auth_pub"));
  EXPECT_EQ(vin[1]("type").getString(), "13");
  EXPECT_EQ(vin[1]("value")("key_ref").getInteger(), 0);
  EXPECT_FALSE(vin[1]("value").contains("auth_pub"));
}

TEST(PqGroupedAuthWire, ParserRejectsReferencesThatDoNotPointBackAtAKey) {
  MixedSpend s;
  Built grouped = build(s.funded, s.owners, groupedContext());
  Transaction parsed;

  // A reference to itself or to a later input has no key to inherit.
  Transaction forward = grouped.tx;
  boost::get<PqInput>(forward.inputs[1]).keyRef = 1;
  EXPECT_FALSE(fromBinaryArray(parsed, toBinaryArray(forward)));
  boost::get<PqInput>(forward.inputs[1]).keyRef = 2;
  EXPECT_FALSE(fromBinaryArray(parsed, toBinaryArray(forward)));

  // A reference to another reference is refused rather than chased.
  Transaction chained = grouped.tx;
  boost::get<PqInput>(chained.inputs[3]).keyRef = 1;
  EXPECT_FALSE(fromBinaryArray(parsed, toBinaryArray(chained)));

  // Tag 0x13 carrying the "no reference" value would re-serialize as a
  // different (key-carrying) input, so it is not a valid encoding at all.
  const BinaryArray blob = toBinaryArray(grouped.tx);
  const Crypto::Hash& txid1 = pqIn(grouped.tx, 1).prevTxid;
  BinaryArray needle{0x13};
  needle.insert(needle.end(), txid1.data, txid1.data + 32);
  auto at = std::search(blob.begin(), blob.end(), needle.begin(), needle.end());
  ASSERT_NE(at, blob.end());
  const std::size_t keyRefOffset = (at - blob.begin()) + needle.size() + 1;  // prevOutIndex < 128
  ASSERT_EQ(blob[keyRefOffset], 0x00);                                      // keyRef = 0
  BinaryArray bad(blob.begin(), blob.begin() + keyRefOffset);
  for (uint8_t b : {0xFF, 0xFF, 0xFF, 0xFF, 0x0F}) bad.push_back(b);          // varint 0xFFFFFFFF
  bad.insert(bad.end(), blob.begin() + keyRefOffset + 1, blob.end());
  EXPECT_FALSE(fromBinaryArray(parsed, bad));
}

TEST(PqGroupedAuthWire, OversizedReferenceListsFailBeforeAnyKeyIsCopied) {
  // 257 inputs, all but the first referencing it: refused at the first reference,
  // before a single 1952-byte key is copied into it.
  Owner a = ownerOf(3, 1);
  TransactionInputs inputs;
  PqInput carrier;
  carrier.authPub.assign(a.pub.begin(), a.pub.end());
  carrier.rhoReveal.assign(PQ_RHO_SIZE, 7);
  inputs.push_back(carrier);
  for (uint32_t n = 1; n <= P::MAX_PQ_GROUPED_INPUTS_PER_TX; ++n) {
    PqInput ref;
    ref.prevOutIndex = n;
    ref.keyRef = 0;
    ref.rhoReveal.assign(PQ_RHO_SIZE, 7);
    inputs.push_back(ref);
  }
  try {
    resolvePqKeyReferences(inputs);
    FAIL() << "expected the input-count guard";
  } catch (const std::runtime_error& e) {
    EXPECT_NE(std::string(e.what()).find("before key-reference expansion"), std::string::npos) << e.what();
  }
  EXPECT_TRUE(boost::get<PqInput>(inputs[1]).authPub.empty());

  // A list of exactly the cap is resolved.
  inputs.pop_back();
  resolvePqKeyReferences(inputs);
  EXPECT_EQ(boost::get<PqInput>(inputs.back()).authPub, carrier.authPub);
}

TEST(PqGroupedAuthWire, TwoHundredFiftySixInputsRoundTripOneMoreDoesNotParse) {
  Owner a = ownerOf(3, 1);
  std::vector<Funded> funded;
  std::vector<const Owner*> owners;
  for (uint32_t n = 0; n < P::MAX_PQ_GROUPED_INPUTS_PER_TX; ++n) {
    funded.push_back(fundedBy(a, 10, n));
    owners.push_back(&a);
  }
  Built full = build(funded, owners, groupedContext());
  ASSERT_EQ(full.tx.pqSignatures.size(), 1u);

  const BinaryArray blob = toBinaryArray(full.tx);
  Transaction parsed;
  ASSERT_TRUE(fromBinaryArray(parsed, blob));
  EXPECT_EQ(toBinaryArray(parsed), blob);
  std::string why;
  EXPECT_TRUE(accepted(parsed, full.resolved, groupedContext(), &why)) << why;

  Transaction over = full.tx;
  PqInput extra = boost::get<PqInput>(over.inputs[1]);
  extra.prevOutIndex += 1000;
  over.inputs.push_back(extra);
  EXPECT_FALSE(fromBinaryArray(parsed, toBinaryArray(over)));
}

// --- Semantic caps --------------------------------------------------------------

TEST(PqGroupedAuthSemantic, ReferenceMustHoldTheReferencedKey) {
  MixedSpend s;
  Built grouped = build(s.funded, s.owners, groupedContext());
  std::string err;
  ASSERT_TRUE(checkPqTransactionSemantic(grouped.tx, &err)) << err;

  // In memory a reference could claim a key other than the one it names; on the
  // wire that would be a different transaction, so it is refused outright.
  Transaction lying = grouped.tx;
  boost::get<PqInput>(lying.inputs[1]).authPub = pqIn(grouped.tx, 2).authPub;
  EXPECT_FALSE(checkPqTransactionSemantic(lying, &err));

  Transaction missingSignature = grouped.tx;
  missingSignature.pqSignatures.pop_back();
  EXPECT_FALSE(checkPqTransactionSemantic(missingSignature, &err));
}

TEST(PqGroupedAuthSemantic, CapsAreThirtyTwoKeysAndTwoHundredFiftySixInputs) {
  // 32 distinct keys, each spending 8 outputs: 256 inputs, 32 signatures.
  std::vector<Owner> keys;
  for (uint8_t k = 0; k < P::MAX_PQ_INPUTS_PER_TX; ++k) keys.push_back(ownerOf(7, k));
  std::vector<Funded> funded;
  std::vector<const Owner*> owners;
  for (uint32_t n = 0; n < P::MAX_PQ_GROUPED_INPUTS_PER_TX; ++n) {
    const Owner& o = keys[n % keys.size()];
    funded.push_back(fundedBy(o, 10, n));
    owners.push_back(&o);
  }
  Built full = build(funded, owners, groupedContext());
  EXPECT_EQ(full.tx.inputs.size(), P::MAX_PQ_GROUPED_INPUTS_PER_TX);
  EXPECT_EQ(full.tx.pqSignatures.size(), P::MAX_PQ_INPUTS_PER_TX);
  EXPECT_LE(toBinaryArray(full.tx).size(), P::MAX_PQ_TX_SIZE);
  std::string why;
  EXPECT_TRUE(accepted(full.tx, full.resolved, groupedContext(), &why)) << why;

  // One more input of an existing key exceeds the total cap.
  funded.push_back(fundedBy(keys[0], 10, 9999));
  owners.push_back(&keys[0]);
  EXPECT_THROW(build(funded, owners, groupedContext()), std::runtime_error);
  Transaction over = full.tx;
  over.inputs.push_back(over.inputs[1]);
  std::string err;
  EXPECT_FALSE(checkPqTransactionSemantic(over, &err));

  // A 33rd key exceeds the key cap however few inputs there are.
  std::vector<Funded> manyKeys;
  std::vector<const Owner*> manyOwners;
  Owner extra = ownerOf(8, 200);
  for (uint32_t k = 0; k < keys.size(); ++k) {
    manyKeys.push_back(fundedBy(keys[k], 10, k));
    manyOwners.push_back(&keys[k]);
  }
  manyKeys.push_back(fundedBy(extra, 10, 777));
  manyOwners.push_back(&extra);
  EXPECT_THROW(build(manyKeys, manyOwners, groupedContext()), std::runtime_error);
}

// --- Height gate and optional grouping --------------------------------------------

TEST(PqGroupedAuthInputs, ReferencesAreRefusedUntilActivation) {
  MixedSpend s;
  Built grouped = build(s.funded, s.owners, groupedContext());
  std::string why;
  ASSERT_TRUE(accepted(grouped.tx, grouped.resolved, groupedContext(), &why)) << why;
  EXPECT_FALSE(accepted(grouped.tx, grouped.resolved, v2Context(), &why));
  EXPECT_NE(why.find("not active"), std::string::npos) << why;
  EXPECT_FALSE(accepted(grouped.tx, grouped.resolved, v1Context(), &why));

  // Grouping is defined on the version-2 transcript only.
  PqSigningContext groupedWithoutV2 = groupedContext();
  groupedWithoutV2.useV2 = false;
  EXPECT_FALSE(accepted(grouped.tx, grouped.resolved, groupedWithoutV2));
  EXPECT_THROW(build(s.funded, s.owners, groupedWithoutV2), std::runtime_error);
}

TEST(PqGroupedAuthInputs, GroupingIsOptionalAfterActivation) {
  // A wallet that signs version 2 but never groups stays valid: same spend, more bytes.
  MixedSpend s;
  Built plain = build(s.funded, s.owners, v2Context());
  std::string why;
  EXPECT_TRUE(accepted(plain.tx, plain.resolved, groupedContext(), &why)) << why;
}

TEST(PqGroupedAuthInputs, NobodyButTheSignerCanChangeAnInputsForm) {
  MixedSpend s;
  const PqSigningContext grouped = groupedContext();
  std::string why;

  // Expanding a reference into a key-carrying input: even reusing the key's own
  // signature, every digest changes, so every signature fails.
  Built g = build(s.funded, s.owners, grouped);
  Transaction expanded = g.tx;
  boost::get<PqInput>(expanded.inputs[1]).keyRef = PQ_NO_KEY_REF;
  expanded.pqSignatures.insert(expanded.pqSignatures.begin() + 1, expanded.pqSignatures[0]);
  EXPECT_NE(getObjectHash(expanded), getObjectHash(g.tx));
  EXPECT_FALSE(accepted(expanded, g.resolved, grouped, &why));
  EXPECT_NE(why.find("signature"), std::string::npos) << why;

  // Compressing a signed input into a reference and dropping its signature.
  Built p = build(s.funded, s.owners, v2Context());
  Transaction compressed = p.tx;
  boost::get<PqInput>(compressed.inputs[1]).keyRef = 0;
  compressed.pqSignatures.erase(compressed.pqSignatures.begin() + 1);
  EXPECT_NE(getObjectHash(compressed), getObjectHash(p.tx));
  EXPECT_FALSE(accepted(compressed, p.resolved, grouped, &why));
  EXPECT_NE(why.find("signature"), std::string::npos) << why;
}

TEST(PqGroupedAuthInputs, AReferenceCannotSpendAnotherKeysOutput) {
  // Input 1 spends B's output but references A's input. The reference forces
  // the input's key to be A, and spend_commit(A, rho) does not open B's output.
  Owner a = ownerOf(3, 1);
  Owner b = ownerOf(4, 9);
  std::vector<Funded> funded = {fundedBy(a, 1000, 1), fundedBy(b, 2000, 2)};
  Built honest = build(funded, {&a, &b}, groupedContext());
  ASSERT_EQ(pqIn(honest.tx, 1).keyRef, PQ_NO_KEY_REF);  // B carries its own key

  Transaction stolen = honest.tx;
  PqInput& in = boost::get<PqInput>(stolen.inputs[1]);
  in.keyRef = 0;
  in.authPub = pqIn(honest.tx, 0).authPub;
  stolen.pqSignatures.pop_back();
  std::string why;
  EXPECT_FALSE(accepted(stolen, honest.resolved, groupedContext(), &why));
  EXPECT_NE(why.find("spend_commit"), std::string::npos) << why;
}

TEST(PqGroupedAuthInputs, TheSignatureCoversEveryReferencingInput) {
  // Point a referencing input at a different outpoint whose (pretend) output has
  // the same commitment and amount: ownership still checks out, so only the
  // signature can notice, and it must.
  MixedSpend s;
  Built g = build(s.funded, s.owners, groupedContext());
  Transaction moved = g.tx;
  boost::get<PqInput>(moved.inputs[3]).prevOutIndex += 1;
  std::string why;
  EXPECT_FALSE(accepted(moved, g.resolved, groupedContext(), &why));
  EXPECT_NE(why.find("signature"), std::string::npos) << why;
}

// --- Digest ----------------------------------------------------------------------

TEST(PqGroupedAuthDigest, BatchedDigestsEqualTheOneShotDefinition) {
  CryptoPQ::UnsignedTx u;
  u.txType = TX_PQ;
  u.fee = 9;
  u.inputs.resize(5);
  for (std::size_t i = 0; i < u.inputs.size(); ++i) {
    u.inputs[i].prevTxid.fill(static_cast<uint8_t>(i + 1));
    u.inputs[i].prevOutIndex = static_cast<uint32_t>(i);
    u.inputs[i].authPub.fill(static_cast<uint8_t>(i % 2));
    u.inputs[i].rhoReveal.fill(static_cast<uint8_t>(40 + i));
  }
  u.inputs[2].keyRef = 0;
  u.inputs[4].keyRef = 1;
  const std::vector<uint32_t> signers = {0, 1, 3};
  const std::vector<CryptoPQ::Hash256> batch = CryptoPQ::txSigningDigestsV2(u, chainId(), signers);
  ASSERT_EQ(batch.size(), signers.size());
  for (std::size_t k = 0; k < signers.size(); ++k) {
    EXPECT_EQ(batch[k], CryptoPQ::txSigningDigestV2(u, chainId(), signers[k]));
  }
  EXPECT_TRUE(CryptoPQ::txSigningDigestsV2(u, chainId(), {}).empty());
}

TEST(PqGroupedAuthDigest, VersionTwoBindsEveryKeyReferenceVersionOneDoesNot) {
  CryptoPQ::UnsignedTx u;
  u.inputs.resize(3);
  const CryptoPQ::Hash256 before = CryptoPQ::txSigningDigestV2(u, chainId(), 0);
  const CryptoPQ::Hash256 v1Before = CryptoPQ::txSigningDigest(u);
  u.inputs[2].keyRef = 0;
  EXPECT_NE(CryptoPQ::txSigningDigestV2(u, chainId(), 0), before);
  // Version 1 predates references; they are invalid under it, not silently bound.
  EXPECT_EQ(CryptoPQ::txSigningDigest(u), v1Before);
}

// --- Builder and sender ------------------------------------------------------------

TEST(PqGroupedAuthBuilder, GroupsOnlyWhenActive) {
  MixedSpend s;
  for (const PqSigningContext& ctx : {v1Context(), v2Context()}) {
    Built b = build(s.funded, s.owners, ctx);
    EXPECT_EQ(b.tx.pqSignatures.size(), b.tx.inputs.size());
    for (std::size_t i = 0; i < b.tx.inputs.size(); ++i) EXPECT_EQ(pqIn(b.tx, i).keyRef, PQ_NO_KEY_REF);
    EXPECT_TRUE(accepted(b.tx, b.resolved, ctx));
  }
}

TEST(PqGroupedAuthSender, OneTransactionMergesTwoHundredFiftySixOutputs) {
  PqWalletKeys me = derivePqWalletKeys(seedBytes(17, 5));
  Owner key{me.spendPub, me.spendSk};
  std::vector<PqSpendInput> available;
  std::vector<Funded> funded;
  for (uint32_t n = 0; n < 300; ++n) {
    funded.push_back(fundedBy(key, 100 + n, n));
    available.push_back(funded.back().input);
  }

  PqConsolidationRequest req;
  req.genesisId = chainId();
  req.scheme = PqDepositScheme::SingleKeyIndex;

  // Today: 32 inputs per transaction.
  PqConsolidationPlan today = planPqConsolidation(available, req);
  EXPECT_EQ(today.selectedInputs, P::MAX_PQ_INPUTS_PER_TX);

  // Grouped: 256 inputs, one key, one signature, one output.
  req.signingHeight = P::PQ_GROUPED_AUTH_HEIGHT;
  PqConsolidationResult merged = buildPqConsolidation(available, me, req);
  ASSERT_EQ(merged.plan.selectedInputs, P::MAX_PQ_GROUPED_INPUTS_PER_TX);
  const Transaction& tx = merged.transaction.tx;
  EXPECT_EQ(tx.pqSignatures.size(), 1u);
  EXPECT_EQ(tx.outputs.size(), 1u);
  EXPECT_LT(toBinaryArray(tx).size(), 30u * 1024);

  std::vector<PqResolvedInput> resolved;
  for (const auto& in : merged.transaction.selected) {
    for (const auto& f : funded) {
      if (f.input.prevTxid == in.prevTxid && f.input.prevOutIndex == in.prevOutIndex) {
        resolved.push_back(f.resolved);
        break;
      }
    }
  }
  ASSERT_EQ(resolved.size(), tx.inputs.size());
  std::string why;
  EXPECT_TRUE(accepted(tx, resolved,
                       pqSigningContextForHeight(P::PQ_GROUPED_AUTH_HEIGHT, chainId()), &why)) << why;
}

TEST(PqGroupedAuthSender, LargePaymentsStopNeedingConsolidation) {
  PqWalletKeys me = derivePqWalletKeys(seedBytes(19, 6));
  Owner key{me.spendPub, me.spendSk};
  std::vector<PqSpendInput> available;
  for (uint32_t n = 0; n < 200; ++n) available.push_back(fundedBy(key, 100, n).input);

  PqSendRequest req;
  req.genesisId = chainId();
  req.scheme = PqDepositScheme::SingleKeyIndex;
  req.recipients.push_back(payee(150 * 100));  // needs ~151 inputs

  try {
    buildPqSend(available, me, req);
    FAIL() << "expected PqSendError before activation";
  } catch (const PqSendError& e) {
    EXPECT_EQ(e.code, PqSendErrorCode::TooLarge);
  }

  req.signingHeight = P::PQ_GROUPED_AUTH_HEIGHT;
  PqSendResult r = buildPqSend(available, me, req);
  EXPECT_GE(r.selected.size(), 151u);
  EXPECT_EQ(r.tx.pqSignatures.size(), 1u);
  // The sweep folds up to PQ_SWEEP_MAX_EXTRA_KEY_REFERENCES more of the same key.
  EXPECT_LE(r.selected.size(), 151u + PQ_SWEEP_MAX_EXTRA_KEY_REFERENCES);
  EXPECT_GE(available.size() - r.selected.size(), PQ_SWEEP_KEEP_OUTPUTS);
}

TEST(PqGroupedAuthSchedule, ActivationIsNotScheduledAndRidesOnTranscriptV2) {
  EXPECT_EQ(P::PQ_GROUPED_AUTH_HEIGHT, P::PQ_TRANSCRIPT_V2_HEIGHT);
  EXPECT_EQ(P::PQ_GROUPED_AUTH_HEIGHT, std::numeric_limits<uint32_t>::max());
  const Crypto::Hash genesis{};
  EXPECT_FALSE(pqSigningContextForHeight(0, genesis).groupedAuth);
  EXPECT_FALSE(pqSigningContextForHeight(std::numeric_limits<uint32_t>::max() - 1, genesis).groupedAuth);
  const PqSigningContext at = pqSigningContextForHeight(P::PQ_GROUPED_AUTH_HEIGHT, genesis);
  EXPECT_TRUE(at.groupedAuth && at.useV2);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
