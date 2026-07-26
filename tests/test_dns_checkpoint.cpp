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

// DNS checkpoint pointer scheme (src/Checkpoints/DnsCheckpoint.*).
//
// The TXT record carries only a pointer; the ML-DSA-65 signature (3309 bytes,
// unpublishable in any TXT encoding) lives in an HTTPS-hosted JSON file that the
// pointer's SHA-256 covers byte for byte. These tests exercise the pure half —
// pointer parsing, canonical serialization, and full file verification.

#include "gtest/gtest.h"

#include <string>
#include <vector>

#include "CheckpointsDns/DnsCheckpoint.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "crypto_pq/PqDsa.h"

using namespace CryptoNote;

namespace {

const char kGenesisHex[] = "ffeb0c0311223344556677889900aabbccddeeff00112233445566778899aabb";
const char kBlockHex[]   = "a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff0";
const uint32_t kHeight   = 123456;

Crypto::Hash genesisHash() {
  Crypto::Hash h{};
  EXPECT_TRUE(Common::podFromHex(std::string(kGenesisHex), h));
  return h;
}

// A deterministic signer, so failures are reproducible.
std::pair<CryptoPQ::DsaPublicKey, CryptoPQ::DsaSecretKey> signer(uint8_t fill = 7) {
  CryptoPQ::DsaKeypairSeed seed{};
  seed.fill(fill);
  return CryptoPQ::dsa_keygen_from_seed(seed);
}

// Build a signed, canonical checkpoint file for the given network/height/hash.
std::string makeFile(const CryptoPQ::DsaSecretKey& sk,
                     const CryptoPQ::DsaPublicKey& pk,
                     const std::string& network = "mainnet",
                     uint32_t height = kHeight,
                     const std::string& blockHex = kBlockHex) {
  CheckpointRecord rec;
  rec.version = 1;
  rec.network = network;
  rec.height  = height;
  EXPECT_TRUE(Common::podFromHex(blockHex, rec.blockHash));
  rec.sigAlg    = kCheckpointSigAlg;
  rec.keyId     = checkpointKeyId(pk);
  rec.signature = signMessagePq(
      buildCheckpointSignedPayload(kGenesisHex, network, height, blockHex), sk);
  return serializeCheckpointJsonCanonical(rec);
}

// The TXT pointer that publishes `fileBytes` at `height`.
std::string makeTxt(const std::string& fileBytes, uint32_t height = kHeight) {
  return "v=1;alg=sha256;height=" + std::to_string(height) +
         ";hash=" + sha256Hex(fileBytes) +
         ";url=https://discrete.cash/checkpoints/" + std::to_string(height) + ".json";
}

CheckpointPointer parseOk(const std::string& txt) {
  CheckpointPointer p;
  std::string reject;
  EXPECT_TRUE(parseCheckpointPointer(txt, p, reject)) << reject;
  return p;
}

}  // namespace

// --------------------------------------------------------------------------
// SHA-256 helper — known-answer, since the whole scheme hangs off this digest.
// --------------------------------------------------------------------------

TEST(DnsCheckpointHash, Sha256KnownAnswers) {
  EXPECT_EQ(sha256Hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(sha256Hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// --------------------------------------------------------------------------
// TXT pointer parsing.
// --------------------------------------------------------------------------

TEST(DnsCheckpointPointer, ValidRecord) {
  const std::string hash(64, 'a');
  CheckpointPointer p = parseOk(
      "v=1;alg=sha256;height=123456;hash=" + hash +
      ";url=https://discrete.cash/checkpoints/123456.json");

  EXPECT_EQ(p.version, 1u);
  EXPECT_EQ(p.alg, "sha256");
  EXPECT_EQ(p.height, 123456u);
  EXPECT_EQ(p.sha256Hex, hash);
  EXPECT_EQ(p.host, "discrete.cash");
  EXPECT_EQ(p.path, "/checkpoints/123456.json");
}

TEST(DnsCheckpointPointer, RejectsMalformedAndUnsupported) {
  const std::string h(64, 'a');
  const std::string url = ";url=https://discrete.cash/checkpoints/123456.json";
  struct Case { const char* name; std::string txt; };

  const std::vector<Case> cases = {
    {"field without =",   "v=1;alg=sha256;height=123456;hash=" + h + ";urlhttps://x"},
    {"missing url",       "v=1;alg=sha256;height=123456;hash=" + h},
    {"missing hash",      "v=1;alg=sha256;height=123456" + url},
    {"missing height",    "v=1;alg=sha256;hash=" + h + url},
    {"unsupported v",     "v=2;alg=sha256;height=123456;hash=" + h + url},
    {"unsupported alg",   "v=1;alg=md5;height=123456;hash=" + h + url},
    {"hash too short",    "v=1;alg=sha256;height=123456;hash=abc" + url},
    {"hash uppercase",    "v=1;alg=sha256;height=123456;hash=" + std::string(64, 'A') + url},
    {"height not number", "v=1;alg=sha256;height=12x;hash=" + h + url},
    {"height negative",   "v=1;alg=sha256;height=-1;hash=" + h + url},
    {"duplicate field",   "v=1;v=1;alg=sha256;height=123456;hash=" + h + url},
    {"not https",         "v=1;alg=sha256;height=123456;hash=" + h +
                          ";url=http://discrete.cash/checkpoints/123456.json"},
    {"unexpected host",   "v=1;alg=sha256;height=123456;hash=" + h +
                          ";url=https://evil.example/checkpoints/123456.json"},
    {"url has no path",   "v=1;alg=sha256;height=123456;hash=" + h + ";url=https://discrete.cash"},
    {"filename mismatch", "v=1;alg=sha256;height=123456;hash=" + h +
                          ";url=https://discrete.cash/checkpoints/999.json"},
  };

  for (const auto& c : cases) {
    CheckpointPointer p;
    std::string reject;
    EXPECT_FALSE(parseCheckpointPointer(c.txt, p, reject)) << "should reject: " << c.name;
    EXPECT_FALSE(reject.empty()) << "no reason given for: " << c.name;
  }
}

// A host that merely *ends with* the pinned host must not slip through.
TEST(DnsCheckpointPointer, RejectsHostSuffixSpoofing) {
  CheckpointPointer p;
  std::string reject;
  EXPECT_FALSE(parseCheckpointPointer(
      "v=1;alg=sha256;height=1;hash=" + std::string(64, 'a') +
      ";url=https://evil-discrete.cash/checkpoints/1.json", p, reject));
}

// --------------------------------------------------------------------------
// Deterministic serialization — the file hash is only meaningful if the exact
// same inputs always produce the exact same bytes.
// --------------------------------------------------------------------------

// Serialization is deterministic for a FIXED record: the same CheckpointRecord
// always produces byte-identical output, so a publisher can hash what it wrote
// and a verifier can re-derive the same digest.
TEST(DnsCheckpointSerialize, IsDeterministicForAFixedRecord) {
  auto kp = signer();
  CheckpointRecord rec;
  rec.version = 1;
  rec.network = "mainnet";
  rec.height  = kHeight;
  ASSERT_TRUE(Common::podFromHex(std::string(kBlockHex), rec.blockHash));
  rec.sigAlg    = kCheckpointSigAlg;
  rec.keyId     = checkpointKeyId(kp.first);
  rec.signature = signMessagePq(
      buildCheckpointSignedPayload(kGenesisHex, "mainnet", kHeight, kBlockHex), kp.second);

  const std::string a = serializeCheckpointJsonCanonical(rec);
  const std::string b = serializeCheckpointJsonCanonical(rec);

  EXPECT_EQ(a, b);
  EXPECT_EQ(sha256Hex(a), sha256Hex(b));
  EXPECT_EQ(a.find('\n'), std::string::npos) << "canonical form carries no newline";
  EXPECT_EQ(a.find("  "), std::string::npos) << "canonical form carries no indentation";
  EXPECT_EQ(a.front(), '{');
  EXPECT_EQ(a.back(), '}');
}

// ...but SIGNING is not reproducible: ML-DSA-65 is randomized (FIPS 204 hedged
// mode), so re-signing the same height yields a different — equally valid —
// file with a different SHA-256.
//
// Operational consequence, and the reason this is pinned by a test: the
// publisher must hash the EXACT bytes it wrote and must never regenerate the
// file after the TXT record is live, or the pointer hash stops matching and
// every client rejects the checkpoint. Republishing means signing again AND
// updating the TXT hash together.
TEST(DnsCheckpointSerialize, ResigningProducesDifferentButValidBytes) {
  auto kp = signer();
  const std::string a = makeFile(kp.second, kp.first);
  const std::string b = makeFile(kp.second, kp.first);

  EXPECT_NE(a, b) << "ML-DSA-65 signing is randomized";
  EXPECT_NE(sha256Hex(a), sha256Hex(b));

  // Both are independently valid — each against its own pointer.
  for (const std::string& json : {a, b}) {
    CheckpointPointer ptr = parseOk(makeTxt(json));
    CheckpointRecord rec;
    std::string reject;
    EXPECT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", rec, reject),
              CheckpointStatus::Accepted) << reject;
  }

  // The pointer for one file must NOT validate the other.
  CheckpointPointer ptrA = parseOk(makeTxt(a));
  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(b, ptrA, {kp.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Malformed);
}

TEST(DnsCheckpointSerialize, FieldOrderIsFixed) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first);

  const size_t v  = json.find("\"version\"");
  const size_t n  = json.find("\"network\"");
  const size_t h  = json.find("\"height\"");
  const size_t bh = json.find("\"block_hash\"");
  const size_t sa = json.find("\"signature_algorithm\"");
  const size_t ki = json.find("\"key_id\"");
  const size_t sg = json.find("\"signature\"");

  ASSERT_NE(sg, std::string::npos);
  EXPECT_LT(v, n);
  EXPECT_LT(n, h);
  EXPECT_LT(h, bh);
  EXPECT_LT(bh, sa);
  EXPECT_LT(sa, ki);
  EXPECT_LT(ki, sg);
}

TEST(DnsCheckpointSerialize, KeyIdIsStableAndDistinguishesSigners) {
  auto a = signer(7);
  auto b = signer(9);

  EXPECT_EQ(checkpointKeyId(a.first), checkpointKeyId(a.first));
  EXPECT_EQ(checkpointKeyId(a.first).size(), 8u);
  EXPECT_NE(checkpointKeyId(a.first), checkpointKeyId(b.first));
}

// --------------------------------------------------------------------------
// Full file verification.
// --------------------------------------------------------------------------

TEST(DnsCheckpointVerify, AcceptsGoodFile) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord rec;
  std::string reject;
  ASSERT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Accepted) << reject;

  EXPECT_EQ(rec.height, kHeight);
  EXPECT_EQ(rec.network, "mainnet");
  EXPECT_EQ(Common::podToHex(rec.blockHash), std::string(kBlockHex));
  EXPECT_EQ(rec.sigAlg, std::string(kCheckpointSigAlg));
  EXPECT_EQ(rec.keyId, checkpointKeyId(kp.first));
}

// Any-of-N: a record signed by one approved signer is accepted even when other
// signers are configured (this is what makes key rotation non-breaking).
TEST(DnsCheckpointVerify, AcceptsAnyApprovedSigner) {
  auto a = signer(7);
  auto b = signer(9);
  const std::string json = makeFile(b.second, b.first);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {a.first, b.first}, genesisHash(), "mainnet",
                                 rec, reject),
            CheckpointStatus::Accepted) << reject;
}

// key_id sits OUTSIDE the signed payload, so a file may claim any value. The
// verifier must report the signer that actually verified, not the claim.
TEST(DnsCheckpointVerify, ReportsRealSignerNotClaimedKeyId) {
  auto kp = signer(7);
  auto other = signer(9);

  CheckpointRecord forged;
  forged.version = 1;
  forged.network = "mainnet";
  forged.height  = kHeight;
  ASSERT_TRUE(Common::podFromHex(std::string(kBlockHex), forged.blockHash));
  forged.sigAlg = kCheckpointSigAlg;
  // Validly signed by kp, but misattributed to `other`.
  forged.keyId     = checkpointKeyId(other.first);
  forged.signature = signMessagePq(
      buildCheckpointSignedPayload(kGenesisHex, "mainnet", kHeight, kBlockHex), kp.second);
  ASSERT_NE(checkpointKeyId(kp.first), checkpointKeyId(other.first));

  const std::string json = serializeCheckpointJsonCanonical(forged);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord rec;
  std::string reject;
  ASSERT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Accepted) << reject;
  EXPECT_EQ(rec.keyId, checkpointKeyId(kp.first)) << "must report the real signer";
}

// The whole point of hashing the exact bytes: reformatting a published file —
// even in ways that leave the JSON semantically identical — invalidates it.
TEST(DnsCheckpointVerify, RejectsWhitespaceModifiedFile) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  const std::string reformatted = json + "\n";

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(reformatted, ptr, {kp.first}, genesisHash(), "mainnet",
                                 rec, reject),
            CheckpointStatus::Malformed);
  EXPECT_NE(reject.find("file hash mismatch"), std::string::npos) << reject;
}

TEST(DnsCheckpointVerify, RejectsWrongFileHash) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first);
  CheckpointPointer ptr = parseOk(makeTxt(json));
  ptr.sha256Hex = std::string(64, 'b');

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Malformed);
}

// Malformed JSON must be rejected as malformed, not crash the parser. The
// pointer hash is recomputed over the junk so parsing is actually reached.
TEST(DnsCheckpointVerify, RejectsMalformedJson) {
  const std::string junk = "{\"version\":1,\"network\":";
  CheckpointPointer ptr = parseOk(makeTxt(junk));

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(junk, ptr, {}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Malformed);
}

TEST(DnsCheckpointVerify, RejectsMissingField) {
  const std::string noSig =
      "{\"version\":1,\"network\":\"mainnet\",\"height\":123456,\"block_hash\":\"" +
      std::string(kBlockHex) + "\",\"signature_algorithm\":\"ML-DSA-65\"}";
  CheckpointPointer ptr = parseOk(makeTxt(noSig));

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(noSig, ptr, {}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Malformed);
}

TEST(DnsCheckpointVerify, RejectsHeightMismatchBetweenTxtAndJson) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first);
  // Pointer claims a different height than the file states.
  CheckpointPointer ptr = parseOk(makeTxt(json, kHeight));
  ptr.height = kHeight + 1;

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Malformed);
  EXPECT_NE(reject.find("height"), std::string::npos) << reject;
}

TEST(DnsCheckpointVerify, RejectsWrongNetwork) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first, "testnet");
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Malformed);
  EXPECT_NE(reject.find("network"), std::string::npos) << reject;
}

TEST(DnsCheckpointVerify, RejectsUnsupportedSignatureAlgorithm) {
  auto kp = signer();
  CheckpointRecord rec;
  rec.version = 1;
  rec.network = "mainnet";
  rec.height  = kHeight;
  ASSERT_TRUE(Common::podFromHex(std::string(kBlockHex), rec.blockHash));
  rec.sigAlg    = "ML-DSA-44";
  rec.keyId     = checkpointKeyId(kp.first);
  rec.signature = signMessagePq(
      buildCheckpointSignedPayload(kGenesisHex, "mainnet", kHeight, kBlockHex), kp.second);
  const std::string json = serializeCheckpointJsonCanonical(rec);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord out;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", out, reject),
            CheckpointStatus::Malformed);
}

TEST(DnsCheckpointVerify, RejectsSignatureFromUnapprovedSigner) {
  auto real    = signer(7);
  auto impostor = signer(9);
  const std::string json = makeFile(impostor.second, impostor.first);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {real.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::BadSignature);
}

TEST(DnsCheckpointVerify, RejectsCorruptedSignature) {
  auto kp = signer();
  CheckpointRecord rec;
  rec.version = 1;
  rec.network = "mainnet";
  rec.height  = kHeight;
  ASSERT_TRUE(Common::podFromHex(std::string(kBlockHex), rec.blockHash));
  rec.sigAlg    = kCheckpointSigAlg;
  rec.keyId     = checkpointKeyId(kp.first);
  rec.signature = "not-a-valid-base58-signature";
  const std::string json = serializeCheckpointJsonCanonical(rec);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord out;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", out, reject),
            CheckpointStatus::BadSignature);
}

// Fail-closed: with no signers configured nothing can ever be accepted.
TEST(DnsCheckpointVerify, RejectsWhenNoSignersConfigured) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::BadSignature);
}

// --------------------------------------------------------------------------
// Genesis binding — the property that stops a testnet/fork record being
// replayed onto mainnet through the shared DNS host.
// --------------------------------------------------------------------------

TEST(DnsCheckpointVerify, RejectsRecordSignedForAnotherChain) {
  auto kp = signer();
  const std::string json = makeFile(kp.second, kp.first);
  CheckpointPointer ptr = parseOk(makeTxt(json));

  Crypto::Hash otherGenesis{};
  ASSERT_TRUE(Common::podFromHex(
      std::string("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
      otherGenesis));

  CheckpointRecord rec;
  std::string reject;
  EXPECT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, otherGenesis, "mainnet", rec, reject),
            CheckpointStatus::BadSignature);
}

TEST(DnsCheckpointPayload, BindsEveryField) {
  const std::string base = buildCheckpointSignedPayload(kGenesisHex, "mainnet", kHeight, kBlockHex);

  EXPECT_EQ(base, std::string(kCheckpointSignedPayloadPrefix) + ":" + kGenesisHex +
                      ":mainnet:" + std::to_string(kHeight) + ":" + kBlockHex);

  // Changing any single component changes the signed string.
  EXPECT_NE(base, buildCheckpointSignedPayload(kGenesisHex, "testnet", kHeight, kBlockHex));
  EXPECT_NE(base, buildCheckpointSignedPayload(kGenesisHex, "mainnet", kHeight + 1, kBlockHex));
  EXPECT_NE(base, buildCheckpointSignedPayload(kGenesisHex, "mainnet", kHeight, std::string(64, 'f')));
  EXPECT_NE(base, buildCheckpointSignedPayload(std::string(64, '0'), "mainnet", kHeight, kBlockHex));
}

// --------------------------------------------------------------------------
// End-to-end: publish exactly as admin-tools does, then verify as a client.
// --------------------------------------------------------------------------

TEST(DnsCheckpointE2E, PublishThenVerifyRoundTrip) {
  auto kp = signer();

  // Publisher side.
  const std::string json = makeFile(kp.second, kp.first);
  const std::string txt  = makeTxt(json);

  // A TXT record must comfortably fit DNS limits — this is the bug that motivated
  // the whole pointer scheme, so assert it explicitly.
  const size_t wireBytes = txt.size() + (txt.size() + 254) / 255;
  EXPECT_LT(wireBytes, 4096u);
  EXPECT_LT(txt.size(), 200u) << "pointer should stay tiny: " << txt;

  // Client side.
  CheckpointPointer ptr = parseOk(txt);
  CheckpointRecord rec;
  std::string reject;
  ASSERT_EQ(verifyCheckpointFile(json, ptr, {kp.first}, genesisHash(), "mainnet", rec, reject),
            CheckpointStatus::Accepted) << reject;
  EXPECT_EQ(rec.height, kHeight);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
