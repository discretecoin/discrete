// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// DiscretePower-2 (signature-tape proof of work) tests — see
// https://docs.discrete.cash/#/consensus/pow (revision D). Covers:
//   * the zero-tape differential anchor (yespower-dp2 == stock yespower);
//   * a frozen known-answer transcript for the yespower-dp2 core (§13.1);
//   * a frozen (blob, minerSpendPk, powSignature) pipeline KAT that dp2_verify
//     replays byte-identically and mode-independently (§13.1);
//   * tape sensitivity (§13.5);
//   * dp2_prove / dp2_verify round trips (§13.3);
//   * the rejection matrix + the "zero yespower-dp2 on early reject" DoS bound
//     asserted via an instrumented counter (§13.4);
//   * block serialize/deserialize preserving powSignature (§13.6);
//   * an informational per-attempt timing split (§12 bench).
//
// The frozen KAT constants below are generated once by the DISABLED_GenerateKat
// test (see the note there) and pasted in. Regenerate them if — and only if —
// the yespower-dp2 algorithm or the transcript domains change on purpose.

#include "gtest/gtest.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Difficulty.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqHash.h"
#include "crypto/yespower.h"

using namespace CryptoNote;

namespace {

std::string toHex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 0x0f]);
  }
  return s;
}
template <class C> std::string toHex(const C& c) { return toHex(c.data(), c.size()); }

std::vector<uint8_t> fromHex(const std::string& s) {
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
  };
  std::vector<uint8_t> v;
  v.reserve(s.size() / 2);
  for (size_t i = 0; i + 1 < s.size(); i += 2)
    v.push_back(static_cast<uint8_t>((nib(s[i]) << 4) | nib(s[i + 1])));
  return v;
}

std::vector<uint8_t> patternBytes(size_t n, uint8_t a, uint8_t b) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i * a + b);
  return v;
}

// H = SHAKE256("DiscretePower/v2/header" || blob, 64) — recomputed independently
// of the internal (anonymous-namespace) helper so the test pins the wire itself.
std::array<uint8_t, 64> computeH(const std::vector<uint8_t>& blob) {
  std::vector<uint8_t> t;
  const size_t dl = std::strlen(DISCRETE_POWER_HEADER_DOMAIN);
  t.insert(t.end(), DISCRETE_POWER_HEADER_DOMAIN, DISCRETE_POWER_HEADER_DOMAIN + dl);
  t.insert(t.end(), blob.begin(), blob.end());
  std::array<uint8_t, 64> H{};
  CryptoPQ::shake256(t.data(), t.size(), H.data(), H.size());
  return H;
}

// Run the yespower-dp2 core directly for a raw (H, tape) pair (bypasses ML-DSA).
std::array<uint8_t, 32> runCore(const std::array<uint8_t, 64>& H,
                                const std::array<uint8_t, parameters::DP2_TAPE_LEN>& tape) {
  const std::array<uint8_t, 32>& P = dp2_memory_personalization();
  yespower_params_t yp{ parameters::DP2_N, parameters::DP2_R, P.data(), P.size() };
  yespower_binary_t y{};
  EXPECT_EQ(yespower_dp2_tls(H.data(), H.size(), &yp, tape.data(), &y), 0);
  std::array<uint8_t, 32> out{};
  std::memcpy(out.data(), y.uc, 32);
  return out;
}

Crypto::Hash finalizePow(const std::array<uint8_t, 64>& H, const std::array<uint8_t, 32>& y) {
  std::vector<uint8_t> t;
  const size_t dl = std::strlen(DISCRETE_POWER_FINAL_DOMAIN);
  t.insert(t.end(), DISCRETE_POWER_FINAL_DOMAIN, DISCRETE_POWER_FINAL_DOMAIN + dl);
  t.insert(t.end(), H.begin(), H.end());
  t.insert(t.end(), y.begin(), y.end());
  Crypto::Hash h{};
  CryptoPQ::shake256(t.data(), t.size(), h.data, sizeof(h.data));
  return h;
}

std::array<uint8_t, parameters::DP2_TAPE_LEN> tapeFromSig(const std::vector<uint8_t>& sig) {
  std::array<uint8_t, parameters::DP2_TAPE_LEN> tape{};
  std::memcpy(tape.data(), sig.data(), parameters::DP2_SIG_LEN);
  tape[parameters::DP2_SIG_LEN + 0] = 0x80;
  tape[parameters::DP2_SIG_LEN + 1] = 0x00;
  tape[parameters::DP2_SIG_LEN + 2] = 0x00;
  return tape;
}

Block makeSerializableBlock(const std::vector<uint8_t>& powSig) {
  Block b;
  b.majorVersion = BLOCK_MAJOR_VERSION_1;
  b.minorVersion = 0;
  b.timestamp = 999;
  for (size_t i = 0; i < sizeof(b.previousBlockHash.data); ++i)
    b.previousBlockHash.data[i] = static_cast<uint8_t>(i * 2 + 1);
  b.nonce = 12345;

  Transaction tx;
  tx.version = TRANSACTION_VERSION_1;
  tx.txType = TX_COINBASE;
  tx.unlockHeight = 10;
  BaseInput bi;
  bi.blockIndex = 1;
  tx.inputs.push_back(bi);
  CoinbaseOutput co;
  for (size_t i = 0; i < sizeof(co.spendCommit.data); ++i)
    co.spendCommit.data[i] = static_cast<uint8_t>(i * 3 + 7);
  TransactionOutput out;
  out.amount = 1000000;
  out.target = co;
  tx.outputs.push_back(out);
  b.baseTransaction = tx;
  b.powSignature = powSig;
  return b;
}

// ─── Frozen KAT constants (generated by DISABLED_GenerateKat) ───────────────────
// Deterministic core transcript: H = patternBytes(64, 7, 3), tape = patternBytes(3312, 5, 1).
const char kCoreY[]   = "0dcb913d67912e8a3b622361f3cd2beee2ab96aa3af200edd0a2e26168f9a5e4";
const char kCorePow[] = "7c0d34948df5e64c7b6260ba0653ef6aeb7b61630e58ca5e190f7ff65461e8a9";
// Pipeline vector: seed = 0xA0..0xBF, blob = patternBytes(160, 13, 7), captured sig.
const char kPipeH[]   = "8a83ab8cd3e87606b71e3ec92917d876faaa097343cfe4027d343460b2c86c71f57b8c19a339b4f426d01bb731ce2ef9a0a393bc010d3244b977f96f0b4947f8";
const char kPipeM[]   = "33e295473f19e5edf7063e0e6173441da415e28101501f4624ee695b9ee9439f296f2733054c4a965fb8b6b68e4034ff02135f7bcada1e6a8d57c1ce7c049163";
const char kPipePow[] = "10fe9c0c935d885557dac04b5c3172861ff63cfbd2418ea8d9a770807e7d063e";
const char kPipeSig[] = "a4535a2bf66dbb3f498e183aaabe8735d224cea3d646012dcf50653148607714b5a242abba71b0bc352474ecada9e1436965bf1677236c2b27916e9f99cecd29ff26fd4c677fcdca0566d042fa4b6cf4d18e2bad6e6761983913c5afb55a2c47430ef134d412cf1b743fa0fb8a15020527585d16fc48f7408c208d58835382b460125d78f1fe30db84bea7c8033502f101a9f86a75894f84899f4f3c63698ebfb2b7e09fc0f91f831d8da8d94e97571c303bc471d38e67dfd9c6bedecbed33f58818f4ed7b74434f81fedb0262c3f5055efd1caa66116da0c29625c729470b16e9963e68df8e4e6f3ff92ef9ead414a13b9e6411118556d37e20e814aa3c0eb01221f2627b1a33bc0622774bcb1173e8ceb32b242a4c64ed69199588a7482c00bdb8479bb1e2459c2abf229178a90098cf91401e666e6bc3de5ba814d86766da612391c2326dd24472c10590914416358afe2680a6aa291117a8dee3ebfa036f7829df201486cb37e81de515ff2a4a33c959a3ff4381645310a747f148d91162ad15b61a1373a39bdc74b7ff3047c8d6eddcd2cfddd81c5d60e75ef7845b0e2adda216c74f6b7e4ca571ece36aa0764be08f6b6c3d87d51e90a6618d2b420fa39ec97363798fecb4e91fdd8e87c12ab3bd090c06b6da6287d4f528550e55c453807167a238bb41cb4305d47f47fee13ddcea5a2db1d6a4faf3c7bcaf77ec03e7bded5e67bd1a905e04bc2b4cc3d88db5eddf87c4ec2fb921d748420956c664069c27ab4b68f78c58daa00fc21b8762c7696f3452c13bb192796b27114a052e65edc23f2daa8b5a7eb24fe70a1d9096c6f134f950642c3585fb2d8cd01ab30365a648a9c84c2cbea84e400cc155a1dc02308280914c92e028db4e1e20a285825977fd0c759540e1498b93ee0724b655eb44d8dcdfbe6a590dbe9f5232d4bfdab2fd1d663777e9d196037276b1cac9d18e2aba7bacacc2153fc42d7aab728d9836be4171d11bf2b67a1f694832a54f3cd9794caa3e1073774106ab1cd7051798bf8e3b2bd60a2374c454564c11b705143b5455da092531e3c592fcada3e6a3bb6c6ff6b7fbb012c4b41411374f1397c7d71f68222d57a02de204992136d5d32d34ffa5b93f693046bdb778e9c54701e970a6df2780d919cfa12575bdd4b158189265171a01cb70625c4df0d6d4020ad27ae580d9878e38e19922f5cafa621061296bef22606ab32b11ac080662b6619e0c4a96fac62b04cd55a59d040838e45d107bd3ed7f52fe0afbb9b80e9434d9e0ca2e00c4a4bcf275a1a8138c38d6125e54b8536c5ca3d30d061bba3e67def6b5beefd9424956e0ad4f6d085a4ad2f5effb48ac694265f3d695959afce354f9b1ba636c3704e0856a9c13bef6afc5e914016fee652c640a47580deaf528959b9c5e9383abeeb14de8d215c4ad39db3dab290a06e2771301478f3d5b6680632a4dee607be148698a029d9751e8049deda20153c0bbf3529c93602479ceee6ed2eb4e65588e315a2ad2a830ac997b9ca5fd4160719ebea7a1cb0d4abc60036184cff4b32adc15cd235029c74b55d391547948fcf6fb414aff139e544f197e0628d55e6afe7315ec8a1115e7b1d2cec1f376c48efd16774f6ed4d62fc2accc59b7561aa8b4f8f292d65d2e980df47ccfc5f98cd5e46c7ac39c2b30f207b0f1dca881998da0b1c3d8cda2c47673f93d6b9444a6b701b47c96ce44ad4439374605150d7642dcf34f20ee5c22fbe3969d4c7ca60a154d3020be73c3e097455bb639618bfad7225c033ed0f75c82f8ad27a739c562c86d14ee69feecad80ea25f23a3c9ac72b04fca74ee063538210fb5529e8465d7ef1b3eece29ad0f211dfc5dd8e7c42043a3e76f18705d0031448742c65f980a8ad7f6b454fa0c513176d1b949864fc8b856f4941b73907a9d47d2c582eaa521967fd9aa69b219b4b449c968ff4d5af1180874d4f956ac010dce9bb6355fc8421ebbca308246222317c39db919544b61e72065023514d2f1906613c6bd4d2c3fd44efbb0011c0a6afc1df1b92d00d1f2f4404e07b3edf50cc77684ee4ddf19b2f26deccb4cc147825e6a44326d4a3f8d0169a63140c8c52e8da719229f028d7fb5a7518b15e5d1b7bcca0b19c93848096cddf726422471519068b86c8a551b6273fc59307b142418c903581da4af2012b579c3e78c18b76d55ce7df5847cbd788c6212b75af8299393fee4831009eeed781e425c5add1acd3d5ff82b063e3e5e5337dbe2d031e8a8902594b18b46458cce70715d031909659d415ddd841afc2db1efd003361b23d9933d50b1b9b93512c284155883361aadabce0ccc4e50a9685fa6884a1961701449d26343fe04f8c1cd560a9c51e2f89cb3c54bce5b8aac11b0e2e5ac8d0ddc85478ca230f3c417153230b795de604bd14f799aaf972f7ea5802ea4686edf78f261c51904fbea5fe894e2e6fc030bfc40221ec0c5dc71fd16a07e8db8abf3b11d30fcdbb7337b056f36ce014d48d68bf07f254fda47de5732e1aa80749b63d59c4b48afc1ab45438fd29868a38c36ba489f9529ee345f2c7e509a2fd532f71efaa18447e440ddc99d937b72001ca4501611a182e7465923fe98e4a1db080b0b4690fca46b520e945d5a3d782765d24529e6a95af3a99ea4c4d8243a0d3c92ca4eaf49ae34e019235f3ceef2c1d81ea807360c1f8fea08ed449cc3e5c6989d2effcd5da70443d1afb535d001fcdfeb65300ec8140a9d385b471dcc2a6c3d45f0fe3b4a97f3c045032d44f950bb103eddd7386eb9534bd5e39f47aaaac59de2c84c1ee2998bc77efeede5e4d559530a28246c253592ad2530cc7e4aa79434ea65d6978fbf92220bb781b704f619bb79bea2591d8a16e3214df12a1e32c332589afa202fe01d8f1d8db0dba5a1e5e6b2d42b23845a635534cae02f710c573877598da4b84067f665adfc62e7c0db5bcb09049f87e2eb1bb0859d7c3b95b3a3b822d826278aefd5cc39cdc63d3281860d35b98c87d1b1e06b280cc0cfcc129fc9768a8ccf9688e8770eff4ec5b5a00cf2963d92a2cd80c0186194208fa785637c2a9ecaed9392f3feb8ec9d92ee4f1d717a1cb21f34cb44b1420da724a049f9365aae3873d333e035ca27b433a033ab2a9513c3fdc49f2632403706c39fb566552de015f46de734ae4bb73e23d740c3505d68c2fbbd2e3c5044650f1023dd4a25aa59d5d066425d9454b14cd3ccb0dc979de76b0f782bd4d41a67b8c7bf3edeefeb31a8566a2d2ddadfc163c794b714561315c64265fa979d27939b2303cd56c3c9b209a6a545b2e9cddc8980b93412ce3b6e397a01f41b57955885a341179fefe45b36b62991ff3016f37a6346b341a73b1e900a9a0aae6a6db4b2a4ad9c6958019e471eed8a2a6dee9a11e28617f3cecddca03a9cd7577a8fdd6777f9fe3cd0e73e7fd175accb22f4c5db405ee430aece9e6d0a23d6d6def33c5c5efe92a61195c9bb495693a873ce998cc75a190ba9a4871a88235721102bc84872c25ccc3649b4a4707bd2529280ad025802dfd5c237f0b77dffc79e076c80b269a311d6aca6050552a4fb95cb31452c04156dd7560c0a47868f0c039abc2dac6e72f60eeed1b94a967c6b5176a3edf028d9761caa42288c1152c3f2ef6f153ab6fcfaf281b208ca7ce48588e3c23a5b0ae03adab5d727b4a8a6e8c49470cd1292db5c1eca38527550a4fbb7bb8f01dac9be60ea6eaaa2932bec96eb1b64d186e6f3db23becb7b06d5bfd04ff5105420f6ce9bc1c832b6538e2baeae49eb48b267e99c89903290659cf7f6bed837abf26efa6e42324b1644343e15ea93c995cf81379ed96fb9bd232875af11fc504e83cd72baf0e16a9833a9ccedb71d0aaf47db8b600f73be7fa04c22c674240cdc0105cb1bfd9647f3170e8dabc46ea4cfc91fb43586521ecab55dab8ad2cfb98f7d12e84ccf16aa96e1b4fca572cf9a387c6999e24d27874bd9403016dfee1327cda27c31f130018508c43d3a2ec6e347c6b967762e8ae89ee632ca0b15e4bfc5cb3d08520c9f015de827f2b831b4dad8cf8d46cfd8803c5c3067e0753edb4c0be39dd1b80f97e1b57f8a297d96b89f5ee5445c8a7fe4c178d8d1f8d6247f84494341295f1c80b2ff99abf9b1bee67bbc9cca4a67a39716bd72bd08f61f34ad162754411e653b9b961007ce0242750d5b950a75258950055d9b9f27dfe155cd77b85b941f491462e0c8211213a8de8f3154870bbbdccf42e1ed6bd6fd930e22b8f1c1415197770fa81dddebf40020eff49264aff7df58dc5ae9ec06ce514d731783f4ad7f1d66c634158dc2de349faf492a616c6ffe70eafdf37bcc7a9cfe5be19e6a19f6a5d5b9bd687bca8177c2ee9a359d3cd12aa6913ccaba0651dd2fb6f19b523ff2d5e3932f4d3c2d7feff3f0cd22b7f098829a29ef1fb0208d976abf1268567ef0d96d97eea720816bcdbd916e60c72f126c9b0febbe217fbd3af9e964f9e37bbfa5963b0c6bde86ceda97ee2cf81d9f280a3c43e3e56e6aa7bb46ef4b5705ca4471b0831fce0b2d1c63e9e506dd9465ee982135251f9b1743280a67d001424798a5aac1e5fcfe1473879fa8cbee20293fe7030f1f333f527b97dfe4f4fcfd1338607a8a9697b20918406f0000000000000000000a1115222a2e";

CryptoPQ::DsaKeypairSeed pipelineSeed() {
  CryptoPQ::DsaKeypairSeed seed{};
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(0xA0 + i);
  return seed;
}
std::vector<uint8_t> pipelineBlob() { return patternBytes(160, 13, 7); }

bool katFrozen() { return kPipeSig[0] != '@'; }

}  // namespace

// The zero/NULL-tape no-op makes yespower-dp2 collapse to stock yespower 1.0.
// This is the differential anchor that the unmodified memory-hard machinery is
// preserved and that the injection plumbing is a pure XOR add-on.
TEST(PqPow, ZeroTapeEqualsStockYespower) {
  const std::array<uint8_t, 32>& P = dp2_memory_personalization();
  for (uint8_t k = 1; k <= 3; ++k) {
    std::array<uint8_t, 64> H{};
    for (size_t i = 0; i < H.size(); ++i) H[i] = static_cast<uint8_t>(i * 7 + k);
    yespower_params_t yp{ parameters::DP2_N, parameters::DP2_R, P.data(), P.size() };
    yespower_binary_t stock{};
    yespower_binary_t dp2{};
    ASSERT_EQ(yespower_tls(H.data(), H.size(), &yp, &stock), 0);
    std::array<uint8_t, parameters::DP2_TAPE_LEN> zeroTape{};  // all-zero => XOR no-op
    ASSERT_EQ(yespower_dp2_tls(H.data(), H.size(), &yp, zeroTape.data(), &dp2), 0);
    EXPECT_EQ(std::memcmp(stock.uc, dp2.uc, 32), 0)
        << "zero-tape yespower-dp2 must equal stock yespower 1.0";
  }
}

// Frozen reference transcript for the yespower-dp2 core (mode-independent; no
// ML-DSA). Any change to y/PoW here means the memory algorithm changed.
TEST(PqPow, CoreKnownAnswer) {
  std::array<uint8_t, 64> H{};
  {
    std::vector<uint8_t> hp = patternBytes(64, 7, 3);
    std::copy(hp.begin(), hp.end(), H.begin());
  }
  std::array<uint8_t, parameters::DP2_TAPE_LEN> tape{};
  {
    std::vector<uint8_t> tp = patternBytes(parameters::DP2_TAPE_LEN, 5, 1);
    std::copy(tp.begin(), tp.end(), tape.begin());
  }
  std::array<uint8_t, 32> y = runCore(H, tape);
  Crypto::Hash pow = finalizePow(H, y);

  if (kCoreY[0] != '@') {
    EXPECT_EQ(toHex(y), kCoreY);
    EXPECT_EQ(toHex(pow.data, 32), kCorePow);
  } else {
    std::printf("[ SKIPPED ] core KAT not frozen yet (run DISABLED_GenerateKat)\n");
  }
}

// Frozen (blob, minerSpendPk, powSignature) → dp2_verify must replay the exact H,
// m, and PoW. The stored signature bytes make this independent of signing mode.
TEST(PqPow, PipelineKnownAnswerVector) {
  if (!katFrozen()) {
    std::printf("[ SKIPPED ] pipeline KAT not frozen yet (run DISABLED_GenerateKat)\n");
    return;
  }
  auto kp = CryptoPQ::dsa_keygen_from_seed(pipelineSeed());
  std::vector<uint8_t> blob = pipelineBlob();
  std::vector<uint8_t> sig = fromHex(kPipeSig);
  ASSERT_EQ(sig.size(), static_cast<size_t>(parameters::DP2_SIG_LEN));

  std::array<uint8_t, 64> H = computeH(blob);
  std::array<uint8_t, 64> m = dp2_sign_message(H);
  EXPECT_EQ(toHex(H), kPipeH);
  EXPECT_EQ(toHex(m), kPipeM);

  Crypto::Hash pow{};
  Dp2Reject reason = Dp2Reject::None;
  ASSERT_TRUE(dp2_verify(blob, kp.first, sig, pow, &reason));
  EXPECT_EQ(reason, Dp2Reject::None);
  EXPECT_EQ(toHex(pow.data, 32), kPipePow);
}

// Flipping any tape byte must perturb the yespower-dp2 output (§13.5 regression).
TEST(PqPow, TapeByteChangesOutput) {
  std::array<uint8_t, 64> H{};
  for (size_t i = 0; i < H.size(); ++i) H[i] = static_cast<uint8_t>(i * 3 + 1);
  std::array<uint8_t, parameters::DP2_TAPE_LEN> tape{};
  for (size_t i = 0; i < tape.size(); ++i) tape[i] = static_cast<uint8_t>(i * 5 + 2);

  std::array<uint8_t, 32> y0 = runCore(H, tape);

  auto t1 = tape; t1[0] ^= 0x01;
  EXPECT_NE(y0, runCore(H, t1)) << "first tape word must matter";

  auto t2 = tape; t2[parameters::DP2_SIG_LEN - 1] ^= 0x01;
  EXPECT_NE(y0, runCore(H, t2)) << "last signature tape byte must matter";
}

// dp2_prove output verifies with dp2_verify (matching key), and get_block_longhash
// on a signed block reproduces the same PoW. Multiple random keys and blobs.
TEST(PqPow, ProveVerifyRoundTrip) {
  for (uint8_t k = 1; k <= 3; ++k) {
    CryptoPQ::DsaKeypairSeed seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i + k * 7);
    auto kp = CryptoPQ::dsa_keygen_from_seed(seed);
    std::vector<uint8_t> blob = patternBytes(120 + k, 11, k);

    std::vector<uint8_t> sig;
    Crypto::Hash powProve{};
    ASSERT_TRUE(dp2_prove(blob, kp.second, sig, powProve));
    EXPECT_EQ(sig.size(), static_cast<size_t>(parameters::DP2_SIG_LEN));

    Crypto::Hash powVerify{};
    Dp2Reject reason = Dp2Reject::None;
    ASSERT_TRUE(dp2_verify(blob, kp.first, sig, powVerify, &reason));
    EXPECT_EQ(reason, Dp2Reject::None);
    EXPECT_EQ(powProve, powVerify);

    // Re-running the memory core over the same (H, tape) is deterministic.
    std::array<uint8_t, 64> H = computeH(blob);
    std::array<uint8_t, 32> y = runCore(H, tapeFromSig(sig));
    EXPECT_EQ(finalizePow(H, y), powProve);
  }
}

// Two valid signatures over the same header produce different tapes and different
// PoW (only meaningful under hedged signing; a no-op assertion if the build signs
// deterministically, which consensus neither requires nor detects).
TEST(PqPow, DistinctSignaturesGiveDistinctPow) {
  CryptoPQ::DsaKeypairSeed seed{};
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i + 3);
  auto kp = CryptoPQ::dsa_keygen_from_seed(seed);
  std::vector<uint8_t> blob = patternBytes(140, 9, 4);

  std::vector<uint8_t> sig1, sig2;
  Crypto::Hash pow1{}, pow2{};
  ASSERT_TRUE(dp2_prove(blob, kp.second, sig1, pow1));
  ASSERT_TRUE(dp2_prove(blob, kp.second, sig2, pow2));
  if (sig1 != sig2) {
    EXPECT_NE(pow1, pow2) << "distinct signatures must yield distinct PoW";
  } else {
    EXPECT_EQ(pow1, pow2);  // deterministic signer: same sig => same PoW
  }
}

// Rejection matrix + DoS ordering: length and signature-verify failures must
// reject with the right reason AND run ZERO yespower-dp2 (asserted via the
// instrumented counter). A good verify runs exactly one.
TEST(PqPow, RejectMatrixAndDosOrdering) {
  auto kp = CryptoPQ::dsa_keygen_from_seed([] {
    CryptoPQ::DsaKeypairSeed s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(i + 42);
    return s;
  }());
  auto other = CryptoPQ::dsa_keygen_from_seed([] {
    CryptoPQ::DsaKeypairSeed s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(i + 99);
    return s;
  }());
  std::vector<uint8_t> blob = patternBytes(120, 11, 5);

  std::vector<uint8_t> sig;
  Crypto::Hash pow{};
  ASSERT_TRUE(dp2_prove(blob, kp.second, sig, pow));

  // Good baseline: exactly one yespower-dp2 execution.
  yespower_dp2_call_count_reset();
  {
    Crypto::Hash h{};
    Dp2Reject r = Dp2Reject::None;
    EXPECT_TRUE(dp2_verify(blob, kp.first, sig, h, &r));
    EXPECT_EQ(r, Dp2Reject::None);
  }
  EXPECT_EQ(yespower_dp2_call_count(), 1u);

  auto expectReject = [&](const std::vector<uint8_t>& s, const CryptoPQ::DsaPublicKey& pk,
                          const std::vector<uint8_t>& b, Dp2Reject want) {
    yespower_dp2_call_count_reset();
    Crypto::Hash h{};
    Dp2Reject r = Dp2Reject::None;
    EXPECT_FALSE(dp2_verify(b, pk, s, h, &r));
    EXPECT_EQ(r, want);
    // Both bad-length and bad-signature reject BEFORE any memory-hard work.
    EXPECT_EQ(yespower_dp2_call_count(), 0u);
  };

  // Length: truncated, oversized, absent.
  { auto s = sig; s.pop_back();      expectReject(s, kp.first, blob, Dp2Reject::BadLength); }
  { auto s = sig; s.push_back(0x00); expectReject(s, kp.first, blob, Dp2Reject::BadLength); }
  { std::vector<uint8_t> s;          expectReject(s, kp.first, blob, Dp2Reject::BadLength); }

  // Bit flip in each of the four signature quarters.
  const size_t q = parameters::DP2_SIG_LEN / 4;
  for (int i = 0; i < 4; ++i) {
    auto s = sig;
    size_t pos = (i == 3) ? (parameters::DP2_SIG_LEN - 1) : static_cast<size_t>(i) * q + 3;
    s[pos] ^= 0x40;
    expectReject(s, kp.first, blob, Dp2Reject::BadSignature);
  }

  // Wrong public key.
  expectReject(sig, other.first, blob, Dp2Reject::BadSignature);

  // Valid signature over the wrong m: mutate the template (nonce/coinbase) after
  // signing so the recomputed H and m no longer match the signature.
  { auto b2 = blob; b2[0] ^= 0x01; expectReject(sig, kp.first, b2, Dp2Reject::BadSignature); }
}

// The target gate lives in the consensus check (check_hash), separate from
// dp2_verify. A valid PoW passes difficulty 1 and fails an unreachable difficulty.
TEST(PqPow, PowTargetGate) {
  auto kp = CryptoPQ::dsa_keygen_from_seed([] {
    CryptoPQ::DsaKeypairSeed s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(i + 5);
    return s;
  }());
  std::vector<uint8_t> blob = patternBytes(96, 7, 2);
  std::vector<uint8_t> sig;
  Crypto::Hash pow{};
  ASSERT_TRUE(dp2_prove(blob, kp.second, sig, pow));

  EXPECT_TRUE(check_hash(pow, 1));                                  // any PoW meets difficulty 1
  EXPECT_FALSE(check_hash(pow, std::numeric_limits<Difficulty>::max()));  // above target
}

// powSignature survives block serialize/deserialize byte-for-byte and stays out
// of the hashing blob.
TEST(PqPow, BlockSerializeRoundTripPreservesPowSignature) {
  std::vector<uint8_t> powSig = patternBytes(parameters::DP2_SIG_LEN, 11, 3);
  Block b = makeSerializableBlock(powSig);

  BinaryArray ba = toBinaryArray(b);
  Block b2;
  ASSERT_TRUE(fromBinaryArray(b2, ba));
  EXPECT_EQ(b2.powSignature, powSig);

  BinaryArray hashingBlob;
  ASSERT_TRUE(get_block_hashing_blob(b, hashingBlob));
  // The 3309-byte signature must not appear in the hashing blob.
  EXPECT_LT(hashingBlob.size(), powSig.size());
}

// Informational only (§12): per-attempt timing split. Never asserted.
TEST(PqPow, BenchTimingSplit) {
  using clock = std::chrono::steady_clock;
  auto kp = CryptoPQ::dsa_keygen_from_seed([] {
    CryptoPQ::DsaKeypairSeed s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(i + 1);
    return s;
  }());
  std::vector<uint8_t> blob = patternBytes(160, 13, 9);
  std::array<uint8_t, 64> H = computeH(blob);
  std::array<uint8_t, 64> m = dp2_sign_message(H);

  const int iters = 8;
  double signMs = 0, coreMs = 0, shakeMs = 0;
  volatile uint8_t sink = 0;
  for (int i = 0; i < iters; ++i) {
    auto t0 = clock::now();
    CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(kp.second, m.data(), m.size());
    auto t1 = clock::now();
    std::array<uint8_t, 32> y = runCore(H, tapeFromSig(std::vector<uint8_t>(sig.begin(), sig.end())));
    auto t2 = clock::now();
    Crypto::Hash pow = finalizePow(H, y);
    sink = static_cast<uint8_t>(sink ^ pow.data[0]);
    auto t3 = clock::now();
    signMs += std::chrono::duration<double, std::milli>(t1 - t0).count();
    coreMs += std::chrono::duration<double, std::milli>(t2 - t1).count();
    shakeMs += std::chrono::duration<double, std::milli>(t3 - t2).count();
  }
  std::printf("[dp2 bench N=%u r=%u] sign=%.3f ms  yespower-dp2=%.3f ms  shake=%.3f ms  (per attempt, avg of %d)\n",
              parameters::DP2_N, parameters::DP2_R, signMs / iters, coreMs / iters, shakeMs / iters, iters);
  SUCCEED();
}

// One-shot generator for the frozen KAT constants above. Run with:
//   pq_pow_tests --gtest_also_run_disabled_tests --gtest_filter=*GenerateKat*
// then paste the printed hex into kCoreY/kCorePow/kPipe*.
TEST(PqPow, DISABLED_GenerateKat) {
  // Core transcript.
  std::array<uint8_t, 64> H{};
  { auto hp = patternBytes(64, 7, 3); std::copy(hp.begin(), hp.end(), H.begin()); }
  std::array<uint8_t, parameters::DP2_TAPE_LEN> tape{};
  { auto tp = patternBytes(parameters::DP2_TAPE_LEN, 5, 1); std::copy(tp.begin(), tp.end(), tape.begin()); }
  std::array<uint8_t, 32> y = runCore(H, tape);
  Crypto::Hash corePow = finalizePow(H, y);
  std::printf("kCoreY   = \"%s\"\n", toHex(y).c_str());
  std::printf("kCorePow = \"%s\"\n", toHex(corePow.data, 32).c_str());

  // Pipeline vector.
  auto kp = CryptoPQ::dsa_keygen_from_seed(pipelineSeed());
  std::vector<uint8_t> blob = pipelineBlob();
  std::vector<uint8_t> sig;
  Crypto::Hash pipePow{};
  ASSERT_TRUE(dp2_prove(blob, kp.second, sig, pipePow));
  std::array<uint8_t, 64> pipeH = computeH(blob);
  std::array<uint8_t, 64> pipeM = dp2_sign_message(pipeH);
  std::printf("kPipeH   = \"%s\"\n", toHex(pipeH).c_str());
  std::printf("kPipeM   = \"%s\"\n", toHex(pipeM).c_str());
  std::printf("kPipePow = \"%s\"\n", toHex(pipePow.data, 32).c_str());
  std::printf("kPipeSig = \"%s\"\n", toHex(sig).c_str());
  SUCCEED();
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
