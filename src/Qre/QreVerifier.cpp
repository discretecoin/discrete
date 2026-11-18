// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "QreVerifier.h"

#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqHash.h"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>

namespace Qre {
namespace {

constexpr size_t BundleHeader = ContextBytes + 2 * Hash{}.size() + 1;
constexpr size_t EnvelopeBytes = Hash{}.size() + 8 + CryptoPQ::kDsaSignatureBytes;
static_assert(MaxBundleBytes == BundleHeader + 32 * EnvelopeBytes, "QRE v1 bundle width");
static_assert(MaxPolicyBytes == 25 + 32 * CryptoPQ::kDsaPublicKeyBytes, "QRE v1 key width");

class Invalid : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

void require(bool condition, const char* reason) {
  if (!condition) throw Invalid(reason);
}

class Reader {
public:
  explicit Reader(const Bytes& bytes) : bytes(bytes) {}

  const uint8_t* take(size_t count) {
    require(count <= bytes.size() - offset, "Truncated input");
    const auto* begin = bytes.data() + offset;
    offset += count;
    return begin;
  }

  uint8_t u8() { return *take(1); }

  template<typename T> T integer() {
    const auto* data = take(sizeof(T));
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
      value |= static_cast<T>(data[i]) << (8 * i);
    }
    return value;
  }

  template<typename Array> Array array() {
    Array value{};
    std::copy_n(take(value.size()), value.size(), value.begin());
    return value;
  }

  void version() {
    require(u8() == 1 && u8() == 1, "Unsupported version or signature suite");
  }

private:
  const Bytes& bytes;
  size_t offset = 0;
};

template<typename Range> void append(Bytes& bytes, const Range& value) {
  bytes.insert(bytes.end(), value.begin(), value.end());
}

void appendTime(Bytes& bytes, uint64_t time) {
  for (size_t i = 0; i < sizeof(time); ++i) {
    bytes.push_back(static_cast<uint8_t>(time >> (i * 8)));
  }
}

template<typename Range> Hash digest(std::string_view domain, const Range& value) {
  Bytes bytes;
  bytes.reserve(domain.size() + value.size());
  append(bytes, domain);
  append(bytes, value);
  return CryptoPQ::sha3_256(bytes.data(), bytes.size());
}

struct Policy {
  Hash id;
  unsigned threshold;
  uint32_t window, age, skew, records, checks;
  std::map<Hash, CryptoPQ::DsaPublicKey> keys;
};

Policy parsePolicy(const Bytes& bytes) {
  require(bytes.size() >= 25 && bytes.size() <= MaxPolicyBytes, "Invalid local policy length");
  Reader reader(bytes);
  reader.version();
  const unsigned n = reader.u8();
  Policy policy{};
  policy.threshold = reader.u8();
  const unsigned f = reader.u8();
  require(n >= 1 && n <= 32 && bytes.size() == 25 + n * CryptoPQ::kDsaPublicKeyBytes,
          "Invalid roster count or length");
  require(f < n && policy.threshold <= n - f && 2 * policy.threshold > n + f,
          "Invalid quorum threshold or fault bound");
  policy.window = reader.integer<uint32_t>();
  policy.age = reader.integer<uint32_t>();
  policy.skew = reader.integer<uint32_t>();
  policy.records = reader.integer<uint32_t>();
  policy.checks = reader.integer<uint32_t>();
  require(policy.window > 0 && policy.age > 0 &&
          policy.records >= policy.threshold && policy.checks >= policy.threshold,
          "Invalid policy limits");
  CryptoPQ::DsaPublicKey previous{};
  for (unsigned i = 0; i < n; ++i) {
    const auto key = reader.array<CryptoPQ::DsaPublicKey>();
    require(i == 0 || previous < key, "Duplicate or unsorted policy key");
    const auto id = digest("discrete-qre-key-v1", key);
    require(policy.keys.emplace(id, key).second, "Duplicate policy key ID");
    previous = key;
  }
  policy.id = digest("discrete-qre-policy-v1", bytes);
  return policy;
}

struct Context {
  Hash id;
  uint64_t start, end;
  uint32_t observationHeight, referenceHeight;
};

Context parseContext(const Policy& policy, const Bytes& bytes, uint64_t now) {
  require(bytes.size() == ContextBytes, "Invalid local context length");
  Reader reader(bytes);
  reader.version();
  reader.take(16); // Exact network UUID is part of the pinned context.
  const auto genesis = reader.array<Hash>();
  require(reader.array<Hash>() == policy.id, "Context belongs to a different policy");
  const auto generation = reader.integer<uint64_t>();
  const auto epoch = reader.integer<uint64_t>();
  require(generation != 0 && epoch != 0 && reader.array<Hash>() != Hash{},
          "Missing policy generation, incident epoch or nonce");
  const auto tipHeight = reader.integer<uint32_t>();
  const auto tip = reader.array<Hash>();
  const auto anchorHeight = reader.integer<uint32_t>();
  const auto anchor = reader.array<Hash>();
  require(anchorHeight <= tipHeight && (anchorHeight != tipHeight || anchor == tip) &&
          (anchorHeight != 0 || anchor == genesis), "Inconsistent local anchor");
  Context ctx{};
  ctx.observationHeight = reader.integer<uint32_t>();
  ctx.referenceHeight = reader.integer<uint32_t>();
  require(uint64_t(ctx.observationHeight) + 10 <= ctx.referenceHeight,
          "Observation lacks depth at the requested reference height");
  ctx.start = reader.integer<uint64_t>();
  ctx.end = reader.integer<uint64_t>();
  require(ctx.start < ctx.end && ctx.end - ctx.start <= policy.window, "Invalid collection window");
  require(ctx.start <= now && now < ctx.end, "Snapshot time outside collection window");
  ctx.id = digest("discrete-qre-context-v1", bytes);
  return ctx;
}

struct Pending {
  Hash signer;
  uint64_t time;
  const uint8_t* signature;
};

struct Statement {
  Hash observation, reference;
  std::vector<Pending> pending;
  // An empty time records an authenticated signer whose support has aged out.
  std::map<Hash, std::optional<uint64_t>> votes;
};

using Statements = std::map<Hash, Statement>;

void readBundle(const Bytes& bytes, const Bytes& expected, const Context& ctx, const Policy& policy,
                uint64_t now, size_t& checks, Statements& statements) {
  require(bytes.size() >= BundleHeader && bytes.size() <= MaxBundleBytes, "Invalid bundle length");
  Reader reader(bytes);
  require(std::equal(expected.begin(), expected.end(), reader.take(ContextBytes)), "Foreign context");
  const auto observation = reader.array<Hash>();
  const auto reference = reader.array<Hash>();
  const auto count = reader.u8();
  require(count >= 1 && count <= policy.keys.size() &&
          bytes.size() == BundleHeader + count * EnvelopeBytes, "Invalid bundle count or length");
  checks += count;
  require(checks <= MaxEnvelopes && checks <= policy.checks, "Signature verification limit exceeded");
  Bytes payload;
  append(payload, ctx.id);
  append(payload, observation);
  append(payload, reference);
  auto& statement = statements[digest("discrete-qre-statement-v1", payload)];
  statement.observation = observation;
  statement.reference = reference;
  Hash previous{};
  for (unsigned i = 0; i < count; ++i) {
    const auto signer = reader.array<Hash>();
    require(i == 0 || previous < signer, "Duplicate or unsorted signer");
    require(policy.keys.count(signer) != 0, "Signer outside pinned roster");
    const auto time = reader.integer<uint64_t>();
    require(time >= ctx.start && time < ctx.end, "Observation outside collection window");
    require(time <= now || time - now <= policy.skew, "Observation exceeds clock skew");
    statement.pending.push_back({signer, time, reader.take(CryptoPQ::kDsaSignatureBytes)});
    previous = signer;
  }
}

Result inspectSnapshot(const Bytes& policyBytes, const Bytes& contextBytes,
                       const std::vector<Bytes>& bundles, uint64_t now) {
  require(bundles.size() <= MaxBundles, "Too many bundles");
  const auto policy = parsePolicy(policyBytes);
  const auto ctx = parseContext(policy, contextBytes, now);
  Statements statements;
  size_t checks = 0;
  for (const auto& bundle : bundles) {
    readBundle(bundle, contextBytes, ctx, policy, now, checks, statements);
  }

  Result result;
  result.status = Status::Insufficient;
  result.policyId = policy.id;
  result.contextId = ctx.id;
  result.threshold = policy.threshold;
  result.rosterSize = static_cast<unsigned>(policy.keys.size());
  result.observationHeight = ctx.observationHeight;
  result.referenceHeight = ctx.referenceHeight;
  std::set<Hash> seen, equivocators;
  size_t records = 0;
  for (auto& entry : statements) {
    const auto& id = entry.first;
    auto& statement = entry.second;
    Bytes prefix;
    append(prefix, std::string_view("discrete-qre-observation-v1"));
    append(prefix, ctx.id);
    append(prefix, id);
    for (const auto& envelope : statement.pending) {
      Bytes message = prefix;
      appendTime(message, envelope.time);
      append(message, envelope.signer);
      CryptoPQ::DsaSignature signature;
      std::copy_n(envelope.signature, signature.size(), signature.begin());
      require(CryptoPQ::dsa_verify(policy.keys.at(envelope.signer), message.data(),
                                   message.size(), signature), "Invalid witness signature");
      const auto vote = statement.votes.try_emplace(envelope.signer);
      if (vote.second) {
        require(++records <= policy.records, "Incident record limit exceeded");
        if (!seen.insert(envelope.signer).second) equivocators.insert(envelope.signer);
      }
      auto& earliestFresh = vote.first->second;
      if ((envelope.time >= now || now - envelope.time <= policy.age) &&
          (!earliestFresh || envelope.time < *earliestFresh)) {
        earliestFresh = envelope.time;
      }
    }
    Group group;
    group.statementId = id;
    group.observationHash = statement.observation;
    group.referenceHash = statement.reference;
    Bytes participants;
    for (const auto& vote : statement.votes) {
      if (vote.second) {
        group.signers.push_back(vote.first);
        append(participants, vote.first);
        appendTime(participants, *vote.second);
      } else {
        group.staleSigners.push_back(vote.first);
      }
    }
    Bytes proof;
    append(proof, id);
    proof.push_back(static_cast<uint8_t>(group.signers.size()));
    append(proof, participants);
    group.evidenceId = digest("discrete-qre-evidence-v1", proof);
    if (group.signers.size() >= policy.threshold) result.status = Status::Quorum;
    result.groups.push_back(std::move(group));
  }
  if (!equivocators.empty()) {
    result.status = Status::Equivocation;
    result.equivocators.assign(equivocators.begin(), equivocators.end());
  }
  return result;
}

} // namespace

Result inspect(const Bytes& policy, const Bytes& context,
               const std::vector<Bytes>& bundles, uint64_t now) {
  try {
    return inspectSnapshot(policy, context, bundles, now);
  } catch (const Invalid& invalid) {
    Result result;
    result.reason = invalid.what();
    return result;
  }
}

} // namespace Qre
