// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Qre {

using Bytes = std::vector<uint8_t>;
using Hash = std::array<uint8_t, 32>;

constexpr size_t MaxPolicyBytes = 25 + 32 * 1952;
constexpr size_t ContextBytes = 226;
constexpr size_t MaxBundleBytes = 291 + 32 * 3349;
constexpr size_t MaxBundles = 64;
constexpr size_t MaxEnvelopes = 256;
constexpr size_t MaxSnapshotBytes = 291 * MaxBundles + 3349 * MaxEnvelopes;

enum class Status { Invalid, Insufficient, Quorum, Equivocation };

struct Group {
  Hash statementId{};
  Hash evidenceId{};
  Hash observationHash{};
  Hash referenceHash{};
  std::vector<Hash> signers;
  std::vector<Hash> staleSigners;
};

struct Result {
  Status status = Status::Invalid;
  std::string reason;
  Hash policyId{};
  Hash contextId{};
  unsigned threshold = 0;
  unsigned rosterSize = 0;
  uint32_t observationHeight = 0;
  uint32_t referenceHeight = 0;
  std::vector<Group> groups;
  std::vector<Hash> equivocators;
};

// Inspect a supplied snapshot against independent local inputs at Unix time now.
// No incident history, trusted chain state or recovery authority is inferred.
Result inspect(const Bytes& policy, const Bytes& context,
               const std::vector<Bytes>& bundles, uint64_t now);

} // namespace Qre
