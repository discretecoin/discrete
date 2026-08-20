// Copyright (c) 2026, The Discrete developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#pragma once

#include <algorithm>
#include <cstddef>
#include <thread>

namespace CryptoNote {

constexpr size_t MAX_AUTO_SYNC_POW_THREADS = 8;
constexpr size_t MAX_EXPLICIT_SYNC_POW_THREADS = 32;

// The three-argument overload is deterministic so the boundary cases can be
// tested without depending on the test runner's CPU topology.
inline size_t resolveSyncPowThreadCount(size_t requestedThreads,
                                        size_t concurrentMiningThreads,
                                        size_t hardwareThreads) noexcept {
  // A non-zero --sync-pow-threads value is an operator override. Mining is
  // deliberately not subtracted from it; only the safety ceiling applies.
  if (requestedThreads != 0) {
    return (std::min)(requestedThreads, MAX_EXPLICIT_SYNC_POW_THREADS);
  }

  hardwareThreads = (std::max)(size_t{1}, hardwareThreads);
  const size_t availableThreads = hardwareThreads > concurrentMiningThreads
    ? hardwareThreads - concurrentMiningThreads
    : size_t{1};
  return (std::min)(availableThreads, MAX_AUTO_SYNC_POW_THREADS);
}

inline size_t resolveSyncPowThreadCount(size_t requestedThreads,
                                        size_t concurrentMiningThreads) noexcept {
  return resolveSyncPowThreadCount(requestedThreads, concurrentMiningThreads,
                                   static_cast<size_t>(std::thread::hardware_concurrency()));
}

inline size_t resolveSyncPowThreadCount(size_t requestedThreads) noexcept {
  return resolveSyncPowThreadCount(requestedThreads, 0);
}

} // namespace CryptoNote
