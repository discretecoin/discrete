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

#pragma once

#include <cstddef>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include "crypto/crypto-util.h"  // sodium_memzero

namespace Tools {

// RAII guard for a secret held in memory: pins its pages so they cannot be paged
// out to swap (a harvest-now gift for a multi-KB PQ secret), and scrubs them on
// scope exit. mlock/VirtualLock failure (e.g. RLIMIT_MEMLOCK) is non-fatal — the
// bytes are always zeroized regardless. Link the Crypto library for sodium_memzero.
class SecretLock {
public:
  SecretLock(void* p, size_t n) : m_p(p), m_n(n), m_locked(false) {
    if (m_p && m_n) {
#if defined(_WIN32)
      m_locked = (::VirtualLock(m_p, m_n) != 0);
#else
      m_locked = (::mlock(m_p, m_n) == 0);
#endif
    }
  }

  ~SecretLock() {
    if (m_p && m_n) {
      sodium_memzero(m_p, m_n);
#if defined(_WIN32)
      if (m_locked) ::VirtualUnlock(m_p, m_n);
#else
      if (m_locked) ::munlock(m_p, m_n);
#endif
    }
  }

  SecretLock(const SecretLock&) = delete;
  SecretLock& operator=(const SecretLock&) = delete;

private:
  void* m_p;
  size_t m_n;
  bool m_locked;
};

}  // namespace Tools
