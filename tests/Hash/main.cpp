// Copyright (c) 2026, The Discrete developers
//
// Current hash/PoW smoke tests for the PQ-only chain. The historical CryptoNote
// vector runner covered cn_slow_hash and the removed extra hash functions; Discrete
// uses SHA3-256 for the chain hash and yespower for PoW.

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "crypto/hash.h"

namespace {

std::string toHex(const Crypto::Hash& h) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t b : h.data) {
    out << std::setw(2) << static_cast<unsigned>(b);
  }
  return out.str();
}

bool expectEq(const char* name, const std::string& actual, const std::string& expected) {
  if (actual == expected) {
    return true;
  }
  std::cerr << name << " mismatch\nexpected: " << expected << "\nactual:   " << actual << "\n";
  return false;
}

bool hashEq(const Crypto::Hash& a, const Crypto::Hash& b) {
  return std::memcmp(a.data, b.data, sizeof(a.data)) == 0;
}

Crypto::Hash chainHash(const void* data, std::size_t len) {
  Crypto::Hash h{};
  Crypto::cn_fast_hash(data, len, h);
  return h;
}

bool testChainSha3() {
  const Crypto::Hash empty = chainHash("", 0);
  const Crypto::Hash abc = chainHash("abc", 3);

  bool ok = true;
  ok &= expectEq("SHA3-256(empty)", toHex(empty),
                 "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  ok &= expectEq("SHA3-256(abc)", toHex(abc),
                 "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  return ok;
}

bool testTreeHashUsesCurrentChainHash() {
  Crypto::Hash leaves[2] = {
      chainHash("left", 4),
      chainHash("right", 5),
  };

  Crypto::Hash root{};
  Crypto::tree_hash(leaves, 2, root);

  uint8_t concat[64];
  std::memcpy(concat, leaves[0].data, 32);
  std::memcpy(concat + 32, leaves[1].data, 32);
  const Crypto::Hash expected = chainHash(concat, sizeof(concat));

  return expectEq("tree_hash(two leaves)", toHex(root), toHex(expected));
}

bool testYespowerPowHash() {
  Crypto::Hash seed{};
  Crypto::Hash h1{};
  Crypto::Hash h2{};
  const char data[] = "Discrete yespower PoW";

  if (!Crypto::y_slow_hash(data, sizeof(data) - 1, seed, h1)) {
    std::cerr << "yespower failed for baseline input\n";
    return false;
  }
  if (!Crypto::y_slow_hash(data, sizeof(data) - 1, seed, h2)) {
    std::cerr << "yespower failed for repeat input\n";
    return false;
  }
  if (!hashEq(h1, h2)) {
    std::cerr << "yespower is not deterministic for identical input/seed\n";
    return false;
  }

  Crypto::Hash changedInput{};
  const char other[] = "Discrete yespower PoW!";
  if (!Crypto::y_slow_hash(other, sizeof(other) - 1, seed, changedInput)) {
    std::cerr << "yespower failed for alternate input\n";
    return false;
  }
  if (hashEq(h1, changedInput)) {
    std::cerr << "yespower output did not change when input changed\n";
    return false;
  }

  return true;
}

}  // namespace

int main() {
  bool ok = true;
  ok &= testChainSha3();
  ok &= testTreeHashUsesCurrentChainHash();
  ok &= testYespowerPowHash();
  return ok ? 0 : 1;
}
