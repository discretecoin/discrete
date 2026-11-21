// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "Common/StringTools.h"
#include "Qre/QreVerifier.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

void usage(std::ostream& out) {
  out << "Usage: qre-verify --policy FILE --context FILE BUNDLE [BUNDLE ...]\n"
         "Inspect binary QRE v1 observations offline. Supply a locally pinned policy and\n"
         "an independently trusted receiver challenge. Include all known bundles for\n"
         "that challenge. The system UTC clock supplies the inspection time.\n"
         "Exit codes: 0 quorum, 1 invalid input, 2 insufficient votes, 3 equivocation.\n";
}

Qre::Bytes readFile(const char* path, std::size_t limit, const std::string& role) {
  std::error_code error;
  if (!std::filesystem::is_regular_file(path, error)) {
    throw std::runtime_error(role + " must be a readable regular file");
  }
  std::ifstream in(path, std::ios::binary | std::ios::ate);
  const std::streamoff size = in.tellg();
  if (size <= 0 || static_cast<std::uintmax_t>(size) > limit) {
    throw std::runtime_error(role + " is unreadable, empty or exceeds the size limit");
  }
  Qre::Bytes bytes(static_cast<std::size_t>(size));
  in.seekg(0);
  if (!in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size)) ||
      in.peek() != std::char_traits<char>::eof() || in.bad()) {
    throw std::runtime_error(role + " could not be read to its measured end");
  }
  return bytes;
}

int report(const Qre::Result& result, uint64_t now) {
  std::cout << "Scope: supplied snapshot only\n"
               "Branch: UNVALIDATED\n"
            << "Inspection time (Unix UTC): " << now << '\n';

  int exitCode = 1;
  switch (result.status) {
    case Qre::Status::Invalid:
      std::cout << "Evidence: INVALID\n" << result.reason << '\n';
      return 1;
    case Qre::Status::Insufficient:
      std::cout << "Evidence: INSUFFICIENT\n";
      exitCode = 2;
      break;
    case Qre::Status::Equivocation:
      std::cout << "Evidence: EQUIVOCATION\n";
      exitCode = 3;
      break;
    case Qre::Status::Quorum:
      std::cout << "Evidence: QUORUM VERIFIED\n";
      exitCode = 0;
      break;
  }
  std::cout << "Policy: " << Common::podToHex(result.policyId) << '\n'
            << "Context: " << Common::podToHex(result.contextId) << '\n'
            << "Required signers: " << result.threshold << " of " << result.rosterSize << '\n';
  for (const auto& group : result.groups) {
    std::cout << "Statement: " << Common::podToHex(group.statementId) << '\n'
              << "  Fresh evidence ID: " << Common::podToHex(group.evidenceId) << '\n'
              << "  Observation at height " << result.observationHeight << ": "
              << Common::podToHex(group.observationHash) << '\n'
              << "  Reference at height " << result.referenceHeight << ": "
              << Common::podToHex(group.referenceHash) << '\n'
              << "  Distinct fresh signers: " << group.signers.size() << '\n';
    for (const auto& signer : group.signers) {
      std::cout << "    " << Common::podToHex(signer) << '\n';
    }
    if (group.signers.empty()) {
      std::cout << "  Historical observation only\n";
    }
    for (const auto& signer : group.staleSigners) {
      std::cout << "  Stale signer: " << Common::podToHex(signer) << '\n';
    }
  }
  for (const auto& signer : result.equivocators) {
    std::cout << "Equivocating signer: " << Common::podToHex(signer) << '\n';
  }
  return exitCode;
}

} // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string_view(argv[1]) == "--help") {
    usage(std::cout);
    return 0;
  }
  if (argc < 6 || std::string_view(argv[1]) != "--policy" ||
      std::string_view(argv[3]) != "--context" ||
      static_cast<std::size_t>(argc - 5) > Qre::MaxBundles) {
    usage(std::cerr);
    return 1;
  }
  try {
    const auto policy = readFile(argv[2], Qre::MaxPolicyBytes, "Policy");
    const auto context = readFile(argv[4], Qre::ContextBytes, "Expected context");
    std::vector<Qre::Bytes> bundles;
    std::size_t remaining = Qre::MaxSnapshotBytes;
    for (int i = 5; i < argc; ++i) {
      bundles.push_back(readFile(argv[i], std::min(remaining, Qre::MaxBundleBytes),
                                 "Bundle " + std::to_string(i - 4)));
      remaining -= bundles.back().size();
    }
    const auto unixSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (unixSeconds <= 0) {
      throw std::runtime_error("System UTC time is unavailable");
    }
    const auto now = static_cast<uint64_t>(unixSeconds);
    return report(Qre::inspect(policy, context, bundles, now), now);
  } catch (const std::exception& e) {
    std::cerr << "Evidence: INVALID\n" << e.what() << '\n';
    return 1;
  }
}
