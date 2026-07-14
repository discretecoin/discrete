// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "PaymentProofArchive.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <system_error>
#include <vector>

#include <boost/filesystem.hpp>

#include "crypto_pq/PqPaymentProof.h"

#ifdef _WIN32
#include <windows.h>
#include <Aclapi.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace CryptoNote {
namespace {

constexpr char kMagic[] = {'D', 'P', 'P', 'R'};
constexpr uint8_t kVersion = 1;
constexpr uint32_t kMaxRecipients = 64;
constexpr uint32_t kMaxAddress = 16 * 1024;
constexpr uint32_t kMaxProof = 1024 * 1024;

void append32(std::string& out, uint32_t v) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>(v >> (8 * i)));
}
void append64(std::string& out, uint64_t v) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<char>(v >> (8 * i)));
}
bool take32(const std::string& in, size_t& p, uint32_t& v) {
  if (p + 4 > in.size()) return false;
  v = 0; for (int i = 0; i < 4; ++i) v |= uint32_t(uint8_t(in[p++])) << (8 * i);
  return true;
}
bool take64(const std::string& in, size_t& p, uint64_t& v) {
  if (p + 8 > in.size()) return false;
  v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(uint8_t(in[p++])) << (8 * i);
  return true;
}
bool takeString(const std::string& in, size_t& p, uint32_t max, std::string& s) {
  uint32_t n = 0; if (!take32(in, p, n) || n > max || p + n > in.size()) return false;
  s.assign(in.data() + p, n); p += n; return true;
}

#ifdef _WIN32
void restrictPathToCurrentUser(const std::wstring& path) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    throw std::system_error(GetLastError(), std::system_category(), "open process token");
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<uint8_t> tokenInfo(size);
  if (size == 0 || !GetTokenInformation(token, TokenUser, tokenInfo.data(), size, &size)) {
    const DWORD error = GetLastError();
    CloseHandle(token);
    throw std::system_error(error, std::system_category(), "read process token");
  }
  CloseHandle(token);

  EXPLICIT_ACCESSW access{};
  access.grfAccessPermissions = GENERIC_ALL;
  access.grfAccessMode = SET_ACCESS;
  access.grfInheritance = NO_INHERITANCE;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_USER;
  access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(
      reinterpret_cast<TOKEN_USER*>(tokenInfo.data())->User.Sid);

  PACL acl = nullptr;
  DWORD error = SetEntriesInAclW(1, &access, nullptr, &acl);
  if (error == ERROR_SUCCESS) {
    error = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, acl, nullptr);
  }
  if (acl) LocalFree(acl);
  if (error != ERROR_SUCCESS)
    throw std::system_error(error, std::system_category(), "secure payment-proof path");
}
#endif

// Crash-safe write to a standalone file: write a temp sibling, flush, then
// atomically rename it over the target.
void durableReplace(const std::string& finalPath, const std::string& bytes) {
  const std::string tempPath = finalPath + ".tmp";
  boost::system::error_code ignored; boost::filesystem::remove(tempPath, ignored);
#ifdef _WIN32
  const std::wstring temp = boost::filesystem::path(tempPath).wstring();
  HANDLE h = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) throw std::system_error(GetLastError(), std::system_category());
  try {
    restrictPathToCurrentUser(temp);
    size_t off = 0;
    while (off < bytes.size()) { DWORD wrote = 0; DWORD n = static_cast<DWORD>((std::min)(bytes.size()-off, size_t(MAXDWORD)));
      if (!WriteFile(h, bytes.data()+off, n, &wrote, nullptr) || wrote == 0) throw std::system_error(GetLastError(), std::system_category()); off += wrote; }
    if (!FlushFileBuffers(h)) throw std::runtime_error("payment-proof flush failed");
    CloseHandle(h); h = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temp.c_str(), boost::filesystem::path(finalPath).wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      throw std::system_error(GetLastError(), std::system_category());
  } catch (...) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); DeleteFileW(temp.c_str()); throw; }
#else
  int fd = ::open(tempPath.c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600);
  if (fd < 0) throw std::system_error(errno, std::system_category());
  try {
    size_t off = 0; while (off < bytes.size()) { ssize_t n = ::write(fd, bytes.data()+off, bytes.size()-off); if (n <= 0) throw std::system_error(errno, std::system_category()); off += size_t(n); }
    if (::fsync(fd) != 0) throw std::runtime_error("payment-proof flush failed");
    ::close(fd); fd = -1;
    if (::rename(tempPath.c_str(), finalPath.c_str()) != 0) throw std::runtime_error("payment-proof rename failed");
    const std::string parent = boost::filesystem::path(finalPath).parent_path().string();
    int dfd = ::open(parent.empty() ? "." : parent.c_str(), O_RDONLY); if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
  } catch (...) { if (fd >= 0) ::close(fd); ::unlink(tempPath.c_str()); throw; }
#endif
}

}  // namespace

std::string PaymentProofArchive::encodeRecord(const Crypto::Hash& genesisId,
                                               const Crypto::Hash& txid,
                                               const SentPaymentRecord& record) {
  if (record.recipients.empty() || record.recipients.size() > kMaxRecipients)
    throw std::runtime_error("invalid payment-proof recipient count");
  std::string out(kMagic, sizeof(kMagic));
  out.push_back(static_cast<char>(kVersion));
  out.append(reinterpret_cast<const char*>(genesisId.data), sizeof(genesisId.data));
  out.append(reinterpret_cast<const char*>(txid.data), sizeof(txid.data));
  append32(out, static_cast<uint32_t>(record.recipients.size()));
  for (const auto& e : record.recipients) {
    if (e.address.size() > kMaxAddress || e.proof.empty() || e.proof.size() > kMaxProof)
      throw std::runtime_error("invalid payment-proof entry size");
    append32(out, static_cast<uint32_t>(e.address.size())); out.append(e.address);
    append64(out, e.amount);
    append32(out, static_cast<uint32_t>(e.proof.size())); out.append(e.proof);
  }
  return out;
}

bool PaymentProofArchive::decodeRecord(const std::string& bytes, Crypto::Hash& genesisId,
                                        Crypto::Hash& txid, SentPaymentRecord& record,
                                        std::string* error) {
  auto fail = [&](const char* why) { if (error) *error = why; return false; };
  const size_t fixed = sizeof(kMagic) + 1 + 32 + 32 + 4;
  if (bytes.size() < fixed || std::memcmp(bytes.data(), kMagic, sizeof(kMagic)) != 0)
    return fail("bad archive magic");
  size_t p = sizeof(kMagic);
  if (uint8_t(bytes[p++]) != kVersion) return fail("unsupported archive version");
  std::memcpy(genesisId.data, bytes.data() + p, 32); p += 32;
  std::memcpy(txid.data, bytes.data() + p, 32); p += 32;
  uint32_t count = 0;
  if (!take32(bytes, p, count) || count == 0 || count > kMaxRecipients)
    return fail("bad recipient count");
  SentPaymentRecord decoded;
  decoded.recipients.resize(count);
  for (auto& e : decoded.recipients) {
    if (!takeString(bytes, p, kMaxAddress, e.address) || !take64(bytes, p, e.amount) ||
        !takeString(bytes, p, kMaxProof, e.proof)) return fail("malformed entry");
    PqPaymentProof proof;
    if (!decodePqPaymentProof(e.proof, proof) ||
        std::memcmp(proof.genesisId.data(), genesisId.data, 32) != 0 ||
        std::memcmp(proof.txid.data(), txid.data, 32) != 0)
      return fail("proof binding mismatch");
  }
  if (p != bytes.size()) return fail("trailing archive data");
  record = std::move(decoded);
  return true;
}

std::string PaymentProofArchive::readExternalFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("cannot open payment-proof file");
  in.seekg(0, std::ios::end); const auto n = in.tellg();
  if (n < 0 || n > static_cast<std::streamoff>(64 * 1024 * 1024))
    throw std::runtime_error("invalid payment-proof file size");
  std::string bytes(static_cast<size_t>(n), '\0'); in.seekg(0);
  if (n && !in.read(&bytes[0], n)) throw std::runtime_error("cannot read payment-proof file");
  return bytes;
}

void PaymentProofArchive::exportRecord(const Crypto::Hash& genesisId, const Crypto::Hash& txid,
                                       const SentPaymentRecord& record, const std::string& path) {
  if (path.empty()) throw std::runtime_error("payment-proof export path is empty");
  durableReplace(path, encodeRecord(genesisId, txid, record));
}

}  // namespace CryptoNote
