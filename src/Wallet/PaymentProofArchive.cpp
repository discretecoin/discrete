// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "PaymentProofArchive.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include "Common/StringTools.h"
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
constexpr char kAuthorityMagic[] = {'D', 'P', 'P', 'A'};
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
bool hashFromHexName(const std::string& name, Crypto::Hash& hash) {
  if (name.size() != 64 + 7 || name.substr(64) != ".pproof") return false;
  const std::string hex = name.substr(0, 64);
  if (hex != boost::algorithm::to_lower_copy(hex)) return false;
  return Common::podFromHex(hex, hash);
}
bool hashEqual(const Crypto::Hash& a, const Crypto::Hash& b) {
  return std::memcmp(a.data, b.data, sizeof(a.data)) == 0;
}

bool recordEqual(const SentPaymentRecord& a, const SentPaymentRecord& b) {
  if (a.recipients.size() != b.recipients.size()) return false;
  for (size_t i = 0; i < a.recipients.size(); ++i) {
    const auto& x = a.recipients[i];
    const auto& y = b.recipients[i];
    if (x.address != y.address || x.amount != y.amount || x.proof != y.proof) return false;
  }
  return true;
}

boost::filesystem::path normalizedPath(const boost::filesystem::path& path) {
  boost::system::error_code ec;
  const auto normalized = boost::filesystem::weakly_canonical(
      boost::filesystem::absolute(path), ec);
  return ec ? boost::filesystem::absolute(path).lexically_normal() : normalized;
}

bool isSameOrChildPath(const boost::filesystem::path& candidate,
                       const boost::filesystem::path& directory) {
  auto child = normalizedPath(candidate).generic_string();
  auto parent = normalizedPath(directory).generic_string();
#ifdef _WIN32
  boost::algorithm::to_lower(child);
  boost::algorithm::to_lower(parent);
#endif
  if (child == parent) return true;
  if (!parent.empty() && parent.back() != '/') parent.push_back('/');
  return child.size() > parent.size() && child.compare(0, parent.size(), parent) == 0;
}

#ifdef _WIN32
void restrictPathToCurrentUser(const std::wstring& path, bool inheritToChildren) {
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
  access.grfInheritance = inheritToChildren
      ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
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

std::string PaymentProofArchive::readFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("cannot open payment-proof archive file");
  in.seekg(0, std::ios::end); const auto n = in.tellg();
  if (n < 0 || n > static_cast<std::streamoff>(64 * 1024 * 1024))
    throw std::runtime_error("invalid payment-proof archive file size");
  std::string bytes(static_cast<size_t>(n), '\0'); in.seekg(0);
  if (n && !in.read(&bytes[0], n)) throw std::runtime_error("cannot read payment-proof archive file");
  return bytes;
}

std::string PaymentProofArchive::pathFor(const Crypto::Hash& txid) const {
  if (!configured()) throw std::runtime_error("payment-proof archive is not configured");
  return (boost::filesystem::path(m_directory) / (Common::podToHex(txid) + ".pproof")).string();
}

void PaymentProofArchive::configure(const std::string& walletFile,
                                    const Crypto::Hash& genesisId,
                                    SentPaymentsStore& store,
                                    std::vector<std::string>* warnings) {
  if (walletFile.empty()) throw std::runtime_error("wallet filename is required for payment-proof storage");
  m_directory = walletFile + ".payment-proofs";
  m_genesisId = genesisId;
  boost::filesystem::create_directories(m_directory);
#ifdef _WIN32
  restrictPathToCurrentUser(boost::filesystem::path(m_directory).wstring(), true);
#else
  ::chmod(m_directory.c_str(), 0700);
#endif

  // The marker makes this directory an authoritative snapshot. Before it exists,
  // migrate the encrypted cache once; afterwards, a missing sidecar is an
  // intentional deletion and must not be resurrected from a stale wallet cache.
  const auto cached = store.records();
  const auto markerPath = boost::filesystem::path(m_directory) / ".authority-v1";
  std::string marker(kAuthorityMagic, sizeof(kAuthorityMagic));
  marker.push_back(static_cast<char>(kVersion));
  marker.append(reinterpret_cast<const char*>(m_genesisId.data), sizeof(m_genesisId.data));
  bool authoritative = false;
  if (boost::filesystem::exists(markerPath)) {
    try {
      authoritative = readFile(markerPath.string()) == marker;
    } catch (...) {
      authoritative = false;
    }
    if (!authoritative && warnings)
      warnings->push_back("invalid payment-proof archive authority marker");
  }
  if (!authoritative) {
    for (const auto& entry : cached) {
      const std::string path = pathFor(entry.first);
      if (boost::filesystem::exists(path)) {
        try {
          Crypto::Hash fileGenesis{}, fileTx{};
          SentPaymentRecord fileRecord;
          if (decodeRecord(readFile(path), fileGenesis, fileTx, fileRecord) &&
              hashEqual(fileGenesis, m_genesisId) && hashEqual(fileTx, entry.first)) {
            continue;
          }
        } catch (...) {
          // Before the authority marker exists, a damaged partial sidecar may
          // be repaired from the encrypted cache during one-time migration.
        }
        if (warnings) warnings->push_back(
            "damaged pre-authority payment-proof record recovered from cache: " +
            Common::podToHex(entry.first));
      }
      std::string bytes;
      try {
        bytes = encodeRecord(m_genesisId, entry.first, entry.second);
      } catch (const std::runtime_error&) {
        if (warnings) warnings->push_back(
            "invalid cached payment-proof record skipped during archive migration: " +
            Common::podToHex(entry.first));
        continue;
      }
      durableReplace(path, bytes);
    }
    durableReplace(markerPath.string(), marker);
  }

  store.clear();
  for (boost::filesystem::directory_iterator it(m_directory), end; it != end; ++it) {
    if (!boost::filesystem::is_regular_file(it->path())) continue;
    Crypto::Hash nameTx{};
    if (!hashFromHexName(it->path().filename().string(), nameTx)) continue;
    try {
#ifdef _WIN32
      restrictPathToCurrentUser(it->path().wstring(), false);
#else
      ::chmod(it->path().string().c_str(), 0600);
#endif
      Crypto::Hash fileGenesis{}, fileTx{}; SentPaymentRecord record; std::string why;
      if (!decodeRecord(readFile(it->path().string()), fileGenesis, fileTx, record, &why) ||
          !hashEqual(fileGenesis, m_genesisId) || !hashEqual(fileTx, nameTx)) {
        if (warnings) warnings->push_back("invalid or conflicting payment-proof record: " + it->path().filename().string());
      } else {
        const auto cachedIt = cached.find(fileTx);
        if (cachedIt != cached.end() && !recordEqual(cachedIt->second, record) && warnings)
          warnings->push_back("cached payment-proof conflict replaced from archive: " + it->path().filename().string());
        store.record(fileTx, record);
      }
    } catch (...) {
      if (warnings) warnings->push_back("unreadable payment-proof record: " + it->path().filename().string());
    }
  }
  for (const auto& entry : cached) {
    if (store.find(entry.first) == nullptr && warnings)
      warnings->push_back("cached payment-proof absent from authoritative archive and discarded: " +
                          Common::podToHex(entry.first));
  }
}

void PaymentProofArchive::durableReplace(const std::string& finalPath, const std::string& bytes) {
  const std::string tempPath = finalPath + ".tmp";
  boost::system::error_code ignored; boost::filesystem::remove(tempPath, ignored);
  if (m_fault == Fault::Create) throw std::runtime_error("injected proof archive create failure");
#ifdef _WIN32
  const std::wstring temp = boost::filesystem::path(tempPath).wstring();
  HANDLE h = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) throw std::system_error(GetLastError(), std::system_category());
  try {
    restrictPathToCurrentUser(temp, false);
    if (m_fault == Fault::Write) throw std::runtime_error("injected proof archive write failure");
    size_t off = 0;
    while (off < bytes.size()) { DWORD wrote = 0; DWORD n = static_cast<DWORD>((std::min)(bytes.size()-off, size_t(MAXDWORD)));
      if (!WriteFile(h, bytes.data()+off, n, &wrote, nullptr) || wrote == 0) throw std::system_error(GetLastError(), std::system_category()); off += wrote; }
    if (m_fault == Fault::Flush || !FlushFileBuffers(h)) throw std::runtime_error("payment-proof flush failed");
    CloseHandle(h); h = INVALID_HANDLE_VALUE;
    if (m_fault == Fault::Rename) throw std::runtime_error("injected proof archive rename failure");
    if (!MoveFileExW(temp.c_str(), boost::filesystem::path(finalPath).wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      throw std::system_error(GetLastError(), std::system_category());
  } catch (...) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); DeleteFileW(temp.c_str()); throw; }
#else
  int fd = ::open(tempPath.c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600);
  if (fd < 0) throw std::system_error(errno, std::system_category());
  try {
    if (m_fault == Fault::Write) throw std::runtime_error("injected proof archive write failure");
    size_t off = 0; while (off < bytes.size()) { ssize_t n = ::write(fd, bytes.data()+off, bytes.size()-off); if (n <= 0) throw std::system_error(errno, std::system_category()); off += size_t(n); }
    if (m_fault == Fault::Flush || ::fsync(fd) != 0) throw std::runtime_error("payment-proof flush failed");
    ::close(fd); fd = -1;
    if (m_fault == Fault::Rename || ::rename(tempPath.c_str(), finalPath.c_str()) != 0) throw std::runtime_error("payment-proof rename failed");
    const std::string parent = boost::filesystem::path(finalPath).parent_path().string();
    int dfd = ::open(parent.empty() ? "." : parent.c_str(), O_RDONLY); if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
  } catch (...) { if (fd >= 0) ::close(fd); ::unlink(tempPath.c_str()); throw; }
#endif
}

void PaymentProofArchive::persist(const Crypto::Hash& txid, const SentPaymentRecord& record) {
  const std::string bytes = encodeRecord(m_genesisId, txid, record);
  const std::string path = pathFor(txid);
  if (boost::filesystem::exists(path)) {
    if (readFile(path) == bytes) return;
    throw std::runtime_error("conflicting payment-proof record for transaction");
  }
  durableReplace(path, bytes);
  const std::string readBack = readFile(path);
  Crypto::Hash g{}, t{}; SentPaymentRecord check;
  if (readBack != bytes || !decodeRecord(readBack, g, t, check) ||
      !hashEqual(g, m_genesisId) || !hashEqual(t, txid))
    throw std::runtime_error("payment-proof archive read-back validation failed");
}

void PaymentProofArchive::erase(const Crypto::Hash& txid) {
  boost::system::error_code ec;
  if (!boost::filesystem::remove(pathFor(txid), ec) && ec) throw boost::filesystem::filesystem_error("remove proof", pathFor(txid), ec);
}

void PaymentProofArchive::replaceAfterExplicitDeletion(const Crypto::Hash& txid,
                                                       const SentPaymentRecord& record) {
  if (record.recipients.empty()) throw std::runtime_error("empty payment-proof replacement");
  durableReplace(pathFor(txid), encodeRecord(m_genesisId, txid, record));
  Crypto::Hash g{}, t{};
  SentPaymentRecord check;
  if (!decodeRecord(readFile(pathFor(txid)), g, t, check) ||
      !hashEqual(g, m_genesisId) || !hashEqual(t, txid))
    throw std::runtime_error("payment-proof archive replacement validation failed");
}

void PaymentProofArchive::exportRecord(const Crypto::Hash& txid,
                                       const SentPaymentRecord& record,
                                       const std::string& path) {
  if (path.empty()) throw std::runtime_error("payment-proof export path is empty");
  if (isSameOrChildPath(path, m_directory))
    throw std::runtime_error("payment-proof export path cannot be inside the authoritative archive");
  durableReplace(path, encodeRecord(m_genesisId, txid, record));
}

}  // namespace CryptoNote
