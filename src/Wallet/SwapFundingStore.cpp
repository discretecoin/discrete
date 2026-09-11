// Copyright (c) 2026, The Discrete developers. LGPL-3.0-or-later.
#include "SwapFundingStore.h"
#include "Common/StringTools.h"
#include "Common/SecureMemory.h"
#include "crypto/random.h"
#include "crypto/crypto.h"
#include "crypto_pq/PqAead.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <set>
#include <stdexcept>
#include <system_error>
#include <boost/filesystem.hpp>
#ifdef _WIN32
#include <windows.h>
#include <Aclapi.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#endif

namespace CryptoNote {
namespace {
constexpr char magic[] = {'X','D','S','S','F','D',1,0};
constexpr size_t headerSize = sizeof(magic) + 32 + 32 + 32 + 1 + 32 + 4;
void require(bool good, const char* message) { if (!good) throw std::runtime_error(message); }
void append32(BinaryArray& out, uint32_t v) { for (int i=0;i<4;++i) out.push_back(uint8_t(v >> (8*i))); }
uint32_t uint32(const BinaryArray& in, size_t at) {
  uint32_t value=0; for (int i=0;i<4;++i) value |= uint32_t(in.at(at+i)) << (8*i); return value;
}
std::string filename(const Crypto::Hash& operation, SwapFundingStore::Stage stage) {
  if (stage == SwapFundingStore::Identity) return "identity";
  require(stage == SwapFundingStore::Draft || stage == SwapFundingStore::Prepared, "invalid swap record stage");
  require(operation != Crypto::Hash{}, "zero swap operation id");
  return Common::podToHex(operation) + (stage == SwapFundingStore::Draft ? ".draft" : ".prepared");
}
bool operationFile(const std::string& name, std::string& operation) {
  if (name.size()!=70 && name.size()!=73) return false;
  if (name.substr(64)!=".draft" && name.substr(64)!=".prepared") return false;
  for (size_t i=0;i<64;++i) if (!((name[i]>='0'&&name[i]<='9')||(name[i]>='a'&&name[i]<='f'))) return false;
  operation=name.substr(0,64); return operation!=std::string(64,'0');
}
#ifdef _WIN32
// Immutable operation names add 73 characters to an existing wallet path.
// Use extended absolute paths explicitly; do not depend on the executable's
// longPathAware manifest or the host-wide Windows long-path policy.
std::wstring nativePath(const boost::filesystem::path& path) {
  auto value=boost::filesystem::absolute(path).lexically_normal().wstring();
  std::replace(value.begin(),value.end(),L'/',L'\\');
  if(value.compare(0,4,L"\\\\?\\")==0)return value;
  if(value.compare(0,2,L"\\\\")==0)return L"\\\\?\\UNC\\"+value.substr(2);
  return L"\\\\?\\"+value;
}
DWORD attributes(const boost::filesystem::path& path) {
  const auto result=GetFileAttributesW(nativePath(path).c_str());
  if(result==INVALID_FILE_ATTRIBUTES) {
    const auto error=GetLastError();
    require(error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND,"swap directory inspection failed");
  }
  return result;
}
#endif
void checkAncestors(const boost::filesystem::path& path) {
  boost::filesystem::path walk;
  for (const auto& part : path) {
    walk /= part;
#ifdef _WIN32
    if(walk==path.root_name())continue;
    const auto flags=attributes(walk);
    if(flags==INVALID_FILE_ATTRIBUTES)continue;
    require(!(flags&FILE_ATTRIBUTE_REPARSE_POINT),"swap directory reparse point rejected");
#else
    boost::system::error_code error;
    const auto state=boost::filesystem::symlink_status(walk,error);
    if (error && error != boost::system::errc::no_such_file_or_directory) throw std::runtime_error("swap directory inspection failed");
    if (!boost::filesystem::exists(state)) continue;
    require(!boost::filesystem::is_symlink(state), "swap directory link rejected");
#endif
  }
}
#ifdef _WIN32
struct PrivateSecurity {
  std::vector<uint8_t> user;
  PACL acl=nullptr;
  SECURITY_DESCRIPTOR descriptor{};
  SECURITY_ATTRIBUTES attributes{};
  PrivateSecurity() {
    HANDLE token=nullptr;
    require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=0,"swap owner token unavailable");
    DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);user.resize(size);
    const bool got=size&&GetTokenInformation(token,TokenUser,user.data(),size,&size);
    CloseHandle(token);require(got,"swap owner identity unavailable");
    EXPLICIT_ACCESSW entry{};entry.grfAccessPermissions=GENERIC_ALL;entry.grfAccessMode=SET_ACCESS;
    entry.grfInheritance=NO_INHERITANCE;entry.Trustee.TrusteeForm=TRUSTEE_IS_SID;entry.Trustee.TrusteeType=TRUSTEE_IS_USER;
    entry.Trustee.ptstrName=reinterpret_cast<LPWSTR>(sid());
    require(SetEntriesInAclW(1,&entry,nullptr,&acl)==ERROR_SUCCESS,"swap private ACL construction failed");
    if (!InitializeSecurityDescriptor(&descriptor,SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor,TRUE,acl,FALSE) ||
        !SetSecurityDescriptorOwner(&descriptor,sid(),FALSE) ||
        !SetSecurityDescriptorControl(&descriptor,SE_DACL_PROTECTED,SE_DACL_PROTECTED)) {
      LocalFree(acl);acl=nullptr;throw std::runtime_error("swap private descriptor construction failed");
    }
    attributes.nLength=sizeof(attributes);attributes.lpSecurityDescriptor=&descriptor;
  }
  ~PrivateSecurity(){if(acl)LocalFree(acl);}
  PSID sid() const {return reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid;}
};
void checkPrivateHandle(HANDLE handle) {
  PSID owner=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
  require(GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
      &owner,nullptr,&acl,nullptr,&descriptor)==ERROR_SUCCESS,"swap ACL inspection failed");
  try {
    PrivateSecurity current;SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;
    require(owner&&EqualSid(owner,current.sid())&&acl&&acl->AceCount==1&&
        GetSecurityDescriptorControl(descriptor,&control,&revision)&&(control&SE_DACL_PROTECTED),
        "swap path must have its private owner ACL");
    void* raw=nullptr;require(GetAce(acl,0,&raw)!=0,"swap ACL entry unavailable");
    const auto* ace=reinterpret_cast<const ACCESS_ALLOWED_ACE*>(raw);
    require(ace->Header.AceType==ACCESS_ALLOWED_ACE_TYPE&&ace->Header.AceFlags==0&&
        EqualSid(const_cast<DWORD*>(&ace->SidStart),current.sid()),"swap path grants access to another identity");
    LocalFree(descriptor);
  } catch (...) {LocalFree(descriptor);throw;}
}
void checkHandle(HANDLE handle, bool directory) {
  BY_HANDLE_FILE_INFORMATION info{};
  require(GetFileInformationByHandle(handle,&info)!=0,"swap file information unavailable");
  require(!(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),"swap reparse point rejected");
  require(bool(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==directory,"swap file type mismatch");
  if (!directory) require(info.nNumberOfLinks==1,"swap hardlink rejected");
  checkPrivateHandle(handle);
}
#else
void checkStat(const struct stat& state, bool directory) {
  require(directory ? S_ISDIR(state.st_mode) : S_ISREG(state.st_mode),"swap file type mismatch");
  require(state.st_uid==geteuid() && !(state.st_mode&0077),"swap path must be private to its owner");
  if (!directory) require(state.st_nlink==1,"swap hardlink rejected");
}
#endif
}

struct SwapFundingStore::Impl {
  boost::filesystem::path path;
  CryptoPQ::Hash256 key;
  Crypto::Hash wallet, genesis;
  bool present=false;
#ifdef _WIN32
  HANDLE directory=INVALID_HANDLE_VALUE, lock=INVALID_HANDLE_VALUE;
#else
  int directory=-1, lock=-1;
#endif
  Impl(const std::string& value,const CryptoPQ::Hash256& secret,const Crypto::Hash& owner,
       const Crypto::Hash& chain,bool create):path(boost::filesystem::absolute(value)),key(secret),wallet(owner),genesis(chain) {
    try {
      require(!value.empty(),"swap preparation path required"); checkAncestors(path);
#ifdef _WIN32
      PrivateSecurity security;
#endif
#ifdef _WIN32
      const bool exists=attributes(path)!=INVALID_FILE_ATTRIBUTES;
#else
      const bool exists=boost::filesystem::exists(path);
#endif
      if (!exists) {
        if (!create) return;
#ifdef _WIN32
        const auto parentFlags=attributes(path.parent_path());
        require(parentFlags!=INVALID_FILE_ATTRIBUTES&&(parentFlags&FILE_ATTRIBUTE_DIRECTORY),"swap parent directory absent");
        require(CreateDirectoryW(nativePath(path).c_str(),&security.attributes)!=0,"swap private directory creation failed");
#else
        require(boost::filesystem::is_directory(path.parent_path()),"swap parent directory absent");
        require(::mkdir(path.string().c_str(),0700)==0,"swap private directory creation failed");
        const int parent=::open(path.parent_path().string().c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        require(parent>=0,"swap parent directory open failed");
        const int synced=::fsync(parent); ::close(parent);
        require(synced==0,"swap parent directory flush failed");
#endif
      }
#ifdef _WIN32
      directory=CreateFileW(nativePath(path).c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
      require(directory!=INVALID_HANDLE_VALUE,"swap directory open failed"); checkHandle(directory,true);
      const auto lockPath=nativePath(path/"lock");
      lock=CreateFileW(lockPath.c_str(),GENERIC_READ|GENERIC_WRITE,0,&security.attributes,create?OPEN_ALWAYS:OPEN_EXISTING,
          FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
      require(lock!=INVALID_HANDLE_VALUE,"swap preparation store busy or lock missing"); checkHandle(lock,false);
#else
      directory=::open(path.string().c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
      require(directory>=0,"swap directory open failed"); struct stat state{};
      require(::fstat(directory,&state)==0,"swap directory stat failed"); checkStat(state,true);
      lock=::openat(directory,"lock",O_RDWR|O_NOFOLLOW|(create?O_CREAT:0),0600);
      require(lock>=0,"swap lock missing"); require(::fstat(lock,&state)==0,"swap lock stat failed"); checkStat(state,false);
      require(::flock(lock,LOCK_EX|LOCK_NB)==0,"swap preparation store busy");
#endif
      present=true;
      const auto identity=readFile("identity");
      if (!identity) {
        require(create,"swap store identity missing");
        require(countOperations()==0,"swap store identity missing with existing operations");
        BinaryArray plain(wallet.data,wallet.data+32); plain.insert(plain.end(),genesis.data,genesis.data+32);
        publish(Crypto::Hash{},Identity,plain);
      } else {
        const auto plain=decode(Crypto::Hash{},Identity,*identity);
        require(plain.size()==64 && std::memcmp(plain.data(),wallet.data,32)==0 &&
            std::memcmp(plain.data()+32,genesis.data,32)==0,"swap store identity mismatch");
      }
    } catch (...) { close(); sodium_memzero(key.data(),key.size()); throw; }
  }
  ~Impl() { close(); sodium_memzero(key.data(),key.size()); }
  void close() {
#ifdef _WIN32
    if (lock!=INVALID_HANDLE_VALUE) { CloseHandle(lock); lock=INVALID_HANDLE_VALUE; }
    if (directory!=INVALID_HANDLE_VALUE) { CloseHandle(directory); directory=INVALID_HANDLE_VALUE; }
#else
    if (lock>=0) { ::close(lock); lock=-1; }
    if (directory>=0) { ::close(directory); directory=-1; }
#endif
  }
  size_t countOperations() const {
    std::set<std::string> operations; size_t files=0;
#ifdef _WIN32
    const boost::filesystem::path scanPath(nativePath(path));
#else
    const auto& scanPath=path;
#endif
    for (boost::filesystem::directory_iterator it(scanPath),end;it!=end;++it) {
      require(++files<=MAX_OPERATIONS*4+8,"swap store file count bound");
      const std::string name=it->path().filename().string();
      if (name=="identity" || name=="lock" || name.compare(0,4,"tmp-")==0) continue;
      std::string operation; require(operationFile(name,operation),"unexpected swap store record"); operations.insert(operation);
    }
    require(operations.size()<=MAX_OPERATIONS,"swap operation count bound"); return operations.size();
  }
  std::optional<BinaryArray> readFile(const std::string& name) const {
    if (!present) return std::nullopt;
    BinaryArray bytes;
#ifdef _WIN32
    HANDLE file=CreateFileW(nativePath(path/name).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if (file==INVALID_HANDLE_VALUE) {
      if (GetLastError()==ERROR_FILE_NOT_FOUND) return std::nullopt;
      throw std::runtime_error("swap record open failed");
    }
    try {
      checkHandle(file,false); LARGE_INTEGER size{};
      require(GetFileSizeEx(file,&size)!=0 && size.QuadPart>=0 && size.QuadPart<=MAX_RECORD_BYTES+headerSize+16,"swap record size bound");
      bytes.resize(static_cast<size_t>(size.QuadPart)); size_t offset=0;
      while(offset<bytes.size()) { DWORD got=0; require(ReadFile(file,bytes.data()+offset,DWORD(bytes.size()-offset),&got,nullptr)!=0&&got,"swap record read failed"); offset+=got; }
      CloseHandle(file);
    } catch (...) { CloseHandle(file); throw; }
#else
    const int file=::openat(directory,name.c_str(),O_RDONLY|O_NOFOLLOW);
    if(file<0) { if(errno==ENOENT)return std::nullopt; throw std::runtime_error("swap record open failed"); }
    try {
      struct stat state{}; require(::fstat(file,&state)==0,"swap record stat failed"); checkStat(state,false);
      require(state.st_size>=0 && uint64_t(state.st_size)<=MAX_RECORD_BYTES+headerSize+16,"swap record size bound");
      bytes.resize(size_t(state.st_size)); size_t offset=0;
      while(offset<bytes.size()) { const auto got=::read(file,bytes.data()+offset,bytes.size()-offset); if(got<0&&errno==EINTR)continue; require(got>0,"swap record read failed"); offset+=size_t(got); }
      ::close(file);
    } catch (...) { ::close(file); throw; }
#endif
    return bytes;
  }
  BinaryArray decode(const Crypto::Hash& operation,Stage stage,const BinaryArray& bytes) const {
    require(bytes.size()>=headerSize+16 && std::memcmp(bytes.data(),magic,sizeof(magic))==0,"swap record envelope rejected");
    size_t at=sizeof(magic);
    require(std::memcmp(bytes.data()+at,wallet.data,32)==0,"swap record wallet mismatch"); at+=32;
    require(std::memcmp(bytes.data()+at,genesis.data,32)==0,"swap record genesis mismatch"); at+=32;
    require(std::memcmp(bytes.data()+at,operation.data,32)==0,"swap record operation mismatch"); at+=32;
    require(bytes[at++]==stage,"swap record stage mismatch");
    const uint8_t* salt=bytes.data()+at; at+=32;
    const uint32_t size=uint32(bytes,at);
    require(size<=MAX_RECORD_BYTES && bytes.size()==headerSize+size+16,"swap record length rejected");
    CryptoPQ::AeadKey subkey{}; Tools::SecretLock scrub(subkey.data(),subkey.size());
    require(CryptoPQ::hkdf_sha3_256_explicit(key.data(),key.size(),salt,32,bytes.data(),headerSize,subkey.data(),subkey.size()),"swap encryption key derivation failed");
    const auto plain=CryptoPQ::aead_decrypt(subkey,{},bytes.data(),headerSize,bytes.data()+headerSize,size+16);
    require(bool(plain),"swap record authentication failed"); return *plain;
  }
  void publish(const Crypto::Hash& operation,Stage stage,const BinaryArray& plain) {
    require(present && plain.size()<=MAX_RECORD_BYTES,"swap record publication bound");
    const auto name=filename(operation,stage);
    if(const auto old=readFile(name)) { require(decode(operation,stage,*old)==plain,"immutable swap record conflict"); return; }
    if(stage==Draft) require(countOperations()<MAX_OPERATIONS,"swap preparation store full");
    if(stage==Prepared) require(bool(readFile(filename(operation,Draft))),"swap draft missing before prepared publication");
    BinaryArray bytes(magic,magic+sizeof(magic));
    bytes.insert(bytes.end(),wallet.data,wallet.data+32); bytes.insert(bytes.end(),genesis.data,genesis.data+32);
    bytes.insert(bytes.end(),operation.data,operation.data+32); bytes.push_back(stage);
    const auto salt=Random::randomBytes(32); bytes.insert(bytes.end(),salt.begin(),salt.end()); append32(bytes,uint32_t(plain.size()));
    CryptoPQ::AeadKey subkey{}; Tools::SecretLock scrub(subkey.data(),subkey.size());
    require(CryptoPQ::hkdf_sha3_256_explicit(key.data(),key.size(),salt.data(),salt.size(),bytes.data(),bytes.size(),subkey.data(),subkey.size()),"swap encryption key derivation failed");
    const auto ciphertext=CryptoPQ::aead_encrypt(subkey,{},bytes.data(),bytes.size(),plain.data(),plain.size());
    bytes.insert(bytes.end(),ciphertext.begin(),ciphertext.end());
    const auto temporary="tmp-"+Common::toHex(Random::randomBytes(16));
#ifdef _WIN32
    PrivateSecurity security;
    HANDLE file=CreateFileW(nativePath(path/temporary).c_str(),GENERIC_WRITE,0,&security.attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    require(file!=INVALID_HANDLE_VALUE,"swap temporary record creation failed");
    try {
      checkHandle(file,false);size_t offset=0;
      while(offset<bytes.size()) { DWORD wrote=0; require(WriteFile(file,bytes.data()+offset,DWORD(bytes.size()-offset),&wrote,nullptr)!=0&&wrote,"swap record write failed"); offset+=wrote; }
      require(FlushFileBuffers(file)!=0,"swap record flush failed"); CloseHandle(file); file=INVALID_HANDLE_VALUE;
      require(MoveFileExW(nativePath(path/temporary).c_str(),nativePath(path/name).c_str(),MOVEFILE_WRITE_THROUGH)!=0,"swap immutable publication failed");
    } catch (...) { if(file!=INVALID_HANDLE_VALUE)CloseHandle(file); DeleteFileW(nativePath(path/temporary).c_str()); throw; }
#else
    int file=::openat(directory,temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    require(file>=0,"swap temporary record creation failed");
    try {
      size_t offset=0; while(offset<bytes.size()) { auto wrote=::write(file,bytes.data()+offset,bytes.size()-offset); if(wrote<0&&errno==EINTR)continue; require(wrote>0,"swap record write failed"); offset+=size_t(wrote); }
      require(::fsync(file)==0,"swap record flush failed"); ::close(file); file=-1;
      // The private directory and exclusive process lock serialize every store
      // writer. A single rename avoids a two-hardlink crash state between link
      // publication and temporary cleanup; existing records were checked above.
#ifdef __linux__
      require(::syscall(SYS_renameat2,directory,temporary.c_str(),directory,name.c_str(),1 /* RENAME_NOREPLACE */)==0,
              "swap immutable publication failed");
#else
      require(::renameat(directory,temporary.c_str(),directory,name.c_str())==0,"swap immutable publication failed");
#endif
      require(::fsync(directory)==0,"swap directory flush failed");
    } catch (...) { if(file>=0)::close(file); ::unlinkat(directory,temporary.c_str(),0); throw; }
#endif
  }
};

SwapFundingStore::SwapFundingStore(const std::string& path,const CryptoPQ::Hash256& key,
    const Crypto::Hash& wallet,const Crypto::Hash& genesis,bool create)
  :impl(new Impl(path,key,wallet,genesis,create)) {}
SwapFundingStore::~SwapFundingStore()=default;
bool SwapFundingStore::available() const { return impl->present; }
std::optional<BinaryArray> SwapFundingStore::read(const Crypto::Hash& operation,Stage stage) const {
  const auto value=impl->readFile(filename(operation,stage));
  if (!value) return std::nullopt;
  return impl->decode(operation,stage,*value);
}
void SwapFundingStore::publish(const Crypto::Hash& operation,Stage stage,const BinaryArray& bytes) { impl->publish(operation,stage,bytes); }
}
