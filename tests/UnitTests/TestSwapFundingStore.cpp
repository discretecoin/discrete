// Wallet sidecar durability/integrity tests. No transaction broadcast or node.
#include "gtest/gtest.h"
#include "Wallet/SwapFundingStore.h"
#include "Common/StringTools.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <algorithm>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
#include <Aclapi.h>
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace CryptoNote;
namespace {
struct StoreFixture {
  boost::filesystem::path root=boost::filesystem::temp_directory_path()/boost::filesystem::unique_path("xds-store-%%%%-%%%%-%%%%");
  CryptoPQ::Hash256 key{};Crypto::Hash wallet{},genesis{},operation{};
  BinaryArray payload=BinaryArray(320,0x73);
  StoreFixture(){boost::filesystem::create_directory(root);key[0]=8;wallet.data[0]=9;genesis.data[0]=10;operation.data[0]=11;}
  ~StoreFixture(){boost::system::error_code ignored;boost::filesystem::remove_all(root,ignored);}
  std::string path() const {return (root/"records").string();}
  boost::filesystem::path file(const char* stage="draft") const {return root/"records"/(Common::podToHex(operation)+"."+stage);}
  void create(){SwapFundingStore store(path(),key,wallet,genesis,true);store.publish(operation,SwapFundingStore::Draft,payload);}
};
}

TEST(SwapFundingStore, AbsentReadDoesNotCreateFiles) {
  StoreFixture f;SwapFundingStore store(f.path(),f.key,f.wallet,f.genesis,false);
  EXPECT_FALSE(store.available());EXPECT_FALSE(store.read(f.operation,SwapFundingStore::Draft));
  EXPECT_FALSE(boost::filesystem::exists(f.path()));
}

TEST(SwapFundingStore, ImmutableEncryptedRecordsSurviveReopen) {
  StoreFixture f;f.create();
  {std::ifstream input(f.file().string(),std::ios::binary);BinaryArray bytes((std::istreambuf_iterator<char>(input)),{});
    EXPECT_GT(bytes.size(),f.payload.size());
    EXPECT_EQ(std::search(bytes.begin(),bytes.end(),f.payload.begin(),f.payload.end()),bytes.end());}
  SwapFundingStore store(f.path(),f.key,f.wallet,f.genesis,false);
  ASSERT_TRUE(store.read(f.operation,SwapFundingStore::Draft));EXPECT_EQ(*store.read(f.operation,SwapFundingStore::Draft),f.payload);
  EXPECT_NO_THROW(store.publish(f.operation,SwapFundingStore::Draft,f.payload));
  auto changed=f.payload;changed[0]^=1;EXPECT_THROW(store.publish(f.operation,SwapFundingStore::Draft,changed),std::runtime_error);
  EXPECT_EQ(*store.read(f.operation,SwapFundingStore::Draft),f.payload);
  EXPECT_NO_THROW(store.publish(f.operation,SwapFundingStore::Prepared,changed));
  EXPECT_EQ(*store.read(f.operation,SwapFundingStore::Prepared),changed);
}

TEST(SwapFundingStore, ExclusiveLockPreventsConcurrentWriterOrReader) {
  StoreFixture f;SwapFundingStore first(f.path(),f.key,f.wallet,f.genesis,true);
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,f.genesis,true),std::runtime_error);
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,f.genesis,false),std::runtime_error);
}

TEST(SwapFundingStore, WalletGenesisKeyAndStageAreAuthenticated) {
  StoreFixture f;f.create();auto wrongKey=f.key;wrongKey[0]^=1;
  EXPECT_THROW(SwapFundingStore(f.path(),wrongKey,f.wallet,f.genesis,false),std::runtime_error);
  auto wrongWallet=f.wallet;wrongWallet.data[0]^=1;
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,wrongWallet,f.genesis,false),std::runtime_error);
  auto wrongGenesis=f.genesis;wrongGenesis.data[0]^=1;
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,wrongGenesis,false),std::runtime_error);
  boost::filesystem::rename(f.file(),f.file("prepared"));
  SwapFundingStore store(f.path(),f.key,f.wallet,f.genesis,false);
  EXPECT_THROW(store.read(f.operation,SwapFundingStore::Prepared),std::runtime_error);
}

TEST(SwapFundingStore, TamperedOrTruncatedRecordIsNeverAbsent) {
  for(unsigned mode=0;mode<3;++mode) {
    StoreFixture f;f.create();
    if(mode==0){std::fstream file(f.file().string(),std::ios::binary|std::ios::in|std::ios::out);
      file.seekg(-1,std::ios::end);const auto previous=file.get();file.seekp(-1,std::ios::end);file.put(char(previous^1));}
    if(mode==1)boost::filesystem::resize_file(f.file(),7);
    if(mode==2)boost::filesystem::resize_file(f.file(),SwapFundingStore::MAX_RECORD_BYTES+1024);
    SwapFundingStore store(f.path(),f.key,f.wallet,f.genesis,false);
    EXPECT_THROW(store.read(f.operation,SwapFundingStore::Draft),std::runtime_error)<<mode;
  }
}

TEST(SwapFundingStore, MissingIdentityWithOperationFailsClosed) {
  StoreFixture f;f.create();boost::filesystem::remove(f.root/"records"/"identity");
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,f.genesis,true),std::runtime_error);
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,f.genesis,false),std::runtime_error);
}

TEST(SwapFundingStore, OperationAndRecordBoundsDoNotPruneExistingDrafts) {
  StoreFixture f;SwapFundingStore store(f.path(),f.key,f.wallet,f.genesis,true);
  EXPECT_THROW(store.publish(f.operation,SwapFundingStore::Prepared,f.payload),std::runtime_error);
  EXPECT_THROW(store.publish(Crypto::Hash{},SwapFundingStore::Draft,f.payload),std::runtime_error);
  EXPECT_THROW(store.publish(f.operation,SwapFundingStore::Draft,BinaryArray(SwapFundingStore::MAX_RECORD_BYTES+1)),std::runtime_error);
  for(size_t i=1;i<=SwapFundingStore::MAX_OPERATIONS;++i){Crypto::Hash id{};id.data[0]=uint8_t(i);store.publish(id,SwapFundingStore::Draft,f.payload);}
  Crypto::Hash extra{};extra.data[1]=1;
  EXPECT_THROW(store.publish(extra,SwapFundingStore::Draft,f.payload),std::runtime_error);
  EXPECT_EQ(*store.read(f.operation,SwapFundingStore::Draft),f.payload);
  EXPECT_NO_THROW(store.publish(f.operation,SwapFundingStore::Prepared,f.payload));
}

TEST(SwapFundingStore, HardlinkedRecordIsRejected) {
  StoreFixture f;f.create();boost::filesystem::create_hard_link(f.file(),f.root/"alias");
  SwapFundingStore store(f.path(),f.key,f.wallet,f.genesis,false);
  EXPECT_THROW(store.read(f.operation,SwapFundingStore::Draft),std::runtime_error);
}

#ifdef _WIN32
TEST(SwapFundingStore, OperationNamesBeyondWin32MaxPathPublishAndReopenExactly) {
  StoreFixture f;
  const auto directory=(f.root/std::string(190-f.root.wstring().size(),'a')).string();
  ASSERT_GT(directory.size()+1+64+9,260u);
  {SwapFundingStore store(directory,f.key,f.wallet,f.genesis,true);
    EXPECT_FALSE(store.read(f.operation,SwapFundingStore::Draft));
    store.publish(f.operation,SwapFundingStore::Draft,f.payload);
    store.publish(f.operation,SwapFundingStore::Prepared,f.payload);}
  SwapFundingStore reopened(directory,f.key,f.wallet,f.genesis,false);
  EXPECT_EQ(*reopened.read(f.operation,SwapFundingStore::Draft),f.payload);
  EXPECT_EQ(*reopened.read(f.operation,SwapFundingStore::Prepared),f.payload);
}

TEST(SwapFundingStore, ExistingNonPrivateDirectoryIsRejectedWithoutRepair) {
  StoreFixture f;f.create();auto path=(f.root/"records").wstring();
  ASSERT_EQ(SetNamedSecurityInfoW(&path[0],SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
      nullptr,nullptr,nullptr,nullptr),DWORD(ERROR_SUCCESS));
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,f.genesis,true),std::runtime_error);
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,f.genesis,false),std::runtime_error);
}
#else
TEST(SwapFundingStore, NonPrivateDirectoryAndSymlinkAreRejected) {
  StoreFixture f;f.create();ASSERT_EQ(::chmod(f.path().c_str(),0755),0);
  EXPECT_THROW(SwapFundingStore(f.path(),f.key,f.wallet,f.genesis,false),std::runtime_error);
  ASSERT_EQ(::chmod(f.path().c_str(),0700),0);
  boost::filesystem::create_directory_symlink(f.path(),f.root/"link");
  EXPECT_THROW(SwapFundingStore((f.root/"link").string(),f.key,f.wallet,f.genesis,false),std::runtime_error);
}

TEST(SwapFundingStore, PublishedRecordSurvivesAbruptProcessExit) {
  StoreFixture f;const pid_t child=::fork();ASSERT_GE(child,0);
  if(child==0){SwapFundingStore store(f.path(),f.key,f.wallet,f.genesis,true);store.publish(f.operation,SwapFundingStore::Draft,f.payload);::_exit(0);}
  int status=0;ASSERT_EQ(::waitpid(child,&status,0),child);ASSERT_TRUE(WIFEXITED(status));ASSERT_EQ(WEXITSTATUS(status),0);
  SwapFundingStore reopened(f.path(),f.key,f.wallet,f.genesis,false);
  EXPECT_EQ(*reopened.read(f.operation,SwapFundingStore::Draft),f.payload);
}
#endif
