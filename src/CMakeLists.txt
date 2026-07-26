
add_definitions(-DSTATICLIB)

include_directories(${CMAKE_SOURCE_DIR}/external/linenoise)
include_directories(${CMAKE_SOURCE_DIR}/external/parallel_hashmap)
include_directories(${LMDB_INCLUDE})

file(GLOB_RECURSE BlockchainExplorer BlockchainExplorer/*)
file(GLOB_RECURSE Checkpoints Checkpoints/*)
file(GLOB_RECURSE CheckpointsDns CheckpointsDns/*)
file(GLOB_RECURSE Common Common/*)
file(GLOB_RECURSE Crypto crypto/*)
file(GLOB_RECURSE CryptoPq crypto_pq/*)
file(GLOB_RECURSE CryptoNoteCore CryptoNoteCore/* CryptoNoteConfig.h)
file(GLOB_RECURSE CryptoNoteProtocol CryptoNoteProtocol/*)
file(GLOB_RECURSE Daemon Daemon/*)
file(GLOB_RECURSE Http HTTP/*)
file(GLOB_RECURSE InProcessNode InProcessNode/*)
file(GLOB_RECURSE Logging Logging/*)
file(GLOB_RECURSE NodeRpcProxy NodeRpcProxy/*)
file(GLOB_RECURSE P2p P2p/*)
file(GLOB_RECURSE Rpc Rpc/*)
file(GLOB_RECURSE Serialization Serialization/*)
file(GLOB_RECURSE SimpleWallet SimpleWallet/*)
file(GLOB_RECURSE Mnemonics Mnemonics/*)
file(GLOB_RECURSE Transfers Transfers/*)
file(GLOB_RECURSE Wallet Wallet/*)
file(GLOB_RECURSE WalletLegacy WalletLegacy/*)
file(GLOB_RECURSE JsonRpcServer JsonRpcServer/*)
file(GLOB_RECURSE PaymentGate PaymentGate/*)
file(GLOB_RECURSE PaymentGateService PaymentGateService/*)
file(GLOB_RECURSE GreenWallet GreenWallet/*)
file(GLOB_RECURSE AdminTools AdminTools/*)

if (MSVC OR MINGW)
  file(GLOB_RECURSE System System/* Platform/Windows/System/*)
elseif (APPLE)
  file(GLOB_RECURSE System System/* Platform/OSX/System/* Platform/Posix/System/*)
elseif (FREEBSD)
  file(GLOB_RECURSE System System/* Platform/FreeBSD/System/* Platform/Posix/System/*)
elseif (ANDROID)
  file(GLOB_RECURSE System System/* Platform/Android/System/* Platform/Posix/System/*)
else()
  file(GLOB_RECURSE System System/* Platform/Linux/System/* Platform/Posix/System/*)
endif()

source_group("" FILES $${Common} ${Checkpoints} ${CheckpointsDns} ${Crypto} ${CryptoNoteCore} ${CryptoNoteProtocol} ${Daemon} ${GreenWallet} ${Http} ${JsonRpcServer} ${Logging} ${Mnemonics} ${NodeRpcProxy} ${P2p} ${Rpc} ${Serialization} ${SimpleWallet} ${System} ${Transfers} ${Wallet} ${WalletLegacy} ${AdminTools})

add_library(BlockchainExplorer ${BlockchainExplorer})
add_library(Checkpoints ${Checkpoints})
add_library(CryptoNoteProtocol ${CryptoNoteProtocol})
# Real target is CryptoNoteCommon; `Common` is kept as an alias so the dozens of
# downstream `target_link_libraries(... Common)` references need no change.
# The distinct project name avoids a case-insensitive clash with liboqs's
# `common` object library in the generated Visual Studio solution (VS treats
# "Common" and "common" as the same item). Aliases don't generate a .vcxproj.
add_library(CryptoNoteCommon ${Common})
add_library(Common ALIAS CryptoNoteCommon)
add_library(Crypto ${Crypto})
add_library(CryptoPq ${CryptoPq})
# Crypto::cn_fast_hash (the chain hash) is SHA3-256 from liboqs, so Crypto links
# oqs and needs liboqs's generated <oqs/*.h> headers (see note below).
target_link_libraries(Crypto PUBLIC oqs)
target_include_directories(Crypto PUBLIC
  $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/external/liboqs/include>)
# CryptoPq depends on shared utilities in Common and chain hash helpers in Crypto.
target_link_libraries(CryptoPq PUBLIC oqs chacha20poly1305 Common Crypto)
# liboqs's generated <oqs/*.h> headers live in PROJECT_BINARY_DIR/include but
# are only exposed via include_directories() in liboqs's own subdir, so they
# don't propagate through the oqs target. Add the path explicitly here.
target_include_directories(CryptoPq PUBLIC
  $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/external/liboqs/include>)
add_library(CryptoNoteCore ${CryptoNoteCore})
# CryptoPq provides PQ derivations (nullifiers) used by consensus state.
target_link_libraries(CryptoNoteCore PUBLIC Checkpoints CryptoPq ${LMDB_LIBRARY})
add_library(Http ${Http})
add_library(InProcessNode ${InProcessNode})
add_library(Logging ${Logging})
add_library(Mnemonics ${Mnemonics})
add_library(NodeRpcProxy ${NodeRpcProxy})
add_library(Rpc ${Rpc})
add_library(P2P ${P2p})
add_library(Serialization ${Serialization})
add_library(System ${System})
# HttpClient drives System's TCP/SSL streams and, through Boost.Asio's SSL
# wrappers, OpenSSL. Declare that on the library itself rather than relying on
# every executable to list System/-lssl/-lcrypto in exactly the right spot: GNU
# ld resolves a static archive only against symbols still undefined when it
# reaches it, so a hand-ordered link line breaks as soon as a new consumer is
# added (which is what adding Http to AdminTools did). Target-level deps let
# CMake order and repeat the archives itself.
target_link_libraries(Http PUBLIC System ${OPENSSL_LIBRARIES})
# DNS checkpoint discovery: the TXT pointer parser, the signed-JSON verifier
# (OpenSSL SHA-256) and the HTTPS downloader (Http + System::Dispatcher +
# OpenSSL's SSL stack). Deliberately NOT part of the Checkpoints library:
# CryptoNoteCore links Checkpoints PUBLIC, so anything added there propagates to
# nearly every target in the project — including all the Pq* unit tests, which
# would then have to link the whole TLS stack. Only the three executables that
# actually resolve DNS link this.
add_library(CheckpointsDns ${CheckpointsDns})
# OpenSSL is listed explicitly as well as via Http: DnsCheckpoint.cpp calls
# EVP_Digest directly for the file SHA-256, independently of the TLS client.
target_link_libraries(CheckpointsDns PUBLIC Checkpoints Http ${OPENSSL_LIBRARIES})
add_library(Transfers ${Transfers})
add_library(Wallet ${Wallet} ${WalletLegacy})
add_library(PaymentGate ${PaymentGate})
add_library(JsonRpcServer ${JsonRpcServer})
# Rpc and Wallet are mutually dependent: the daemon's check_transaction_proof
# reuses the wallet's proof-transaction view (Wallet/PqTransactionBuilder) and
# Wallet's RPC server throws JsonRpc::JsonRpcError. Declaring the cycle makes
# CMake repeat both archives on the link line, which GNU ld needs to resolve
# them (MSVC resolves regardless of order).
target_link_libraries(Rpc Wallet)
target_link_libraries(Wallet Rpc)

if (MSVC)
  add_executable(Daemon ${Daemon} BinaryInfo/daemon.rc)
  add_executable(SimpleWallet ${SimpleWallet} BinaryInfo/simplewallet.rc)
  add_executable(GreenWallet ${GreenWallet} BinaryInfo/greenwallet.rc)
  add_executable(PaymentGateService ${PaymentGateService} BinaryInfo/walletd.rc)
  add_executable(AdminTools ${AdminTools} BinaryInfo/admin-tools.rc)
else()
  add_executable(Daemon ${Daemon})
  add_executable(SimpleWallet ${SimpleWallet})
  add_executable(GreenWallet ${GreenWallet})
  add_executable(PaymentGateService ${PaymentGateService})
  add_executable(AdminTools ${AdminTools})
endif()

if (MINGW)
  target_link_libraries(CryptoNoteCommon dnsapi)
  target_link_libraries(P2P bcrypt)
  target_link_libraries(System ws2_32)
endif()

# Common/DnsTools.cpp calls ns_initparse/ns_parserr, which live in libresolv on
# Linux/macOS. Attach it to the library that needs it so every consumer inherits
# it: a per-executable -lresolv lands before the repeated archives that GNU ld
# emits for cyclic static libs, and the symbols go unresolved again.
if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR APPLE AND NOT ANDROID)
  target_link_libraries(CryptoNoteCommon resolv)
endif()

# Wallet/Transfers/NodeRpcProxy/Mnemonics are linked for the read-only mining-key
# loader (start_mining reads the encrypted wallet container; see MiningKeyLoader).
# CheckpointsDns is the DNS-checkpoint HTTPS fetch (discreted calls fetchDnsCheckpoints
# at startup) — see src/CheckpointsDns/CheckpointsDnsFetch.h for why it is a
# separate library from Checkpoints.
target_link_libraries(Daemon Wallet Transfers NodeRpcProxy Mnemonics Rpc Http P2P CryptoNoteCore Logging Serialization Crypto System Checkpoints CheckpointsDns CryptoNoteProtocol BlockchainExplorer Common upnpc-static ${Boost_LIBRARIES} ${LMDB_LIBRARY})
target_link_libraries(SimpleWallet Wallet Transfers NodeRpcProxy Rpc Http CryptoNoteCore Logging Serialization Crypto System Checkpoints Mnemonics Common ${Boost_LIBRARIES})
target_link_libraries(GreenWallet Wallet Transfers NodeRpcProxy Rpc Http CryptoNoteCore Logging Serialization Crypto System Checkpoints Mnemonics Common ${Boost_LIBRARIES})
target_link_libraries(PaymentGateService PaymentGate JsonRpcServer InProcessNode Wallet Transfers NodeRpcProxy Rpc Http P2P CryptoNoteCore Logging Serialization Crypto System Checkpoints CheckpointsDns
                      CryptoNoteProtocol BlockchainExplorer Common upnpc-static ${Boost_LIBRARIES} ${LMDB_LIBRARY})
# Wallet/Transfers/NodeRpcProxy/Rpc/Http are linked for the DNS checkpoint signer:
# the read-only wallet seed loader (MiningKeyLoader) and the HTTPS checkpoint
# downloader used by --verify-checkpoint (CheckpointsDns).
target_link_libraries(AdminTools Wallet Transfers NodeRpcProxy Rpc Http CryptoNoteCore Checkpoints CheckpointsDns Logging Serialization Crypto Mnemonics Common System ${Boost_LIBRARIES})

if (OPENSSL_FOUND)
    target_link_libraries(Daemon ${OPENSSL_LIBRARIES})
    target_link_libraries(SimpleWallet ${OPENSSL_LIBRARIES})
    target_link_libraries(GreenWallet ${OPENSSL_LIBRARIES})
    target_link_libraries(PaymentGateService ${OPENSSL_LIBRARIES})
    target_link_libraries(AdminTools ${OPENSSL_LIBRARIES})

  # prevent error LNK2019: unresolved external symbol _vsnprintf
  if(MSVC AND NOT (MSVC_VERSION LESS 1900))
    target_link_libraries(Daemon "legacy_stdio_definitions.lib")
    target_link_libraries(SimpleWallet "legacy_stdio_definitions.lib")
    target_link_libraries(GreenWallet "legacy_stdio_definitions.lib")
    target_link_libraries(PaymentGateService "legacy_stdio_definitions.lib")
    target_link_libraries(AdminTools "legacy_stdio_definitions.lib")
  endif()
endif ()

if (MSVC OR MINGW)
  target_link_libraries(System crypt32 ws2_32)
  target_link_libraries(Wallet advapi32)
  target_link_libraries(Daemon Rpcrt4 ws2_32 advapi32 crypt32 gdi32 user32)
  target_link_libraries(SimpleWallet Rpcrt4 ws2_32 advapi32 crypt32 gdi32 user32)
  target_link_libraries(PaymentGateService Rpcrt4 ws2_32 advapi32 crypt32 gdi32 user32)
  target_link_libraries(AdminTools Rpcrt4 ws2_32 advapi32 crypt32 gdi32 user32)
else()
  target_link_libraries(Daemon ${EXTRA_LIBRARIES})
  target_link_libraries(SimpleWallet ${EXTRA_LIBRARIES})
  target_link_libraries(GreenWallet ${EXTRA_LIBRARIES})
  target_link_libraries(PaymentGateService ${EXTRA_LIBRARIES})
  target_link_libraries(AdminTools ${EXTRA_LIBRARIES})
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" OR APPLE AND NOT ANDROID)
  target_link_libraries(SimpleWallet -lresolv)
  target_link_libraries(Daemon -lresolv)
  target_link_libraries(PaymentGateService -lresolv)
  target_link_libraries(AdminTools -lresolv)
  target_link_libraries(GreenWallet -lresolv)
endif()

if (ANDROID)
  target_link_libraries(SimpleWallet dl)
  target_link_libraries(Daemon dl)
  target_link_libraries(PaymentGateService dl)
  target_link_libraries(GreenWallet dl)
endif()

if (FREEBSD)
  target_link_libraries(SimpleWallet -lthr)
  target_link_libraries(Daemon -lthr)
  target_link_libraries(PaymentGateService -lthr)
  target_link_libraries(GreenWallet -lthr)
  target_link_libraries(AdminTools -lthr)
endif()

add_dependencies(P2P version)
add_dependencies(Rpc version)
add_dependencies(PaymentGate version)
add_dependencies(CryptoNoteCore version)
add_dependencies(InProcessNode version)

set_property(TARGET Daemon PROPERTY OUTPUT_NAME "discreted")
set_property(TARGET SimpleWallet PROPERTY OUTPUT_NAME "simplewallet")
set_property(TARGET GreenWallet PROPERTY OUTPUT_NAME "greenwallet")
set_property(TARGET PaymentGateService PROPERTY OUTPUT_NAME "walletd")
set_property(TARGET AdminTools PROPERTY OUTPUT_NAME "admin-tools")

