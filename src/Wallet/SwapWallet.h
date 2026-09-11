#pragma once
#include <functional>
#include "INode.h"
#include "Wallet/PqWallet.h"
#include "Wallet/SwapTransactionBuilder.h"

namespace CryptoNote {
struct SwapWalletFundingRequest {
  Crypto::Hash genesis{};
  SwapOutput contract{};
  uint64_t principal = 0;
  CryptoPQ::Rho refundRho{};
};
struct SwapWalletSpendRequest {
  Crypto::Hash genesis{};
  Crypto::Hash fundingTxid{};
  uint32_t outputIndex = 0;
  uint8_t branch = 1;
  CryptoPQ::Rho rho{};
  std::vector<uint8_t> secret;
};
struct SwapWalletPrepared {
  Transaction tx;
  BinaryArray wire;
  Crypto::Hash txid{};
  uint64_t fee = 0;
  uint64_t principal = 0;
  std::vector<PqSpendInput> selectedInputs;
};
using SwapWalletReadOutpoint = std::function<SwapOutpointInfo(const Crypto::Hash&, uint32_t, const Crypto::Hash&)>;

// Pure preparation over wallet-owned inputs and a validated node snapshot reader.
// No relay, input reservation, secret persistence or journal transition occurs here.
// This helper follows WalletLegacy's fixed SingleKeyIndex scheme: depositIndex
// is routing metadata; primary, T>0 and unattributed inputs share spend authority.
// AggregatedMultikey inputs from other wallet containers are not accepted.
SwapWalletPrepared prepareSwapWalletFunding(const SwapWalletFundingRequest& request,
  const std::vector<PqSpendInput>& available, const PqWalletKeys& keys,
  const Crypto::Hash& genesis, uint32_t scannedHeight, const SwapWalletReadOutpoint& read);
SwapWalletPrepared prepareSwapWalletFundingWithDraftSink(const SwapWalletFundingRequest& request,
  const std::vector<PqSpendInput>& available, const PqWalletKeys& keys,
  const Crypto::Hash& genesis, uint32_t scannedHeight, const SwapWalletReadOutpoint& read,
  const SwapFundingDraftSink& sink);
struct SwapFundingPreparation {
  enum Status { Absent, Draft, Prepared } status = Absent;
  Crypto::Hash operation{}, requestHash{}, draftHash{};
  SwapWalletPrepared prepared;
};
Crypto::Hash swapFundingRequestHash(const Crypto::Hash& operation, const SwapWalletFundingRequest& request);
SwapFundingPreparation lookupSwapWalletFunding(const std::string& path, const Crypto::Hash& operation,
  const PqWalletKeys& keys, const Crypto::Hash& genesis);
SwapFundingPreparation prepareSwapWalletFundingOnce(const std::string& path, const Crypto::Hash& operation,
  const SwapWalletFundingRequest& request, const std::vector<PqSpendInput>& available,
  const PqWalletKeys& keys, const Crypto::Hash& genesis, uint32_t scannedHeight,
  const SwapWalletReadOutpoint& read);
SwapWalletPrepared prepareSwapWalletSpend(const SwapWalletSpendRequest& request,
  const PqWalletKeys& keys, const Crypto::Hash& genesis, const SwapWalletReadOutpoint& read);
}
