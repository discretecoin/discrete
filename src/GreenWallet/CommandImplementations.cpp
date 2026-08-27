// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019, The Karbo Developers
//
// Please see the included LICENSE file for more information.

/////////////////////////////////////////////
#include <GreenWallet/CommandImplementations.h>
/////////////////////////////////////////////

#include <atomic>
#include <initializer_list>
#include "Common/Base58.h"
#include "Common/StringTools.h"
#include "Common/FormatTools.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqSender.h"
#include "Wallet/PqRecipient.h"
#include "CryptoNoteCore/PqValidation.h"
#include <GreenWallet/Transfer.h>

#ifndef MSVC
#include <fstream>
#endif

#include "Mnemonics/electrum-words.h"

#include <future>

#include <GreenWallet/AddressBook.h>
#include <Common/ColouredMsg.h>
#include <GreenWallet/Commands.h>
#include <GreenWallet/Menu.h>
#include <GreenWallet/Open.h>
#include <GreenWallet/Sync.h>
#include <GreenWallet/Tools.h>
#include <GreenWallet/Transfer.h>
#include <GreenWallet/Types.h>
#include <GreenWallet/WalletConfig.h>

void changePassword(std::shared_ptr<WalletInfo> walletInfo)
{
    /* Check the user knows the current password */
    confirmPassword(walletInfo->walletPass, "Confirm your current password: ");

    /* Get a new password for the wallet */
    const std::string newPassword
        = getWalletPassword(true, "Enter your new password: ");

    /* Change the wallet password */
    walletInfo->wallet.changePassword(walletInfo->walletPass, newPassword);

    /* Change the stored wallet metadata */
    walletInfo->walletPass = newPassword;

    /* Make sure we save with the new password */
    walletInfo->wallet.save();

    std::cout << SuccessMsg("Your password has been changed!") << std::endl;
}

void exportKeys(std::shared_ptr<WalletInfo> walletInfo)
{
    confirmPassword(walletInfo->walletPass);
    printPrivateKeys(walletInfo->wallet, walletInfo->viewWallet);
}

std::string getGUIPrivateKey(CryptoNote::WalletGreen &wallet)
{
    auto viewKey = wallet.getViewKey();
    auto spendKey = wallet.getAddressSpendKey(0);

    CryptoNote::AccountPublicAddress addr
    {
        spendKey.publicKey,
        viewKey.publicKey,
    };

    CryptoNote::AccountKeys keys
    {
        addr,
        spendKey.secretKey,
        viewKey.secretKey,
    };

    return Tools::Base58::encode_addr
    (
        CryptoNote::parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
        std::string(reinterpret_cast<char*>(&keys), sizeof(keys))
    );
}

void printPrivateKeys(CryptoNote::WalletGreen &wallet, bool viewWallet)
{
    auto privateViewKey = wallet.getViewKey().secretKey;
    CryptoNote::PqTrackingKeys pqTrackingKeys;

    if (viewWallet)
    {
        if (wallet.getPqTrackingKeys(pqTrackingKeys))
        {
            std::cout << SuccessMsg("Tracking key:")
                      << std::endl
                      << SuccessMsg(CryptoNote::encodePqTrackingKey(pqTrackingKeys))
                      << std::endl;
        }
        else
        {
            std::cout << WarningMsg("Tracking key is unavailable for this wallet.")
                      << std::endl;
        }
        return;
    }

    auto privateSpendKey = wallet.getAddressSpendKey(0).secretKey;

    Crypto::SecretKey derivedPrivateViewKey;

    CryptoNote::AccountBase::generateViewFromSpend(privateSpendKey,
                                                   derivedPrivateViewKey);

    const bool deterministicPrivateKeys
             = derivedPrivateViewKey == privateViewKey;

    std::cout << SuccessMsg("Private spend key:")
              << std::endl
              << SuccessMsg(Common::podToHex(privateSpendKey))
              << std::endl
              << std::endl
              << SuccessMsg("Private view key:")
              << std::endl
              << SuccessMsg(Common::podToHex(privateViewKey))
              << std::endl;

    if (deterministicPrivateKeys)
    {
        std::string mnemonicSeed;

        Crypto::ElectrumWords::bytes_to_words(privateSpendKey,
                                              mnemonicSeed,
                                              "English");

        std::cout << std::endl
                  << SuccessMsg("Mnemonic seed:")
                  << std::endl
                  << SuccessMsg(mnemonicSeed)
                  << std::endl;
    }

    std::cout << std::endl
              << SuccessMsg("GUI Importable Private Key:")
              << std::endl
              << SuccessMsg(getGUIPrivateKey(wallet))
              << std::endl;

    if (wallet.getPqTrackingKeys(pqTrackingKeys))
    {
        std::cout << std::endl
                  << SuccessMsg("Tracking key:")
                  << std::endl
                  << SuccessMsg(CryptoNote::encodePqTrackingKey(pqTrackingKeys))
                  << std::endl;
    }
}

void balance(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet,
             bool viewWallet)
{
    const uint64_t totalBalance = wallet.pqActualBalance();
    const uint64_t availableBalance = wallet.pqSpendableBalance();
    const uint64_t lockedBalance = totalBalance >= availableBalance
        ? totalBalance - availableBalance
        : 0;

    const uint32_t localHeight = node.getLastLocalBlockHeight();
    const uint32_t remoteHeight = node.getLastKnownBlockHeight();
    const uint32_t walletHeight = wallet.getBlockCount();

    std::cout << "Available balance: "
              << SuccessMsg(formatAmount(availableBalance)) << std::endl
              << "Locked (immature/unconfirmed) balance: "
              << WarningMsg(formatAmount(lockedBalance))
              << std::endl << "Total balance: "
              << InformationMsg(formatAmount(totalBalance)) << std::endl;

    if (viewWallet)
    {
        std::cout << std::endl
                  << InformationMsg("Please note that tracking wallets "
                                    "can audit transactions,")
                  << std::endl
                  << InformationMsg("but cannot create or sign spends.") << std::endl;
    }

    if (localHeight < remoteHeight)
    {
        std::cout << std::endl
                  << InformationMsg("Your daemon is not fully synced with "
                                    "the network!")
                  << std::endl
                  << "Your balance may be incorrect until you are fully "
                  << "synced!" << std::endl;
    }
    /* Small buffer because wallet height doesn't update instantly like node
       height does */
    else if (walletHeight + 1000 < remoteHeight)
    {
        std::cout << std::endl
                  << InformationMsg("The blockchain is still being scanned for "
                                    "your transactions.")
                  << std::endl
                  << "Balances might be incorrect whilst this is ongoing."
                  << std::endl;
    }
}

void blockchainHeight(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet)
{
    const uint32_t localHeight = node.getLastLocalBlockHeight();
    const uint32_t remoteHeight = node.getLastKnownBlockHeight();
    const uint32_t walletHeight = wallet.getBlockCount() - 1;

    /* This is the height that the wallet has been scanned to. The blockchain
       can be fully updated, but we have to walk the chain to find our
       transactions, and this number indicates that progress. */
    std::cout << "Wallet blockchain height: ";

    /* Small buffer because wallet height doesn't update instantly like node
       height does */
    if (walletHeight + 1000 > remoteHeight)
    {
        std::cout << SuccessMsg(std::to_string(walletHeight));
    }
    else
    {
        std::cout << WarningMsg(std::to_string(walletHeight));
    }

    std::cout << std::endl << "Local blockchain height: ";

    if (localHeight == remoteHeight)
    {
        std::cout << SuccessMsg(std::to_string(localHeight));
    }
    else
    {
        std::cout << WarningMsg(std::to_string(localHeight));
    }

    std::cout << std::endl << "Network blockchain height: "
              << SuccessMsg(std::to_string(remoteHeight)) << std::endl;

    if (localHeight == 0 && remoteHeight == 0)
    {
        std::cout << WarningMsg("Uh oh, it looks like you don't have ")
                  << WarningMsg(WalletConfig::daemonName)
                  << WarningMsg(" open!")
                  << std::endl;
    }
    else if (walletHeight + 1000 < remoteHeight && localHeight == remoteHeight)
    {
        std::cout << InformationMsg("You are synced with the network, but the "
                                    "blockchain is still being scanned for "
                                    "your transactions.")
                  << std::endl
                  << "Balances might be incorrect whilst this is ongoing."
                  << std::endl;
    }
    else if (localHeight == remoteHeight)
    {
        std::cout << SuccessMsg("Yay! You are synced!") << std::endl;
    }
    else
    {
        std::cout << WarningMsg("Be patient, you are still syncing with the "
                                "network!") << std::endl;
    }
}

void printHeights(uint32_t localHeight, uint32_t remoteHeight,
    uint32_t walletHeight)
{
    /* This is the height that the wallet has been scanned to. The blockchain
       can be fully updated, but we have to walk the chain to find our
       transactions, and this number indicates that progress. */
    std::cout << "Wallet blockchain height: ";

    /* Small buffer because wallet height doesn't update instantly like node
       height does */
    if (walletHeight + 1000 > remoteHeight)
    {
        std::cout << SuccessMsg(std::to_string(walletHeight));
    }
    else
    {
        std::cout << WarningMsg(std::to_string(walletHeight));
    }

    std::cout << std::endl << "Local blockchain height: ";

    if (localHeight == remoteHeight)
    {
        std::cout << SuccessMsg(std::to_string(localHeight));
    }
    else
    {
        std::cout << WarningMsg(std::to_string(localHeight));
    }

    std::cout << std::endl << "Network blockchain height: "
        << SuccessMsg(std::to_string(remoteHeight)) << std::endl;
}

void printSyncStatus(uint32_t localHeight, uint32_t remoteHeight,
    uint32_t walletHeight)
{
    std::string networkSyncPercentage
        = Common::Format::get_sync_percentage(localHeight, remoteHeight) + "%";

    std::string walletSyncPercentage
        = Common::Format::get_sync_percentage(walletHeight, remoteHeight) + "%";

    std::cout << "Network sync status: ";

    if (localHeight == remoteHeight)
    {
        std::cout << SuccessMsg(networkSyncPercentage) << std::endl;
    }
    else
    {
        std::cout << WarningMsg(networkSyncPercentage) << std::endl;
    }

    std::cout << "Wallet sync status: ";

    /* Small buffer because wallet height is not always completely accurate */
    if (walletHeight + 1000 > remoteHeight)
    {
        std::cout << SuccessMsg(walletSyncPercentage) << std::endl;
    }
    else
    {
        std::cout << WarningMsg(walletSyncPercentage) << std::endl;
    }
}

void printSyncSummary(uint32_t localHeight, uint32_t remoteHeight,
    uint32_t walletHeight)
{
    if (localHeight == 0 && remoteHeight == 0)
    {
        std::cout << WarningMsg("Uh oh, it looks like you don't have ")
            << WarningMsg(WalletConfig::daemonName)
            << WarningMsg(" open!")
            << std::endl;
    }
    else if (walletHeight + 1000 < remoteHeight && localHeight == remoteHeight)
    {
        std::cout << InformationMsg("You are synced with the network, but the "
            "blockchain is still being scanned for "
            "your transactions.")
            << std::endl
            << "Balances might be incorrect whilst this is ongoing."
            << std::endl;
    }
    else if (localHeight == remoteHeight)
    {
        std::cout << SuccessMsg("Yay! You are synced!") << std::endl;
    }
    else
    {
        std::cout << WarningMsg("Be patient, you are still syncing with the "
            "network!") << std::endl;
    }
}

void printPeerCount(size_t peerCount)
{
    std::cout << "Peers: " << SuccessMsg(std::to_string(peerCount))
              << std::endl;
}

void printHashrate(uint64_t difficulty)
{
    /* Offline node / not responding */
    if (difficulty == 0)
    {
        return;
    }

    /* Hashrate is difficulty divided by block target time */
    uint32_t hashrate = static_cast<uint32_t>(
        round(difficulty / CryptoNote::parameters::DIFFICULTY_TARGET)
    );

    std::cout << "Network hashrate: "
              << SuccessMsg(Common::Format::get_mining_speed(hashrate))
              << " (Based on the last local block)" << std::endl;
}

/* This makes sure to call functions on the node which only return cached
   data. This ensures it returns promptly, and doesn't hang waiting for a
   response when the node is having issues. */
void status(CryptoNote::INode &node, CryptoNote::WalletGreen &wallet)
{
    uint32_t localHeight = node.getLastLocalBlockHeight();
    uint32_t remoteHeight = node.getLastKnownBlockHeight();
    uint32_t walletHeight = wallet.getBlockCount() - 1;

    /* Print the heights of local, remote, and wallet */
    printHeights(localHeight, remoteHeight, walletHeight);

    std::cout << std::endl;

    /* Print the network and wallet sync status in percentage */
    printSyncStatus(localHeight, remoteHeight, walletHeight);

    std::cout << std::endl;

    /* Print the network hashrate, based on the last local block */
    printHashrate(node.getLastLocalBlockHeaderInfo().difficulty);

    /* Print the amount of peers we have */
    printPeerCount(node.getPeerCount());

    std::cout << std::endl;

    /* Print a summary of the sync status */
    printSyncSummary(localHeight, remoteHeight, walletHeight);
}

void reset(CryptoNote::INode &node, std::shared_ptr<WalletInfo> walletInfo)
{
    uint64_t scanHeight = getScanHeight();

    std::cout << std::endl
        << InformationMsg("This process may take some time to complete.")
        << std::endl
        << InformationMsg("You can't make any transactions during the ")
        << InformationMsg("process.")
        << std::endl << std::endl;

    if (!confirm("Are you sure?"))
    {
        return;
    }

    std::cout << InformationMsg("Resetting wallet...") << std::endl;

    walletInfo->wallet.reset(scanHeight);

    syncWallet(node, walletInfo);
}

void saveCSV(CryptoNote::WalletGreen &wallet, CryptoNote::INode &node)
{
    const size_t numTransactions = wallet.getTransactionCount();

    std::ofstream csv;
    csv.open(WalletConfig::csvFilename);

    if (!csv)
    {
        std::cout << WarningMsg("Couldn't open transactions.csv file for "
                                "saving!")
                  << std::endl
                  << WarningMsg("Ensure it is not open in any other "
                                "application.")
                  << std::endl;
        return;
    }

    std::cout << InformationMsg("Saving CSV file...") << std::endl;

    /* Create CSV header */
    csv << "Timestamp,Block Height,Hash,Amount,In/Out"
        << std::endl;

    /* Loop through transactions */
    for (size_t i = 0; i < numTransactions; i++)
    {
        const CryptoNote::WalletTransaction t = wallet.getTransaction(i);

        /* Ignore zero-amount transactions */
        if (t.totalAmount == 0)
        {
            continue;
        }

        const std::string amount = formatAmountBasic(std::abs(t.totalAmount));

        const std::string direction = t.totalAmount > 0 ? "IN" : "OUT";

        csv << unixTimeToDate(t.timestamp) << ","       /* Timestamp */
            << t.blockHeight << ","                     /* Block Height */
            << Common::podToHex(t.hash) << ","          /* Hash */
            << amount << ","                            /* Amount */
            << direction                                /* In/Out */
            << std::endl;
    }

    csv.close();

    std::cout << SuccessMsg("CSV successfully written to ")
              << SuccessMsg(WalletConfig::csvFilename)
              << SuccessMsg("!")
              << std::endl;
}

void printOutgoingTransfer(CryptoNote::WalletTransaction t,
                           CryptoNote::INode &node)
{
    std::cout << WarningMsg("Outgoing transfer:")
              << std::endl
              << WarningMsg("Hash: " + Common::podToHex(t.hash))
              << std::endl;

    /* Block height will be garbage from memory if not confirmed yet */
    if (t.timestamp != 0)
    {
        std::cout << WarningMsg("Block height: ")
                  << WarningMsg(std::to_string(t.blockHeight))
                  << std::endl
                  << WarningMsg("Timestamp: ")
                  << WarningMsg(unixTimeToDate(t.timestamp))
                  << std::endl;
    }

    std::cout << WarningMsg("Spent: " + formatAmount(-t.totalAmount - t.fee))
              << std::endl
              << WarningMsg("Fee: " + formatAmount(t.fee))
              << std::endl
              << WarningMsg("Total Spent: " + formatAmount(-t.totalAmount))
              << std::endl;

    const std::string paymentID = getPaymentIDFromExtra(t.extra);

    if (paymentID != "")
    {
        std::cout << WarningMsg("Payment ID: " + paymentID) << std::endl;
    }

    std::cout << std::endl;
}

void printIncomingTransfer(CryptoNote::WalletTransaction t,
                           CryptoNote::INode &node)
{
    std::cout << SuccessMsg("Incoming transfer:")
              << std::endl
              << SuccessMsg("Block height: " + std::to_string(t.blockHeight))
              << std::endl;

    /* Block height will be garbage from memory if not confirmed yet */
    if (t.timestamp != 0)
    {
        std::cout << SuccessMsg("Block height: ")
                  << SuccessMsg(std::to_string(t.blockHeight))
                  << std::endl
                  << SuccessMsg("Timestamp: ")
                  << SuccessMsg(unixTimeToDate(t.timestamp))
                  << std::endl;
    }

    std::cout << SuccessMsg("Hash: " + Common::podToHex(t.hash))
              << std::endl
              << SuccessMsg("Amount: " + formatAmount(t.totalAmount))
              << std::endl;

    const std::string paymentID = getPaymentIDFromExtra(t.extra);

    if (paymentID != "")
    {
        std::cout << SuccessMsg("Payment ID: " + paymentID) << std::endl;
    }

    std::cout << std::endl;
}

void listTransfers(bool incoming, bool outgoing,
                   CryptoNote::WalletGreen &wallet, CryptoNote::INode &node)
{
    const size_t numTransactions = wallet.getTransactionCount();

    int64_t totalSpent = 0;
    int64_t totalReceived = 0;

    for (size_t i = 0; i < numTransactions; i++)
    {
        const CryptoNote::WalletTransaction t = wallet.getTransaction(i);

        if (t.totalAmount < 0 && outgoing)
        {
            printOutgoingTransfer(t, node);
            totalSpent += -t.totalAmount;
        }
        else if (t.totalAmount > 0 && incoming)
        {
            printIncomingTransfer(t, node);
            totalReceived += t.totalAmount;
        }
    }

    if (incoming)
    {
        std::cout << SuccessMsg("Total received: "
                              + formatAmount(totalReceived))
                  << std::endl;
    }

    if (outgoing)
    {
        std::cout << WarningMsg("Total spent: " + formatAmount(totalSpent))
                  << std::endl;
    }
}

void save(CryptoNote::WalletGreen &wallet)
{
    std::cout << InformationMsg("Saving.") << std::endl;
    wallet.save();
    std::cout << InformationMsg("Saved.") << std::endl;
}

void help(std::shared_ptr<WalletInfo> wallet)
{
    if (wallet->viewWallet)
    {
        printCommands(basicViewWalletCommands());
    }
    else
    {
        printCommands(basicCommands());
    }
}

void advanced(std::shared_ptr<WalletInfo> wallet)
{
    /* We pass the offset of the command to know what index to print for
       command numbers */
    if (wallet->viewWallet)
    {
        printCommands(advancedViewWalletCommands(),
                      (int)basicViewWalletCommands().size());
    }
    else
    {
        printCommands(advancedCommands(),
                      (int)basicCommands().size());
    }
}

void signMessage(std::shared_ptr<WalletInfo> walletInfo, bool viewWallet)
{
    if (viewWallet)
    {
        std::cout << WarningMsg("This is tracking wallet. ")
                  << WarningMsg("The message can be signed ")
                  << WarningMsg("only by a full wallet.")
                  << std::endl;
        return;
    }

    std::string message;

    while (true)
    {
        std::cout << InformationMsg("Enter message to sign: ");

        std::getline(std::cin, message);
        boost::algorithm::trim(message);

        if (!message.empty())
        {
          break;
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
            break;
        }
    }

    try
    {
        // Discrete signs with the wallet's post-quantum (ML-DSA) spend key — the
        // same identity its PQ address publishes — not the classical ECC key.
        Crypto::SecretKey spendSecret = walletInfo->wallet.getAddressSpendKey(0).secretKey;
        CryptoNote::PqWalletKeys pq = CryptoNote::derivePqWalletKeys(spendSecret);
        std::string signature = CryptoNote::signMessagePq(message, pq.spendSk);

        std::cout << SuccessMsg("Signature: ")
                  << InformationMsg(signature)
                  << std::endl;
    }
    catch (const std::exception &e) {
        std::cout << WarningMsg("Failed to sign message: ")
                  << WarningMsg(e.what())
                  << std::endl;
    }
}

void verifyMessage(CryptoNote::WalletGreen &wallet)
{
    (void)wallet;  // verification needs only the public PQ address, not the wallet
    std::string addrStr;
    CryptoNote::PqAddress pqAddr{};

    while (true)
    {
        std::cout << InformationMsg("Enter address: ");

        std::getline(std::cin, addrStr);
        boost::algorithm::trim(addrStr);

        // Discrete verifies against the PQ address's ML-DSA spend key.
        if (!CryptoNote::parsePqAddress(addrStr, pqAddr))
        {
            std::cout << WarningMsg("Failed to parse address") << std::endl;
        }
        else
        {
            break;
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
            break;
        }
    }

    std::string message;

    while (true)
    {
        std::cout << InformationMsg("Enter message: ");

        std::getline(std::cin, message);
        boost::algorithm::trim(message);

        if (!message.empty())
        {
            break;
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
            break;
        }
    }

    std::string signature;

    while (true)
    {
        std::cout << InformationMsg("Enter signature: ");

        std::getline(std::cin, signature);
        boost::algorithm::trim(signature);

        if (!signature.empty())
        {
            break;
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
            break;
        }
    }

    try
    {
        bool r = CryptoNote::verifyMessagePq(message, pqAddr.spendPub, signature);

        if (r)
        {
            std::cout << SuccessMsg("Signature is valid")
                      << std::endl;
        }
        else
        {
            std::cout << WarningMsg("Signature is invalid")
                      << std::endl;
        }
    }
    catch (const std::exception &e) {
        std::cout << WarningMsg("Failed to verify message: ")
                  << WarningMsg(e.what())
                  << std::endl;
    }
}

void pqAddress(std::shared_ptr<WalletInfo> walletInfo)
{
    std::string b58 = walletInfo->wallet.getPqAddress();
    if (b58.empty())
    {
        std::cout << WarningMsg("Address is unavailable for this wallet.")
                  << std::endl;
        return;
    }

    std::cout << InformationMsg("Your address (" + std::to_string(b58.size())
                                + " chars):")
              << std::endl
              << SuccessMsg(b58) << std::endl
              << InformationMsg("Anyone can pay this; a tracking wallet can audit it but cannot spend.")
              << std::endl;
}

void pqBalance(std::shared_ptr<WalletInfo> walletInfo)
{
    if (!walletInfo->wallet.pqEnabled())
    {
        std::cout << WarningMsg("Balance is unavailable for this wallet.")
                  << std::endl;
        return;
    }

    // "Available" must be what can actually be spent now (confirmed AND unlocked), not
    // the raw total: after a reorg an orphaned receive returns to the mempool and would
    // otherwise be advertised as available yet rejected at spend time. Show the locked
    // remainder (immature coinbase + pending) separately, like simplewallet.
    const uint64_t total = walletInfo->wallet.pqActualBalance();
    const uint64_t available = walletInfo->wallet.pqSpendableBalance();

    std::cout << "Available balance: "
              << SuccessMsg(formatAmount(available)) << std::endl;
    if (total > available)
    {
        std::cout << "Locked (immature/unconfirmed): "
                  << WarningMsg(formatAmount(total - available)) << std::endl;
    }
    std::cout << "Scanned to height: "
              << InformationMsg(std::to_string(walletInfo->wallet.pqSyncedHeight())) << std::endl
              << std::endl;
}

// Resolve a recipient string (a raw PQ address OR an H-I-A-C account number) to
// its view + spend public keys, querying the node for an account number.
static bool resolvePqRecipientGreen(CryptoNote::INode &node, bool testnet, const std::string &s,
                                    CryptoPQ::KemPublicKey &viewPub, CryptoPQ::DsaPublicKey &spendPub,
                                    uint64_t &subaddrIndexT, std::string &error)
{
    // Delegate to the shared resolver so every front-end parses addresses identically.
    return CryptoNote::resolvePqRecipient(node, testnet, s, viewPub, spendPub, subaddrIndexT, &error);
}

void pqTransfer(std::shared_ptr<WalletInfo> walletInfo, CryptoNote::INode &node)
{
    CryptoNote::WalletGreen &wallet = walletInfo->wallet;
    if (walletInfo->viewWallet || !wallet.pqEnabled())
    {
        std::cout << WarningMsg("Spending is unavailable for this wallet.") << std::endl;
        return;
    }

    std::cout << InformationMsg("Recipient (address or account number): ");
    std::string addrStr;
    std::getline(std::cin, addrStr);
    CryptoPQ::KemPublicKey destView;
    CryptoPQ::DsaPublicKey destSpend;
    uint64_t destSubaddrT = 0;  // non-zero only for an H-I-A-T-C deposit subaddress
    std::string resolveError;
    if (!resolvePqRecipientGreen(node, wallet.isTestnet(), addrStr, destView, destSpend,
                                 destSubaddrT, resolveError))
    {
        std::cout << WarningMsg(resolveError.empty()
                                    ? std::string("Not a valid address or account number.")
                                    : resolveError)
                  << std::endl;
        return;
    }

    std::cout << InformationMsg("Amount: ");
    std::string amountStr;
    std::getline(std::cin, amountStr);
    uint64_t amount = 0;
    if (!parseAmount(amountStr, amount) || amount == 0)
    {
        std::cout << WarningMsg("Invalid amount.") << std::endl;
        return;
    }

    // The deterministic build + relay live in the common sender, shared with
    // simplewallet and walletd.
    try
    {
        CryptoNote::PqSendOutput out{destView, destSpend, amount, destSubaddrT};
        CryptoNote::PqSendResult r = wallet.sendPqTransfer({out});
        std::cout << InformationMsg("Sent " + formatAmount(r.sent) + " (fee "
                                    + formatAmount(r.fee) + ")...")
                  << std::endl;
        std::cout << SuccessMsg("Transaction hash: "
                                + Common::podToHex(CryptoNote::getObjectHash(r.tx)))
                  << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << WarningMsg(std::string("Failed to send transaction: ") + e.what())
                  << std::endl;
    }
}

void pqRegister(std::shared_ptr<WalletInfo> walletInfo, CryptoNote::INode &node)
{
    CryptoNote::WalletGreen &wallet = walletInfo->wallet;
    if (walletInfo->viewWallet)
    {
        std::cout << WarningMsg("Tracking wallets cannot register account numbers.") << std::endl;
        return;
    }

    Crypto::SecretKey spendSecret = wallet.getAddressSpendKey(0).secretKey;
    CryptoNote::PqWalletKeys pq = CryptoNote::derivePqWalletKeys(spendSecret);

    Crypto::Hash refBlockHash = node.getLastLocalBlockHeaderInfo().hash;
    if (refBlockHash == boost::value_initialized<Crypto::Hash>())
    {
        std::cout << WarningMsg("Node has no known block yet; try again once synced.") << std::endl;
        return;
    }

    std::cout << InformationMsg("Assigning your account number (solving anti-spam PoW)...")
              << std::endl;
    uint64_t nonce = 0;
    while (!CryptoNote::checkFreeRegPow(pq.viewPub, pq.spendPub, refBlockHash, nonce))
    {
        ++nonce;
    }

    try
    {
        CryptoNote::Transaction tx =
            CryptoNote::buildFreeRegTransaction(pq.viewPub, pq.spendPub, refBlockHash, nonce);

        std::promise<std::error_code> promise;
        auto future = promise.get_future();
        node.relayTransaction(tx, [&promise](std::error_code ec) { promise.set_value(ec); });
        std::error_code ec = future.get();
        if (ec)
        {
            std::cout << WarningMsg("Failed to relay registration: " + ec.message()) << std::endl;
            return;
        }
        std::cout << SuccessMsg("Registration submitted. Tx hash: "
                                + Common::podToHex(CryptoNote::getObjectHash(tx)))
                  << std::endl
                  << InformationMsg("Once confirmed, run 'account' to see your account number.")
                  << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << WarningMsg(std::string("Failed to build registration: ") + e.what())
                  << std::endl;
    }
}

void pqRegisterPaid(std::shared_ptr<WalletInfo> walletInfo, CryptoNote::INode &node)
{
    CryptoNote::WalletGreen &wallet = walletInfo->wallet;
    if (walletInfo->viewWallet)
    {
        std::cout << WarningMsg("Tracking wallets cannot register account numbers.") << std::endl;
        return;
    }

    Crypto::SecretKey spendSecret = wallet.getAddressSpendKey(0).secretKey;
    CryptoNote::PqWalletKeys pq = CryptoNote::derivePqWalletKeys(spendSecret);
    std::string viewHex = Common::toHex(pq.viewPub.data(), pq.viewPub.size());
    std::string spendHex = Common::toHex(pq.spendPub.data(), pq.spendPub.size());

    bool registered = false;
    uint32_t blockHeight = 0, txIndex = 0;
    {
        std::promise<std::error_code> promise;
        auto future = promise.get_future();
        node.getPqAccount(viewHex, spendHex, registered, blockHeight, txIndex,
                          [&promise](std::error_code ec) { promise.set_value(ec); });
        std::error_code ec = future.get();
        if (ec)
        {
            std::cout << WarningMsg("Failed to check existing account: " + ec.message())
                      << std::endl;
            return;
        }
    }
    if (registered)
    {
        // Naming the number is publication: confirm the coordinates through the
        // trusted-daemon gate before printing them. Refusing to register again
        // does not depend on that.
        uint32_t confirmedH = 0, confirmedI = 0;
        const CryptoNote::PqAccountPublication status =
            CryptoNote::lookupOwnPqAccount(node, viewHex, spendHex, confirmedH, confirmedI);
        if (status == CryptoNote::PqAccountPublication::Ok)
        {
            CryptoNote::AccountNumber acct{confirmedH, confirmedI};
            std::cout << WarningMsg("This identity already has account number: ")
                      << SuccessMsg(acct.toString(wallet.pqAccountFingerprint())) << std::endl;
        }
        else
        {
            std::cout << WarningMsg("This identity is already registered. ")
                      << InformationMsg(CryptoNote::pqAccountPublicationMessage(status))
                      << std::endl;
        }
        return;
    }

    std::cout << InformationMsg("Register an account number with a normal fee-paying transaction?")
              << std::endl;
    std::cout << "Proceed? (Y/n): ";

    std::string confirm;
    std::getline(std::cin, confirm);
    if (!confirm.empty() && confirm[0] != 'y' && confirm[0] != 'Y')
    {
        std::cout << WarningMsg("Cancelling registration.") << std::endl;
        return;
    }

    std::vector<uint8_t> extra;
    CryptoNote::addPqAccountRegistrationToExtra(extra, pq.viewPub, pq.spendPub);

    try
    {
        CryptoNote::TransactionParameters params;
        params.destinations.push_back({walletInfo->walletAddress, CryptoNote::parameters::DEFAULT_DUST_THRESHOLD});
        params.fee = node.getMinimalFee();
        params.extra = std::string(extra.begin(), extra.end());
        params.sourceAddresses = {walletInfo->walletAddress};
        params.changeDestination = walletInfo->walletAddress;

        Crypto::SecretKey txSecretKey;
        size_t txId = wallet.transfer(params, txSecretKey);

        auto txHash = wallet.getTransaction(txId).hash;
        std::cout << SuccessMsg("Account registration transaction sent!")
                  << std::endl
                  << SuccessMsg("Transaction hash: ")
                  << Common::podToHex(txHash) << std::endl
                  << InformationMsg("Your account number will be available once the transaction is confirmed.")
                  << std::endl;
    }
    catch (const std::system_error &e)
    {
        std::cout << WarningMsg("Failed to send registration transaction: ")
                  << WarningMsg(e.what()) << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << WarningMsg("Failed to send registration transaction: ")
                  << WarningMsg(e.what()) << std::endl;
    }
}

void pqAccount(std::shared_ptr<WalletInfo> walletInfo, CryptoNote::INode &node)
{
    CryptoNote::WalletGreen &wallet = walletInfo->wallet;
    if (walletInfo->viewWallet)
    {
        std::cout << WarningMsg("Tracking wallets cannot use account-number registration.") << std::endl;
        return;
    }

    std::string viewHex;
    std::string spendHex;
    if (!wallet.getPqRegistrationKeysHex(viewHex, spendHex))
    {
        std::cout << WarningMsg("Identity is unavailable for this wallet.") << std::endl;
        return;
    }

    uint32_t blockHeight = 0, txIndex = 0;
    const CryptoNote::PqAccountPublication status =
        CryptoNote::lookupOwnPqAccount(node, viewHex, spendHex, blockHeight, txIndex);
    if (status != CryptoNote::PqAccountPublication::Ok)
    {
        std::cout << InformationMsg(CryptoNote::pqAccountPublicationMessage(status)) << std::endl;
        return;
    }
    CryptoNote::AccountNumber acct{blockHeight, txIndex};
    uint32_t fp = wallet.pqAccountFingerprint();
    std::cout << SuccessMsg("Your account number: " + acct.toString(fp)) << std::endl;
    std::cout << InformationMsg(
                     "The '" + CryptoNote::AccountNumber::encodeFingerprint(fp) +
                     "' part is a fingerprint of your keys. It is safe to share and use once it has " +
                     std::to_string(CryptoNote::parameters::CRYPTONOTE_FINALITY_DEPTH) +
                     " confirmations.")
              << std::endl;
}
