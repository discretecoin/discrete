// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019, The Karbo Developers
//
// Please see the included LICENSE file for more information.

///////////////////////////////
#include <GreenWallet/Transfer.h>
///////////////////////////////

#include <boost/algorithm/string.hpp>

#include <chrono>
#include <future>
#include <thread>

#include <Common/StringTools.h>

#include "CryptoNoteConfig.h"

#include <CryptoNoteCore/CryptoNoteBasicImpl.h>
#include <CryptoNoteCore/TransactionExtra.h>

#include "PqAddress.h"
#include "AccountNumber.h"

#include <iostream>

#include "IWallet.h"

#define _GLIBCXX_USE_NANOSLEEP 1

/* NodeErrors.h and WalletErrors.h have some conflicting enums, e.g. they
   both export NOT_INITIALIZED, we can get round this by using a namespace */
namespace NodeErrors
{
    #include <NodeRpcProxy/NodeErrors.h>
}

#include <Common/ColouredMsg.h>
#include <GreenWallet/Tools.h>
#include <GreenWallet/WalletConfig.h>

namespace WalletErrors
{
    #include <Wallet/WalletErrors.h>
}

#include <Wallet/WalletGreen.h>

#include "Common/DnsTools.h"
#include "Common/UrlTools.h"

bool parseAmount(std::string strAmount, uint64_t &amount)
{
    boost::algorithm::trim(strAmount);
    /* If the user entered thousand separators, remove them */
    boost::erase_all(strAmount, ",");

    const size_t pointIndex = strAmount.find_first_of('.');
    const size_t numDecimalPlaces = WalletConfig::numDecimalPlaces;

    size_t fractionSize;

    if (std::string::npos != pointIndex)
    {
        fractionSize = strAmount.size() - pointIndex - 1;

        while (numDecimalPlaces < fractionSize && '0' == strAmount.back())
        {
            strAmount.erase(strAmount.size() - 1, 1);
            --fractionSize;
        }

        if (numDecimalPlaces < fractionSize)
        {
            return false;
        }

        strAmount.erase(pointIndex, 1);
    }
    else
    {
        fractionSize = 0;
    }

    if (strAmount.empty())
    {
        return false;
    }

    if (!std::all_of(strAmount.begin(), strAmount.end(), ::isdigit))
    {
        return false;
    }

    if (fractionSize < numDecimalPlaces)
    {
        strAmount.append(numDecimalPlaces - fractionSize, '0');
    }

    bool success = Common::fromString(strAmount, amount);

    if (!success)
    {
        return false;
    }

    return amount >= WalletConfig::minimumSend;
}

bool confirmTransaction(CryptoNote::TransactionParameters t,
                        std::shared_ptr<WalletInfo> walletInfo)
{
    std::cout << std::endl
              << InformationMsg("Confirm Transaction?") << std::endl;

    std::cout << "You are sending "
              << SuccessMsg(formatAmount(t.destinations[0].amount))
              << ", with a network fee of " << SuccessMsg(formatAmount(t.fee));

    const std::string paymentID = getPaymentIDFromExtra(t.extra);

    if (paymentID != "")
    {
        std::cout << ", " << std::endl
                  << "and a Payment ID of " << SuccessMsg(paymentID);
    }
    else
    {
        std::cout << ".";
    }

    std::cout << std::endl << std::endl
              << "FROM: " << SuccessMsg(walletInfo->walletFileName)
              << std::endl
              << "TO: " << SuccessMsg(t.destinations[0].address)
              << std::endl << std::endl;

    if (confirm("Is this correct?"))
    {
        confirmPassword(walletInfo->walletPass);
        return true;
    }

    return false;
}

void sendMultipleTransactions(CryptoNote::WalletGreen &wallet,
                              std::vector<CryptoNote::TransactionParameters>
                              transfers)
{
    const size_t numTxs = transfers.size();
    size_t currentTx = 1;

    std::cout << "Your transaction has been split up into " << numTxs
              << " separate transactions of " 
              << formatAmount(transfers[0].destinations[0].amount)
              << ". "
              << std::endl
              << "It may take some time to send all the transactions."
              << std::endl << std::endl;

    for (auto tx : transfers)
    {
        while (true)
        {
            std::cout << "Attempting to send transaction "
                      << InformationMsg(std::to_string(currentTx))
                      << " of " << InformationMsg(std::to_string(numTxs))
                      << std::endl;

            Crypto::SecretKey txSecretKey;

            wallet.updateInternalCache();

            const uint64_t neededBalance = tx.destinations[0].amount + tx.fee;

            if (neededBalance <= wallet.pqSpendableBalance())
            {
                const size_t id = wallet.transfer(tx, txSecretKey);

                const CryptoNote::WalletTransaction sentTx
                    = wallet.getTransaction(id);

                std::cout << SuccessMsg("Transaction has been sent!")
                          << std::endl
                          << SuccessMsg("Hash: "
                                      + Common::podToHex(sentTx.hash))
                          << std::endl << std::endl;

                break;
            }

            std::cout << "Waiting for balance to unlock to send next "
                      << "transaction."
                      << std::endl
                      << "Will try again in 5 seconds..."
                      << std::endl << std::endl;

            std::this_thread::sleep_for(std::chrono::seconds(5));
        }

        currentTx++;
    }

    std::cout << SuccessMsg("All transactions sent!") << std::endl;
}

void splitTx(CryptoNote::WalletGreen &wallet,
             CryptoNote::TransactionParameters p)
{
    std::cout << "Transaction is still too large to send, splitting into "
              << "multiple chunks."
              << std::endl
              << "This may take a long time."
              << std::endl
              << "It may also slightly raise the fee you have to pay,"
              << std::endl
              << "and hence reduce the total amount you can send if"
              << std::endl
              << "your balance cannot cover it." << std::endl;

    if (!confirm("Is this OK?"))
    {
        std::cout << WarningMsg("Cancelling transaction.") << std::endl;
        return;
    }

    CryptoNote::TransactionParameters restoreInitialTx = p;

    const uint64_t maxSize = wallet.getMaxTxSize();
    const size_t txSize = wallet.getTxSize(p);
    const uint64_t defaultFee = WalletConfig::defaultFee;

    for (int numTxMultiplier = 1; ; numTxMultiplier++)
    {
        /* We modify p a bit in this function, so restore back to initial
           state each time */
        p = restoreInitialTx;

        /* We can't just evenly divide a transaction up to be < 115k bytes by
           decreasing the amount we're sending, because depending upon the
           inputs we might need to split into more transactions, so instead
           check at the end that each transaction is small enough, and
           if not, we up the numTxMultiplier and try again with more
           transactions. */
        int numTransactions
            = int(numTxMultiplier *
                 (std::ceil(double(txSize) / double(maxSize))));

        /* Split the requested fee over each transaction, i.e. if a fee of 200
           TRTL was requested and we split it into 4 transactions each one will
           have a fee of 5 TRTL. If the fee per transaction is less than the
           default fee, use the default fee. */
        const uint64_t feePerTx = std::max (p.fee / numTransactions, defaultFee);

        const uint64_t totalFee = feePerTx * numTransactions;

        const uint64_t totalCost = p.destinations[0].amount + totalFee;

        /* If we have to use the minimum fee instead of splitting the total fee,
           then it is possible the user no longer has the balance to cover this
           transaction. So, we slightly lower the amount they are sending. */
        if (totalCost > wallet.pqSpendableBalance())
        {
            const uint64_t available = wallet.pqSpendableBalance();
            if (available <= totalFee)
            {
                std::cout << WarningMsg("You don't have enough unlocked funds to cover the fee.")
                          << std::endl;
                return;
            }
            p.destinations[0].amount = available - totalFee;
        }

        const uint64_t amountPerTx = p.destinations[0].amount / numTransactions;
        /* Left over amount from integral division */
        const uint64_t change = p.destinations[0].amount % numTransactions;

        std::vector<CryptoNote::TransactionParameters> transfers;

        for (int i = 0; i < numTransactions; i++)
        {
            CryptoNote::TransactionParameters tmp = p;
            tmp.destinations[0].amount = amountPerTx;
            tmp.fee = feePerTx;
            transfers.push_back(tmp);
        }

        /* Add the extra change to the first transaction */
        transfers[0].destinations[0].amount += change;

        for (const auto &tx : transfers)
        {
            /* One of the transfers is too large. Retry, cutting the
               transactions into smaller pieces */
            if (wallet.txIsTooLarge(tx))
            {
                continue;
            }
        }

        sendMultipleTransactions(wallet, transfers);
        return;
    }
}

void transfer(std::shared_ptr<WalletInfo> walletInfo, uint32_t height, bool sendAll)
{
    (void)height;
    std::cout << InformationMsg("Note: You can type cancel at any time to "
                                "cancel the transaction")
              << std::endl << std::endl;

    const uint64_t balance = walletInfo->wallet.pqSpendableBalance();

    const auto maybeAddress = getDestinationAddress();

    if (!maybeAddress.isJust)
    {
        std::cout << WarningMsg("Cancelling transaction.") << std::endl;
        return;
    }

    std::string address = maybeAddress.x;

    /* Make sure we set this later if we're sending everything by deducting
       the fee from full balance */
    uint64_t amount = 0;

    /* If we're sending everything, obviously we don't need to ask them how
    much to send */
    if (!sendAll)
    {
        const auto maybeAmount = getTransferAmount();
        if (!maybeAmount.isJust)
        {
            std::cout << WarningMsg("Cancelling transaction.") << std::endl;
            return;
        }
        amount = maybeAmount.x;

        switch (doWeHaveEnoughBalance(amount, WalletConfig::defaultFee,
            walletInfo, height))
        {
            case NotEnoughBalance:
            {
                std::cout << WarningMsg("Cancelling transaction.") << std::endl;
                return;
            }
            default:
            {
                break;
            }
        }
    }

    const auto maybeFee = getFee();

    if (!maybeFee.isJust)
    {
        std::cout << WarningMsg("Cancelling transaction.") << std::endl;
        return;
    }

    const uint64_t fee = maybeFee.x;

    switch (doWeHaveEnoughBalance(amount, fee, walletInfo, height))
    {
        case NotEnoughBalance:
        {
            std::cout << WarningMsg("Cancelling transaction.") << std::endl;
            return;
        }
        default:
        {
            break;
        }
    }

    if (sendAll)
    {
        if (balance <= fee)
        {
            std::cout << WarningMsg("You don't have enough unlocked funds to cover the fee.")
                      << std::endl;
            return;
        }
        amount = balance - fee;
    }

    const auto maybeExtra = getExtra();

    if (!maybeExtra.isJust)
    {
        std::cout << WarningMsg("Cancelling transaction.") << std::endl;
        return;
    }

    const std::string extra = maybeExtra.x;

    doTransfer(address, amount, fee, extra, walletInfo, height);
}

BalanceInfo doWeHaveEnoughBalance(uint64_t amount, uint64_t fee,
                                  std::shared_ptr<WalletInfo> walletInfo,
                                  uint32_t height)
{
    (void)height;
    const uint64_t balance = walletInfo->wallet.pqSpendableBalance();

    /* They have to include at least a fee of this large */
    if (balance < amount + fee)
    {
        std::cout << std::endl
            << WarningMsg("You don't have enough funds to cover ")
            << WarningMsg("this transaction!") << std::endl << std::endl
            << "Funds needed: "
            << InformationMsg(formatAmount(amount + fee))
            << " (Includes a network fee of "
            << InformationMsg(formatAmount(fee))
            << ")"
            << std::endl
            << "Unlocked funds available: "
            << SuccessMsg(formatAmount(balance))
            << std::endl << std::endl;

        return NotEnoughBalance;
    }
    else
    {
        return EnoughBalance;
    }

    return NotEnoughBalance;
}

void doTransfer(std::string address, uint64_t amount, uint64_t fee,
                std::string extra, std::shared_ptr<WalletInfo> walletInfo,
                uint32_t height)
{
    (void)height;
    Crypto::SecretKey txSecretKey;
    const uint64_t balance = walletInfo->wallet.pqSpendableBalance();

    if (balance < amount + fee)
    {
        std::cout << WarningMsg("You don't have enough funds to cover this ")
                  << WarningMsg("transaction!")
                  << std::endl
                  << InformationMsg("Funds needed: ")
                  << InformationMsg(formatAmount(amount + fee))
                  << std::endl
                  << SuccessMsg("Unlocked funds available: " + formatAmount(balance))
                  << std::endl;
        return;
    }

    CryptoNote::TransactionParameters p;

    p.destinations = std::vector<CryptoNote::WalletOrder>
    {
        {address, amount}
    };

    p.fee = fee;
    p.extra = extra;
    p.changeDestination = walletInfo->walletAddress;

    if (!confirmTransaction(p, walletInfo))
    {
        std::cout << WarningMsg("Cancelling transaction.") << std::endl;
        return;
    }

    bool retried = false;

    while (true)
    {
        try
        {
            if (walletInfo->wallet.txIsTooLarge(p))
            {
                splitTx(walletInfo->wallet, p);
            }
            else
            {
                const size_t id = walletInfo->wallet.transfer(p, txSecretKey);

                const CryptoNote::WalletTransaction tx
                    = walletInfo->wallet.getTransaction(id);

                std::cout << SuccessMsg("Transaction has been sent!")
                          << std::endl
                          << SuccessMsg("Hash: " +
                                        Common::podToHex(tx.hash))
                          << std::endl;
            }
        }
        catch (const std::system_error &e)
        {
            if (retried)
            {
                std::cout << WarningMsg("Failed to send transaction!")
                          << std::endl << "Error message: " << e.what()
                          << std::endl;
                return;
            }

            switch (e.code().value())
            {
                case WalletErrors::CryptoNote::error::WRONG_AMOUNT:
                {
                    std::cout << WarningMsg("Failed to send transaction - not enough funds!")
                              << std::endl
                              << "Try lowering the amount you are sending."
                              << std::endl;
                    break;
                }
                case NodeErrors::CryptoNote::error::NETWORK_ERROR:
                case NodeErrors::CryptoNote::error::CONNECT_ERROR:
                {
                    std::cout << WarningMsg("Couldn't connect to the network "
                                            "to send the transaction!")
                              << std::endl
                              << "Ensure " << WalletConfig::daemonName
                              << " or the remote node you are using is open "
                              << "and functioning."
                              << std::endl;
                    break;
                }
                default:
                {
                    /* Some errors don't have an associated value, just an
                       error string */
                    std::string msg = e.what();

                    if (msg == "Failed add key input: key image already spent")
                    {
                        std::cout << WarningMsg("Failed to send transaction - "
                                                "wallet is not synced yet!")
                                  << std::endl
                                  << "Use the " << InformationMsg("bc_height")
                                  << " command to view the wallet sync status."
                                  << std::endl;
                        return;
                    }

                    std::cout << WarningMsg("Failed to send transaction!")
                              << std::endl << "Error message: " << msg
                              << std::endl
                              << "Please report what you were doing to cause "
                              << "this error so we can fix it! :)"
                              << std::endl;
                    break;
                }
            }
        }

        break;
    }
}

Maybe<std::string> getPaymentID(std::string msg)
{
    while (true)
    {
        std::string paymentID;

        std::cout << msg
                  << WarningMsg("Warning: If you were given a payment ID,")
                  << std::endl
                  << WarningMsg("you MUST use it, or your funds may be lost!")
                  << std::endl
                  << "Hit enter for the default of no payment ID: ";

        std::getline(std::cin, paymentID);

        if (paymentID == "")
        {
            return Just<std::string>(paymentID);
        }

        if (paymentID == "cancel")
        {
            return Nothing<std::string>();
        }

        std::vector<uint8_t> extra;

        /* Convert the payment ID into an "extra" */
        if (!CryptoNote::createTxExtraWithPaymentId(paymentID, extra))
        {
            std::cout << WarningMsg("Failed to parse! Payment ID's are 64 "
                                    "character hexadecimal strings.")
                      << std::endl;
            continue;
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
        }

        return Just<std::string>(paymentID);
    }
}

std::string getExtraFromPaymentID(std::string paymentID)
{
    if (paymentID == "")
    {
        return paymentID;
    }

    std::vector<uint8_t> extra;

    /* Convert the payment ID into an "extra" */
    CryptoNote::createTxExtraWithPaymentId(paymentID, extra);

    /* Then convert the "extra" back into a string so we can pass
       the argument that walletgreen expects. Note this string is not
       the same as the original paymentID string! */
    std::string extraString;

    for (auto i : extra)
    {
        extraString += static_cast<char>(i);
    }

    return extraString;
}

Maybe<std::string> getExtra()
{
    std::stringstream msg;

    msg << std::endl
        << InformationMsg("What payment ID do you want to use?")
        << std::endl
        << "These are usually used for sending to exchanges."
        << std::endl;

    auto maybePaymentID = getPaymentID(msg.str());

    if (!maybePaymentID.isJust)
    {
        return maybePaymentID;
    }

    if (maybePaymentID.x == "")
    {
        return maybePaymentID;
    }

    return Just<std::string>(getExtraFromPaymentID(maybePaymentID.x));
}

Maybe<uint64_t> getFee()
{
    while (true)
    {
        std::string stringAmount;
        std::cout << std::endl
                  << InformationMsg("What fee do you want to use?")
                  << std::endl
                  << "Hit enter for the default fee of "
                  << formatAmount(WalletConfig::defaultFee)
                  << ": ";

        std::getline(std::cin, stringAmount);

        if (stringAmount == "")
        {
            return Just<uint64_t>(WalletConfig::defaultFee);
        }

        if (stringAmount == "cancel")
        {
            return Nothing<uint64_t>();
        }

        uint64_t amount;

        if (parseFee(stringAmount))
        {
            parseAmount(stringAmount, amount);
            return Just<uint64_t>(amount);
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
        }
    }
}

Maybe<uint64_t> getTransferAmount()
{
    while (true)
    {
        std::string stringAmount;

        std::cout << std::endl
                  << InformationMsg("How much ")
                  << InformationMsg(WalletConfig::ticker)
                  << InformationMsg(" do you want to send?: ");

        std::getline(std::cin, stringAmount);

        if (stringAmount == "cancel")
        {
            return Nothing<uint64_t>();
        }

        uint64_t amount;

        if (parseAmount(stringAmount))
        {
            parseAmount(stringAmount, amount);
            return Just<uint64_t>(amount);
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
        }
    }
}

Maybe<std::string> getDestinationAddress()
{
    while (true)
    {
        std::string transferAddr;

        std::cout << InformationMsg("What address do you want to ")
                  << InformationMsg("transfer to?: ");

        std::getline(std::cin, transferAddr);
        boost::algorithm::trim(transferAddr);

        if (transferAddr == "cancel")
        {
            return Nothing<std::string>();
        }

#ifndef __ANDROID__
        std::string aliasAddress;
        if (getOpenAlias(transferAddr, aliasAddress))
        {
           return Just<std::string>(aliasAddress);
        }
#endif

        if (parseAddress(transferAddr))
        {
            return Just<std::string>(transferAddr);
        }

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
        }
    }
}

bool parseFee(std::string feeString)
{
    uint64_t fee;

    if (!parseAmount(feeString, fee))
    {
        std::cout << WarningMsg("Failed to parse fee! Ensure you entered the "
                                "value correctly.")
                  << std::endl
                  << "Please note, you can only use "
                  << WalletConfig::numDecimalPlaces << " decimal places."
                  << std::endl;

        return false;
    }
    else if (fee < WalletConfig::minimumFee)
    {
        std::cout << WarningMsg("Fee must be at least ")
                  << formatAmount(WalletConfig::minimumFee) << "!"
                  << std::endl;

        return false;
    }

    return true;
}


bool parseAddress(std::string address)
{
    /* Discrete addresses are post-quantum: either a (variable-length) bech32m
       PQ address, or a human-readable H-I-A-C / H-I-A-T-C account number. Both are
       self-validating offline (bech32m checksum / Luhn check char). The full
       network + on-chain-existence check happens in wallet.transfer()'s recipient
       resolution; this is just a fast pre-check so a typo re-prompts the user. */
    CryptoNote::PqAddress pq;
    if (CryptoNote::decodePqAddress(address, pq))
    {
        return true;
    }

    CryptoNote::AccountNumber acct;
    uint32_t subaddrIndex = 0;
    if (CryptoNote::AccountNumber::fromStringWithIndex(address, acct, subaddrIndex)
     || CryptoNote::AccountNumber::fromString(address, acct))
    {
        return true;
    }

    std::cout << WarningMsg("Failed to parse address, it is not a valid ")
              << WarningMsg(WalletConfig::ticker)
              << WarningMsg(" address or account number!") << std::endl
              << std::endl;

    return false;
}

bool parseAmount(std::string amountString)
{
    uint64_t amount;

    if (!parseAmount(amountString, amount))
    {
        std::cout << WarningMsg("Failed to parse amount! Ensure you entered "
                                "the value correctly.")
                  << std::endl
                  << "Please note, the minimum you can send is "
                  << formatAmount(WalletConfig::minimumSend) << ","
                  << std::endl
                  << "and you can only use " << WalletConfig::numDecimalPlaces
                  << " decimal places."
                  << std::endl;

        return false;
    }

    return true;
}

#ifndef __ANDROID__
bool getOpenAlias(const std::string& alias, std::string& address)
{
    // If string doesn't contain a dot, we won't consider it an URL
    if (strchr(alias.c_str(), '.') == NULL)
    {
        return false;
    }

    std::string aliasAddress;

    try
    {
        aliasAddress = resolveAlias(alias);
    }
    catch (std::exception& e)
    {
        std::cout << WarningMsg("Couldn't resolve alias: ") << alias
                  << WarningMsg(" due to: ") << e.what() << std::endl;
        return false;
    }

    // Validate address
    if (!parseAddress(aliasAddress))
    {
        return false;
    }

    // Ask for confirmation that this is intended address
    if (!askAliasesTransfersConfirmation(aliasAddress))
    {
        return false;
    }

    address = aliasAddress;

    return true;
}

std::string resolveAlias(const std::string& aliasUrl)
{
    std::string host, uri, address;
    std::vector<std::string>records;

    if (!Common::fetch_dns_txt(aliasUrl, records)) {
        throw std::runtime_error("Failed to lookup DNS record");
    }

    for (const auto& record : records) {
        if (processServerAliasResponse(record, address)) {
            return address; // return first found address
        }
    }
    throw std::runtime_error("Failed to parse server response");
}

bool processServerAliasResponse(const std::string& s, std::string& address)
{
    try {
        // Courtesy of Monero Project
        // make sure the txt record has "oa1:krb" and find it
        auto pos = s.find("oa1:krb");
        if (pos == std::string::npos)
            return false;

        // search from there to find "recipient_address="
        pos = s.find("recipient_address=", pos);
        if (pos == std::string::npos)
            return false;
        pos += 18; // move past "recipient_address="

        // find the next semicolon
        auto pos2 = s.find(";", pos);
        if (pos2 != std::string::npos)
        {
            // length of address == 95, we can at least validate that much here
            if (pos2 - pos == 95)
            {
                address = s.substr(pos, 95);
            }
            else {
                return false;
            }
        }
    }
    catch (std::exception&) {
        return false;
    }

    return true;
}

bool askAliasesTransfersConfirmation(const std::string address)
{
    std::cout << InformationMsg("Would you like to send money ")
              << InformationMsg("to the following address?")
              << std::endl << SuggestionMsg(address) << std::endl;

    std::string answer;
    do {
        std::cout << InformationMsg("y/n: ");
        std::getline(std::cin, answer);

        if (std::cin.fail() || std::cin.eof()) {
            std::cin.clear();
            break;
        }

    } while (answer != "y" && answer != "Y" && answer != "n" && answer != "N");

    return answer == "y" || answer == "Y";
}
#endif

