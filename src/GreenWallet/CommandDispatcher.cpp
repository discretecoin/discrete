// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2016-2026, The Karbo developers
//
// Please see the included LICENSE file for more information.

////////////////////////////////////////
#include <GreenWallet/CommandDispatcher.h>
////////////////////////////////////////

#include <GreenWallet/AddressBook.h>
#include <Common/ColouredMsg.h>
#include <GreenWallet/CommandImplementations.h>
#include <GreenWallet/Open.h>
#include <GreenWallet/Transfer.h>

bool handleCommand(const std::string command,
                   std::shared_ptr<WalletInfo> walletInfo,
                   CryptoNote::INode &node)
{
    /* Basic commands */
    if (command == "advanced")
    {
        advanced(walletInfo);
    }
    else if (command == "address")
    {
        pqAddress(walletInfo);
    }
    else if (command == "balance")
    {
        pqBalance(walletInfo);
    }
    else if (command == "backup")
    {
        exportKeys(walletInfo);
    }
    else if (command == "exit")
    {
        return false;
    }
    else if (command == "help")
    {
        help(walletInfo);
    }
    else if (command == "transfer")
    {
        pqTransfer(walletInfo, node);
    }
    /* Advanced commands */
    else if (command == "ab_add")
    {
        addToAddressBook();
    }
    else if (command == "ab_delete")
    {
        deleteFromAddressBook();
    }
    else if (command == "ab_list")
    {
        listAddressBook();
    }
    else if (command == "ab_send")
    {
        sendFromAddressBook(walletInfo, node.getLastKnownBlockHeight());
    }
    else if (command == "change_password")
    {
        changePassword(walletInfo);
    }
    else if (command == "incoming_transfers")
    {
        listTransfers(true, false, walletInfo->wallet, node);
    }
    else if (command == "list_transfers")
    {
        listTransfers(true, true, walletInfo->wallet, node);
    }
    else if (command == "outgoing_transfers")
    {
        listTransfers(false, true, walletInfo->wallet, node);
    }
    else if (command == "reset")
    {
        reset(node, walletInfo);
    }
    else if (command == "save")
    {
        save(walletInfo->wallet);
    }
    else if (command == "save_csv")
    {
        saveCSV(walletInfo->wallet, node);
    }
    else if (command == "send_all")
    {
        transfer(walletInfo, node.getLastKnownBlockHeight(), true);
    }
    else if (command == "status")
    {
        status(node, walletInfo->wallet);
    }
    else if (command == "sign_message")
    {
      signMessage(walletInfo, walletInfo->viewWallet);
    }
    else if (command == "verify_message")
    {
      verifyMessage(walletInfo->wallet);
    }
    else if (command == "register")
    {
        pqRegister(walletInfo, node);
    }
    else if (command == "register_paid")
    {
        pqRegisterPaid(walletInfo, node);
    }
    else if (command == "account")
    {
        pqAccount(walletInfo, node);
    }
    /* This should never happen */
    else
    {
        throw std::runtime_error("Command was defined but not hooked up!");
    }

    return true;
}

std::shared_ptr<WalletInfo> handleLaunchCommand(CryptoNote::WalletGreen &wallet,
                                                std::string launchCommand,
                                                Config &config)
{
    if (launchCommand == "create")
    {
        return generateWallet(wallet);
    }
    else if (launchCommand == "open")
    {
        return openWallet(wallet, config);
    }
    else if (launchCommand == "seed_restore")
    {
        return mnemonicImportWallet(wallet);
    }
    else if (launchCommand == "key_restore")
    {
        return importWallet(wallet);
    }
    else if (launchCommand == "gui_restore")
    {
      return importGUIWallet(wallet);
    }
    else if (launchCommand == "view_wallet")
    {
        return createViewWallet(wallet);
    }
    /* This should never happen */
    else
    {
        throw std::runtime_error("Command was defined but not hooked up!");
    }
}
