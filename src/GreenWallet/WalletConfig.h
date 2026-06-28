// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2018-2019, The Karbo Developers
// 
// Please see the included LICENSE file for more information.

#pragma once

#include "CryptoNoteConfig.h"

/* Make sure everything in here is const - or it won't compile! */
namespace WalletConfig
{
    /* The human-readable prefix (HRP) a bech32m address starts with. Shown in
       messages only; address validation no longer length/prefix-matches (see
       parseAddress in Transfer.cpp), since PQ addresses are variable-length. */
    const std::string addressPrefix = "disc";

    /* Your coins 'Ticker', e.g. Monero = XMR, Bitcoin = BTC */
    const std::string ticker = "XDS";

    /* The filename to output the CSV to in save_csv */
    const std::string csvFilename = "transactions.csv";

    /* The filename to read+write the address book to - consider starting with
       a leading '.' to make it hidden under mac+linux */
    const std::string addressBookFilename = ".addressBook.json";

    /* The name of your deamon */
    const std::string daemonName = "discreted";

    /* The name to call this wallet */
    const std::string walletName = "GreenWallet";

    /* The name of walletd, the programmatic rpc interface to a wallet */
    const std::string walletdName = "walletd";

    /* The full name of your crypto */
    const std::string coinName = "Discrete";

    /* Where can your users contact you for support? E.g. discord */
    const std::string contactLink = "https://discrete.cash";

    /* The number of decimals your coin has */
    const int numDecimalPlaces = CryptoNote::parameters
                                           ::CRYPTONOTE_DISPLAY_DECIMAL_POINT;

    /* The default fee value to use with transactions (in ATOMIC units!) */
    const uint64_t defaultFee = CryptoNote::parameters::MINIMUM_FEE; 

    /* The minimum fee value to allow with transactions (in ATOMIC units!) */
    const uint64_t minimumFee = CryptoNote::parameters::MINIMUM_FEE;

    /* The minimum amount allowed to be sent - usually 1 (in ATOMIC units!) */
    const uint64_t minimumSend = 1;

}
