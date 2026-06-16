// Copyright (c) 2021, The Talleo developers
// Copyright (c) 2021 - 2025, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo. If not, see <http://www.gnu.org/licenses/>.

#ifdef WIN32
#include <windows.h>
#endif

#include <boost/program_options.hpp>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "Common/int-util.h"
#include "Common/Base58.h"
#include "Common/ColouredMsg.h"
#include "Common/CommandLine.h"
#include "Common/ConsoleTools.h"
#include "Common/StringTools.h"
#include "Common/Varint.h"
#include "crypto/hash.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/keccak.h"
}
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/GenesisTreasuryReserve.h"
#include "PqAddress.h"
#include "crypto_pq/PqHash.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"
#include "Logging/LoggerGroup.h"
#include "Logging/ConsoleLogger.h"
#include "Logging/LoggerRef.h"
#include "Logging/LoggerManager.h"
#include "Mnemonics/electrum-words.h"
#include "System/Dispatcher.h"
#include "System/RemoteContext.h"
#include "CryptoNoteConfig.h"
#include "CryptoTypes.h"
#include "version.h"

#undef ERROR

using namespace CryptoNote;
using namespace Logging;

namespace po = boost::program_options;

std::mutex outputMutex;

namespace command_line
{
  const command_line::arg_descriptor<std::string> arg_prefix = {"prefix", "Specify the address prefix"};
  const command_line::arg_descriptor<int> arg_count = {"count", "Specify the number of addresses to find", 1};
  const command_line::arg_descriptor<int> arg_threads = {"threads", "Specify the number of threads to use", 1};
  const command_line::arg_descriptor<std::string> arg_file = {"file", "Specify the file name to save generated keys to file, "
    "by default found keys are just shown in console. If the file exists, new keys are appended"};
  const command_line::arg_descriptor<int> arg_treasury_reserve = {"treasury-reserve-accounts",
    "Generate N independent PQ accounts for the genesis Treasury Reserve: writes <file>.txt "
    "(mnemonics/secrets) and <file>.inc (GenesisTreasuryReserveKeys.inc with the public keys)", 0};
}

void seedFormater(std::string& seed) {
    const unsigned int word_width = 12;
    const unsigned int seed_col = 5;
    std::string word_buff;
    std::vector<std::string> seed_array;
    unsigned int word_n = 0;
    for (unsigned int n = 0; n <= seed.length(); n++) {
        if (seed[n] != 0x20 && seed[n] != 0x0A && seed[n] != 0x00) {
            word_buff.push_back(seed[n]);
        }
        else {
            if (!word_buff.empty()) {
                seed_array.push_back(word_buff);
                word_buff.clear();
            }
        }
    }
    seed.clear();
    for (std::string word : seed_array) {
        seed.append(word);
        for (unsigned int k = 2; k <= word_width - word.length() && word.length() <= word_width; k++) seed.append(" ");
        seed.append(" ");
        word_n++;
        if (word_n >= seed_col) {
            word_n = 0;
            seed.append("\n           ");
        }
    }
    seed.erase(seed.size() - 11); // remove last line of spacers
}

bool is_valid_prefix(const std::string& prefix, Currency& currency) {
    if (prefix.length() <= 2 || prefix.length() >= 95)
        return false;

    const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for (const char& c : prefix) {
        if (std::string(alphabet).find(c) == std::string::npos)
            return false;
    }

    std::string zerohex = "0000000000000000000000000000000000000000000000000000000000000000";
    std::string ffhex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    AccountPublicAddress lowest_acc;
    AccountPublicAddress highest_acc;

    Common::podFromHex(zerohex, lowest_acc.spendPublicKey);
    Common::podFromHex(zerohex, lowest_acc.viewPublicKey);
    Common::podFromHex(ffhex, highest_acc.spendPublicKey);
    Common::podFromHex(ffhex, highest_acc.viewPublicKey);

    std::string lowest_address = currency.accountAddressAsString(lowest_acc);
    std::string highest_address = currency.accountAddressAsString(highest_acc);

    std::string lowest = lowest_address.substr(0, prefix.length());
    std::string highest = highest_address.substr(0, prefix.length());

    if (prefix < lowest)
        return false;
    if (prefix > highest)
        return false;

    return true;
}

bool check_address_prefix(const std::string& prefix, Currency& currency, const po::variables_map& vm, AccountKeys& _keys) {
    CryptoNote::AccountPublicAddress publicKeys;
    if (secret_key_to_public_key(_keys.spendSecretKey, publicKeys.spendPublicKey)) {
        AccountBase::generateViewFromSpend(_keys.spendSecretKey, _keys.viewSecretKey, publicKeys.viewPublicKey);
        std::string address = currency.accountAddressAsString(publicKeys);
        if ((address.substr(0, prefix.length()) == prefix)) {
            std::lock_guard<std::mutex> guard(outputMutex);

            std::string found = "\n";

            found += "Address:   " + address + "\n";
            found += "Spend key: " + Common::podToHex(_keys.spendSecretKey) + "\n";
            found += "View key:  " + Common::podToHex(_keys.viewSecretKey) + "\n";

            std::string electrum_words;
            std::string lang = "English";
            Crypto::ElectrumWords::bytes_to_words(_keys.spendSecretKey, electrum_words, lang);
            Crypto::SecretKey second;
            keccak((uint8_t*)&_keys.spendSecretKey, sizeof(Crypto::SecretKey), (uint8_t*)&second, sizeof(Crypto::SecretKey));
            sc_reduce32((uint8_t*)&second);
            bool success = memcmp(second.data, _keys.viewSecretKey.data, sizeof(Crypto::SecretKey)) == 0;
            if (success)
            {
                seedFormater(electrum_words);
                found += "Mnemonic:  ";
                found += electrum_words + "\n";
            }

            std::cout << SuccessMsg(found) << ENDL;

            if (!command_line::get_arg(vm, command_line::arg_file).empty()) {
                std::string filename = command_line::get_arg(vm, command_line::arg_file);
                std::ofstream ofs;
                ofs.open(filename + ".txt", std::ofstream::out | std::ofstream::app);
                ofs << found;
                ofs.close();
            }

            return true;
        }
    }

    return false;
}

void prefix_worker(const std::string& prefix, Currency& currency, const po::variables_map& vm, int threads, int threadId, volatile int& found, int count) {
    bool found_needed = false;
    while (!found_needed) {
        AccountKeys keys;
        Crypto::SecretKey second;
        Crypto::generate_keys(keys.address.spendPublicKey, keys.spendSecretKey);
        keccak((uint8_t*)&keys.spendSecretKey, sizeof(Crypto::SecretKey), (uint8_t*)&second, sizeof(Crypto::SecretKey));
        Crypto::generate_deterministic_keys(keys.address.viewPublicKey, keys.viewSecretKey, second);

        if (check_address_prefix(prefix, currency, vm, keys)) {
            found++;
        }

        if (found >= count) {
            found_needed = true;
        }
    }

    return;
}

bool find_prefix(const po::variables_map& vm, Currency& currency, System::Dispatcher& dispatcher) {
    std::string prefix = command_line::get_arg(vm, command_line::arg_prefix);
    int count = command_line::get_arg(vm, command_line::arg_count);
    int threads = std::max(1, command_line::get_arg(vm, command_line::arg_threads));
    int found = 0;

    if ((prefix.substr(0, 1) != "K") || prefix.length() > 95 || prefix.length() < 2) {
        std::cerr << WarningMsg("Invalid address prefix!") << std::endl;
        return false;
    }

    if (!is_valid_prefix(prefix, currency)) {
        std::cerr << WarningMsg("Invalid character in prefix!") << std::endl;
        return false;
    }

    std::cout << InformationMsg("Trying to find address for prefix \"") << prefix << InformationMsg("\"...") << std::endl << std::endl;

    std::vector<std::unique_ptr<System::RemoteContext<void>>> m_workers;

    for (int i = 0; i < threads; i++) {
        m_workers.emplace_back(
               new System::RemoteContext<void>(dispatcher, [&, i]() {
                   prefix_worker(prefix, currency, vm, threads, i, found, count);
               })
        );
    }

    m_workers.clear();
    return found != 0;
}

// Generate N independent PQ accounts for the genesis Treasury Reserve. Each account
// is a fresh classical keypair (with its 25-word electrum mnemonic) whose PQ
// identity is derived EXACTLY as CryptoNote::derivePqWalletKeys does — so the same
// mnemonic loaded into simplewallet recovers the batch. Public keys go into a
// committed GenesisTreasuryReserveKeys.inc; secrets go to a separate (gitignored) file.
bool generate_treasury_reserve_accounts(const po::variables_map& vm, Currency& currency) {
    int count = command_line::get_arg(vm, command_line::arg_treasury_reserve);
    std::string filePrefix = command_line::get_arg(vm, command_line::arg_file);
    if (filePrefix.empty()) filePrefix = "treasury-reserve-accounts";

    // CEMENTED wallet-layer seed domain (must match PqWallet.h kPqWalletSeedDomain).
    static const char kSeedDomain[] = "karbo-pq-wallet-seed-v1";

    std::ofstream secrets(filePrefix + ".txt", std::ofstream::out | std::ofstream::trunc);
    if (!secrets) {
        std::cerr << WarningMsg("Cannot open secrets file " + filePrefix + ".txt") << std::endl;
        return false;
    }
    secrets << "# Discrete genesis Treasury Reserve recipient accounts — SECRET, keep offline.\n";
    secrets << "# " << count << " independent accounts. Each mnemonic recovers its batch in simplewallet.\n\n";

    std::vector<std::string> viewHex, spendHex;
    for (int i = 0; i < count; ++i) {
        AccountKeys keys;
        Crypto::SecretKey second;
        Crypto::generate_keys(keys.address.spendPublicKey, keys.spendSecretKey);
        keccak((uint8_t*)&keys.spendSecretKey, sizeof(Crypto::SecretKey), (uint8_t*)&second, sizeof(Crypto::SecretKey));
        Crypto::generate_deterministic_keys(keys.address.viewPublicKey, keys.viewSecretKey, second);

        std::string mnemonic, lang = "English";
        Crypto::ElectrumWords::bytes_to_words(keys.spendSecretKey, mnemonic, lang);
        std::string classicalAddr = currency.accountAddressAsString(keys.address);

        // PQ identity = derivePqWalletKeys(spendSecretKey): seed_master = HKDF(
        // spendSecret, domain), then ML-KEM view + ML-DSA spend keygen.
        CryptoPQ::Hash256 okm = CryptoPQ::hkdf_sha3_256(
            keys.spendSecretKey.data, sizeof(keys.spendSecretKey.data),
            kSeedDomain, sizeof(kSeedDomain) - 1);
        CryptoPQ::SeedMaster sm{};
        std::copy(okm.begin(), okm.end(), sm.begin());
        auto view = CryptoPQ::deriveViewKeys(sm);
        auto spend = CryptoPQ::deriveSpendKeys(sm);

        CryptoNote::PqAddress addr =
            CryptoNote::makePqAddress(currency.publicAddressBase58Prefix(), view.first, spend.first);
        std::string pqAddr = CryptoNote::encodePqAddress(addr, CryptoNote::PqAddressEncoding::Base58);

        std::string vh = Common::toHex(view.first.data(), view.first.size());
        std::string sh = Common::toHex(spend.first.data(), spend.first.size());
        viewHex.push_back(vh);
        spendHex.push_back(sh);

        secrets << "## Batch " << i << "\n";
        secrets << "mnemonic:          " << mnemonic << "\n";
        secrets << "classical_address: " << classicalAddr << "\n";
        secrets << "pq_address:        " << pqAddr << "\n";
        secrets << "spend_secret_hex:  " << Common::podToHex(keys.spendSecretKey) << "\n";
        secrets << "view_pub_hex:      " << vh << "\n";
        secrets << "spend_pub_hex:     " << sh << "\n\n";
    }
    secrets.close();

    std::ofstream inc(filePrefix + ".inc", std::ofstream::out | std::ofstream::trunc);
    if (!inc) {
        std::cerr << WarningMsg("Cannot open include file " + filePrefix + ".inc") << std::endl;
        return false;
    }
    inc << "// AUTO-GENERATED by `vanitygen --treasury-reserve-accounts` — DO NOT EDIT BY HAND.\n";
    inc << "//\n";
    inc << "// Recipient PUBLIC keys for the genesis Treasury Reserve, one entry per batch.\n";
    inc << "// The matching mnemonics/secrets are NOT in the repo — see docs/GENESIS.md.\n\n";
    inc << "static const char* const kGenesisTreasuryReserveViewPubHex[CryptoNote::GENESIS_TREASURY_RESERVE_BATCHES] = {\n";
    for (const auto& h : viewHex) inc << "  \"" << h << "\",\n";
    inc << "};\n\n";
    inc << "static const char* const kGenesisTreasuryReserveSpendPubHex[CryptoNote::GENESIS_TREASURY_RESERVE_BATCHES] = {\n";
    for (const auto& h : spendHex) inc << "  \"" << h << "\",\n";
    inc << "};\n";
    inc.close();

    std::cout << SuccessMsg("\nGenerated " + std::to_string(count) + " Treasury Reserve accounts.\n");
    std::cout << "  secrets: " << filePrefix << ".txt  (KEEP OFFLINE, do not commit)\n";
    std::cout << "  keys:    " << filePrefix << ".inc  (copy to src/CryptoNoteCore/GenesisTreasuryReserveKeys.inc)\n";
    return true;
}

int main(int argc, char** argv) {
    LoggerManager logManager;
    LoggerRef logger(logManager, "vanitygen");

    CurrencyBuilder builder(logManager);
    Currency currency = builder.currency();

    System::Dispatcher dispatcher;

    std::string coinName(CryptoNote::CRYPTONOTE_NAME);
    std::cout << InformationMsg(coinName + " address generator v. " + std::string(PROJECT_VERSION)) << std::endl;

    try {
        po::options_description desc_cmd_only("Available command line options");

        command_line::add_arg(desc_cmd_only, command_line::arg_prefix);
        command_line::add_arg(desc_cmd_only, command_line::arg_count);
        command_line::add_arg(desc_cmd_only, command_line::arg_threads);
        command_line::add_arg(desc_cmd_only, command_line::arg_file);
        command_line::add_arg(desc_cmd_only, command_line::arg_treasury_reserve);

        command_line::add_arg(desc_cmd_only, command_line::arg_help);

        bool r = command_line::handle_error_helper(desc_cmd_only, [&]()
        {
            po::variables_map vm;
            po::store(po::parse_command_line(argc, argv, desc_cmd_only), vm);

            if (command_line::get_arg(vm, command_line::arg_treasury_reserve) > 0) {
                return generate_treasury_reserve_accounts(vm, currency);
            }

            if (!command_line::get_arg(vm, command_line::arg_prefix).empty()) {
                return find_prefix(vm, currency, dispatcher);
            }

            if (command_line::get_arg(vm, command_line::arg_help)) {
                std::cout << desc_cmd_only << std::endl;
                return true;
            }

            std::cout << desc_cmd_only << std::endl;

            return true;
        });

        if (!r)
            return 1;
    } catch (const std::exception& e) {
        logger(Logging::ERROR, BRIGHT_RED) << "Exception: " << e.what();
        return 1;
    }
    return 0;
}
