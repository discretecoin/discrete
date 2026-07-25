// Copyright (c) 2021, The Talleo developers
// Copyright (c) 2021 - 2026, The Karbo developers
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
#include <cctype>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <System/Dispatcher.h>

#include "Common/CommandLine.h"
#include "Common/ColouredMsg.h"
#include "Common/JsonValue.h"
#include "Common/PasswordContainer.h"
#include "Common/StringTools.h"
#include "Checkpoints/DnsCheckpoint.h"
#include "Checkpoints/CheckpointDownloader.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/GenesisTreasuryReserve.h"
#include "PqAddress.h"
#include "crypto_pq/PqSeed.h"
#include "crypto/crypto-util.h"
#include "Logging/LoggerManager.h"
#include "Logging/LoggerRef.h"
#include "Mnemonics/electrum-words.h"
#include "Wallet/MiningKeyLoader.h"
#include "CryptoNoteConfig.h"
#include "version.h"

#undef ERROR

using namespace CryptoNote;
using namespace Logging;

namespace po = boost::program_options;

namespace command_line
{
  const command_line::arg_descriptor<std::string> arg_file = {"file", "Specify the file name prefix to save generated keys to. "
    "Defaults to \"treasury-reserve-accounts\"."};
  const command_line::arg_descriptor<int> arg_treasury_reserve = {"treasury-reserve-accounts",
    "Generate N independent PQ accounts for the genesis Treasury Reserve: writes <file>.txt "
    "(mnemonics/secrets) and <file>.inc (GenesisTreasuryReserveKeys.inc with the public keys)", 0};

  // DNS checkpoint publishing / verification.
  const command_line::arg_descriptor<bool> arg_sign_checkpoint = {"sign-checkpoint",
    "Sign a checkpoint and emit the JSON file + DNS TXT pointer. Requires --height and "
    "--block-hash. Reads the signer mnemonic from stdin, or use --wallet-file.", false};
  const command_line::arg_descriptor<bool> arg_checkpoint_key = {"checkpoint-key",
    "Print the checkpoint signer's Discrete address and key_id (reads the mnemonic from "
    "stdin, or use --wallet-file). Bake the address into DNS_CHECKPOINT_SIGNERS.", false};
  const command_line::arg_descriptor<bool> arg_verify_checkpoint = {"verify-checkpoint",
    "Verify a checkpoint against the configured signers. Use --txt \"<record>\" to fetch and "
    "verify over HTTPS, or --json-file <path> to verify a local file.", false};
  const command_line::arg_descriptor<uint32_t> arg_height = {"height", "Checkpoint block height.", 0};
  const command_line::arg_descriptor<std::string> arg_block_hash = {"block-hash", "Checkpoint block hash (64 hex).", ""};
  const command_line::arg_descriptor<std::string> arg_wallet_file = {"wallet-file",
    "Read the signer seed from a wallet file instead of a mnemonic on stdin.", ""};
  const command_line::arg_descriptor<std::string> arg_out_dir = {"out-dir",
    "Directory to write the checkpoint JSON file into (default: current directory).", ""};
  const command_line::arg_descriptor<std::string> arg_txt = {"txt", "DNS TXT pointer record to verify.", ""};
  const command_line::arg_descriptor<std::string> arg_json_file = {"json-file", "Local checkpoint JSON file to verify.", ""};
}

// Generate N independent PQ accounts for the genesis Treasury Reserve. Each account
// is a fresh CSPRNG master seed; its Electrum mnemonic is the recovery secret
// (load in simplewallet to recover). Public keys go into a committed
// GenesisTreasuryReserveKeys.inc; secrets go to a separate (gitignored) file.
bool generate_treasury_reserve_accounts(const po::variables_map& vm, Currency& currency) {
    int count = command_line::get_arg(vm, command_line::arg_treasury_reserve);
    std::string filePrefix = command_line::get_arg(vm, command_line::arg_file);
    if (filePrefix.empty()) filePrefix = "treasury-reserve-accounts";

    std::ofstream secrets(filePrefix + ".txt", std::ofstream::out | std::ofstream::trunc);
    if (!secrets) {
        std::cerr << WarningMsg("Cannot open secrets file " + filePrefix + ".txt") << std::endl;
        return false;
    }
    secrets << "# Discrete genesis Treasury Reserve recipient accounts — SECRET, keep offline.\n";
    secrets << "# " << count << " independent accounts. Load the mnemonic in simplewallet to recover.\n\n";

    std::vector<std::string> viewHex, spendHex;
    for (int i = 0; i < count; ++i) {
        // Generate a fresh 32-byte PQ master seed (same derivation path as the wallet).
        CryptoPQ::SeedMaster seed{};
        secure_random_bytes(seed.data(), seed.size());

        // Mnemonic = Electrum words of the raw seed bytes (same as simplewallet getSeed).
        std::string mnemonic, lang = "English";
        Crypto::SecretKey seedKey;
        std::memcpy(seedKey.data, seed.data(), sizeof(seedKey.data));
        Crypto::ElectrumWords::bytes_to_words(seedKey, mnemonic, lang);

        auto view  = CryptoPQ::deriveViewKeys(seed);
        auto spend = CryptoPQ::deriveSpendKeys(seed);

        CryptoNote::PqAddress addr =
            CryptoNote::makePqAddress(currency.publicAddressBase58Prefix(), view.first, spend.first);
        std::string pqAddr = CryptoNote::encodePqAddress(addr, CryptoNote::pqBech32Hrp(currency.isTestnet()));

        std::string vh = Common::toHex(view.first.data(),  view.first.size());
        std::string sh = Common::toHex(spend.first.data(), spend.first.size());
        viewHex.push_back(vh);
        spendHex.push_back(sh);

        secrets << "## Batch " << i << "\n";
        secrets << "mnemonic:      " << mnemonic << "\n";
        secrets << "pq_address:    " << pqAddr << "\n";
        secrets << "view_pub_hex:  " << vh << "\n";
        secrets << "spend_pub_hex: " << sh << "\n\n";
    }
    secrets.close();

    std::ofstream inc(filePrefix + ".inc", std::ofstream::out | std::ofstream::trunc);
    if (!inc) {
        std::cerr << WarningMsg("Cannot open include file " + filePrefix + ".inc") << std::endl;
        return false;
    }
    inc << "// AUTO-GENERATED by `admin-tools --treasury-reserve-accounts` — DO NOT EDIT BY HAND.\n";
    inc << "//\n";
    inc << "// Recipient PUBLIC keys for the genesis Treasury Reserve, one entry per batch.\n";
    inc << "// The matching mnemonics/secrets are NOT in the repo — see https://docs.discrete.cash/#/consensus/genesis.\n\n";
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

// ---------------------------------------------------------------------------
// DNS checkpoint publishing / verification.
//
// The DNS TXT record holds only a small pointer; the ML-DSA-65 signature (3309
// bytes — far past what any TXT encoding can carry) travels in the JSON file the
// pointer references. Spec: the DNS_CHECKPOINT_SIGNERS block in CryptoNoteConfig.h.
// ---------------------------------------------------------------------------

// Load the signer's 32-byte master seed, either from a wallet file (password
// prompted, empty accepted — same as simplewallet) or from a mnemonic on stdin.
// The mnemonic is never taken from argv, so it can't leak into shell history or
// a process listing.
static bool load_signer_seed(const po::variables_map& vm, Logging::ILogger& log,
                             CryptoPQ::SeedMaster& seedOut) {
    const std::string walletFile = command_line::get_arg(vm, command_line::arg_wallet_file);

    if (!walletFile.empty()) {
        Tools::PasswordContainer pwd;
        if (!pwd.read_password(false, "Wallet password (empty if unencrypted): ")) {
            std::cerr << WarningMsg("Failed to read password") << std::endl;
            return false;
        }
        try {
            Crypto::SecretKey seed = CryptoNote::loadMiningSpendSecret(walletFile, pwd.password(), log);
            std::copy(std::begin(seed.data), std::end(seed.data), seedOut.begin());
            sodium_memzero(&seed, sizeof(seed));
            return true;
        } catch (const std::exception& e) {
            std::cerr << WarningMsg(std::string("Cannot open wallet: ") + e.what()) << std::endl;
            return false;
        }
    }

    std::cout << "Enter the signer mnemonic (25 words), then press Enter:" << std::endl;
    std::string mnemonic;
    if (!std::getline(std::cin, mnemonic) || mnemonic.empty()) {
        std::cerr << WarningMsg("No mnemonic supplied on stdin") << std::endl;
        return false;
    }

    Crypto::SecretKey seedKey;
    std::string language;
    if (!Crypto::ElectrumWords::words_to_bytes(mnemonic, seedKey, language)) {
        sodium_memzero(&mnemonic[0], mnemonic.size());
        std::cerr << WarningMsg("Invalid mnemonic") << std::endl;
        return false;
    }
    sodium_memzero(&mnemonic[0], mnemonic.size());
    std::copy(std::begin(seedKey.data), std::end(seedKey.data), seedOut.begin());
    sodium_memzero(&seedKey, sizeof(seedKey));
    return true;
}

// Print the signer's Discrete address (to bake into DNS_CHECKPOINT_SIGNERS) and
// its advisory key_id.
static bool checkpoint_key(const po::variables_map& vm, Currency& currency,
                           Logging::ILogger& log) {
    CryptoPQ::SeedMaster seed{};
    if (!load_signer_seed(vm, log, seed)) return false;

    auto view  = CryptoPQ::deriveViewKeys(seed);
    auto spend = CryptoPQ::deriveSpendKeys(seed);
    sodium_memzero(seed.data(), seed.size());

    CryptoNote::PqAddress addr =
        CryptoNote::makePqAddress(currency.publicAddressBase58Prefix(), view.first, spend.first);
    const std::string address =
        CryptoNote::encodePqAddress(addr, CryptoNote::pqBech32Hrp(currency.isTestnet()));

    std::cout << SuccessMsg("\nCheckpoint signer\n");
    std::cout << "  address: " << address << "\n";
    std::cout << "  key_id:  " << CryptoNote::checkpointKeyId(spend.first) << "\n\n";
    std::cout << "Add the address to DNS_CHECKPOINT_SIGNERS in src/CryptoNoteConfig.h.\n";
    return true;
}

// Sign a checkpoint: write the canonical JSON file and print the TXT pointer.
// Nothing is uploaded or published from here — the maintainer uploads the file
// first, then updates the TXT record.
static bool sign_checkpoint(const po::variables_map& vm, Currency& currency,
                            Logging::ILogger& log) {
    const uint32_t height = command_line::get_arg(vm, command_line::arg_height);
    std::string blockHashHex = command_line::get_arg(vm, command_line::arg_block_hash);

    if (height == 0) {
        std::cerr << WarningMsg("--height is required and must be non-zero") << std::endl;
        return false;
    }
    // Accept an upper-case hash (explorers vary); the signed payload and the JSON
    // always use the lowercase form.
    std::transform(blockHashHex.begin(), blockHashHex.end(), blockHashHex.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    Crypto::Hash blockHash{};
    if (blockHashHex.size() != 64 || !Common::podFromHex(blockHashHex, blockHash)) {
        std::cerr << WarningMsg("--block-hash must be 64 hex characters") << std::endl;
        return false;
    }

    CryptoPQ::SeedMaster seed{};
    if (!load_signer_seed(vm, log, seed)) return false;
    auto spend = CryptoPQ::deriveSpendKeys(seed);
    sodium_memzero(seed.data(), seed.size());

    const std::string network = currency.isTestnet() ? "testnet" : "mainnet";
    const std::string genesisHex = Common::podToHex(currency.genesisBlockHash());

    // Sign the genesis-bound, domain-separated payload.
    const std::string payload =
        CryptoNote::buildCheckpointSignedPayload(genesisHex, network, height, blockHashHex);
    const std::string signature = CryptoNote::signMessagePq(payload, spend.second);

    CryptoNote::CheckpointRecord rec;
    rec.version   = 1;
    rec.network   = network;
    rec.height    = height;
    rec.blockHash = blockHash;
    rec.sigAlg    = CryptoNote::kCheckpointSigAlg;
    rec.keyId     = CryptoNote::checkpointKeyId(spend.first);
    rec.signature = signature;

    const std::string json = CryptoNote::serializeCheckpointJsonCanonical(rec);

    // Self-check before publishing: re-verify the bytes we are about to write
    // against our own public key, so a broken signer never ships a dead record.
    {
        CryptoNote::CheckpointPointer selfPtr;
        selfPtr.version   = 1;
        selfPtr.alg       = "sha256";
        selfPtr.height    = height;
        selfPtr.sha256Hex = CryptoNote::sha256Hex(json);
        selfPtr.host      = CryptoNote::kCheckpointHost;
        CryptoNote::CheckpointRecord back;
        std::string reject;
        if (CryptoNote::verifyCheckpointFile(json, selfPtr, {spend.first},
                                             currency.genesisBlockHash(), network,
                                             back, reject) !=
            CryptoNote::CheckpointStatus::Accepted) {
            std::cerr << WarningMsg("Self-verification failed: " + reject) << std::endl;
            return false;
        }
    }

    std::string outDir = command_line::get_arg(vm, command_line::arg_out_dir);
    if (!outDir.empty() && outDir.back() != '/' && outDir.back() != '\\') outDir += '/';
    const std::string fileName = outDir + std::to_string(height) + ".json";

    {
        // Binary mode: the file hash must cover exactly these bytes, so no
        // platform newline translation may touch them.
        std::ofstream out(fileName, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
        if (!out) {
            std::cerr << WarningMsg("Cannot write " + fileName) << std::endl;
            return false;
        }
        out << json;
    }

    const std::string fileHash = CryptoNote::sha256Hex(json);
    const std::string url = std::string("https://") + CryptoNote::kCheckpointHost +
                            "/checkpoints/" + std::to_string(height) + ".json";
    std::ostringstream txt;
    txt << "v=1;alg=sha256;height=" << height << ";hash=" << fileHash << ";url=" << url;
    const std::string txtRecord = txt.str();

    // Guard against ever emitting an unpublishable record again. A TXT record is
    // chunked into <=255-byte character-strings, each costing one length byte on
    // the wire, and the whole rdata must stay under 4096 wire bytes.
    const size_t wireBytes = txtRecord.size() + (txtRecord.size() + 254) / 255;
    if (wireBytes >= 4096) {
        std::cerr << WarningMsg("Refusing to emit a TXT record of " +
                                std::to_string(wireBytes) + " wire bytes (limit 4096)") << std::endl;
        return false;
    }

    std::cout << SuccessMsg("\nSigned checkpoint " + std::to_string(height) + "\n");
    std::cout << "  network:    " << network << "\n";
    std::cout << "  block hash: " << blockHashHex << "\n";
    std::cout << "  file:       " << fileName << "  (" << json.size() << " bytes)\n";
    std::cout << "  file sha256:" << fileHash << "\n";
    std::cout << "  key_id:     " << rec.keyId << "\n";
    std::cout << "  TXT size:   " << wireBytes << " wire bytes\n\n";
    std::cout << InformationMsg("1. Upload the file to " + url + "\n");
    std::cout << InformationMsg("2. Verify:  admin-tools --verify-checkpoint --txt \"<record below>\"\n");
    std::cout << InformationMsg("3. Then set the TXT record at " +
                                std::string(CryptoNote::DNS_CHECKPOINTS_HOST) + " to:\n\n");
    std::cout << txtRecord << "\n\n";
    return true;
}

// Verify a checkpoint against the signers baked into this build — either a live
// pointer (fetching the file over HTTPS) or a local JSON file.
static bool verify_checkpoint(const po::variables_map& vm, Currency& currency) {
    const std::string txtRecord = command_line::get_arg(vm, command_line::arg_txt);
    const std::string jsonFile  = command_line::get_arg(vm, command_line::arg_json_file);

    if (txtRecord.empty() && jsonFile.empty()) {
        std::cerr << WarningMsg("Pass --txt \"<record>\" or --json-file <path>") << std::endl;
        return false;
    }

    // Signers come from the build config, so this checks exactly what a node would.
    std::vector<CryptoPQ::DsaPublicKey> signers;
    for (size_t i = 0; i < CryptoNote::DNS_CHECKPOINT_SIGNERS_COUNT; ++i) {
        CryptoNote::PqAddress addr;
        if (CryptoNote::decodePqAddress(CryptoNote::DNS_CHECKPOINT_SIGNERS[i], addr)) {
            signers.push_back(addr.spendPub);
        } else {
            std::cerr << WarningMsg("DNS_CHECKPOINT_SIGNERS[" + std::to_string(i) +
                                    "] is not a valid Discrete address; skipping") << std::endl;
        }
    }
    if (signers.empty()) {
        std::cerr << WarningMsg("No usable signers in DNS_CHECKPOINT_SIGNERS; nothing can verify")
                  << std::endl;
        return false;
    }

    std::string fileBytes;
    CryptoNote::CheckpointPointer ptr;
    std::string reject;

    if (!txtRecord.empty()) {
        if (!CryptoNote::parseCheckpointPointer(txtRecord, ptr, reject)) {
            std::cerr << WarningMsg("FAIL: bad TXT pointer: " + reject) << std::endl;
            return false;
        }
        std::cout << "Fetching " << ptr.url << " ...\n";
        System::Dispatcher dispatcher;
        std::string err;
        if (!CryptoNote::downloadCheckpointFile(dispatcher, ptr, fileBytes, err)) {
            std::cerr << WarningMsg("FAIL: " + err) << std::endl;
            return false;
        }
    } else {
        std::ifstream in(jsonFile, std::ifstream::in | std::ifstream::binary);
        if (!in) {
            std::cerr << WarningMsg("Cannot read " + jsonFile) << std::endl;
            return false;
        }
        fileBytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());

        // No TXT pointer to cross-check against, so synthesize one from the file
        // itself: its own hash and its own height. The schema and signature are
        // still fully checked, but a TXT/JSON height or hash DISAGREEMENT cannot
        // be caught here by construction — use --txt for the real end-to-end check
        // before publishing.
        ptr.version   = 1;
        ptr.alg       = "sha256";
        ptr.sha256Hex = CryptoNote::sha256Hex(fileBytes);
        ptr.host      = CryptoNote::kCheckpointHost;
        {
            Common::JsonValue probe;
            try {
                probe = Common::JsonValue::fromString(fileBytes);
            } catch (const std::exception&) {
                std::cerr << WarningMsg("FAIL: json parse failed") << std::endl;
                return false;
            }
            if (!probe.isObject() || !probe.contains("height") || !probe("height").isInteger()) {
                std::cerr << WarningMsg("FAIL: json missing height") << std::endl;
                return false;
            }
            const int64_t h = probe("height").getInteger();
            if (h < 0 || h > 0xFFFFFFFFll) {
                std::cerr << WarningMsg("FAIL: json height out of range") << std::endl;
                return false;
            }
            ptr.height = static_cast<uint32_t>(h);
        }
        std::cout << "Verifying local file " << jsonFile << " ...\n";
    }

    const std::string network = currency.isTestnet() ? "testnet" : "mainnet";
    CryptoNote::CheckpointRecord rec;
    const CryptoNote::CheckpointStatus st =
        CryptoNote::verifyCheckpointFile(fileBytes, ptr, signers, currency.genesisBlockHash(),
                                         network, rec, reject);
    if (st != CryptoNote::CheckpointStatus::Accepted) {
        std::cerr << WarningMsg("FAIL: " + reject) << std::endl;
        return false;
    }

    std::cout << SuccessMsg("\nPASS\n");
    std::cout << "  network:    " << rec.network << "\n";
    std::cout << "  height:     " << rec.height << "\n";
    std::cout << "  block hash: " << Common::podToHex(rec.blockHash) << "\n";
    std::cout << "  key_id:     " << rec.keyId << "\n";
    return true;
}

int main(int argc, char** argv) {
    LoggerManager logManager;
    LoggerRef logger(logManager, "admin-tools");

    CurrencyBuilder builder(logManager);
    Currency currency = builder.currency();

    std::string coinName(CryptoNote::CRYPTONOTE_NAME);
    std::cout << InformationMsg(coinName + " admin tools v. " + std::string(PROJECT_VERSION)) << std::endl;

    try {
        po::options_description desc_cmd_only("Available command line options");

        command_line::add_arg(desc_cmd_only, command_line::arg_file);
        command_line::add_arg(desc_cmd_only, command_line::arg_treasury_reserve);
        command_line::add_arg(desc_cmd_only, command_line::arg_sign_checkpoint);
        command_line::add_arg(desc_cmd_only, command_line::arg_checkpoint_key);
        command_line::add_arg(desc_cmd_only, command_line::arg_verify_checkpoint);
        command_line::add_arg(desc_cmd_only, command_line::arg_height);
        command_line::add_arg(desc_cmd_only, command_line::arg_block_hash);
        command_line::add_arg(desc_cmd_only, command_line::arg_wallet_file);
        command_line::add_arg(desc_cmd_only, command_line::arg_out_dir);
        command_line::add_arg(desc_cmd_only, command_line::arg_txt);
        command_line::add_arg(desc_cmd_only, command_line::arg_json_file);
        command_line::add_arg(desc_cmd_only, command_line::arg_help);

        bool r = command_line::handle_error_helper(desc_cmd_only, [&]()
        {
            po::variables_map vm;
            po::store(po::parse_command_line(argc, argv, desc_cmd_only), vm);

            if (command_line::get_arg(vm, command_line::arg_treasury_reserve) > 0) {
                return generate_treasury_reserve_accounts(vm, currency);
            }
            if (command_line::get_arg(vm, command_line::arg_checkpoint_key)) {
                return checkpoint_key(vm, currency, logManager);
            }
            if (command_line::get_arg(vm, command_line::arg_sign_checkpoint)) {
                return sign_checkpoint(vm, currency, logManager);
            }
            if (command_line::get_arg(vm, command_line::arg_verify_checkpoint)) {
                return verify_checkpoint(vm, currency);
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
