// Copyright (c) 2016-2026, The Karbo developers
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
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include "BuiltinExplorer.h"

#include "RpcServer.h"
#include "version.h"

#include <ctime>
#include <array>
#include <list>
#include <string>
#include <vector>

#include <crypto/crypto.h>
#include <crypto/random.h>
#include "BlockchainExplorerData.h"
#include "Common/StringTools.h"
#include "AccountNumber.h"
#include "PqAddress.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "PqTxType.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "P2p/NetNode.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

namespace CryptoNote {

namespace {

// Common page chrome — opening <html>…<body> with the SVG logo and the
// node version, plus the closing tags. Held here because every explorer
// page renders them. Palette matches the discrete-cash website: dark
// background, whitish text, mint (#5FE29F) accent.
const std::string index_start =
R"(<!DOCTYPE html><html><head><meta http-equiv='refresh' content='60'/>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 600 600'><g fill='none' stroke='%235FE29F' stroke-width='40' stroke-miterlimit='10'><circle cx='297.4' cy='300.4' r='264.8'/><line x1='300.4' y1='35.2' x2='300.4' y2='564.8'/><line x1='211.1' y1='50.4' x2='211.1' y2='550.8'/><line x1='124' y1='100.2' x2='124' y2='500.6'/></g></svg>"/>
<style>
:root { color-scheme: dark; }
* { font-family: monospace; }
body { background: #0D1115; color: #AEB8BF; }
h1, h2, h3, b, th { color: #E4E9EC; }
a { color: #5FE29F; text-decoration: none; }
a:hover { text-decoration: underline; }
::selection { background: #5FE29F; color: #08110D; }
.wrap { word-break: break-all; word-wrap: break-word; }
table { border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; border-bottom: 1px solid rgba(154,167,178,.25); }
table.counter tbody tr td:first-child { text-align: right; }
details summary { cursor: pointer; color: #9AA7B2; }
details p { margin: 4px 0; }
hr { border: none; border-top: 1px solid rgba(154,167,178,.25); }
input[type=text] { background: #10171B; color: #E4E9EC; border: 1px solid rgba(154,167,178,.32); border-radius: 6px; padding: 6px 10px; }
input[type=submit] { background: #5FE29F; color: #08110D; border: none; border-radius: 6px; padding: 6px 14px; cursor: pointer; }
</style></head><body>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 600" width="48" height="48" style="vertical-align:middle; padding-right: 10px;">
<g fill="none" stroke="#5FE29F" stroke-width="40" stroke-miterlimit="10"><circle cx="297.4" cy="300.4" r="264.8"/><line x1="300.4" y1="35.2" x2="300.4" y2="564.8"/><line x1="211.1" y1="50.4" x2="211.1" y2="550.8"/><line x1="124" y1="100.2" x2="124" y2="500.6"/></g></svg>
)" + std::string(CRYPTONOTE_NAME) + " node v. " PROJECT_VERSION_LONG R"( &bull; )";

const std::string index_finish = " </body></html>";

// Collapsible hex dump for large binary fields (ML-DSA/ML-KEM keys and
// signatures run to kilobytes). Closed it reads "<summary> (N bytes)"; open it
// shows the full hex.
std::string foldedHex(const std::string& summary, const uint8_t* data, size_t size) {
  return "<details><summary>" + summary + " (" + std::to_string(size) +
         " bytes)</summary><p class=\"wrap\">" + Common::toHex(data, size) + "</p></details>";
}

const char* txTypeName(uint8_t txType) {
  switch (txType) {
    case TX_COINBASE: return "coinbase";
    case TX_PQ:       return "transfer";
    case TX_FREE_REG: return "account registration";
    default:          return "unknown";
  }
}

} // anonymous namespace

BuiltinExplorer::BuiltinExplorer(Core& core,
                                 NodeServer& p2p,
                                 const ICryptoNoteProtocolQuery& protocolQuery,
                                 BlockchainExplorerDataBuilder& explorerBuilder,
                                 RpcServer& parent)
  : m_core(core)
  , m_p2p(p2p)
  , m_protocolQuery(protocolQuery)
  , m_explorerBuilder(explorerBuilder)
  , m_parent(parent)
{}

// ── Status pages ────────────────────────────────────────────────────────

bool BuiltinExplorer::on_get_index(const COMMAND_HTTP::request& /*req*/, COMMAND_HTTP::response& res) {
  const std::time_t uptime = std::time(nullptr) - m_core.getStartTime();
  const std::string uptime_str = std::to_string((unsigned int)floor(uptime / 60.0 / 60.0 / 24.0)) + "d " + std::to_string((unsigned int)floor(fmod((uptime / 60.0 / 60.0), 24.0))) + "h "
    + std::to_string((unsigned int)floor(fmod((uptime / 60.0), 60.0))) + "m " + std::to_string((unsigned int)fmod(uptime, 60.0)) + "s";
  uint32_t top_block_index = m_core.getCurrentBlockchainHeight() - 1;
  uint32_t top_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  size_t outConn = m_p2p.get_outgoing_connections_count();
  size_t incConn = m_p2p.get_connections_count() - outConn;
  Crypto::Hash last_block_hash = m_core.getBlockIdByHeight(top_block_index);
  size_t white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  size_t grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  size_t alt_blocks_count = m_core.getAlternativeBlocksCount();
  size_t total_tx_count = m_core.getBlockchainTotalTransactions() - top_block_index + 1;
  size_t tx_pool_count = m_core.getPoolTransactionsCount();

  const std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") +
    "<ul>" +
      "<li>" + "Synchronization status: " + std::to_string(top_block_index) + "/" + std::to_string(top_known_block_index) +
      "<li>" + "Last block hash: " + Common::podToHex(last_block_hash) + "</li>" +
      "<li>" + "Difficulty: " + std::to_string(m_core.getNextBlockDifficulty()) + "</li>" +
      "<li>" + "Alt. blocks: " + std::to_string(alt_blocks_count) + "</li>" +
      "<li>" + "Total transactions in network: " + std::to_string(total_tx_count) + "</li>" +
      "<li>" + "Transactions in pool: " + std::to_string(tx_pool_count) + "</li>" +
      "<li>" + "Connections:" +
        "<ul>" +
          "<li>" + "RPC: " + std::to_string(m_parent.getRpcConnectionsCount()) + "</li>" +
          "<li>" + "OUT: " + std::to_string(outConn) + "</li>" +
          "<li>" + "INC: " + std::to_string(incConn) + "</li>" +
        "</ul>" +
      "</li>" +
      "<li>" + "Peers: " + std::to_string(white_peerlist_size) + " white, " + std::to_string(grey_peerlist_size) + " grey" + "</li>" +
      "<li>" + "Uptime: " + uptime_str + "</li>" +
    "</ul>" +
    index_finish;

  res = body;

  return true;
}

bool BuiltinExplorer::on_get_supply(const COMMAND_HTTP::request& /*req*/, COMMAND_HTTP::response& res) {
  std::string already_generated_coins = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  res = already_generated_coins;

  return true;
}

bool BuiltinExplorer::on_get_payment_id(const COMMAND_HTTP::request& /*req*/, COMMAND_HTTP::response& res) {
  Crypto::Hash result;
  Random::randomBytes(32, result.data);
  res = Common::podToHex(result);

  return true;
}

// ── Block-explorer pages ───────────────────────────────────────────────

bool BuiltinExplorer::on_get_explorer(const COMMAND_EXPLORER::request& req, COMMAND_EXPLORER::response& res) {
  uint32_t top_block_index = m_core.getCurrentBlockchainHeight() - 1;
  std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") +
    "\n<p>" + "Height: <b>" + std::to_string(top_block_index) + "</b>" +
    " &bull; " + "Difficulty: <b>" + std::to_string(m_core.getNextBlockDifficulty()) + "</b>" +
    " &bull; " + "Alt. blocks: <b>" + std::to_string(m_core.getAlternativeBlocksCount()) + "</b>" +
    " &bull; " + "Transactions: <b>" + std::to_string(m_core.getBlockchainTotalTransactions() - top_block_index + 1) + "</b>" +
    " &bull; " + "Emission: <b>" + m_core.currency().formatAmount(m_core.getTotalGeneratedAmount()) + "</b>" +
    " &bull; " + "Next reward: <b>" + m_core.currency().formatAmount(m_core.currency().calculateReward(m_core.getTotalGeneratedAmount())) + "</b>" +
    "</p>\n";

  const uint32_t print_blocks_count = 10;
  // Clamp to the actual chain: a fresh chain shorter than one page used to make
  // the loop below ask for nonexistent heights and 500 the whole page.
  uint32_t req_height = std::min<uint32_t>(req.height == 0 ? top_block_index : req.height, top_block_index);
  uint32_t last_height = req_height >= print_blocks_count ? req_height - (print_blocks_count - 1) : 0;

  // Search
  body += R"(
  <form style='padding: 10px;' name='searchform' action='javascript:handleSearch()'>
    <input type='text' name='search' id='txt_search' size='80' placeholder='Search by block height/hash, tx hash, payment id, account number, address...'>
    <input type='submit' value='Search'>
  </form>
  <script>
  function handleSearch() {
    var search_str = document.getElementById('txt_search').value;
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/json_rpc', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
      method: 'search',
      params: {
        query: search_str
      }
    }));
    xhr.onload = function() {
      var data = JSON.parse(this.responseText);
      if (data.result) {
        window.location.href = data.result.result;
      } else if (data.error) {
        alert(data.error.message);
      }
    }
  }
  </script>)";

  // show mempool only on home page
  if (req_height == top_block_index) {
    auto pool = m_core.getMemoryPool();
    if (!pool.empty()) {
      body += "<h2>Transaction pool</h2>";
      body += "<table cellpadding=\"10px\">\n";
      body += "  <thead>\n";
      body += "  <tr>\n";
      body += "    <th>Date</th><th>Hash</th><th>Amount</th><th>Fee</th><th>Size</th>\n";
      body += "  </tr>\n";
      body += "</thead>\n";
      body += "<tbody>\n";
      for (const CryptoNote::tx_memory_pool::TransactionDetails& txd : pool) {
        time_t rawtime = (const time_t)txd.receiveTime;
        struct tm* timeinfo;
        timeinfo = gmtime(&rawtime);
        std::string txHashStr = Common::podToHex(txd.id);

        body += "  <tr>\n";
        body += "    <td>";
        body += asctime(timeinfo);
        body.pop_back(); // remove newline after asctime
        body += "</td>\n    <td>";
        body += "<a class=\"wrap\" href=\"/explorer/tx/" + txHashStr + "\">";
        body += txHashStr;
        body += "</a>";
        body += "</td>\n    <td>";
        body += m_core.currency().formatAmount(getOutputAmount(txd.tx));
        body += "</td>\n    <td>";
        body += m_core.currency().formatAmount(txd.fee);
        body += "</td>\n    <td>";
        body += std::to_string(txd.blobSize);
        body += "</td>\n";
        body += "  </tr>\n";
      }
      body += "</tbody>\n";
      body += "</table>\n";
    }
  }

  // list last 10 blocks with txs
  body += "<h2>Blocks</h2>";
  body += "<table cellpadding=\"10px\">\n";
  body += "  <thead>\n";
  body += "  <tr>\n";
  body += "    <th>Height</th><th>Date</th><th>Hash</th><th>Size</th><th>Difficulty</th><th>Txs</th>\n";
  body += "  </tr>\n";
  body += "</thead>\n";
  body += "<tbody>\n";

  // Inclusive [last_height, req_height], newest first — the old exclusive lower
  // bound could never show the genesis block.
  for (uint32_t i = req_height; ; i--) {
    Crypto::Hash blockHash = m_core.getBlockIdByHeight(i);
    Block blk;
    if (!m_core.getBlockByHash(blockHash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }

    time_t rawtime = (const time_t)blk.timestamp;
    struct tm* timeinfo;
    timeinfo = gmtime(&rawtime);

    Difficulty blockDifficulty;
    m_core.getBlockDifficulty(static_cast<uint32_t>(i), blockDifficulty);
    size_t tx_cumulative_block_size;
    m_core.getBlockSize(blockHash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    uint64_t blockSize = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;

    body += "  <tr>\n";
    body += "    <td>";
    body += std::to_string(i);
    body += "</td>\n    <td>";
    body += asctime(timeinfo);
    body.pop_back(); // remove newline after asctime
    body += "</td>\n    <td>";
    body += "<a class=\"wrap\" href=\"/explorer/block/" + Common::podToHex(blockHash) + "\">";
    body += Common::podToHex(blockHash);
    body += "</a>";
    body += "</td>\n    <td>";
    body += std::to_string(blockSize);
    body += "</td>\n    <td>";
    body += std::to_string(blockDifficulty);
    body += "</td>\n    <td>";
    body += std::to_string(blk.transactionHashes.size() + 1);
    body += "</td>\n";
    body += "  </tr>\n";

    if (i == last_height)
      break;
  }

  body += "</tbody>\n";
  body += "</table>\n";

  uint32_t curr_page = req_height == 0 ? 0 : (top_block_index - req_height) / print_blocks_count;
  uint32_t total_pages = top_block_index / print_blocks_count;
  uint32_t next_page = req_height - print_blocks_count;
  uint32_t prev_page = std::min<uint32_t>(req_height + print_blocks_count, top_block_index);

  body += "<p>";
  if (curr_page != 0) {
    if (prev_page <= top_block_index - print_blocks_count) {
      body += "<a href=\"/explorer/height/";
      body += std::to_string(prev_page);
      body += "\">previous page</a> | ";
    }
    body += "<a href=\"/explorer/\">first page</a> | ";
  }
  body += "current page: ";
  body += std::to_string(curr_page);
  body += " / ";
  body += std::to_string(total_pages);
  if (req_height != 0 && req_height > print_blocks_count) {
    body += " | <a href=\"/explorer/height/";
    body += std::to_string(next_page);
    body += "\">next page</a></p>";
  }

  body += index_finish;

  res = body;

  return true;
}

bool BuiltinExplorer::on_explorer_search(const COMMAND_RPC_EXPLORER_SEARCH::request& req, COMMAND_RPC_EXPLORER_SEARCH::response& res) {
  // Try as address (PQ bech32m for this network, or an H-I-A-C / H-I-A-T-C account number)
  {
    PqAddress pq;
    AccountNumber acct;
    uint32_t subaddrIndex = 0;
    if (decodePqAddress(req.query, m_core.currency().isTestnet(), pq) ||
        AccountNumber::fromStringWithIndex(req.query, acct, subaddrIndex) ||
        AccountNumber::fromString(req.query, acct)) {
      res.result = "/explorer/address/" + req.query;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }
  }

  Crypto::Hash hash;

  if (req.query.size() < 64) {
    // assume it's height
    uint32_t height = static_cast<uint32_t>(std::stoul(req.query));
    hash = m_core.getBlockIdByHeight(height);
  }
  else if (!parse_hash256(req.query, hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse query: " + req.query };
  }

  // check if it's block
  if (m_core.have_block(hash)) {
    res.result = "/explorer/block/" + Common::podToHex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  // check if it's tx
  if (m_core.haveTransaction(hash)) {
    res.result = "/explorer/tx/" + Common::podToHex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  // check if it's payment id
  std::vector<Crypto::Hash> txHashes = m_core.getTransactionHashesByPaymentId(hash);
  if (!txHashes.empty()) {
    res.result = "/explorer/payment_id/" + Common::podToHex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Not found" };

  return true;
}

bool BuiltinExplorer::on_get_explorer_block_by_hash(const COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::response& res) {
  try {
    Crypto::Hash block_hash;
    if (!parse_hash256(req.hash, block_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
    }
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
    }

    Crypto::Hash blockHash = get_block_hash(blk);
    uint32_t blockIndex = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;

    std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") + "\n<p>";

    body += "<a href=\"/explorer/\">Home</a>";
    body += "<hr />";

    body += "<h2>Block ID <span class=\"wrap\">" + Common::podToHex(blockHash) + "</span></h2>\n";

    body += "<ul>\n";
    body += "  <li>\n";
    body += "    Index: " + std::to_string(blockIndex) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    time_t rawtime = (const time_t)blk.timestamp;
    struct tm* timeinfo;
    timeinfo = gmtime(&rawtime);
    body += "    Time: " + std::to_string(blk.timestamp) + " &bull; ";
    body += asctime(timeinfo);
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    \tVersion: " + std::to_string(blk.majorVersion) + "." + std::to_string(blk.minorVersion) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    Crypto::Hash tmpHash = m_core.getBlockIdByHeight(blockIndex);
    bool isOrphaned = blockHash != tmpHash;
    body += "    \tOrphan: ";
    if (isOrphaned)
      body += "YES\n";
    else
      body += "NO\n";
    body += "  </li>\n";
    body += "  <li>\n";
    size_t tx_cumulative_block_size;
    m_core.getBlockSize(blockHash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    size_t blockSize = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    body += "    \tSize: " + std::to_string(blockSize) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    uint64_t blockDifficulty = 0;
    if (!m_core.getBlockDifficulty(blockIndex, blockDifficulty)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't calcualate difficulty for block " + req.hash + '.' };
    }
    body += "    Difficulty: " + std::to_string(blockDifficulty) + "\n";
    body += "  </li>\n";

    // Fetch the block's transactions once: the header shows reward and total
    // fees, the table below shows per-tx details instead of bare hashes.
    std::list<Crypto::Hash> missedTxs;
    std::list<Transaction> blockTxs;
    if (!blk.transactionHashes.empty()) {
      std::vector<Crypto::Hash> txHashes(blk.transactionHashes.begin(), blk.transactionHashes.end());
      m_core.getTransactions(txHashes, blockTxs, missedTxs, true);
    }
    uint64_t totalFees = 0;
    for (const Transaction& tx : blockTxs) {
      uint64_t fee = 0;
      if (tx.txType == TX_PQ && m_core.getPqTransactionFee(tx, fee)) {
        totalFees += fee;
      }
    }

    body += "  <li>\n";
    body += "    Reward: " + m_core.currency().formatAmount(get_outs_money_amount(blk.baseTransaction)) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Fees: " + m_core.currency().formatAmount(totalFees) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Previous block: ";
    body += "<a class=\"wrap\" href=\"/explorer/block/" + Common::podToHex(blk.previousBlockHash) + "\">";
    body += Common::podToHex(blk.previousBlockHash);
    body += "</a>\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    " + foldedHex("PoW signature, ML-DSA-65", blk.signature.data(), blk.signature.size()) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Signature witness (W_B): <span class=\"wrap\">" +
      Common::podToHex(get_block_signature_witness(blk.signature)) + "</span>\n";
    body += "  </li>\n";
    body += "</ul>";

    body += "<h3>Transactions</h3>\n";

    body += "<table cellpadding=\"10px\">\n";
    body += "  <thead>\n";
    body += "  <tr>\n";
    body += "    <th>Hash</th><th>Type</th><th>Amount</th><th>Fee</th><th>Size</th>\n";
    body += "  </tr>\n";
    body += "</thead>\n";
    body += "<tbody>\n";

    auto appendTxRow = [&](const Transaction& tx) {
      const std::string hashStr = Common::podToHex(getObjectHash(tx));
      uint64_t fee = 0;
      const bool paysFee = tx.txType == TX_PQ && m_core.getPqTransactionFee(tx, fee);
      body += "  <tr>\n";
      body += "    <td><a class=\"wrap\" href=\"/explorer/tx/" + hashStr + "\">" + hashStr + "</a></td>\n";
      body += "    <td>" + std::string(txTypeName(tx.txType)) + "</td>\n";
      body += "    <td>" + m_core.currency().formatAmount(get_outs_money_amount(tx)) + "</td>\n";
      body += "    <td>" + (paysFee ? m_core.currency().formatAmount(fee) : std::string("&mdash;")) + "</td>\n";
      body += "    <td>" + std::to_string(getObjectBinarySize(tx)) + "</td>\n";
      body += "  </tr>\n";
    };

    appendTxRow(blk.baseTransaction);
    for (const Transaction& tx : blockTxs) {
      appendTxRow(tx);
    }

    body += "</tbody>\n";
    body += "</table>\n";

    body += index_finish;

    res = body;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }

  return true;
}

bool BuiltinExplorer::on_get_explorer_tx_by_hash(const COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::response& res) {
  try {
    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    std::vector<Crypto::Hash> hashes;
    Crypto::Hash tx_hash;
    if (!parse_hash256(req.hash, tx_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
    }
    hashes.push_back(tx_hash);
    m_core.getTransactions(hashes, txs, missed_txs, true);

    if (txs.empty() || !missed_txs.empty()) {
      std::string hash_str = Common::podToHex(missed_txs.back());
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "transaction wasn't found. Hash = " + hash_str + '.' };
    }

    TransactionDetails transactionsDetails;
    if (!m_explorerBuilder.fillTransactionDetails(txs.back(), transactionsDetails)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't fill transaction details." };
    }

    std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") + "\n<p>";

    body += "<a href=\"/explorer/\">Home</a>";
    body += "<hr />";

    body += "<h2>Transaction <span class=\"wrap\">" + Common::podToHex(transactionsDetails.hash) + "</span></h2>\n";

    body += "<ul>\n";
    if (transactionsDetails.inBlockchain) {
      body += "  <li>\n";
      body += "    In block: ";
      body += "<a class=\"wrap\" href=\"/explorer/block/" + Common::podToHex(transactionsDetails.blockHash) + "\">";
      body += std::to_string(transactionsDetails.blockHeight) + " (" + Common::podToHex(transactionsDetails.blockHash) + ")";
      body += "    </a>\n";
      body += "  </li>\n";
      body += "  <li>\n";
      time_t rawtime = (const time_t)transactionsDetails.timestamp;
      struct tm* timeinfo;
      timeinfo = gmtime(&rawtime);
      body += "    First confirmation time: ";
      body += asctime(timeinfo);
      body += "  </li>\n";
    }
    else {
      body += "  <li>\n";
      body += "    Unconfirmed\n";
      body += "  </li>\n";
    }
    const bool isCoinbase = transactionsDetails.txType == TX_COINBASE;
    body += "  <li>\n";
    body += "    Type: " + std::string(txTypeName(transactionsDetails.txType)) + " (v" + std::to_string(transactionsDetails.version) + ")\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += std::string(isCoinbase ? "    Reward: " : "    Sum of outputs: ") + m_core.currency().formatAmount(transactionsDetails.totalOutputsAmount) + "\n";
    body += "  </li>\n";
    if (transactionsDetails.txType == TX_PQ) {
      body += "  <li>\n";
      body += "    Fee: " + m_core.currency().formatAmount(transactionsDetails.fee) + "\n";
      body += "  </li>\n";
    } else if (transactionsDetails.txType == TX_FREE_REG) {
      body += "  <li>\n";
      body += "    Fee: none (priced by anti-spam proof-of-work)\n";
      body += "  </li>\n";
    }
    body += "  <li>\n";
    body += "    Size: " + std::to_string(transactionsDetails.size) + " bytes\n";
    body += "  </li>\n";
    if (transactionsDetails.unlockHeight != 0) {
      body += "  <li>\n";
      body += "    Unlocks at height: " + std::to_string(transactionsDetails.unlockHeight) + "\n";
      body += "  </li>\n";
    }
    if (transactionsDetails.hasPaymentId) {
      body += "  <li>\n";
      body += "    Payment ID: <span class=\"wrap\">" + Common::podToHex(transactionsDetails.paymentId) + "</span>\n";
      body += "  </li>\n";
    }
    if (!transactionsDetails.extra.raw.empty()) {
      body += "  <li>\n";
      body += "    " + foldedHex("Extra", transactionsDetails.extra.raw.data(), transactionsDetails.extra.raw.size()) + "\n";
      body += "  </li>\n";
    }
    if (isCoinbase) {
      std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> minerSpendPub;
      if (getPqMinerSpendPubFromExtra(txs.back().extra, minerSpendPub)) {
        body += "  <li>\n";
        body += "    " + foldedHex("Miner spend public key, ML-DSA-65", minerSpendPub.data(), minerSpendPub.size()) + "\n";
        body += "  </li>\n";
      }
    }
    // Check for account registration in tx extra
    {
      TransactionExtraPqAccountRegistration reg;
      if (getPqAccountRegistrationFromExtra(txs.back().extra, reg)) {
        body += "  <li>\n";
        body += "    Registers account identity: <span class=\"wrap\">" + Common::podToHex(getPqAccountIdentityHash(reg)) + "</span>\n";
        body += "  </li>\n";
        body += "  <li>\n";
        body += "    " + foldedHex("View public key, ML-KEM-768", reg.viewPub.data(), reg.viewPub.size()) + "\n";
        body += "  </li>\n";
        body += "  <li>\n";
        body += "    " + foldedHex("Spend public key, ML-DSA-65", reg.spendPub.data(), reg.spendPub.size()) + "\n";
        body += "  </li>\n";

        if (transactionsDetails.inBlockchain) {
          uint32_t bh = transactionsDetails.blockHeight;
          std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> viewPub;
          std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub;
          for (uint32_t i = 0; i < 1000; ++i) {
            if (m_core.resolvePqAccountNumber(bh, i, viewPub, spendPub) &&
                viewPub == reg.viewPub && spendPub == reg.spendPub) {
              AccountNumber an{bh, i};
              uint32_t fp = pqAccountFingerprint(
                  m_core.currency().isTestnet(), reg.spendPub.data(), reg.spendPub.size(),
                  reg.viewPub.data(), reg.viewPub.size());
              body += "  <li>\n";
              body += "    Account number: " + an.toString(fp) + "\n";
              body += "  </li>\n";
              break;
            }
          }
        }
      }
    }
    body += "</ul>\n";

    body += "<h3>Inputs</h3>\n";

    body += "<table class=\"counter\" cellpadding=\"10px\">\n";
    body += "  <thead>\n";
    body += "  <tr>\n";
    body += "    <th>No</th><th>Amount</th><th>Nullifier</th><th>Spent output</th>\n";
    body += "  </tr>\n";
    body += "</thead>\n";
    body += "<tbody>\n";
    for (size_t i = 0; i < transactionsDetails.inputs.size(); ++i) {
      const auto& in = transactionsDetails.inputs[i];
      body += "  <tr>\n";
      body += "    <td>" + std::to_string(i) + ")</td>";
      body += "    <td>";
      if (in.type() == typeid(BaseInputDetails)) {
        BaseInputDetails c = boost::get<BaseInputDetails>(in);
        body += m_core.currency().formatAmount(c.amount);
        body += "</td>\n    <td colspan=\"2\">coinbase</td>\n";
      }
      else if (in.type() == typeid(KeyInputDetails)) {
        KeyInputDetails k = boost::get<KeyInputDetails>(in);
        body += m_core.currency().formatAmount(k.input.amount);
        body += "</td>\n    <td class=\"wrap\">";
        body += Common::podToHex(k.input.keyImage);
        body += "</td>\n    <td>";
        for (size_t i = 0; i < k.input.outputIndexes.size(); ++i) {
          body += "    <a href=\"/explorer/tx/" + Common::podToHex(k.outputs[i].transactionHash) + "\">";
          body += std::to_string(k.input.outputIndexes[i]); // key_offset
          body += " (output No " + std::to_string(k.outputs[i].number) +")</a>"; // tx output reference
          body += ", ";
        }
        body.pop_back();
        body.pop_back();
        body += "    </td>\n";
      }
      else if (in.type() == typeid(PqInputDetails)) {
        PqInputDetails p = boost::get<PqInputDetails>(in);
        body += m_core.currency().formatAmount(p.amount);
        body += "</td>\n    <td class=\"wrap\">";
        body += Common::podToHex(p.nullifier);
        body += "</td>\n    <td>";
        body += "    <a href=\"/explorer/tx/" + Common::podToHex(p.output.transactionHash) + "\">";
        body += "output No " + std::to_string(p.output.number) + "</a>";
        body += foldedHex("Authorization public key, ML-DSA-65", p.input.authPub.data(), p.input.authPub.size());
        body += "    </td>\n";
      }
      body += "  </tr>\n";
    }
    body += "</tbody>\n";
    body += "</table>\n";

    body += "<h3>Outputs</h3>\n";

    body += "<table class=\"counter\" cellpadding=\"10px\">\n";
    body += "  <thead>\n";
    body += "  <tr>\n";
    body += "    <th>No</th><th>Amount</th><th>Output target</th><th>Spend lock</th>\n";
    body += "  </tr>\n";
    body += "</thead>\n";
    body += "<tbody>\n";
    for (size_t i = 0; i < transactionsDetails.outputs.size(); ++i) {
      const auto& o = transactionsDetails.outputs[i];
      body += "  <tr>\n";
      body += "    <td>" + std::to_string(i) + ")</td>";
      body += "    <td>";
      body += m_core.currency().formatAmount(o.output.amount);
      body += "</td>\n    <td class=\"wrap\">";
      if (o.output.target.type() == typeid(KeyOutput)) {
        KeyOutput ko = boost::get<KeyOutput>(o.output.target);
        body += Common::podToHex(ko);
      } else if (o.output.target.type() == typeid(PqOutput)) {
        PqOutput po = boost::get<PqOutput>(o.output.target);
        body += "spend commit: " + Common::podToHex(po.spendCommit);
        body += foldedHex("Key encapsulation, ML-KEM-768", po.kemCt.data(), po.kemCt.size());
        body += foldedHex("Encrypted payload", po.encPayload.data(), po.encPayload.size());
      }
      body += "</td>\n    <td>";
      if (o.output.unlockHeight != 0) {
        body += "until height " + std::to_string(o.output.unlockHeight);
      } else {
        body += "&mdash;";
      }
      body += "    </td>\n";
      body += "  </tr>\n";
    }
    body += "</tbody>\n";
    body += "</table>\n";

    // ML-DSA-65 signatures, one per input (none in coinbase and free
    // registrations).
    const Transaction& rawTx = txs.back();
    if (!rawTx.pqSignatures.empty()) {
      body += "<h3>Signatures</h3>\n";
      body += "<p>" + std::to_string(rawTx.pqSignatures.size()) + " ML-DSA-65 signature(s), one per input, "
           + std::to_string(CryptoNote::PQ_SIGNATURE_SIZE) + " bytes each.</p>\n";
      body += "<ol>\n";
      for (const auto& sig : rawTx.pqSignatures) {
        body += "  <li>\n";
        body += "    " + foldedHex("Signature", sig.data(), sig.size()) + "\n";
        body += "  </li>\n";
      }
      body += "</ol>\n";
    }

    body += index_finish;

    res = body;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }

  return true;
}

bool BuiltinExplorer::on_get_explorer_txs_by_payment_id(const COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
  Crypto::Hash paymentId;
  if (!parse_hash256(req.payment_id, paymentId)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse Payment ID: " + req.payment_id + '.' };
  }

  std::vector<Crypto::Hash> txHashes = m_core.getTransactionHashesByPaymentId(paymentId);

  if (txHashes.empty())
    return false;

  std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") + "\n<p>";

  body += "<a href=\"/explorer/\">Home</a>";
  body += "<hr />";

  body += "<h2>Payment ID <span class=\"wrap\">" + Common::podToHex(paymentId) + "</span></h2>\n";

  body += "<h3>Transactions with this Payment ID:</h3>\n";

  // simple list of tx hashes without details
  body += "<ol>\n";
  for (const auto& tx : txHashes) {
    std::string txHashStr = Common::podToHex(tx);
    body += "  <li>\n";
    body += "    <a class=\"wrap\" href=\"/explorer/tx/" + txHashStr + "\">";
    body += txHashStr;
    body += "    </a>";
    body += "  </li>\n";
  }
  body += "</ol>\n";

  body += index_finish;

  res = body;

  return true;
}

bool BuiltinExplorer::on_get_explorer_address(const COMMAND_EXPLORER_GET_ADDRESS::request& req, COMMAND_EXPLORER_GET_ADDRESS::response& res) {
  // Discrete addresses are PQ: a bech32m address for this network, or an
  // H-I-A-C / H-I-A-T-C account number. Both are self-validating (bech32m checksum /
  // Luhn check char), so a successful decode means the address is well-formed.
  PqAddress pq;
  AccountNumber acct;
  uint32_t subaddrIndex = 0;
  const bool isPq = decodePqAddress(req.address, m_core.currency().isTestnet(), pq);
  const bool isSubaddr = !isPq && AccountNumber::fromStringWithIndex(req.address, acct, subaddrIndex);
  const bool isAcct = !isPq && (isSubaddr || AccountNumber::fromString(req.address, acct));
  if (!isPq && !isAcct) {
    return false;
  }

  std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") + "\n<p>";
  body += "<a href=\"/explorer/\">Home</a>";
  body += "<hr />";

  body += "<h2>Address</h2>\n";
  body += "<p class=\"wrap\">" + req.address + "</p>\n";

  body += "<h3>Validation</h3>\n";
  body += "<ul>\n";
  if (isPq) {
    body += "  <li>Form: post-quantum bech32m address &#10004;</li>\n";
    body += "  <li>View public key (ML-KEM-768, " + std::to_string(pq.viewPub.size()) + " bytes): <span class=\"wrap\">"
         + Common::toHex(pq.viewPub.data(), pq.viewPub.size()) + "</span></li>\n";
    body += "  <li>Spend public key (ML-DSA-65, " + std::to_string(pq.spendPub.size()) + " bytes): <span class=\"wrap\">"
         + Common::toHex(pq.spendPub.data(), pq.spendPub.size()) + "</span></li>\n";
    // If this identity is registered on-chain, show its account number too.
    uint32_t regHeight = 0, regTxIndex = 0;
    if (m_core.getPqAccountNumber(getPqAccountIdentityHash(pq.viewPub, pq.spendPub), regHeight, regTxIndex)) {
      uint32_t fp = pqAccountFingerprint(
          m_core.currency().isTestnet(), pq.spendPub.data(), pq.spendPub.size(),
          pq.viewPub.data(), pq.viewPub.size());
      std::string an = AccountNumber{regHeight, regTxIndex}.toString(fp);
      body += "  <li>Registered account number: <a href=\"/explorer/address/" + an + "\">" + an + "</a></li>\n";
    }
  } else {
    body += "  <li>Form: registered account number (keys are stored on-chain) &#10004;</li>\n";
    body += "  <li>Registration block height: " + std::to_string(acct.blockHeight) + "</li>\n";
    body += "  <li>Transaction index: " + std::to_string(acct.txIndex) + "</li>\n";
    if (isSubaddr) {
      body += "  <li>Subaddress index: " + std::to_string(subaddrIndex)
           + " (routes attribution; spend authority is the base account)</li>\n";
    }
    // Resolve the registration coordinates to the on-chain keys and show the
    // bech32m address they encode to.
    std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> viewPub;
    std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub;
    if (m_core.resolvePqAccountNumber(acct.blockHeight, acct.txIndex, viewPub, spendPub)) {
      PqAddress resolved = makePqAddress(m_core.currency().publicAddressBase58Prefix(), viewPub, spendPub);
      std::string bech = encodePqAddress(resolved, pqBech32Hrp(m_core.currency().isTestnet()));
      body += "  <li>Resolves to address: <a class=\"wrap\" href=\"/explorer/address/" + bech + "\">" + bech + "</a></li>\n";
    } else {
      body += "  <li>No account registration found at these coordinates &#10060;</li>\n";
    }
  }
  body += "</ul>\n";

  body += index_finish;
  res = body;
  return true;
}

} // namespace CryptoNote
