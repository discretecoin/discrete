// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2016, The Forknote developers
// Copyright (c) 2018-2023 Conceal Network & Conceal Devs
// Copyright (c) 2016-2026, The Karbo developers
// Copyright (c) 2026, The Discrete developers
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

#include "RpcServer.h"
#include "BuiltinExplorer.h"
#include "version.h"

#include <future>
#include <limits>
#include <unordered_map>
#include <time.h>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>

// CryptoNote
#include <crypto/crypto.h>
#include <crypto/random.h>
#include "BlockchainExplorerData.h"
#include "Common/Base58.h"
#include "Common/DnsTools.h"
#include "Common/Math.h"
#include "Common/FormatTools.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "PqAddress.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "AccountNumber.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "PqTxType.h"
#include "Wallet/PqTransactionBuilder.h"
#include "P2p/ConnectionContext.h"
#include "P2p/NetNode.h"

#include "Common/SecureMemory.h"
#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

const uint32_t MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST = 10000;
const uint64_t BLOCK_LIST_MAX_COUNT = 1000;

namespace CryptoNote {

namespace {

template <typename T>
static bool print_as_json(const T& obj) {
  std::cout << CryptoNote::storeToJson(obj) << ENDL;
  return true;
}

static block_stats_entry make_block_stats_response(const BlockStatsEntry& stat) {
  block_stats_entry entry{};
  entry.height = stat.height;
  entry.already_generated_coins = stat.alreadyGeneratedCoins;
  entry.transactions_count = stat.transactionsCount;
  entry.block_size = stat.blockSize;
  entry.difficulty = stat.difficulty;
  entry.reward = stat.reward;
  entry.timestamp = stat.timestamp;
  return entry;
}

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToBinaryKeyValue(res.data()));
    response.addHeader("Content-Type", "application/octet-stream");
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    std::string cors_domain = obj->getCorsDomain();
    if (!cors_domain.empty()) {
      response.addHeader("Access-Control-Allow-Origin", cors_domain);
      response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    }
    response.setBody(storeToJson(res.data()));
    response.addHeader("Content-Type", "application/json");
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction httpMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);

    std::string cors_domain = obj->getCorsDomain();
    if (!cors_domain.empty()) {
      response.addHeader("Access-Control-Allow-Origin", cors_domain);
      response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    }
    response.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response.addHeader("Expires", "0");
    response.setStatus(CryptoNote::HttpResponse::STATUS_200);

    response.setBody(res);
    response.addHeader("Content-Type", "text/html; charset=UTF-8");

    return result;
  };
}

}

std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {

  // binary handlers
  { "/getblocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), true } },
  { "/queryblocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), true } },
  { "/queryblockslite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), true } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::on_get_pool_changes), true } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::on_get_pool_changes_lite), true } },

  // plain text/html handlers
  { "/", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_index), true } },
  { "/supply", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_supply), false } },
  { "/paymentid", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_payment_id), true } },

  // get json handlers
  { "/getinfo", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::on_get_info), true } },
  { "/getheight", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::on_get_height), true } },
  { "/gettransactionspool", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT>(&RpcServer::on_get_transactions_pool_short), true } },
  { "/gettransactionsinpool", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_POOL>(&RpcServer::on_get_transactions_pool), true } },
  { "/getrawtransactionspool", { jsonMethod<COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL>(&RpcServer::on_get_transactions_pool_raw), true } },

  // post json handlers
  { "/gettransactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::on_get_transactions), false } },
  { "/sendrawtransaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TRANSACTION>(&RpcServer::on_send_raw_transaction), false } },
  { "/getblocks", { jsonMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), false } },
  { "/queryblocks", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), false } },
  { "/queryblockslite", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), false } },
  { "/get_pool_changes", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::on_get_pool_changes), true } },
  { "/get_pool_changes_lite", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::on_get_pool_changes_lite), true } },
  { "/get_block_details_by_height", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT>(&RpcServer::on_get_block_details_by_height), true } },
  { "/get_block_details_by_hash", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH>(&RpcServer::on_get_block_details_by_hash), true } },
  { "/get_blocks_details_by_heights", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS>(&RpcServer::on_get_blocks_details_by_heights), true } },
  { "/get_blocks_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES>(&RpcServer::on_get_blocks_details_by_hashes), true } },
  { "/get_blocks_hashes_by_timestamps", { jsonMethod<COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS>(&RpcServer::on_get_blocks_hashes_by_timestamps), true } },
  { "/get_transaction_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES>(&RpcServer::on_get_transactions_details_by_hashes), true } },
  { "/get_transaction_details_by_hash", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH>(&RpcServer::on_get_transaction_details_by_hash), true } },
  { "/get_transaction_details_by_heights", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS>(&RpcServer::on_get_transactions_details_by_heights), true } },
  { "/get_wallet_sync_data", { jsonMethod<COMMAND_RPC_GET_WALLET_SYNC_DATA>(&RpcServer::on_get_wallet_sync_data), true } },
  { "/get_transaction_hashes_by_payment_id", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID>(&RpcServer::on_get_transaction_hashes_by_paymentid), true } },
  
  // disabled in restricted rpc mode
  // allowBusyCore = true: mining control must work even before the node is
  // "synchronized" — otherwise a fresh network (no peers) could never mine its
  // first blocks to bootstrap.
  { "/start_mining", { jsonMethod<COMMAND_RPC_START_MINING>(&RpcServer::on_start_mining), true } },
  { "/stop_mining", { jsonMethod<COMMAND_RPC_STOP_MINING>(&RpcServer::on_stop_mining), true } },
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::on_stop_daemon), true } },
  { "/getconnections", { jsonMethod<COMMAND_RPC_GET_CONNECTIONS>(&RpcServer::on_get_connections), true } },
  { "/getpeers", { jsonMethod<COMMAND_RPC_GET_PEER_LIST>(&RpcServer::on_get_peer_list), true } },


  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(
  RpcServerConfig& config,
  System::Dispatcher& dispatcher,
  Logging::ILogger& log,
  CryptoNote::Core& core,
  NodeServer& p2p, ICryptoNoteProtocolQuery& protocolQuery
) :
  m_config(config),
  m_dispatcher(dispatcher),
  m_workingContextGroup(dispatcher),
  logger(log, "RpcServer"),
  m_core(core),
  m_p2p(p2p),
  m_protocolQuery(protocolQuery),
  blockchainExplorerDataBuilder(core, protocolQuery),
  m_restricted_rpc(m_config.isRestricted()),
  m_cors_domain(m_config.getCors())
{
  if (!m_config.getContactInfo().empty()) {
    m_contact_info = m_config.getContactInfo();
  }

  // Built-in explorer + status pages live in their own TU.
  m_builtinExplorer = std::make_unique<BuiltinExplorer>(
      m_core, m_p2p, m_protocolQuery, blockchainExplorerDataBuilder, *this);

  // Create HTTP server
  m_httpServer = std::make_unique<CryptoNote::HttpServer>(m_dispatcher, log);
  m_httpServer->setRequestHandler(
    std::bind(&RpcServer::processRequest, this, std::placeholders::_1, std::placeholders::_2));

  // Create HTTPS server if SSL is enabled
  if (m_config.isEnabledSSL()) {
    m_httpsServer = std::make_unique<CryptoNote::HttpServer>(m_dispatcher, log);
    m_httpsServer->setRequestHandler(
      std::bind(&RpcServer::processRequest, this, std::placeholders::_1, std::placeholders::_2));
  }
}

RpcServer::~RpcServer() {
  try {
    stop();
  }
  catch (...) {
    // Suppress exceptions in destructor
  }
}

void RpcServer::start() {
  std::string address = m_config.getBindIP();
  uint16_t port = m_config.getBindPort();

  logger(Logging::INFO, Logging::BRIGHT_MAGENTA) << "Starting HTTP RPC server on " << address << ":" << port;

  // Start HTTP server
  m_httpServer->start(address, port, m_config.getRpcUser(), m_config.getRpcPassword());

  // Start HTTPS server if SSL is enabled
  if (m_config.isEnabledSSL() && m_httpsServer) {
    uint16_t ssl_port = m_config.getBindPortSSL();
    logger(Logging::INFO, Logging::BRIGHT_MAGENTA) << "Starting HTTPS RPC server on " << address << ":" << ssl_port;

    m_httpsServer->startSsl(
      address,
      ssl_port,
      m_config.getChainFile(),
      m_config.getKeyFile(),
      "", // DH file (optional)
      m_config.getRpcUser(),
      m_config.getRpcPassword()
    );
  }

  logger(Logging::INFO) << "RPC server started successfully";
}

void RpcServer::stop() {
  logger(Logging::INFO) << "Stopping RPC server...";

  if (m_httpServer) {
    m_httpServer->stop();
  }

  if (m_httpsServer) {
    m_httpsServer->stop();
  }

  logger(Logging::INFO) << "RPC server stopped";
}

size_t RpcServer::getRpcConnectionsCount() {
  size_t count = m_httpServer ? m_httpServer->getConnectionsCount() : 0;
  if (m_httpsServer) {
    count += m_httpsServer->getConnectionsCount();
  }
  return count;
}

void RpcServer::processRequest(const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response) {
  logger(Logging::TRACE) << "Incoming RPC request to endpoint " << request.getUrl();

  // CORS must be attached before dispatch so preflight and error responses are
  // readable by browser-based clients such as the block explorer.
  if (!m_cors_domain.empty()) {
    response.addHeader("Access-Control-Allow-Origin", m_cors_domain);
    response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  }

  if (request.getMethod() == "OPTIONS") {
    response.setStatus(CryptoNote::HttpResponse::STATUS_200);
    response.setBody("");
    return;
  }

  try {
    const std::string url = request.getUrl();
    auto it = s_handlers.find(url);

    if (it == s_handlers.end()) {

      if (Common::starts_with(url, "/api/")) {

        std::string block_height_method = "/api/block/height/";
        std::string block_hash_method = "/api/block/hash/";
        std::string tx_hash_method = "/api/transaction/";
        std::string payment_id_method = "/api/payment_id/";
        std::string tx_mempool_method = "/api/mempool/";

        if (Common::starts_with(url, block_height_method)) {

          std::string height_str = url.substr(block_height_method.size());
          uint32_t height = Common::integer_cast<uint32_t>(height_str);
          auto it = s_handlers.find("/get_block_details_by_height");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Core is busy");
            response.addHeader("Content-Type", "text/html");
            return;
          }
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request req;
          req.blockHeight = height;
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response rsp;
          bool r = on_get_block_details_by_height(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(storeToJson(rsp));
            response.addHeader("Content-Type", "application/json");
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Internal error");
            response.addHeader("Content-Type", "text/html");
          }
          return;

        }
        else if (Common::starts_with(url, block_hash_method)) {

          std::string hash_str = url.substr(block_hash_method.size());
          auto it = s_handlers.find("/get_block_details_by_hash");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Core is busy");
            response.addHeader("Content-Type", "text/html");
            return;
          }
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response rsp;
          bool r = on_get_block_details_by_hash(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(storeToJson(rsp));
            response.addHeader("Content-Type", "application/json");
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Internal error");
            response.addHeader("Content-Type", "text/html");
          }
          return;

        }
        else if (Common::starts_with(url, tx_hash_method)) {
          std::string hash_str = url.substr(tx_hash_method.size());
          auto it = s_handlers.find("/get_transaction_details_by_hash");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Core is busy");
            response.addHeader("Content-Type", "text/html");
            return;
          }
          COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response rsp;
          bool r = on_get_transaction_details_by_hash(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(storeToJson(rsp));
            response.addHeader("Content-Type", "application/json");
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Internal error");
            response.addHeader("Content-Type", "text/html");
          }
          return;

        }
        else if (Common::starts_with(url, payment_id_method)) {

          std::string pid_str = url.substr(payment_id_method.size());
          auto it = s_handlers.find("/get_transaction_hashes_by_payment_id");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Core is busy");
            response.addHeader("Content-Type", "text/html");
            return;
          }
          COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request req;
          req.paymentId = pid_str;
          COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response rsp;
          bool r = on_get_transaction_hashes_by_paymentid(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(storeToJson(rsp));
            response.addHeader("Content-Type", "application/json");
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Internal error");
            response.addHeader("Content-Type", "text/html");
          }
          return;

        }
        else if (Common::starts_with(url, tx_mempool_method)) {

          auto it = s_handlers.find("/gettransactionsinpool");
          if (!it->second.allowBusyCore && !isCoreReady())
          {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Core is busy");
            response.addHeader("Content-Type", "text/html");
            return;
          }

          COMMAND_RPC_GET_TRANSACTIONS_POOL::request req;
          COMMAND_RPC_GET_TRANSACTIONS_POOL::response rsp;
          bool r = on_get_transactions_pool(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(storeToJson(rsp));
            response.addHeader("Content-Type", "application/json");
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Internal error");
            response.addHeader("Content-Type", "text/html");
          }

          return;

        }
      }

      if (Common::starts_with(url, "/explorer/")) {

        std::string page_method = "/explorer/height/";
        std::string block_method = "/explorer/block/";
        std::string tx_method = "/explorer/tx/";
        std::string payment_id_method = "/explorer/payment_id/";
        
        if (Common::starts_with(url, block_method)) {
          std::string hash_str = url.substr(block_method.size());
          if (hash_str.size() < 64) {
            // assume it's height
            uint32_t height = static_cast<uint32_t>(std::stoul(hash_str));
            if (m_core.getCurrentBlockchainHeight() <= height) {
              throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                std::string("Too big height: ") + std::to_string(height) +
                ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
            }
            Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
            hash_str = Common::podToHex(block_hash);
          }

          COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::response rsp;
          bool r = on_get_explorer_block_by_hash(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(rsp);
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Internal error");
          }
          response.addHeader("Content-Type", "text/html");

          return;
        }

        if (Common::starts_with(url, tx_method)) {
          std::string hash_str = url.substr(tx_method.size());
          
          COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::response rsp;

          bool r = on_get_explorer_tx_by_hash(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(rsp);
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_500);
            response.setBody("Internal error");
          }
          response.addHeader("Content-Type", "text/html");

          return;
        }

        if (Common::starts_with(url, payment_id_method)) {
          std::string payment_id_str = url.substr(payment_id_method.size());

          COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::request req;
          req.payment_id = payment_id_str;
          COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::response rsp;

          bool r = on_get_explorer_txs_by_payment_id(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(rsp);
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_404);
            response.setBody("Not found");
          }
          response.addHeader("Content-Type", "text/html");

          return;
        }

        std::string address_method = "/explorer/address/";
        if (Common::starts_with(url, address_method)) {
          std::string address_str = url.substr(address_method.size());

          COMMAND_EXPLORER_GET_ADDRESS::request req;
          req.address = address_str;
          COMMAND_EXPLORER_GET_ADDRESS::response rsp;

          bool r = on_get_explorer_address(req, rsp);
          if (r) {
            response.setStatus(CryptoNote::HttpResponse::STATUS_200);
            response.setBody(rsp);
          }
          else {
            response.setStatus(CryptoNote::HttpResponse::STATUS_404);
            response.setBody("Not found");
          }
          response.addHeader("Content-Type", "text/html");

          return;
        }

        // default is explorer home
        uint32_t height = 0;
        if (Common::starts_with(url, page_method)) {
          std::string height_str = url.substr(page_method.size());
          height = Common::integer_cast<uint32_t>(height_str);
        }

        COMMAND_EXPLORER::request req;
        req.height = height;
        COMMAND_EXPLORER::response rsp;
        bool r = on_get_explorer(req, rsp);
        if (r) {
          response.setStatus(CryptoNote::HttpResponse::STATUS_200);
          response.setBody(rsp);
        }
        else {
          response.setStatus(CryptoNote::HttpResponse::STATUS_500);
          response.setBody("Internal error");
        }
        response.addHeader("Content-Type", "text/html");

        return;

      }

      response.setStatus(CryptoNote::HttpResponse::STATUS_404);
      response.setBody("Not found");
      response.addHeader("Content-Type", "text/html");

      return;
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      response.setStatus(CryptoNote::HttpResponse::STATUS_500);
      response.setBody("Core is busy");
      response.addHeader("Content-Type", "text/html");
      return;
    }

    it->second.handler(this, request, response);

  }
  catch (const JsonRpc::JsonRpcError& err) {
    response.setStatus(CryptoNote::HttpResponse::STATUS_500);
    response.setBody(storeToJsonValue(err).toString());
    response.addHeader("Content-Type", "application/json");
  }
  catch (const std::exception& e) {
    response.setStatus(CryptoNote::HttpResponse::STATUS_500);
    response.setBody(e.what());
    response.addHeader("Content-Type", "text/html");
  }
}

bool RpcServer::processJsonRpcRequest(const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response) {

  using namespace JsonRpc;

  response.addHeader("Content-Type", "application/json");
  if (!m_cors_domain.empty()) {
    response.addHeader("Access-Control-Allow-Origin", m_cors_domain);
    response.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  }
  response.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  try {
    //logger(Logging::TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonRpc::JsonMemberMethod>> jsonRpcHandlers = {
  
      { "getblockcount", { makeMemberMethod(&RpcServer::on_getblockcount), true } },
      { "getblockhash", { makeMemberMethod(&RpcServer::on_getblockhash), true } },
      { "getblockheaderbyhash", { makeMemberMethod(&RpcServer::on_get_block_header_by_hash), true } },
      { "getblockheaderbyheight", { makeMemberMethod(&RpcServer::on_get_block_header_by_height), true } },
      { "getblocktimestamp", { makeMemberMethod(&RpcServer::on_get_block_timestamp_by_height), true } },
      { "getblockbyheight", { makeMemberMethod(&RpcServer::on_get_block_details_by_height), true } },
      { "getblockbyhash", { makeMemberMethod(&RpcServer::on_get_block_details_by_hash), true } },
      { "getblocksbyheights", { makeMemberMethod(&RpcServer::on_get_blocks_details_by_heights), true } },
      { "getblocksbyhashes", { makeMemberMethod(&RpcServer::on_get_blocks_details_by_hashes), true } },
      { "getblockshashesbytimestamps", { makeMemberMethod(&RpcServer::on_get_blocks_hashes_by_timestamps), true } },
      { "getblockslist", { makeMemberMethod(&RpcServer::on_blocks_list_json), true } },
      { "getaltblockslist", { makeMemberMethod(&RpcServer::on_alt_blocks_list_json), true } },
      { "getlastblockheader", { makeMemberMethod(&RpcServer::on_get_last_block_header), true } },
      { "gettransaction", { makeMemberMethod(&RpcServer::on_get_transaction_details_by_hash), true } },
      { "gettransactionspool", { makeMemberMethod(&RpcServer::on_get_transactions_pool_short), true } },
      { "getrawtransactionspool", { makeMemberMethod(&RpcServer::on_get_transactions_pool_raw), true } },
      { "gettransactionsinpool", { makeMemberMethod(&RpcServer::on_get_transactions_pool), true } },
      { "gettransactionsbypaymentid", { makeMemberMethod(&RpcServer::on_get_transactions_by_payment_id), true } },
      { "gettransactionhashesbypaymentid", { makeMemberMethod(&RpcServer::on_get_transaction_hashes_by_paymentid), true } },
      { "gettransactionsbyhashes", { makeMemberMethod(&RpcServer::on_get_transactions_details_by_hashes), true } },
      { "gettransactionsbyheights", { makeMemberMethod(&RpcServer::on_get_transactions_details_by_heights), true } },
      { "getcurrencyid", { makeMemberMethod(&RpcServer::on_get_currency_id), true } },
      { "getstatsbyheights", { makeMemberMethod(&RpcServer::on_get_stats_by_heights), false } },
      { "getstatsinrange", { makeMemberMethod(&RpcServer::on_get_stats_by_heights_range), false } },
      { "checktransactionproof", { makeMemberMethod(&RpcServer::on_check_transaction_proof), true } },
      { "validateaddress", { makeMemberMethod(&RpcServer::on_validate_address), true } },
      { "verifymessage", { makeMemberMethod(&RpcServer::on_verify_message), true } },
      { "resolveopenalias", { makeMemberMethod(&RpcServer::on_resolve_open_alias), true } },
      { "search", { makeMemberMethod(&RpcServer::on_explorer_search), true } },
      { "getaccountnumber", { makeMemberMethod(&RpcServer::on_get_pq_account), true } },
      { "resolveaccountnumber", { makeMemberMethod(&RpcServer::on_resolve_pq_account), true } },
      { "resync_to_majority", { makeMemberMethod(&RpcServer::on_resync_to_majority), true } },

    };

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.setBody(jsonResponse.getBody());
  response.addHeader("Content-Type", "application/json");
  //logger(Logging::TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

std::string RpcServer::getCorsDomain() {
  return m_cors_domain;
}

bool RpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_p2p.get_payload_object().isSynchronized();
}

//
// Binary handlers
//

bool RpcServer::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (req.block_ids.empty()) {
    res.status = "Failed";
    return false;
  }

  if (req.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    res.status = "Failed";
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(req.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  res.current_height = totalBlockCount;
  res.start_height = startBlockIndex;

  for (const auto& blockId : supplement) {
    assert(m_core.have_block(blockId));
    auto completeBlock = m_core.getBlock(blockId);
    assert(completeBlock != nullptr);

    res.blocks.resize(res.blocks.size() + 1);
    res.blocks.back().block = Common::asString(toBinaryArray(completeBlock->getBlock()));

    res.blocks.back().txs.reserve(completeBlock->getTransactionCount());
    for (size_t i = 0; i < completeBlock->getTransactionCount(); ++i) {
      res.blocks.back().txs.push_back(Common::asString(toBinaryArray(completeBlock->getTransaction(i))));
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(req.block_ids, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.start_height = startHeight;
  res.current_height = currentHeight;
  res.full_offset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;
  if (!m_core.queryBlocksLite(req.blockIds, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.startHeight = startHeight;
  res.currentHeight = currentHeight;
  res.fullOffset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_pool_changes(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  std::vector<CryptoNote::Transaction> addedTransactions;
  rsp.isTailBlockActual = m_core.getPoolChanges(req.tailBlockId, req.knownTxsIds, addedTransactions, rsp.deletedTxsIds);
  for (auto& tx : addedTransactions) {
    BinaryArray txBlob;
    if (!toBinaryArray(tx, txBlob)) {
      rsp.status = "Internal error";
      break;;
    }

    rsp.addedTxs.emplace_back(std::move(txBlob));
  }
  return true;
}


bool RpcServer::on_get_pool_changes_lite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  rsp.isTailBlockActual = m_core.getPoolChangesLite(req.tailBlockId, req.knownTxsIds, rsp.addedTxs, rsp.deletedTxsIds);

  return true;
}

bool RpcServer::on_get_blocks_details_by_heights(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    if (req.blockHeights.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.blockHeights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }
    std::vector<BlockDetails> blockDetails;
    for (const uint32_t& height : req.blockHeights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }
      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }
      BlockDetails detail;
      if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, detail, false)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
      }
      blockDetails.push_back(detail);
    }
    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_details_by_hashes(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::response& rsp) {
  try {
    if (req.blockHashes.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.blockHashes.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }
    std::vector<BlockDetails> blockDetails;
    for (const Crypto::Hash& hash : req.blockHashes) {
      Block blk;
      if (!m_core.getBlockByHash(hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by hash " + Common::podToHex(hash) + '.' };
      }
      BlockDetails detail;
      if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, detail, false)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
      }
      blockDetails.push_back(detail);
    }
    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_details_by_height(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response& rsp) {
  try {
    BlockDetails blockDetails;
    if (m_core.getCurrentBlockchainHeight() <= req.blockHeight) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
        std::string("To big height: ") + std::to_string(req.blockHeight) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
    }
    Crypto::Hash block_hash = m_core.getBlockIdByHeight(req.blockHeight);
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height " + std::to_string(req.blockHeight) + '.' };
  }
    if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, blockDetails, true)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
    }
    rsp.block = blockDetails;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_details_by_hash(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response& rsp) {
  try {
    BlockDetails blockDetails;
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
    if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, blockDetails, true)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
    }
    rsp.block = blockDetails;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_hashes_by_timestamps(const COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::request& req, COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::response& rsp) {
  try {
    uint32_t count;
    std::vector<Crypto::Hash> blockHashes;
    if (!m_core.get_blockchain_storage().getBlockIdsByTimestamp(req.timestampBegin, req.timestampEnd, req.limit, blockHashes, count)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get blocks within timestamps " + std::to_string(req.timestampBegin) + " - " + std::to_string(req.timestampEnd) + "." };
    }
    rsp.blockHashes = std::move(blockHashes);
    rsp.count = count;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_details_by_hashes(const COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES::response& rsp) {
  try {
    std::vector<TransactionDetails> transactionsDetails;
    transactionsDetails.reserve(req.transactionHashes.size());

    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    m_core.getTransactions(req.transactionHashes, txs, missed_txs, true);

    if (!txs.empty()) {
      for (const Transaction& tx : txs) {
        TransactionDetails txDetails;
        if (!blockchainExplorerDataBuilder.fillTransactionDetails(tx, txDetails)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
            "Internal error: can't fill transaction details." };
        }
        transactionsDetails.push_back(txDetails);
      }

      rsp.transactions = std::move(transactionsDetails);
      rsp.status = CORE_RPC_STATUS_OK;
    }
    if (txs.empty() || !missed_txs.empty()) {
      std::ostringstream ss;
      std::string separator;
      for (const auto& h : missed_txs) {
        ss << separator << Common::podToHex(h);
        separator = ",";
      }
      rsp.status = "transaction(s) not found: " + ss.str() + ".";
    }
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

bool RpcServer::on_get_transaction_details_by_hash(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response& rsp) {
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
    if (!blockchainExplorerDataBuilder.fillTransactionDetails(txs.back(), transactionsDetails)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't fill transaction details." };
    }

    rsp.transaction = std::move(transactionsDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_details_by_heights(const COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    if (req.heights.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.heights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }

    std::vector<uint32_t> heights;

    if (req.range) {
      if (req.heights.size() != 2) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("The range is set to true but heights size is not equal to 2") };
      }
      uint32_t upperBound = std::min(req.heights[1], m_core.getCurrentBlockchainHeight());
      for (uint32_t i = 0; i < (upperBound - req.heights[0]); i++) {
        heights.push_back(req.heights[0] + i);
      }
    }
    else {
      heights = req.heights;
    }

    std::vector<TransactionDetails> transactions;

    for (const uint32_t& height : heights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }

      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }

      if (req.include_miner_txs) {
        transactions.reserve(blk.transactionHashes.size() + 1);

        TransactionDetails transactionDetails;
        if (!blockchainExplorerDataBuilder.fillTransactionDetails(blk.baseTransaction, transactionDetails, blk.timestamp)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill miner's tx details." };
        }
        transactions.push_back(std::move(transactionDetails));
      }
      else {
        transactions.reserve(blk.transactionHashes.size());
      }

      std::list<Transaction> found;
      std::list<Crypto::Hash> missed;

      if (!blk.transactionHashes.empty()) {
        m_core.getTransactions(blk.transactionHashes, found, missed, false);
        //if (found.size() != blk.transactionHashes.size()) {
        //  throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: not all block's txs were found." };
        //}

        for (const Transaction& tx : found) {
          TransactionDetails transactionDetails;
          if (!blockchainExplorerDataBuilder.fillTransactionDetails(tx, transactionDetails, blk.timestamp)) {
            throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill tx details." };
          }
          if (req.exclude_signatures) {
            transactionDetails.signatures.clear();
          }
          transactions.push_back(std::move(transactionDetails));
        }

        for (const auto& miss_tx : missed) {
          rsp.missed_txs.push_back(Common::podToHex(miss_tx));
        }
      }
    }
    rsp.transactions = std::move(transactions);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_wallet_sync_data(const COMMAND_RPC_GET_WALLET_SYNC_DATA::request& req,
                                        COMMAND_RPC_GET_WALLET_SYNC_DATA::response& rsp) {
  try {
    if (req.block_count == 0 || req.block_count > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("block_count must be between 1 and ") + std::to_string(BLOCK_LIST_MAX_COUNT)};
    }

    uint32_t chainHeight = 0;
    std::vector<WalletSyncBlockInfo> blocks;
    if (!m_core.getWalletSyncBlocks(req.start_height, req.block_count, chainHeight, blocks)) {
      throw JsonRpc::JsonRpcError{CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Failed to read wallet synchronization snapshot"};
    }
    rsp.top_height = chainHeight == 0 ? 0 : chainHeight - 1;
    rsp.blocks.reserve(blocks.size());

    for (auto& source : blocks) {
      wallet_sync_block entry;
      entry.height = source.height;
      entry.hash = source.hash;
      entry.previous_hash = source.block.previousBlockHash;
      entry.timestamp = source.block.timestamp;
      entry.transactions.reserve(source.transactions.size() + (req.include_miner_txs ? 1 : 0));

      if (req.include_miner_txs) {
        wallet_sync_transaction coinbase;
        coinbase.transaction = static_cast<const TransactionPrefix&>(source.block.baseTransaction);
        coinbase.hash = getObjectHash(source.block.baseTransaction);
        coinbase.coinbase = true;
        entry.transactions.push_back(std::move(coinbase));
      }

      for (size_t index = 0; index < source.transactions.size(); ++index) {
        wallet_sync_transaction txEntry;
        txEntry.transaction = static_cast<const TransactionPrefix&>(source.transactions[index]);
        txEntry.hash = source.block.transactionHashes[index];
        txEntry.coinbase = false;
        entry.transactions.push_back(std::move(txEntry));
      }

      rsp.blocks.push_back(std::move(entry));
    }
  } catch (const JsonRpc::JsonRpcError&) {
    throw;
  } catch (const std::exception& e) {
    throw JsonRpc::JsonRpcError{CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Error: " + std::string(e.what())};
  }

  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transaction_hashes_by_paymentid(const COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response& rsp) {
  Crypto::Hash pid_hash;
  if (!parse_hash256(req.paymentId, pid_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of payment id. Hex = " + req.paymentId + '.' };
  }
  try {
    rsp.transactionHashes = m_core.getTransactionHashesByPaymentId(pid_hash);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

//
// HTTP handlers
//

// All HTML / HTTP page handlers below are thin forwarders into
// BuiltinExplorer. See src/Rpc/BuiltinExplorer.{h,cpp} for the bodies.

bool RpcServer::on_get_index(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  return m_builtinExplorer->on_get_index(req, res);
}

bool RpcServer::on_get_supply(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  return m_builtinExplorer->on_get_supply(req, res);
}

bool RpcServer::on_get_payment_id(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  return m_builtinExplorer->on_get_payment_id(req, res);
}

//
// Explorer
//

bool RpcServer::on_get_explorer(const COMMAND_EXPLORER::request& req, COMMAND_EXPLORER::response& res) {
  return m_builtinExplorer->on_get_explorer(req, res);
}

bool RpcServer::on_explorer_search(const COMMAND_RPC_EXPLORER_SEARCH::request& req, COMMAND_RPC_EXPLORER_SEARCH::response& res) {
  return m_builtinExplorer->on_explorer_search(req, res);
}

bool RpcServer::on_get_explorer_block_by_hash(const COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::response& res) {
  return m_builtinExplorer->on_get_explorer_block_by_hash(req, res);
}

bool RpcServer::on_get_explorer_tx_by_hash(const COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::response& res) {
  return m_builtinExplorer->on_get_explorer_tx_by_hash(req, res);
}

bool RpcServer::on_get_explorer_txs_by_payment_id(const COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
  return m_builtinExplorer->on_get_explorer_txs_by_payment_id(req, res);
}

bool RpcServer::on_get_explorer_address(const COMMAND_EXPLORER_GET_ADDRESS::request& req, COMMAND_EXPLORER_GET_ADDRESS::response& res) {
  return m_builtinExplorer->on_get_explorer_address(req, res);
}

//
// JSON handlers
//

bool RpcServer::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res) {
  res.height = m_core.getCurrentBlockchainHeight();
  res.difficulty = m_core.getNextBlockDifficulty();
  res.transactions_count = m_core.getBlockchainTotalTransactions() - res.height; //without coinbase
  res.transactions_pool_size = m_core.getPoolTransactionsCount();
  if (!m_core.getCanonicalAccountRegistrationsCount(res.registered_account_numbers_count)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get registered account numbers count." };
  }
  res.alt_blocks_count = m_core.getAlternativeBlocksCount();
  uint64_t total_conn = m_p2p.get_connections_count();
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = total_conn - res.outgoing_connections_count;
  res.rpc_connections_count = getRpcConnectionsCount();
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  Crypto::Hash last_block_hash = m_core.getBlockIdByHeight(res.height - 1);
  res.top_block_hash = Common::podToHex(last_block_hash);
  res.version = PROJECT_VERSION_LONG;
  res.contact = m_contact_info.empty() ? std::string() : m_contact_info;
  res.min_fee = m_core.getMinimalFee();
  res.start_time = (uint64_t)m_core.getStartTime();
  uint64_t alreadyGeneratedCoins = m_core.getTotalGeneratedAmount();
  // that large uint64_t number is unsafe in JavaScript environment and therefore as a JSON value so we display it as a formatted string
  res.already_generated_coins = m_core.currency().formatAmount(alreadyGeneratedCoins);
  res.block_major_version = m_core.getCurrentBlockMajorVersion();
  uint64_t nextReward = m_core.currency().calculateReward(alreadyGeneratedCoins);
  res.next_reward = nextReward;
  if (!m_core.getBlockCumulativeDifficulty(res.height - 1, res.cumulative_difficulty)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last cumulative difficulty." };
  }
  res.max_cumulative_block_size = (uint64_t)m_core.currency().maxBlockCumulativeSize(res.height);

  // First-seen finality is always on locally (from genesis). max_reorg_depth
  // is now the fixed consensus constant CRYPTONOTE_FINALITY_DEPTH.
  uint32_t finalityDepth = m_core.getFinalityDepth();
  res.deep_reorg_protection = true;
  res.max_reorg_depth = finalityDepth;
  if (res.height > finalityDepth) {
    res.finalized_height = res.height - 1 - finalityDepth;
    res.finalized_hash = Common::podToHex(m_core.getBlockIdByHeight(res.finalized_height));
  } else {
    res.finalized_height = 0;
    res.finalized_hash = std::string();
  }

  // Finality-fork warning (operator messaging). peer_split and the hint are human
  // heuristics computed live from peer-advertised heights — never validity inputs.
  CryptoNote::FinalityForkState fork = m_core.getFinalityForkState();
  res.finality_fork_warning = fork.active;
  res.divergence_height = fork.active ? fork.divergenceHeight : 0;
  if (fork.active) {
    res.local_tip = std::to_string(fork.localTipHeight) + ":" + Common::podToHex(fork.localTipHash);
    res.competing_tip = std::to_string(fork.competingTipHeight) + ":" + Common::podToHex(fork.competingTipHash);

    size_t peersOnCompeting = 0, peersTotal = 0;
    std::vector<CryptoNote::CryptoNoteConnectionContext> conns;
    if (m_protocolQuery.getConnections(conns)) {
      for (const auto& c : conns) {
        ++peersTotal;
        if (c.m_remote_blockchain_height >= fork.competingTipHeight) {
          ++peersOnCompeting;
        }
      }
    }
    res.peer_split = std::to_string(peersOnCompeting) + "/" + std::to_string(peersTotal);
    // Casual, reassuring guidance - never an alarming assertion. The out-of-band
    // explorer check is the safeguard: it stops a node that is correctly refusing
    // an attacker's chain from being rolled back onto it.
    res.finality_hint = "usually just a brief connectivity hiccup; check the tip on the official "
                        "block explorer, and if this node is behind run resync_to_majority --confirm to rejoin the main chain";
  } else {
    res.local_tip = std::string();
    res.competing_tip = std::string();
    res.peer_split = std::string();
    res.finality_hint = std::string();
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_stats_by_heights(const COMMAND_RPC_GET_STATS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_STATS_BY_HEIGHTS::response& res) {
  std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();

  const uint32_t currentHeight = m_core.getCurrentBlockchainHeight();
  if (currentHeight == 0 && !req.heights.empty()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Blockchain is empty" };
  }

  const uint64_t requestedBlocks = req.heights.size();
  if (m_restricted_rpc && requestedBlocks > MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Requested stats count: " + std::to_string(requestedBlocks) + " exceeded max limit of " + std::to_string(MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST) };
  }

  for (const uint32_t height : req.heights) {
    if (height >= currentHeight) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
        "Too big height: " + std::to_string(height) + ", current blockchain height = " + std::to_string(currentHeight - 1) };
    }
  }

  std::vector<BlockStatsEntry> stats;
  if (!m_core.getBlockStats(req.heights, stats)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for requested heights" };
  }

  res.stats.reserve(stats.size());
  for (const BlockStatsEntry& stat : stats) {
    res.stats.push_back(make_block_stats_response(stat));
  }

  std::chrono::duration<double> duration = std::chrono::steady_clock::now() - timePoint;
  res.duration = duration.count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_stats_by_heights_range(const COMMAND_RPC_GET_STATS_BY_HEIGHTS_RANGE::request& req, COMMAND_RPC_GET_STATS_BY_HEIGHTS_RANGE::response& res) {
  std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();

  const uint32_t currentHeight = m_core.getCurrentBlockchainHeight();
  if (currentHeight == 0) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Blockchain is empty" };
  }

  const uint32_t min = req.start_height;
  const uint32_t max = std::min<uint32_t>(req.end_height, currentHeight - 1);
  if (min > max) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong start and end heights" };
  }

  const uint64_t requestedBlocks = static_cast<uint64_t>(max) - min + 1;
  if (m_restricted_rpc && requestedBlocks > MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Requested stats count: " + std::to_string(requestedBlocks) + " exceeded max limit of " + std::to_string(MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST) };
  }

  std::vector<BlockStatsEntry> stats;
  if (!m_core.getBlockStats(min, max, stats)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for range [" + std::to_string(min) + ", " + std::to_string(max) + "]" };
  }

  res.stats.reserve(stats.size());
  for (const BlockStatsEntry& stat : stats) {
    res.stats.push_back(make_block_stats_response(stat));
  }

  std::chrono::duration<double> duration = std::chrono::steady_clock::now() - timePoint;
  res.duration = duration.count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res) {
  res.height = m_core.getCurrentBlockchainHeight();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res) {
  std::vector<Crypto::Hash> vh;
  for (const auto& tx_hex_str : req.txs_hashes) {
    BinaryArray b;
    if (!Common::fromHex(tx_hex_str, b))
    {
      res.status = "Failed to parse hex representation of transaction hash";
      return true;
    }
    if (b.size() != sizeof(Crypto::Hash))
    {
      res.status = "Failed, size of data mismatch";
    }
    vh.push_back(*reinterpret_cast<const Crypto::Hash*>(b.data()));
  }
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(vh, txs, missed_txs);

  for (auto& tx : txs) {
    res.txs_as_hex.push_back(Common::toHex(toBinaryArray(tx)));
  }

  for (const auto& miss_tx : missed_txs) {
    res.missed_txs.push_back(Common::podToHex(miss_tx));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_send_raw_transaction(const COMMAND_RPC_SEND_RAW_TRANSACTION::request& req, COMMAND_RPC_SEND_RAW_TRANSACTION::response& res) {
  BinaryArray tx_blob;
  if (!Common::fromHex(req.tx_as_hex, tx_blob))
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: Failed to parse transaction from hexbuff: " << req.tx_as_hex;
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse transaction from hexbuff" };
  }

  Crypto::Hash transactionHash = Crypto::cn_fast_hash(tx_blob.data(), tx_blob.size());
  logger(Logging::DEBUGGING) << "transaction " << transactionHash << " came in on_send_raw_tx";

  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  if (!m_core.handle_incoming_tx(tx_blob, tvc, false))
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: Failed to process tx";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to process tx" };
  }

  if (tvc.m_verification_failed)
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: Transaction verification failed";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Transaction verification failed" };
  }

  if (!tvc.m_should_be_relayed)
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: transaction accepted, but not relayed";
    res.status = "Not relayed";
    return true;
  }

  try {
    NOTIFY_NEW_TRANSACTIONS::request r;
    r.stem = true;
    r.txs.push_back(Common::asString(tx_blob));
    m_core.get_protocol()->relay_transactions(r);
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  if (m_protocolQuery.getPeerCount() == 0) {
    // Solo mining (e.g. bootstrapping a fresh network) is allowed — warn only.
    logger(Logging::INFO) << "Starting mining with no connected peers (solo).";
  }

  // Discrete: identity-bound mining. The reward goes to the miner's PQ identity
  // AND the miner signs each block with that identity's spend key, both derived
  // from the classical spend secret the (co-located) wallet sends over loopback
  // RPC — the daemon cannot read the wallet's file itself because the wallet keeps
  // it memory-mapped while running. The spend secret is mlocked and scrubbed as
  // soon as the PQ keys are derived; it is never logged.
  Crypto::Hash key_hash;
  size_t size;
  if (!Common::fromHex(req.miner_spend_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    sodium_memzero(&key_hash, sizeof(key_hash));
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner spend key" };
  }
  Crypto::SecretKey spendSecret = *(struct Crypto::SecretKey *) &key_hash;

  CryptoPQ::KemPublicKey pqViewPub;
  CryptoPQ::DsaPublicKey pqSpendPub;
  CryptoPQ::DsaSecretKey pqSpendSk;
  {
    Tools::SecretLock hashGuard(&key_hash, sizeof(key_hash));
    Tools::SecretLock seedGuard(&spendSecret, sizeof(spendSecret));
    Tools::SecretLock pqGuard(pqSpendSk.data(), pqSpendSk.size());
    deriveMinerPqKeys(spendSecret, pqViewPub, pqSpendPub, pqSpendSk);

    if (!m_core.get_miner().startPq(pqViewPub, pqSpendPub, pqSpendSk, static_cast<size_t>(req.threads_count))) {
      res.status = "Already mining";
      return true;
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  if (!m_core.get_miner().stop()) {
    res.status = "Not mining - nothing to stop";
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  if (m_core.currency().isTestnet()) {
    m_p2p.sendStopSignal();
    res.status = CORE_RPC_STATUS_OK;
  } else {
    res.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }
  return true;
}

bool RpcServer::on_resync_to_majority(const COMMAND_RPC_RESYNC_TO_MAJORITY::request& req, COMMAND_RPC_RESYNC_TO_MAJORITY::response& res) {
  // Mutating admin action — never available on restricted RPC.
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    res.rolled_back_to = 0;
    return false;
  }
  // Explicit operator confirmation is mandatory; recovery is never automatic.
  if (!req.confirm) {
    res.status = "refused: set \"confirm\": true to run recovery (this pops local blocks and re-syncs)";
    res.rolled_back_to = 0;
    return false;
  }

  std::string message;
  bool ok = m_core.resyncToMajority(message); // refuses unless a finality fork is flagged
  res.status = (ok ? std::string(CORE_RPC_STATUS_OK) + ": " : std::string("refused: ")) + message;
  res.rolled_back_to = ok ? m_core.getCurrentBlockchainHeight() - 1 : 0;
  return ok;
}

bool RpcServer::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::list<AnchorPeerlistEntry> pl_anchor;
  std::vector<PeerlistEntry> pl_wite;
  std::vector<PeerlistEntry> pl_gray;
  m_p2p.getPeerlistManager().get_peerlist_full(pl_anchor, pl_gray, pl_wite);
  for (const auto& pe : pl_anchor) {
    std::stringstream ss;
    ss << pe.adr;
    res.anchor_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_wite) {
    std::stringstream ss;
    ss << pe.adr;
    res.white_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_gray) {
    std::stringstream ss;
    ss << pe.adr;
    res.gray_peers.push_back(ss.str());
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::vector<CryptoNoteConnectionContext> peers;
  if(!m_protocolQuery.getConnections(peers)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get connections" };
  }

  for (const auto& p : peers) {
    p2p_connection_entry c;

    c.version = p.version;
    c.state = get_protocol_state_string(p.m_state);
    c.connection_id = boost::lexical_cast<std::string>(p.m_connection_id);
    c.remote_ip = Common::ipAddressToString(p.m_remote_ip);
    c.remote_port = p.m_remote_port;
    c.is_incoming = p.m_is_income;
    c.started = static_cast<uint64_t>(p.m_started);
    c.remote_blockchain_height = p.m_remote_blockchain_height;
    c.last_response_height = p.m_last_response_height;

    res.connections.push_back(c);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------

bool RpcServer::on_blocks_list_json(const COMMAND_RPC_GET_BLOCKS_LIST::request& req, COMMAND_RPC_GET_BLOCKS_LIST::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  uint32_t print_blocks_count = 10;
  if(req.count <= BLOCK_LIST_MAX_COUNT)
    print_blocks_count = req.count;
  
  uint32_t last_height = req.height - print_blocks_count;
  if (req.height <= print_blocks_count)  {
    last_height = 0;
  }

  for (uint32_t i = req.height; i >= last_height; i--) {
    Crypto::Hash block_hash = m_core.getBlockIdByHeight(i);
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }

    size_t tx_cumulative_block_size;
    m_core.getBlockSize(block_hash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    Difficulty blockDiff;
    m_core.getBlockDifficulty(static_cast<uint32_t>(i), blockDiff);

    block_short_response block_short;
    block_short.timestamp = blk.timestamp;
    block_short.height = i;
    block_short.hash = Common::podToHex(block_hash);
    block_short.cumulative_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    block_short.transactions_count = blk.transactionHashes.size() + 1;
    block_short.difficulty = blockDiff;

    res.blocks.push_back(block_short);

    if (i == 0)
      break;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_alt_blocks_list_json(const COMMAND_RPC_GET_ALT_BLOCKS_LIST::request& req, COMMAND_RPC_GET_ALT_BLOCKS_LIST::response& res) {
  std::list<Block> alt_blocks;

  if (m_core.get_alternative_blocks(alt_blocks) && !alt_blocks.empty()) {
    for (const auto & b : alt_blocks) {
      Crypto::Hash block_hash = get_block_hash(b);
      uint32_t block_height = boost::get<BaseInput>(b.baseTransaction.inputs.front()).blockIndex;
      size_t tx_cumulative_block_size;
      m_core.getBlockSize(block_hash, tx_cumulative_block_size);
      size_t blokBlobSize = getObjectBinarySize(b);
      size_t minerTxBlobSize = getObjectBinarySize(b.baseTransaction);
      Difficulty blockDiff;
      m_core.getBlockDifficulty(static_cast<uint32_t>(block_height), blockDiff);

      block_short_response block_short;
      block_short.timestamp = b.timestamp;
      block_short.height = block_height;
      block_short.hash = Common::podToHex(block_hash);
      block_short.cumulative_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
      block_short.transactions_count = b.transactionHashes.size() + 1;
      block_short.difficulty = blockDiff;

      res.alt_blocks.push_back(block_short);
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool_short(const COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::response& res) {
  auto pool = m_core.getMemoryPool();
  for (const CryptoNote::tx_memory_pool::TransactionDetails& txd : pool) {
    transaction_pool_response mempool_transaction;
    mempool_transaction.hash = Common::podToHex(txd.id);
    mempool_transaction.fee = txd.fee;
    mempool_transaction.amount_out = getOutputAmount(txd.tx);
    mempool_transaction.size = txd.blobSize;
    mempool_transaction.receive_time = txd.receiveTime;
    res.transactions.push_back(mempool_transaction);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool(const COMMAND_RPC_GET_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL::response& res) {
  auto pool = m_core.getMemoryPool();

  for (const auto& txd : pool) {
    TransactionDetails transactionDetails;
    if (!blockchainExplorerDataBuilder.fillTransactionDetails(txd.tx, transactionDetails, txd.receiveTime)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill mempool tx details." };
    }
    res.transactions.push_back(std::move(transactionDetails));
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool_raw(const COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::response& res) {
  auto pool = m_core.getMemoryPool();

  for (const auto& txd : pool) {
    res.transactions.push_back(wallet_sync_transaction());
    wallet_sync_transaction &e = res.transactions.back();
    e.hash = txd.id;
    e.coinbase = false;
    e.transaction = *static_cast<const TransactionPrefix*>(&txd.tx);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_by_payment_id(const COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
  if (!req.payment_id.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected payment_id" };
  }

  Crypto::Hash paymentId;
  std::vector<Transaction> transactions;

  if (!parse_hash256(req.payment_id, paymentId)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse Payment ID: " + req.payment_id + '.' };
  }

  if (!m_core.getTransactionsByPaymentId(paymentId, transactions)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get transactions by Payment ID: " + req.payment_id + '.' };
  }

  for (const Transaction& tx : transactions) {
    transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(tx, amount_in);
    uint64_t amount_out = get_outs_money_amount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    res.transactions.push_back(transaction_short);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res) {
  res.count = m_core.getCurrentBlockchainHeight();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t h = static_cast<uint32_t>(req[0]);
  Crypto::Hash blockId = m_core.getBlockIdByHeight(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{ 
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight())
    };
  }

  res = Common::podToHex(blockId);
  return true;
}

namespace {
  uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
  {
    void* buf = start_buff;
    void* end = (char*)buf + buflen - patlen;
    while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
    {
      if (buf>end)
        return 0;
      if (memcmp(buf, pat, patlen) == 0)
        return (char*)buf - (char*)start_buff;
      buf = (char*)buf + 1;
    }
    return 0;
  }
}

bool RpcServer::on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& /*req*/, COMMAND_RPC_GET_CURRENCY_ID::response& res) {
  Crypto::Hash currencyId = m_core.currency().genesisBlockHash();
  res.currency_id_blob = Common::podToHex(currencyId);
  return true;
}

namespace {
  uint64_t get_block_reward(const Block& blk) {
    uint64_t reward = 0;
    for (const TransactionOutput& out : blk.baseTransaction.outputs) {
      reward += out.amount;
    }
    return reward;
  }
}

void RpcServer::fill_block_header_response(const Block& blk, bool orphan_status, uint32_t height, const Crypto::Hash& hash, block_header_response& responce) {
  responce.major_version = blk.majorVersion;
  responce.minor_version = blk.minorVersion;
  responce.timestamp = blk.timestamp;
  responce.prev_hash = Common::podToHex(blk.previousBlockHash);
  responce.nonce = blk.nonce;
  responce.orphan_status = orphan_status;
  responce.height = height;
  responce.depth = m_core.getCurrentBlockchainHeight() - height - 1;
  responce.hash = Common::podToHex(hash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(height), responce.difficulty);
  responce.reward = get_block_reward(blk);
}

bool RpcServer::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res) {
  uint32_t last_block_height;
  Crypto::Hash last_block_hash;
  
  m_core.get_blockchain_top(last_block_height, last_block_hash);

  Block last_block;
  if (!m_core.getBlockByHash(last_block_hash, last_block)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last block hash." };
  }
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(last_block_height);
  bool is_orphaned = last_block_hash != tmp_hash;
  fill_block_header_response(last_block, is_orphaned, last_block_height, last_block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res) {
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

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint32_t block_height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(block_height);
  bool is_orphaned = block_hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, block_height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  Crypto::Hash block_hash = m_core.getBlockIdByHeight(static_cast<uint32_t>(req.height));
  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.' };
  }
  
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(req.height);
  bool is_orphaned = block_hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, req.height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_timestamp_by_height(const COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  res.status = CORE_RPC_STATUS_OK;

  m_core.getBlockTimestamp(req.height, res.timestamp);

  return true;
}

bool RpcServer::on_check_transaction_proof(
    const COMMAND_RPC_CHECK_TRANSACTION_PROOF::request& req,
    COMMAND_RPC_CHECK_TRANSACTION_PROOF::response& res) {
  Crypto::Hash transactionId;
  if (!parse_hash256(req.transaction_id, transactionId)) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse transaction ID"};
  }

  ResolvedRecipient recipient;
  PqAddress address;
  if (decodePqAddress(req.destination_address, m_core.currency().isTestnet(), address)) {
    recipient.viewPub = address.viewPub;
    recipient.spendPub = address.spendPub;
  } else {
    AccountNumber account;
    uint32_t subaddressIndex = 0;
    uint32_t wantFingerprint = 0;
    const bool hasSubaddress = AccountNumber::fromStringWithIndex(
        req.destination_address, account, subaddressIndex, wantFingerprint);
    if (!hasSubaddress && !AccountNumber::fromString(req.destination_address, account, wantFingerprint)) {
      throw JsonRpc::JsonRpcError{
          CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse destination address"};
    }
    if (!m_core.resolvePqAccountNumber(
            account.blockHeight, account.txIndex,
            recipient.viewPub, recipient.spendPub)) {
      throw JsonRpc::JsonRpcError{
          CORE_RPC_ERROR_CODE_WRONG_PARAM, "Destination account number was not found"};
    }
    // Failsafe: the resolved keys must fingerprint to the A embedded in the number.
    const uint32_t gotFingerprint = pqAccountFingerprint(
        m_core.currency().isTestnet(),
        recipient.spendPub.data(), recipient.spendPub.size(),
        recipient.viewPub.data(), recipient.viewPub.size());
    if (gotFingerprint != wantFingerprint) {
      throw JsonRpc::JsonRpcError{
          CORE_RPC_ERROR_CODE_WRONG_PARAM,
          "Destination account fingerprint does not match the on-chain keys"};
    }
    recipient.subaddrIndexT = hasSubaddress ? subaddressIndex : 0;
  }

  PqPaymentProof proof;
  if (!decodePqPaymentProof(req.signature, m_core.currency().isTestnet(), proof)) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM, "Payment proof decoding error"};
  }

  std::vector<Crypto::Hash> transactionIds{transactionId};
  std::list<Transaction> transactions;
  std::list<Crypto::Hash> missedTransactions;
  m_core.getTransactions(transactionIds, transactions, missedTransactions, true);
  if (!missedTransactions.empty() || transactions.size() != 1) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Couldn't find transaction " + req.transaction_id};
  }

  res.signature_valid = false;
  res.received_amount = 0;
  res.outputs.clear();
  res.output_indices.clear();
  res.confirmations = 0;

  try {
    const Transaction& transaction = transactions.front();
    if (transaction.txType != TX_PQ) {
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }
    const PqPaymentProofTransaction proofTransaction =
        makePqPaymentProofTransaction(transaction);
    CryptoPQ::Hash256 expectedGenesis{};
    const Crypto::Hash genesis = m_core.currency().genesisBlockHash();
    std::memcpy(expectedGenesis.data(), genesis.data, expectedGenesis.size());

    res.received_amount = verifyPqPaymentProof(
        proof, expectedGenesis, proofTransaction, recipient);
    res.signature_valid = true;
    res.output_indices.reserve(proof.entries.size());
    res.outputs.reserve(proof.entries.size());
    for (const PqPaymentProofEntry& entry : proof.entries) {
      res.output_indices.push_back(entry.outputIndex);
      res.outputs.push_back(transaction.outputs[entry.outputIndex]);
    }
  } catch (const PqPaymentProofError&) {
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  Crypto::Hash blockHash;
  uint32_t blockHeight = 0;
  if (m_core.getBlockContainingTx(transactionId, blockHash, blockHeight)) {
    const uint32_t chainHeight = m_core.getCurrentBlockchainHeight();
    if (chainHeight > blockHeight) {
      res.confirmations = chainHeight - blockHeight;
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_validate_address(const COMMAND_RPC_VALIDATE_ADDRESS::request& req, COMMAND_RPC_VALIDATE_ADDRESS::response& res) {
  // Discrete is PQ-only: valid forms are a bech32m PQ address (this network's HRP)
  // or an H-I-A-C / H-I-A-T-C account number. The classical base58 ECC form is never valid.
  CryptoNote::PqAddress pq;
  CryptoNote::AccountNumber acct;
  uint32_t subaddrIndex = 0;
  res.is_valid = CryptoNote::decodePqAddress(req.address, m_core.currency().isTestnet(), pq) ||
                 CryptoNote::AccountNumber::fromStringWithIndex(req.address, acct, subaddrIndex) ||
                 CryptoNote::AccountNumber::fromString(req.address, acct);
  if (res.is_valid) {
    // PQ spend/view keys are large (ML-DSA-65 / ML-KEM-768) and account-number keys
    // live on-chain, so only the address itself is echoed back.
    res.address = req.address;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_verify_message(const COMMAND_RPC_VERIFY_MESSAGE::request& req, COMMAND_RPC_VERIFY_MESSAGE::response& res) {
  // Discrete identities are post-quantum (ML-DSA). Decode the PQ address to its
  // spend key and verify the ML-DSA signature against it.
  CryptoNote::PqAddress addr;
  if (!CryptoNote::decodePqAddress(req.address, addr)) {
    throw JsonRpc::JsonRpcError{CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address" };
  }

  res.sig_valid = CryptoNote::verifyMessagePq(req.message, addr.spendPub, req.signature);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_resolve_open_alias(const COMMAND_RPC_RESOLVE_OPEN_ALIAS::request& req, COMMAND_RPC_RESOLVE_OPEN_ALIAS::response& res) {

#ifndef __ANDROID__
  try {
    res.address = Common::resolveAlias(req.url);

    // The alias must resolve to a PQ address on this network (bech32m HRP check).
    CryptoNote::PqAddress pq;
    if (!CryptoNote::decodePqAddress(res.address, m_core.currency().isTestnet(), pq)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Address \"" + res.address + "\" is invalid" };
    }
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't resolve alias: " + std::string(e.what()) };
    return true;
  }
#endif

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_pq_account(const COMMAND_RPC_GET_PQ_ACCOUNT::request& req,
                                  COMMAND_RPC_GET_PQ_ACCOUNT::response& res) {
  std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> viewPub;
  std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub;
  size_t sz = 0;
  if (!Common::fromHex(req.view_pub, viewPub.data(), viewPub.size(), sz) || sz != viewPub.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Invalid view_pub hex" };
  }
  sz = 0;
  if (!Common::fromHex(req.spend_pub, spendPub.data(), spendPub.size(), sz) || sz != spendPub.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Invalid spend_pub hex" };
  }

  uint32_t blockHeight = 0, txIndex = 0;
  res.registered = m_core.getPqAccountNumber(getPqAccountIdentityHash(viewPub, spendPub), blockHeight, txIndex);
  res.block_height = res.registered ? blockHeight : 0;
  res.tx_index = res.registered ? txIndex : 0;
  if (res.registered) {
    // Render the full H-I-A-C number from the caller's own keys. This does NOT go
    // through resolvePqAccountNumber, so the owner sees their number as soon as the
    // registration is confirmed — even before it is final and payable by others.
    const uint32_t fp = pqAccountFingerprint(m_core.currency().isTestnet(),
                                             spendPub.data(), spendPub.size(),
                                             viewPub.data(), viewPub.size());
    res.account_number = AccountNumber{blockHeight, txIndex}.toString(fp);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_resolve_pq_account(const COMMAND_RPC_RESOLVE_PQ_ACCOUNT::request& req,
                                      COMMAND_RPC_RESOLVE_PQ_ACCOUNT::response& res) {
  std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> viewPub;
  std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub;
  res.found = m_core.resolvePqAccountNumber(req.block_height, req.tx_index, viewPub, spendPub);
  if (res.found) {
    res.view_pub = Common::toHex(viewPub.data(), viewPub.size());
    res.spend_pub = Common::toHex(spendPub.data(), spendPub.size());
    const uint32_t fp = pqAccountFingerprint(m_core.currency().isTestnet(),
                                             spendPub.data(), spendPub.size(),
                                             viewPub.data(), viewPub.size());
    res.account_number = AccountNumber{req.block_height, req.tx_index}.toString(fp);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

}
