// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2022, The Karbo developers
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

#include "Miner.h"

#include <future>
#include <numeric>
#include <sstream>
#include <thread>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/limits.hpp>
#include <boost/utility/value_init.hpp>

#include "crypto/crypto.h"
#include "crypto/random.h"
#include "Common/CommandLine.h"
#include "Common/StringTools.h"
#include "Serialization/SerializationTools.h"

#include "CryptoNoteFormatUtils.h"
#include "TransactionExtra.h"
#include "crypto_pq/PqDsa.h"

#undef ERROR

using namespace Logging;

namespace CryptoNote
{

  miner::miner(const Currency& currency, IMinerHandler& handler, Logging::ILogger& log) :
    m_currency(currency),
    logger(log, "miner"),
    m_stop(true),
    m_template(boost::value_initialized<Block>()),
    m_template_no(0),
    m_diffic(0),
    m_handler(handler),
    m_pausers_count(0),
    m_threads_total(0),
    m_starter_nonce(0),
    m_last_hr_merge_time(0),
    m_hashes(0),
    m_do_print_hashrate(false),
    m_do_log_hashrate(false),
    m_do_mining(false),
    m_current_hash_rate(0),
    m_update_block_template_interval(5),
    m_update_merge_hr_interval(2),
    m_update_log_hr_interval(60)
  {
  }
  //-----------------------------------------------------------------------------------------------------
  miner::~miner() {
    stop();
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_block_template(const Block& bl, const Difficulty& di) {
    std::lock_guard<decltype(m_template_lock)> lk(m_template_lock);

    m_template = bl;

    if (m_template.majorVersion == BLOCK_MAJOR_VERSION_2 || m_template.majorVersion == BLOCK_MAJOR_VERSION_3) {
      CryptoNote::TransactionExtraMergeMiningTag mm_tag;
      mm_tag.depth = 0;
      if (!CryptoNote::get_aux_block_header_hash(m_template, mm_tag.merkleRoot)) {
        return false;
      }

      m_template.parentBlock.baseTransaction.extra.clear();
      if (!CryptoNote::appendMergeMiningTagToExtra(m_template.parentBlock.baseTransaction.extra, mm_tag)) {
        return false;
      }
    }

    m_diffic = di;
    ++m_template_no;
    m_starter_nonce = Random::randomValue<uint32_t>();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_block_chain_update() {
    if (!is_mining()) {
      return true;
    }

    return request_block_template();
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::request_block_template() {
    Block bl = boost::value_initialized<Block>();
    Difficulty di = 0;
    uint32_t height;
    CryptoNote::BinaryArray extra_nonce;

    if(m_extra_messages.size() && m_config.current_extra_message_index < m_extra_messages.size()) {
      extra_nonce = m_extra_messages[m_config.current_extra_message_index];
    }

    // Discrete mines PQ blocks: the coinbase pays the reward to the miner's PQ
    // identity (m_pq_view_pub/m_pq_spend_pub) and the worker signs each candidate
    // with the matching spend secret (m_pq_spend_sk). The ECC get_block_template
    // path is dead (constructMinerTx returns false).
    if (!m_pq_keys_set) {
      logger(ERROR) << "PQ miner keys not set — call startPq() before mining";
      return false;
    }
    if(!m_handler.get_block_template_pq(bl, m_pq_view_pub, m_pq_spend_pub, di, height, extra_nonce)) {
      logger(ERROR) << "Failed to get_block_template_pq(), stopping mining";
      return false;
    }

    set_block_template(bl, di);
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_idle()
  {
    m_update_block_template_interval.call([&](){
      if(is_mining()) 
        request_block_template();
      return true;
    });

    m_update_merge_hr_interval.call([&](){
      merge_hr(false);
      return true;
    });
    
    m_update_log_hr_interval.call([&](){
      merge_hr(true);
      return true;
    });

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::do_print_hashrate(bool do_hr)
  {
    m_do_print_hashrate = do_hr;
  }

  uint64_t millisecondsSinceEpoch() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  }

  //-----------------------------------------------------------------------------------------------------
  void miner::merge_hr(bool do_log)
  {
    if(m_last_hr_merge_time && is_mining()) {
      m_current_hash_rate = m_hashes * 1000 / (millisecondsSinceEpoch() - m_last_hr_merge_time + 1);
      std::lock_guard<std::mutex> lk(m_last_hash_rates_lock);
      m_last_hash_rates.push_back(m_current_hash_rate);
      if(m_last_hash_rates.size() > 19)
        m_last_hash_rates.pop_front();

      uint64_t total_hr = std::accumulate(m_last_hash_rates.begin(), m_last_hash_rates.end(), (uint64_t)0);
      float hr = static_cast<float>(total_hr) / static_cast<float>(m_last_hash_rates.size());

      if(m_do_print_hashrate)
        std::cout << "Hashrate: " << std::setprecision(2) << std::fixed << hr << " H/s" << "        \r";

      if (do_log && m_do_log_hashrate)
        logger(INFO, BRIGHT_WHITE) << "Hashrate: " << std::setprecision(2) << std::fixed << hr << " H/s";
    }

    m_last_hr_merge_time = millisecondsSinceEpoch();
    m_hashes = 0;
  }

  bool miner::init(const MinerConfig& config) {
    if (!config.extraMessages.empty()) {
      std::string buff;
      if (!Common::loadFileToString(config.extraMessages, buff)) {
        logger(ERROR, BRIGHT_RED) << "Failed to load file with extra messages: " << config.extraMessages; 
        return false; 
      }
      std::vector<std::string> extra_vec;
      boost::split(extra_vec, buff, boost::is_any_of("\n"), boost::token_compress_on );
      m_extra_messages.resize(extra_vec.size());
      for(size_t i = 0; i != extra_vec.size(); i++) {
        boost::algorithm::trim(extra_vec[i]);
        if(!extra_vec[i].size())
          continue;
        BinaryArray ba = Common::asBinaryArray(Common::base64Decode(extra_vec[i]));
        if(buff != "0")
          m_extra_messages[i] = ba;
      }
      m_config_folder_path = boost::filesystem::path(config.extraMessages).parent_path().string();
      m_config = boost::value_initialized<decltype(m_config)>();

      std::string filebuf;
      if (Common::loadFileToString(m_config_folder_path + "/" + CryptoNote::parameters::MINER_CONFIG_FILE_NAME, filebuf)) {
        loadFromJson(m_config, filebuf);
      }

      logger(INFO) << "Loaded " << m_extra_messages.size() << " extra messages, current index " << m_config.current_extra_message_index;
    }

    // Headless mining is armed from Daemon.cpp (it derives the PQ identity from
    // the --mining-wallet container and calls startPq); init() only carries the
    // thread/hashrate knobs. The classical spend/view-key flags are gone — a raw
    // 32-byte secret on the command line never derived the PQ keys, so it could
    // not sign blocks and silently failed.
    m_threads_total = 1;
    if (config.miningThreads > 0) {
      m_threads_total = config.miningThreads;
    }

    m_do_print_hashrate = config.printHashrate;
    m_do_log_hashrate = config.logHashrate;

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::is_mining()
  {
    return !m_stop;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::startPq(const CryptoPQ::KemPublicKey& viewPub,
                      const CryptoPQ::DsaPublicKey& spendPub,
                      const CryptoPQ::DsaSecretKey& spendSk,
                      size_t threads_count) {
    m_pq_view_pub   = viewPub;
    m_pq_spend_pub  = spendPub;
    m_pq_spend_sk   = spendSk;
    m_pq_keys_set   = true;
    // Delegate to the common threading setup (with a dummy ECC account).
    return start(AccountKeys{}, threads_count);
  }

  bool miner::start(const AccountKeys& acc, size_t threads_count)
  {
    if (is_mining()) {
      logger(ERROR) << "Starting miner but it's already started";
      return false;
    }

    std::lock_guard<std::mutex> lk(m_threads_lock);

    if(!m_threads.empty()) {
      logger(ERROR) << "Unable to start miner because there are active mining threads";
      return false;
    }

    m_mine_account = acc;

    m_threads_total = static_cast<uint32_t>(threads_count);
    m_starter_nonce = Random::randomValue<uint32_t>();

    if (!m_template_no) {
      if (!request_block_template()) { //lets update block template
        return false;
      }
    }

    m_do_mining = true;
    m_stop = false;
    m_pausers_count = 0; // in case mining wasn't resumed after pause

    for (uint32_t i = 0; i != threads_count; i++) {
      m_threads.push_back(std::thread(std::bind(&miner::worker_thread, this, i)));
    }

    logger(INFO) << "Mining has started with " << threads_count << " threads, good luck!";
    return true;
  }
  
  //-----------------------------------------------------------------------------------------------------
  uint64_t miner::get_speed()
  {
    if(is_mining())
      return m_current_hash_rate;
    else
      return 0;
  }
  
  //-----------------------------------------------------------------------------------------------------
  void miner::send_stop_signal() 
  {
    m_stop = true;
  }

  //-----------------------------------------------------------------------------------------------------
  bool miner::stop(bool keepMiningRequested)
  {
    if (!keepMiningRequested) {
      m_do_mining = false;
    }

    std::lock_guard<std::mutex> lk(m_threads_lock);

    bool mining = !m_threads.empty();
    if (!mining)
    {
      logger(TRACE) << "Not mining - nothing to stop";
      return false;
    }

    send_stop_signal();

    for (auto& th : m_threads) {
      th.join();
    }

    m_threads.clear();
    m_current_hash_rate = 0;
    m_last_hash_rates.clear();
    logger(INFO) << "Mining has been stopped, " << m_threads.size() << " finished" ;
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::on_synchronized()
  {
    if(m_do_mining && !is_mining()) {
      start(m_mine_account, m_threads_total);
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::pause()
  {
    std::lock_guard<std::mutex> lk(m_miners_count_lock);
    ++m_pausers_count;
    if(m_pausers_count == 1 && is_mining())
      logger(TRACE) << "MINING PAUSED";
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::resume()
  {
    std::lock_guard<std::mutex> lk(m_miners_count_lock);
    --m_pausers_count;
    if(m_pausers_count < 0)
    {
      m_pausers_count = 0;
      logger(ERROR) << "Unexpected miner::resume() called";
    }
    if(!m_pausers_count && is_mining())
      logger(TRACE) << "MINING RESUMED";
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::worker_thread(uint32_t th_local_index)
  {
    logger(INFO) << "Miner thread was started ["<< th_local_index << "]";
    uint32_t nonce = m_starter_nonce + th_local_index;
    Difficulty local_diff = 0;
    uint32_t local_template_ver = 0;
    Block b;

    while(!m_stop)
    {
      if(m_pausers_count) //anti split workaround
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        continue;
      }

      if(local_template_ver != m_template_no) {
        std::unique_lock<std::mutex> lk(m_template_lock);
        b = m_template;
        local_diff = m_diffic;
        lk.unlock();

        local_template_ver = m_template_no;
        nonce = m_starter_nonce + th_local_index;
      }

      if(!local_template_ver)//no any set_block_template call
      {
        logger(TRACE) << "Block template not set yet";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        continue;
      }

      b.nonce = nonce;

      // DiscretePower (https://docs.discrete.cash/#/consensus/pow §5): per nonce, sign the
      // candidate header digest m with the resident hot-account spend key and run
      // the signature-tape yespower-discrete chain in one shot. discrete_power_prove fills
      // b.signature and pow. This is identity-bound, delegation-hostile mining:
      // the reward binds to the signing key. Key handling (mlock / zeroize / hot
      // sweep / no-echo password) is owned by startPq() and untouched here.
      Crypto::Hash pow;
      if (!m_pq_keys_set) {
        logger(ERROR) << "PQ miner keys not set — call startPq() before mining.";
        m_stop = true;
      }
      if (!m_stop) {
        try {
          BinaryArray blob;
          if (!get_block_hashing_blob(b, blob)) {
            logger(ERROR) << "get_block_hashing_blob failed.";
            m_stop = true;
          } else if (!discrete_power_prove(blob, m_pq_spend_sk, b.signature, pow)) {
            logger(ERROR) << "discrete_power_prove failed.";
            m_stop = true;
          }
        } catch (const std::exception& e) {
          logger(WARNING) << "PQ block signing / PoW failed: " << e.what();
          m_stop = true;
        }
      }

      if (!m_stop && check_hash(pow, local_diff)) {
        // we lucky!
        ++m_config.current_extra_message_index;

        uint32_t bh = boost::get<BaseInput>(b.baseTransaction.inputs[0]).blockIndex;
        Crypto::Hash id;
        if (!get_block_hash(b, id)) {
          logger(ERROR) << "Failed to get block hash.";
          m_stop = true;
        }

        logger(INFO, GREEN) << "Found block for difficulty "
                            << local_diff
                            << " at height " << bh
                            << " v. " << (int)b.majorVersion << "\r\n"
                            << "POW: " << Common::podToHex(pow) << "\r\n"
                            << " ID: " << Common::podToHex(id);

        if (!m_handler.handle_block_found(b)) {
          --m_config.current_extra_message_index;
        } else {
          //success update, lets update config
          Common::saveStringToFile(m_config_folder_path + "/" + CryptoNote::parameters::MINER_CONFIG_FILE_NAME, storeToJson(m_config));
        }
      }

      nonce += m_threads_total;
      ++m_hashes;
    }
    logger(INFO) << "Miner thread stopped ["<< th_local_index << "]";
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
}
