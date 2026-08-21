// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2014-2016 XDN developers
// Copyright (c) 2006-2013 Andrey N.Sabelnikov, www.sabelnikov.net
// Copyright (c) 2020-2022, The Talleo developers
// Copyright (c) 2016-2012 The Karbowanec developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ConsoleHandler.h"

#include <iostream>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#else
#include <unistd.h>
#include <stdio.h>
#endif

#include <boost/algorithm/string.hpp>
#include "linenoise.hpp"

using Common::Console::Color;

namespace Common {

namespace {

std::string colorizePrompt(const std::string& prompt, Color color) {
  static const char* ansiColors[] = {
    "\033[0m",   "\033[0;34m", "\033[0;32m", "\033[0;31m",
    "\033[0;33m", "\033[0;37m", "\033[0;36m", "\033[0;35m",
    "\033[1;34m", "\033[1;32m", "\033[1;31m", "\033[1;33m",
    "\033[1;37m", "\033[1;36m", "\033[1;35m"
  };

  if (color == Color::Default || color > Color::BrightMagenta) {
    return prompt;
  }

  return std::string(ansiColors[static_cast<size_t>(color)]) + prompt + ansiColors[0];
}

class DefaultConsoleInput : public IConsoleInput {
public:
  bool isInteractive() const override {
    return linenoise::IsInteractive();
  }

  ConsoleReadResult readInteractive(const std::string& prompt, std::string& line,
                                    const std::function<bool()>& cancelled) override {
    switch (linenoise::ReadlineInterruptible(prompt.c_str(), line, cancelled)) {
      case linenoise::ReadlineResult::Success:
        return ConsoleReadResult::Success;
      case linenoise::ReadlineResult::EndOfInput:
        return ConsoleReadResult::EndOfInput;
      case linenoise::ReadlineResult::Cancelled:
        return ConsoleReadResult::Cancelled;
      case linenoise::ReadlineResult::Error:
        return ConsoleReadResult::Error;
      case linenoise::ReadlineResult::Unsupported:
        return ConsoleReadResult::Unsupported;
    }
    return ConsoleReadResult::Unsupported;
  }

  bool waitInput(const std::function<bool()>& cancelled) override {
#ifndef _WIN32
    #if defined(__OpenBSD__) || defined(__ANDROID__)
      int stdin_fileno = fileno(stdin);
    #else
      int stdin_fileno = ::fileno(stdin);
    #endif

    while (!cancelled()) {
      fd_set read_set;
      FD_ZERO(&read_set);
      FD_SET(stdin_fileno, &read_set);

      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 100 * 1000;

      int retval = ::select(stdin_fileno + 1, &read_set, NULL, NULL, &tv);
      if (retval == -1 && errno == EINTR) {
        continue;
      }
      if (retval < 0) {
        return false;
      }
      if (retval > 0) {
        return true;
      }
    }
#else
    while (!cancelled()) {
      DWORD retval = ::WaitForSingleObject(::GetStdHandle(STD_INPUT_HANDLE), 100);
      switch (retval) {
        case WAIT_FAILED:
          return false;
        case WAIT_OBJECT_0:
          return true;
        default:
          break;
      }
    }
#endif
    return !cancelled();
  }

  bool readLegacy(std::string& line) override {
    return static_cast<bool>(std::getline(std::cin, line));
  }
};

} // namespace

/////////////////////////////////////////////////////////////////////////////
// AsyncConsoleReader
/////////////////////////////////////////////////////////////////////////////
AsyncConsoleReader::AsyncConsoleReader(std::shared_ptr<IConsoleInput> input)
    : m_input(input ? std::move(input) : std::make_shared<DefaultConsoleInput>()), m_stop(true) {
}

AsyncConsoleReader::~AsyncConsoleReader() {
  stop();
}

void AsyncConsoleReader::start(bool memoryHistory, const std::string& prompt,
                               Console::Color promptColor) {
  m_memoryHistory = memoryHistory;
  m_prompt = prompt;
  m_promptColor = promptColor;
  m_lineEditorEnabled = memoryHistory && m_input->isInteractive();
  m_stop = false;
  m_thread = std::thread(std::bind(&AsyncConsoleReader::consoleThread, this));
}

bool AsyncConsoleReader::getline(std::string& line) {
  return m_queue.pop(line);
}

void AsyncConsoleReader::inputConsumed() {
  std::lock_guard<std::mutex> lock(m_inputMutex);
  m_inputPending = false;
  m_inputConsumed.notify_one();
}

bool AsyncConsoleReader::usesLineEditor() const {
  return m_lineEditorEnabled;
}

void AsyncConsoleReader::pause() {
  if (m_stop) {
    return;
  }

  m_stop = true;
  m_inputConsumed.notify_all();

  if (m_thread.joinable()) {
    m_thread.join();
  }

  m_thread = std::thread();
}

void AsyncConsoleReader::unpause() {
  start(m_memoryHistory, m_prompt, m_promptColor);
} 

void AsyncConsoleReader::stop() {

  if (m_stop) {
    return; // already stopping/stopped
  }

  m_stop = true;
  m_inputConsumed.notify_all();
  m_queue.close();

  if (m_thread.joinable()) {
    m_thread.join();
  }

  m_thread = std::thread();
}

bool AsyncConsoleReader::stopped() const {
  return m_stop;
}

void AsyncConsoleReader::consoleThread() {

  if (m_lineEditorEnabled) {
    // History is deliberately process-local. Do not call linenoise's
    // SaveHistory/LoadHistory APIs: wallet commands may contain sensitive data.
    linenoise::SetHistoryMaxLen(256);
  }

  bool inputEnded = false;
  while (!m_stop) {
    {
      std::unique_lock<std::mutex> lock(m_inputMutex);
      m_inputConsumed.wait(lock, [this] { return !m_inputPending || m_stop; });
      if (m_stop) {
        break;
      }
    }

    // Linenoise must enter raw mode and render the prompt before the first key
    // arrives. The legacy getline path keeps its interruptible select loop.
    if (!m_lineEditorEnabled && !m_input->waitInput([this] { return m_stop.load(); })) {
      inputEnded = !m_stop;
      break;
    }

    std::string line;

    if (m_lineEditorEnabled) {
      const std::string prompt = colorizePrompt(m_prompt, m_promptColor);
      const auto result = m_input->readInteractive(
          prompt, line, [this] { return m_stop.load(); });
      if (result == ConsoleReadResult::Cancelled) {
        break;
      }
      if (result == ConsoleReadResult::Error) {
        inputEnded = !m_stop;
        break;
      }
      if (result == ConsoleReadResult::Unsupported) {
        m_lineEditorEnabled = false;
        if (!m_prompt.empty()) {
          if (m_promptColor != Color::Default) {
            Console::setTextColor(m_promptColor);
          }
          std::cout << m_prompt;
          std::cout.flush();
          if (m_promptColor != Color::Default) {
            Console::setTextColor(Color::Default);
          }
        }
        continue;
      }
      if (result == ConsoleReadResult::EndOfInput) {
        // Treat Ctrl-C/Ctrl-D like the wallet's exit command so the command
        // handler can perform its normal shutdown.
        line = "exit";
      } else {
        std::string historyLine = line;
        boost::algorithm::trim(historyLine);
        if (!historyLine.empty()) {
          linenoise::AddHistory(historyLine.c_str());
        }
      }
    } else if (!m_input->readLegacy(line)) {
      inputEnded = !m_stop;
      break;
    }

    {
      std::lock_guard<std::mutex> lock(m_inputMutex);
      m_inputPending = true;
    }
    if (!m_queue.push(line)) {
      std::lock_guard<std::mutex> lock(m_inputMutex);
      m_inputPending = false;
      break;
    }

    // Do not begin a second terminal read until the command has completed.
    // This keeps pause and exit safe while linenoise is in raw terminal mode.
    std::unique_lock<std::mutex> lock(m_inputMutex);
    m_inputConsumed.wait(lock, [this] { return !m_inputPending || m_stop; });
  }

  if (inputEnded) {
    m_queue.close();
  }
}

/////////////////////////////////////////////////////////////////////////////
// ConsoleHandler
/////////////////////////////////////////////////////////////////////////////
ConsoleHandler::~ConsoleHandler() {
  stop();
}

void ConsoleHandler::start(bool startThread, const std::string& prompt, Console::Color promptColor,
                           bool memoryHistory) {
  m_prompt = prompt;
  m_promptColor = promptColor;
  m_consoleReader.start(memoryHistory, prompt, promptColor);

  if (startThread) {
    m_thread = std::thread(std::bind(&ConsoleHandler::handlerThread, this));
  } else {
    handlerThread();
  }
}

void ConsoleHandler::stop() {
  requestStop();
  wait();
}

void ConsoleHandler::pause() {
  m_consoleReader.pause();
}

void ConsoleHandler::unpause() {
  m_consoleReader.unpause();
}
  
void ConsoleHandler::wait() {

  try {
    if (m_thread.joinable() && m_thread.get_id() != std::this_thread::get_id()) {
      m_thread.join();
    }
  } catch (std::exception& e) {
    std::cerr << "Exception in ConsoleHandler::wait - " << e.what() << std::endl;
  }
}

void ConsoleHandler::requestStop() {
  m_consoleReader.stop();
}

std::string ConsoleHandler::getUsage() const {

  if (m_handlers.empty()) {
    return std::string();
  }
  
  std::stringstream ss;

  size_t maxlen = std::max_element(m_handlers.begin(), m_handlers.end(), [](
    CommandHandlersMap::const_reference& a, CommandHandlersMap::const_reference& b) { 
      return a.first.size() < b.first.size(); })->first.size();

  for (auto& x : m_handlers) {
    ss << std::left << std::setw(maxlen + 3) << x.first << x.second.second << std::endl;
  }

  return ss.str();
}

void ConsoleHandler::setHandler(const std::string& command, const ConsoleCommandHandler& handler, const std::string& usage) {
  m_handlers[command] = std::make_pair(handler, usage);
}

bool ConsoleHandler::runCommand(const std::vector<std::string>& cmdAndArgs) {
  if (cmdAndArgs.size() == 0) {
    return false;
  }

  const auto& cmd = cmdAndArgs.front();
  auto hIter = m_handlers.find(cmd);

  if (hIter == m_handlers.end()) {
    std::cout << "Unknown command: " << cmd << std::endl;
    return false;
  }

  std::vector<std::string> args(cmdAndArgs.begin() + 1, cmdAndArgs.end());
  hIter->second.first(args);
  return true;
}

void ConsoleHandler::handleCommand(const std::string& cmd) {
  bool parseString = false;
  std::string arg;
  std::vector<std::string> argList;

  for (auto ch : cmd) {
    switch (ch) {
    case ' ':
      if (parseString) {
        arg += ch;
      } else if (!arg.empty()) {
        argList.emplace_back(std::move(arg));
        arg.clear();
      }
      break;

    case '"':
      if (!arg.empty()) {
        argList.emplace_back(std::move(arg));
        arg.clear();
      }

      parseString = !parseString;
      break;

    default:
      arg += ch;
    }
  }

  if (!arg.empty()) {
    argList.emplace_back(std::move(arg));
  }

  runCommand(argList);
}

void ConsoleHandler::handlerThread() {
  std::string line;

  while(!m_consoleReader.stopped()) {
    try {
      if (!m_consoleReader.usesLineEditor() && !m_prompt.empty()) {
        if (m_promptColor != Color::Default) {
          Console::setTextColor(m_promptColor);
        }

        std::cout << m_prompt;
        std::cout.flush();

        if (m_promptColor != Color::Default) {
          Console::setTextColor(Color::Default);
        }
      }

      if (!m_consoleReader.getline(line)) {
        break;
      }

      boost::algorithm::trim(line);
      if (!line.empty()) {
        handleCommand(line);
      }

      m_consoleReader.inputConsumed();

    } catch (std::exception&) {
      m_consoleReader.inputConsumed();
      // ignore errors
    }
  }
}

}
