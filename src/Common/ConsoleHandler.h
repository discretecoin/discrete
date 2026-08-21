// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "BlockingQueue.h"
#include "ConsoleTools.h"

#ifndef _WIN32
#include <sys/select.h>
#endif 

namespace Common {

enum class ConsoleReadResult {
  Success,
  EndOfInput,
  Cancelled,
  Error,
  Unsupported
};

class IConsoleInput {
public:
  virtual ~IConsoleInput() = default;
  virtual bool isInteractive() const = 0;
  virtual ConsoleReadResult readInteractive(const std::string& prompt, std::string& line,
                                            const std::function<bool()>& cancelled) = 0;
  virtual bool waitInput(const std::function<bool()>& cancelled) = 0;
  virtual bool readLegacy(std::string& line) = 0;
};

class AsyncConsoleReader {

public:

  explicit AsyncConsoleReader(std::shared_ptr<IConsoleInput> input = nullptr);
  ~AsyncConsoleReader();

  void start(bool memoryHistory = false, const std::string& prompt = "",
             Console::Color promptColor = Console::Color::Default);
  bool getline(std::string& line);
  void inputConsumed();
  bool usesLineEditor() const;
  void stop();
  bool stopped() const;
  void pause();
  void unpause();
  
private:

  void consoleThread();

  std::shared_ptr<IConsoleInput> m_input;
  std::atomic<bool> m_stop;
  std::thread m_thread;
  BlockingQueue<std::string> m_queue;
  bool m_memoryHistory = false;
  std::string m_prompt;
  Console::Color m_promptColor = Console::Color::Default;
  std::atomic<bool> m_lineEditorEnabled{false};
  std::mutex m_inputMutex;
  std::condition_variable m_inputConsumed;
  bool m_inputPending = false;
};


class ConsoleHandler {
public:

  ~ConsoleHandler();

  typedef std::function<bool(const std::vector<std::string> &)> ConsoleCommandHandler;

  std::string getUsage() const;
  void setHandler(const std::string& command, const ConsoleCommandHandler& handler, const std::string& usage = "");
  void requestStop();
  bool runCommand(const std::vector<std::string>& cmdAndArgs);

  void start(bool startThread = true, const std::string& prompt = "", Console::Color promptColor = Console::Color::Default,
             bool memoryHistory = false);
  void stop();
  void wait();
  void pause();
  void unpause();

private:

  typedef std::map<std::string, std::pair<ConsoleCommandHandler, std::string>> CommandHandlersMap;

  virtual void handleCommand(const std::string& cmd);

  void handlerThread();

  std::thread m_thread;
  std::string m_prompt;
  Console::Color m_promptColor = Console::Color::Default;
  CommandHandlersMap m_handlers;
  AsyncConsoleReader m_consoleReader;
};

}
