#include "Common/ConsoleHandler.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace std::chrono_literals;

class FakeConsoleInput : public Common::IConsoleInput {
public:
  bool isInteractive() const override {
    return interactive;
  }

  Common::ConsoleReadResult readInteractive(
      const std::string& prompt, std::string& line,
      const std::function<bool()>& cancelled) override {
    {
      std::lock_guard<std::mutex> lock(mutex);
      lastPrompt = prompt;
    }
    interactiveEntered = true;
    while (blockInteractive && !cancelled()) {
      std::this_thread::sleep_for(1ms);
    }
    if (cancelled()) {
      return Common::ConsoleReadResult::Cancelled;
    }
    line = interactiveLine;
    return interactiveResult;
  }

  bool waitInput(const std::function<bool()>& cancelled) override {
    waitEntered = true;
    while (blockWait && !cancelled()) {
      std::this_thread::sleep_for(1ms);
    }
    return waitResult && !cancelled();
  }

  bool readLegacy(std::string& line) override {
    const size_t index = legacyIndex++;
    if (index >= legacyLines.size()) {
      return false;
    }
    line = legacyLines[index];
    return true;
  }

  std::string prompt() const {
    std::lock_guard<std::mutex> lock(mutex);
    return lastPrompt;
  }

  bool interactive = true;
  std::atomic<bool> interactiveEntered{false};
  std::atomic<bool> blockInteractive{false};
  Common::ConsoleReadResult interactiveResult = Common::ConsoleReadResult::Success;
  std::string interactiveLine;

  std::atomic<bool> waitEntered{false};
  std::atomic<bool> blockWait{false};
  bool waitResult = true;
  std::vector<std::string> legacyLines;
  std::atomic<size_t> legacyIndex{0};

private:
  mutable std::mutex mutex;
  std::string lastPrompt;
};

bool waitUntil(const std::atomic<bool>& value) {
  for (size_t i = 0; i < 1000; ++i) {
    if (value) {
      return true;
    }
    std::this_thread::sleep_for(1ms);
  }
  return false;
}

TEST(ConsoleHandler, ExternalStopInterruptsIdleLineEditor) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->blockInteractive = true;
  Common::AsyncConsoleReader reader(input);
  reader.start(true, "wallet> ");
  ASSERT_TRUE(waitUntil(input->interactiveEntered));

  const auto started = std::chrono::steady_clock::now();
  reader.stop();
  EXPECT_LT(std::chrono::steady_clock::now() - started, 1s);
}

TEST(ConsoleHandler, PipedEofClosesInputQueue) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->interactive = false;
  input->legacyLines = {"help"};
  Common::AsyncConsoleReader reader(input);
  reader.start(true, "wallet> ");

  std::string line;
  ASSERT_TRUE(reader.getline(line));
  EXPECT_EQ("help", line);
  reader.inputConsumed();
  EXPECT_FALSE(reader.getline(line));
  reader.stop();
}

TEST(ConsoleHandler, RedirectedConsoleFallsBackToLegacyInput) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->interactive = false;
  input->legacyLines = {"balance"};
  Common::AsyncConsoleReader reader(input);
  reader.start(true, "wallet> ", Common::Console::Color::BrightYellow);

  EXPECT_FALSE(reader.usesLineEditor());
  std::string line;
  ASSERT_TRUE(reader.getline(line));
  EXPECT_EQ("balance", line);
  reader.inputConsumed();
  reader.stop();
}

TEST(ConsoleHandler, RawModeFailureFallsBackToLegacyInput) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->interactiveResult = Common::ConsoleReadResult::Unsupported;
  input->legacyLines = {"balance"};
  Common::AsyncConsoleReader reader(input);
  reader.start(true);

  std::string line;
  ASSERT_TRUE(reader.getline(line));
  EXPECT_FALSE(reader.usesLineEditor());
  EXPECT_EQ("balance", line);
  reader.inputConsumed();
  reader.stop();
}

TEST(ConsoleHandler, InteractiveReadErrorClosesInputQueue) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->interactiveResult = Common::ConsoleReadResult::Error;
  Common::AsyncConsoleReader reader(input);
  reader.start(true);

  std::string line;
  EXPECT_FALSE(reader.getline(line));
  reader.stop();
}

TEST(ConsoleHandler, LegacyWaitErrorClosesInputQueue) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->interactive = false;
  input->waitResult = false;
  Common::AsyncConsoleReader reader(input);
  reader.start(true);

  std::string line;
  EXPECT_FALSE(reader.getline(line));
  reader.stop();
}

TEST(ConsoleHandler, ControlEndOfInputQueuesGracefulExit) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->interactiveResult = Common::ConsoleReadResult::EndOfInput;
  Common::AsyncConsoleReader reader(input);
  reader.start(true, "wallet> ");

  std::string line;
  ASSERT_TRUE(reader.getline(line));
  EXPECT_EQ("exit", line);
  reader.inputConsumed();
  reader.stop();
}

TEST(ConsoleHandler, PauseAndUnpausePreserveInteractiveInput) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->blockInteractive = true;
  Common::AsyncConsoleReader reader(input);
  reader.start(true, "wallet> ");
  ASSERT_TRUE(waitUntil(input->interactiveEntered));

  reader.pause();
  input->interactiveEntered = false;
  input->blockInteractive = false;
  input->interactiveLine = "help";
  reader.unpause();

  std::string line;
  ASSERT_TRUE(reader.getline(line));
  EXPECT_EQ("help", line);
  reader.inputConsumed();
  reader.stop();
}

TEST(ConsoleHandler, DefaultModeRetainsLegacyDaemonPath) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->legacyLines = {"status"};
  Common::AsyncConsoleReader reader(input);
  reader.start(false);

  EXPECT_FALSE(reader.usesLineEditor());
  std::string line;
  ASSERT_TRUE(reader.getline(line));
  EXPECT_EQ("status", line);
  reader.inputConsumed();
  reader.stop();
}

TEST(ConsoleHandler, LineEditorReceivesColoredPrompt) {
  auto input = std::make_shared<FakeConsoleInput>();
  input->interactiveLine = "help";
  Common::AsyncConsoleReader reader(input);
  reader.start(true, "wallet> ", Common::Console::Color::BrightYellow);

  std::string line;
  ASSERT_TRUE(reader.getline(line));
  EXPECT_EQ("\033[1;33mwallet> \033[0m", input->prompt());
  reader.inputConsumed();
  reader.stop();
}

} // namespace
