// Copyright (c) 2026, The Discrete developers

#include "gtest/gtest.h"

#include "Common/SignalHandler.h"

#ifndef _WIN32

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <mutex>
#include <thread>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

TEST(SignalHandler, PosixCallbackRunsOutsideRawSignalContext) {
  const pid_t child = fork();
  ASSERT_NE(child, -1);

  if (child == 0) {
    std::mutex gate;
    gate.lock();

    if (!Tools::SignalHandler::install([&gate] {
          std::lock_guard<std::mutex> lock(gate);
          _exit(EXIT_SUCCESS);
        })) {
      _exit(2);
    }

    // The legacy implementation invoked the callback synchronously here. It
    // tried to lock gate again on this same thread and deadlocked forever. A
    // self-pipe handler returns from raise(), letting this thread release gate;
    // the normal dispatch thread can then run the callback and exit cleanly.
    if (raise(SIGTERM) != 0) {
      _exit(3);
    }
    gate.unlock();

    std::this_thread::sleep_for(std::chrono::seconds(5));
    _exit(4);
  }

  int status = 0;
  bool exited = false;
  for (size_t attempt = 0; attempt < 200; ++attempt) {
    const pid_t result = waitpid(child, &status, WNOHANG);
    ASSERT_NE(result, -1);
    if (result == child) {
      exited = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  if (!exited) {
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
  }

  ASSERT_TRUE(exited) << "signal callback deadlocked in the raw signal context";
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}

#endif
