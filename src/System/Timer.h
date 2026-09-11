// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2025, The Karbo developers

#pragma once

#include <chrono>
#include <cassert>
#include <stdexcept>
#include "Dispatcher.h"
#include "InterruptedException.h"

namespace System {

  class Timer {
  public:
    Timer() = default;
    explicit Timer(Dispatcher& dispatcher) : dispatcher(&dispatcher) {}
    Timer(const Timer&) = delete;
    Timer(Timer&& other) noexcept : dispatcher(other.dispatcher) { other.dispatcher = nullptr; }
    ~Timer() = default;
    Timer& operator=(const Timer&) = delete;
    Timer& operator=(Timer&& other) noexcept {
      if (this != &other) {
        dispatcher = other.dispatcher;
        other.dispatcher = nullptr;
      }
      return *this;
    }

    void sleep(std::chrono::nanoseconds duration) {
      assert(dispatcher != nullptr);

      if (dispatcher->interrupted()) {
        throw InterruptedException();
      }

      // Preserve the existing minimum tick and non-positive duration behavior.
      uint64_t durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
      if (durationMs == 0) durationMs = 1;

      const auto now = std::chrono::steady_clock::now().time_since_epoch();
      const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(now);
      uint64_t expireTime = static_cast<uint64_t>(nowMs.count()) + durationMs;
      if (duration > std::chrono::nanoseconds::zero()) {
        // Round the absolute deadline up. Split off whole milliseconds so adding
        // a large duration to the steady-clock epoch cannot overflow nanoseconds.
        const auto fraction = duration >= std::chrono::milliseconds(1)
          ? duration - std::chrono::duration_cast<std::chrono::milliseconds>(duration)
          : std::chrono::nanoseconds::zero();
        expireTime += static_cast<uint64_t>(std::chrono::ceil<std::chrono::milliseconds>(
          now - nowMs + fraction).count());
        const auto maximumMs = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::duration::max()).count();
        if (expireTime > static_cast<uint64_t>(maximumMs)) {
          throw std::overflow_error("Timer deadline exceeds steady clock range");
        }
      }

      auto* context = dispatcher->getCurrentContext();
      bool interrupted = false;

      // Set interrupt procedure
      context->interruptProcedure = [&]() {
        if (!interrupted) {
          dispatcher->interruptTimer(expireTime, context);
          interrupted = true;
        }
        };

      // Register timer with dispatcher
      dispatcher->addTimer(expireTime, context);

      // Yield once; dispatcher will resume this fiber when timer fires or if interrupted
      dispatcher->dispatch();

      // Clear interrupt procedure
      context->interruptProcedure = nullptr;

      // Throw if fiber was interrupted (e.g., during shutdown)
      if (dispatcher->interrupted() || interrupted) {
        throw InterruptedException();
      }
    }

  private:
    Dispatcher* dispatcher{ nullptr };
  };

} // namespace System
