// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace Common {

// Waits for every future that still owns shared state. This is intended as a
// scope guard for bounded task batches so accepted work cannot outlive an early
// return or exception from the submitting scope.
class FutureDrain {
public:
  explicit FutureDrain(std::vector<std::future<void>>& futures) noexcept : m_futures(futures) {}

  ~FutureDrain() noexcept {
    for (std::future<void>& future : m_futures) {
      if (future.valid()) {
        try {
          future.wait();
        } catch (...) {
          // Destructors must not throw. Task exceptions remain observable by
          // callers that consume the corresponding future with get().
        }
      }
    }
  }

  FutureDrain(const FutureDrain&) = delete;
  FutureDrain& operator=(const FutureDrain&) = delete;

private:
  std::vector<std::future<void>>& m_futures;
};

// A small fixed-size worker pool. Callers retain control over queue bounds by
// limiting the number of submitted futures before waiting; the sync path keeps
// at most one task per worker in flight.
class ThreadPool {
public:
  explicit ThreadPool(size_t workerCount, std::function<void()> workerExit = {}) :
    m_workerExit(std::move(workerExit)) {
    if (workerCount == 0) {
      throw std::invalid_argument("ThreadPool requires at least one worker");
    }

    try {
      m_workers.reserve(workerCount);
      for (size_t i = 0; i < workerCount; ++i) {
        m_workers.emplace_back([this] {
          for (;;) {
            std::function<void()> task;
            {
              std::unique_lock<std::mutex> lock(m_mutex);
              m_ready.wait(lock, [this] { return m_stopping || !m_tasks.empty(); });
              if (m_stopping && m_tasks.empty()) {
                break;
              }
              task = std::move(m_tasks.front());
              m_tasks.pop_front();
            }
            task();
          }

          if (m_workerExit) {
            try {
              m_workerExit();
            } catch (...) {
              // A worker cleanup failure must not terminate the process or
              // prevent the remaining workers from being joined.
            }
          }
        });
      }
    } catch (...) {
      stopAndJoin();
      throw;
    }
  }

  ~ThreadPool() {
    stopAndJoin();
  }

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;

  size_t size() const noexcept { return m_workers.size(); }

  std::future<void> submit(std::function<void()> task) {
    auto packaged = std::make_shared<std::packaged_task<void()>>(std::move(task));
    std::future<void> result = packaged->get_future();
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      if (m_stopping) {
        throw std::runtime_error("cannot submit work to a stopped ThreadPool");
      }
      m_tasks.emplace_back([packaged] { (*packaged)(); });
    }
    m_ready.notify_one();
    return result;
  }

private:
  void stopAndJoin() {
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      m_stopping = true;
    }
    m_ready.notify_all();
    for (std::thread& worker : m_workers) {
      if (worker.joinable()) {
        worker.join();
      }
    }
  }

  std::function<void()> m_workerExit;
  std::vector<std::thread> m_workers;
  std::deque<std::function<void()>> m_tasks;
  std::mutex m_mutex;
  std::condition_variable m_ready;
  bool m_stopping = false;
};

} // namespace Common
