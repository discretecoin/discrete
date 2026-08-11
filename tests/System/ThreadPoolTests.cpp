// Copyright (c) 2026, The Discrete developers

#include "gtest/gtest.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <stdexcept>
#include <thread>
#include <vector>

#include "Common/ThreadPool.h"

namespace {

bool waitUntil(const std::function<bool()>& predicate) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!predicate()) {
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    std::this_thread::yield();
  }
  return true;
}

} // namespace

TEST(ThreadPool, ExecutesSubmittedWorkAndPropagatesExceptions) {
  Common::ThreadPool pool(3);
  std::atomic<unsigned int> completed{0};
  std::vector<std::future<void>> futures;
  for (unsigned int i = 0; i < 12; ++i) {
    futures.emplace_back(pool.submit([&completed] {
      completed.fetch_add(1, std::memory_order_relaxed);
    }));
  }
  for (std::future<void>& future : futures) {
    EXPECT_NO_THROW(future.get());
  }
  EXPECT_EQ(completed.load(std::memory_order_relaxed), 12u);

  std::future<void> failed = pool.submit([] { throw std::runtime_error("expected"); });
  EXPECT_THROW(failed.get(), std::runtime_error);
}

TEST(ThreadPool, DestructorDrainsAcceptedWork) {
  std::atomic<unsigned int> completed{0};
  {
    Common::ThreadPool pool(2);
    for (unsigned int i = 0; i < 8; ++i) {
      pool.submit([&completed] {
        completed.fetch_add(1, std::memory_order_relaxed);
      });
    }
  }
  EXPECT_EQ(completed.load(std::memory_order_relaxed), 8u);
}

TEST(ThreadPool, WorkerExitCallbackRunsExactlyOncePerWorker) {
  constexpr unsigned int workerCount = 3;
  std::atomic<unsigned int> entered{0};
  std::atomic<unsigned int> completed{0};
  std::atomic<unsigned int> exited{0};
  std::promise<void> releasePromise;
  std::shared_future<void> release = releasePromise.get_future().share();

  {
    Common::ThreadPool pool(workerCount, [&exited] {
      exited.fetch_add(1, std::memory_order_relaxed);
    });
    for (unsigned int i = 0; i < workerCount; ++i) {
      pool.submit([&entered, &completed, release] {
        entered.fetch_add(1, std::memory_order_relaxed);
        release.wait();
        completed.fetch_add(1, std::memory_order_relaxed);
      });
    }

    const bool allWorkersEntered = waitUntil([&entered, workerCount] {
      return entered.load(std::memory_order_relaxed) == workerCount;
    });
    EXPECT_TRUE(allWorkersEntered);
    releasePromise.set_value();
  }

  EXPECT_EQ(completed.load(std::memory_order_relaxed), workerCount);
  EXPECT_EQ(exited.load(std::memory_order_relaxed), workerCount);
}

TEST(FutureDrain, ScopeExitWaitsForEveryAcceptedTask) {
  Common::ThreadPool pool(2);
  std::atomic<unsigned int> entered{0};
  std::atomic<unsigned int> completed{0};
  std::promise<void> releasePromise;
  std::shared_future<void> release = releasePromise.get_future().share();

  std::future<void> scope = std::async(std::launch::async, [&] {
    std::vector<std::future<void>> futures;
    for (unsigned int i = 0; i < 2; ++i) {
      futures.emplace_back(pool.submit([&entered, &completed, release] {
        entered.fetch_add(1, std::memory_order_relaxed);
        release.wait();
        completed.fetch_add(1, std::memory_order_relaxed);
      }));
    }

    Common::FutureDrain drain(futures);
    // Returning immediately exercises the same early-scope path used by
    // processObjects when a peer supplies an invalid block or transaction.
  });

  const bool allTasksEntered = waitUntil([&entered] {
    return entered.load(std::memory_order_relaxed) == 2;
  });
  EXPECT_TRUE(allTasksEntered);
  if (allTasksEntered) {
    EXPECT_EQ(scope.wait_for(std::chrono::milliseconds(50)), std::future_status::timeout);
  }

  releasePromise.set_value();
  EXPECT_EQ(scope.wait_for(std::chrono::seconds(5)), std::future_status::ready);
  EXPECT_NO_THROW(scope.get());
  EXPECT_EQ(completed.load(std::memory_order_relaxed), 2u);
}
