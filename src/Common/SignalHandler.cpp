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

#include "SignalHandler.h"

#include <iostream>
#include <mutex>
#include <thread>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#endif

namespace {

  std::function<void(void)>& registeredHandler() {
    // Signal dispatch lives until process exit. Deliberately keep these objects
    // alive too, so a detached POSIX dispatch thread can never race static
    // destruction while the process is terminating.
    static auto* handler = new std::function<void(void)>;
    return *handler;
  }

  std::mutex& registeredHandlerMutex() {
    static auto* mutex = new std::mutex;
    return *mutex;
  }

  void setHandler(std::function<void(void)> handler) {
    std::lock_guard<std::mutex> lock(registeredHandlerMutex());
    registeredHandler() = std::move(handler);
  }

  std::function<void(void)> getHandler() {
    std::lock_guard<std::mutex> lock(registeredHandlerMutex());
    return registeredHandler();
  }

  void handleSignal() {
    static std::mutex m_mutex;
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
      return;
    }
    auto handler = getHandler();
    if (handler) {
      handler();
    }
  }


#if defined(WIN32)
BOOL WINAPI winHandler(DWORD type) {
  if (CTRL_C_EVENT == type || CTRL_BREAK_EVENT == type) {
    handleSignal();
    return TRUE;
  } else {
    std::cerr << "Got control signal " << type << ". Exiting without saving...";
    return FALSE;
  }
  return TRUE;
}

#else

int signalPipe[2] = {-1, -1};
std::once_flag signalPipeInitFlag;
bool signalPipeReady = false;

void posixHandler(int /*type*/) {
  const int savedErrno = errno;
  const unsigned char marker = 1;

  // write(2) is async-signal-safe. Everything else -- std::function,
  // std::mutex, logging, Boost.Asio and Dispatcher -- must run after returning
  // from the raw signal context, or a signal that interrupts code holding one
  // of their locks can self-deadlock trying to acquire the same lock again.
  if (signalPipe[1] >= 0) {
    const ssize_t ignored = write(signalPipe[1], &marker, sizeof(marker));
    (void) ignored;
  }

  errno = savedErrno;
}

void dispatchPosixSignals() {
  unsigned char markers[64];

  for (;;) {
    const ssize_t count = read(signalPipe[0], markers, sizeof(markers));
    if (count > 0) {
      // Coalesce a burst of signals into one callback, matching the old
      // try-lock behavior that ignored concurrent shutdown requests.
      try {
        handleSignal();
      } catch (...) {
        // Never let an application callback terminate the signal dispatch
        // thread. Shutdown code owns its own logging/error reporting.
      }
      continue;
    }

    if (count < 0 && errno == EINTR) {
      continue;
    }

    return;
  }
}

bool initializeSignalPipe() {
  if (pipe(signalPipe) != 0) {
    return false;
  }

  const int readDescriptorFlags = fcntl(signalPipe[0], F_GETFD);
  const int writeDescriptorFlags = fcntl(signalPipe[1], F_GETFD);
  const int writeStatusFlags = fcntl(signalPipe[1], F_GETFL);
  if (readDescriptorFlags < 0 || writeDescriptorFlags < 0 || writeStatusFlags < 0 ||
      fcntl(signalPipe[0], F_SETFD, readDescriptorFlags | FD_CLOEXEC) != 0 ||
      fcntl(signalPipe[1], F_SETFD, writeDescriptorFlags | FD_CLOEXEC) != 0 ||
      fcntl(signalPipe[1], F_SETFL, writeStatusFlags | O_NONBLOCK) != 0) {
    close(signalPipe[0]);
    close(signalPipe[1]);
    signalPipe[0] = -1;
    signalPipe[1] = -1;
    return false;
  }

  try {
    std::thread(dispatchPosixSignals).detach();
  } catch (...) {
    close(signalPipe[0]);
    close(signalPipe[1]);
    signalPipe[0] = -1;
    signalPipe[1] = -1;
    return false;
  }

  return true;
}
#endif

}


namespace Tools {

  bool SignalHandler::install(std::function<void(void)> t)
  {
#if defined(WIN32)
    bool r = TRUE == ::SetConsoleCtrlHandler(&winHandler, TRUE);
    if (r)  {
      setHandler(std::move(t));
    }
    return r;
#else
    std::call_once(signalPipeInitFlag, [] {
      signalPipeReady = initializeSignalPipe();
    });
    if (!signalPipeReady) {
      return false;
    }

    setHandler(std::move(t));

    struct sigaction newMask;
    std::memset(&newMask, 0, sizeof(struct sigaction));
    newMask.sa_handler = posixHandler;
    if (sigaction(SIGINT, &newMask, nullptr) != 0) {
      return false;
    }

    if (sigaction(SIGTERM, &newMask, nullptr) != 0) {
      return false;
    }

    std::memset(&newMask, 0, sizeof(struct sigaction));
    newMask.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &newMask, nullptr) != 0) {
      return false;
    }

    return true;
#endif
  }

}
