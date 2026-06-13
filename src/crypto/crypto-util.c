// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

// Copyright (c) 2013-2018
// Frank Denis <j at pureftpd dot org>
// See https://github.com/jedisct1/libsodium/blob/master/LICENSE for details

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#include "crypto-util.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>  /* arc4random_buf */
#endif
#endif

void sodium_memzero(void *pnt, size_t len) {
#ifdef _WIN32
	SecureZeroMemory(pnt, len);
#else
	volatile unsigned char *volatile pnt_ = (volatile unsigned char *volatile)pnt;
	size_t i                              = (size_t)0U;

	while (i < len) {
		pnt_[i++] = 0U;
	}
#endif
}

int sodium_compare(const void *a1, const void *a2, size_t len) {
	const volatile unsigned char *volatile b1 = (const volatile unsigned char *)a1;
	const volatile unsigned char *volatile b2 = (const volatile unsigned char *)a2;
	size_t i;
	volatile unsigned char gt = 0U;
	volatile unsigned char eq = 1U;
	uint16_t x1, x2;

	i = len;
	while (i != 0U) {
		i--;
		x1 = b1[i];
		x2 = b2[i];
		gt |= ((x2 - x1) >> 8) & eq;
		eq &= ((x2 ^ x1) - 1) >> 8;
	}
	return (int)(gt + gt + eq) - 1;
}

#ifndef _WIN32
/* Drain /dev/urandom into buf. Returns 0 on success, -1 on hard failure. */
static int fill_from_urandom(void *buf, size_t length) {
	int fd;
	do {
		fd = open("/dev/urandom", O_RDONLY
#ifdef O_CLOEXEC
			| O_CLOEXEC
#endif
		);
	} while (fd == -1 && errno == EINTR);
	if (fd < 0) return -1;

	unsigned char *p = (unsigned char *)buf;
	size_t remaining = length;
	while (remaining > 0) {
		ssize_t n = read(fd, p, remaining);
		if (n < 0) {
			if (errno == EINTR) continue;
			close(fd);
			return -1;
		}
		if (n == 0) {  /* unexpected EOF on /dev/urandom */
			close(fd);
			return -1;
		}
		p += (size_t)n;
		remaining -= (size_t)n;
	}
	close(fd);
	return 0;
}
#endif

void secure_random_bytes(void *buf, size_t length) {
	if (length == 0) return;

#ifdef _WIN32
	NTSTATUS rc = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)length,
	                              BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (rc != 0) {
		fprintf(stderr, "secure_random_bytes: BCryptGenRandom failed (0x%lx)\n",
		        (unsigned long)rc);
		abort();
	}
#elif defined(__linux__)
	/* Prefer the getrandom(2) syscall on Linux >= 3.17. Fall back to
	 * /dev/urandom if it's not available (older kernels / sandboxes). */
	unsigned char *p = (unsigned char *)buf;
	size_t remaining = length;
#  ifdef SYS_getrandom
	while (remaining > 0) {
		long n = syscall(SYS_getrandom, p, remaining, 0);
		if (n < 0) {
			if (errno == EINTR) continue;
			/* ENOSYS => fall back to /dev/urandom */
			break;
		}
		p += (size_t)n;
		remaining -= (size_t)n;
	}
#  endif
	if (remaining > 0 && fill_from_urandom(p, remaining) != 0) {
		fprintf(stderr, "secure_random_bytes: /dev/urandom fallback failed\n");
		abort();
	}
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	arc4random_buf(buf, length);
#else
	if (fill_from_urandom(buf, length) != 0) {
		fprintf(stderr, "secure_random_bytes: /dev/urandom failed\n");
		abort();
	}
#endif
}
