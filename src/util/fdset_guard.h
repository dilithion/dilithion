// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// fdset_guard.h — the ONLY sanctioned way to put a socket into an fd_set.
//
// BKL-30 / M-30 (2026-09-04). FD_SET() has no bounds check of its own:
//
//   POSIX  fd_set is a bitmask indexed by the descriptor VALUE. FD_SET(fd)
//          with fd >= FD_SETSIZE is undefined behaviour; glibc compiled with
//          -D_FORTIFY_SOURCE=2 (our default CXXFLAGS) expands it to
//          __fdelt_chk -> __chk_fail -> SIGABRT. Any remote party that can push
//          the process past ~1024 open descriptors (idle RPC connections were
//          the cheapest way) could therefore kill the node the moment the P2P
//          select() loop touched the next socket. FD_ISSET has the same check.
//
//   Win32  fd_set is a COUNT-bounded array {fd_count, fd_array[FD_SETSIZE]}.
//          FD_SET silently ignores the socket once fd_count == FD_SETSIZE, so
//          an over-full set never aborts — it goes blind. Winsock's default
//          FD_SETSIZE is 64, below the node's connection budget; the Makefile
//          defines FD_SETSIZE=1024 for every Windows TU and the static_assert
//          below refuses to compile a TU where that define was lost.
//
// Contract: every FD_SET in the tree goes through FdSetAdd(). A false return
// means "this socket can never be waited on with select()"; the caller MUST
// treat that as an error on that socket (close it if it owns it, otherwise
// report it as error-ready so its owner disconnects it) and MUST NOT fall
// back to a raw FD_SET, and MUST NOT FD_ISSET it either.
//
// Roster check (run from the repo root; expected: only this header):
//   grep -rn "FD_SET(" src/ --include=*.cpp --include=*.h | grep -v fdset_guard.h

#pragma once

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/select.h>
#endif

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
static_assert(FD_SETSIZE >= 1024,
              "FD_SETSIZE must be defined to >= 1024 before <winsock2.h> is included "
              "in EVERY translation unit (Makefile: CXXFLAGS += -DFD_SETSIZE=1024 on "
              "Windows). With winsock's default of 64 the select() loops silently "
              "ignore every socket beyond the 64th and the node goes blind.");
using fdset_sock_t = SOCKET;
#else
using fdset_sock_t = int;
#endif

/**
 * True iff `sock` may be passed to FD_SET / FD_ISSET without undefined
 * behaviour. POSIX: 0 <= sock < FD_SETSIZE. Win32: any non-INVALID socket
 * (the value is not used as an index there; capacity is checked by FdSetAdd).
 */
inline bool IsFdSelectable(fdset_sock_t sock) {
#ifdef _WIN32
    return sock != INVALID_SOCKET;
#else
    return sock >= 0 && sock < FD_SETSIZE;
#endif
}

/**
 * Guarded FD_SET. Returns false and leaves *set untouched when the socket
 * cannot be represented: value out of range (POSIX) or the set is already
 * full (Win32, where FD_SET would otherwise drop it silently).
 */
inline bool FdSetAdd(fdset_sock_t sock, fd_set* set) {
#ifdef _WIN32
    if (sock == INVALID_SOCKET) return false;
    if (set->fd_count >= static_cast<unsigned>(FD_SETSIZE)) return false;
    FD_SET(sock, set);
    return true;
#else
    if (!IsFdSelectable(sock)) return false;
    FD_SET(sock, set);
    return true;
#endif
}

/**
 * Log-volume limiter for refusal paths a remote party can drive in a loop:
 * true on the 1st, 2nd, 4th, 8th, ... occurrence, i.e. O(log n) log lines for
 * n refusals. Pass the caller's own monotonically increasing counter value.
 */
inline bool ShouldLogRefusal(uint64_t n) {
    return n != 0 && (n & (n - 1)) == 0;
}
