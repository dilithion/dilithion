// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// Socket utilities implementation
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#include <net/sock.h>
#include <util/fdset_guard.h>
#include <util/logging.h>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#endif

#include <algorithm>
#include <stdexcept>

bool CSock::SetNonBlocking(socket_t sock) {
    if (!IsValid(sock)) return false;

#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool CSock::SetRecvTimeout(socket_t sock, std::chrono::milliseconds timeout) {
    if (!IsValid(sock)) return false;

#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout.count());
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#else
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

bool CSock::SetSendTimeout(socket_t sock, std::chrono::milliseconds timeout) {
    if (!IsValid(sock)) return false;

#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout.count());
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#else
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

bool CSock::SetNoDelay(socket_t sock, bool enable) {
    if (!IsValid(sock)) return false;

    int flag = enable ? 1 : 0;
    return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&flag), sizeof(flag)) == 0;
}

bool CSock::SetReuseAddr(socket_t sock, bool enable) {
    if (!IsValid(sock)) return false;

    int flag = enable ? 1 : 0;
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<const char*>(&flag), sizeof(flag)) == 0;
}

bool CSock::IsValid(socket_t sock) {
#ifdef _WIN32
    return sock != INVALID_SOCKET;
#else
    return sock >= 0;
#endif
}

void CSock::Close(socket_t& sock) {
    if (!IsValid(sock)) return;

#ifdef _WIN32
    closesocket(sock);
    sock = INVALID_SOCKET;
#else
    close(sock);
    sock = -1;
#endif
}

int CSock::Wait(socket_t sock, int events, std::chrono::milliseconds timeout) {
    if (!IsValid(sock)) return -1;

    fd_set fd_recv, fd_send, fd_error;
    FD_ZERO(&fd_recv);
    FD_ZERO(&fd_send);
    FD_ZERO(&fd_error);

    // BKL-30 (M-30): a descriptor at/above FD_SETSIZE must never be indexed
    // into an fd_set (UB; SIGABRT via __fdelt_chk under -D_FORTIFY_SOURCE=2).
    // Refuse it as an error on this socket. The caller owns `sock` and closes
    // it on -1; closing here would hand back a dangling number and invite a
    // double close of whatever descriptor gets that number next.
    if (!IsFdSelectable(sock)) {
        static std::atomic<uint64_t> s_refusals{0};
        const uint64_t n = ++s_refusals;
        if (ShouldLogRefusal(n)) {
            LogPrintf(NET, ERROR, "[CSock] Wait: refusing socket %lld - descriptor >= FD_SETSIZE (%d); "
                      "the process is at its open-file limit (refusal #%llu)\n",
                      static_cast<long long>(sock), static_cast<int>(FD_SETSIZE),
                      static_cast<unsigned long long>(n));
        }
        return -1;
    }
    if ((events & static_cast<int>(SocketEvent::RECV)) && !FdSetAdd(sock, &fd_recv)) return -1;
    if ((events & static_cast<int>(SocketEvent::SEND)) && !FdSetAdd(sock, &fd_send)) return -1;
    if ((events & static_cast<int>(SocketEvent::ERR)) && !FdSetAdd(sock, &fd_error)) return -1;

    struct timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

#ifdef _WIN32
    int result = select(0, &fd_recv, &fd_send, &fd_error, &tv);
#else
    int result = select(sock + 1, &fd_recv, &fd_send, &fd_error, &tv);
#endif

    if (result <= 0) {
        return result;  // 0 = timeout, -1 = error
    }

    int ready = 0;
    if (FD_ISSET(sock, &fd_recv)) ready |= static_cast<int>(SocketEvent::RECV);
    if (FD_ISSET(sock, &fd_send)) ready |= static_cast<int>(SocketEvent::SEND);
    if (FD_ISSET(sock, &fd_error)) ready |= static_cast<int>(SocketEvent::ERR);

    return ready;
}

int CSock::WaitMany(std::set<socket_t>& recv_set, std::set<socket_t>& send_set,
                    std::set<socket_t>& error_set, std::chrono::milliseconds timeout) {
    if (recv_set.empty() && send_set.empty() && error_set.empty()) {
        return 0;
    }

    fd_set fd_recv, fd_send, fd_error;
    FD_ZERO(&fd_recv);
    FD_ZERO(&fd_send);
    FD_ZERO(&fd_error);

    socket_t max_fd = 0;
    size_t n_added = 0;
    // BKL-30: sockets an fd_set cannot hold (value >= FD_SETSIZE on POSIX, set
    // full on Win32). They are handed back as error-ready so their owner
    // disconnects them; they are never FD_SET (UB) nor FD_ISSET (also UB).
    std::set<socket_t> unselectable;
    auto add_all = [&](const std::set<socket_t>& src, fd_set* dst) {
        for (socket_t sock : src) {
            if (!FdSetAdd(sock, dst)) {
                unselectable.insert(sock);
                continue;
            }
            ++n_added;
#ifndef _WIN32
            if (sock > max_fd) max_fd = sock;
#endif
        }
    };
    add_all(recv_set, &fd_recv);
    add_all(send_set, &fd_send);
    add_all(error_set, &fd_error);
    if (!unselectable.empty()) {
        static std::atomic<uint64_t> s_refusals{0};
        const uint64_t n = ++s_refusals;
        if (ShouldLogRefusal(n)) {
            LogPrintf(NET, ERROR, "[CSock] WaitMany: %zu socket(s) with descriptor >= FD_SETSIZE (%d) "
                      "cannot be waited on; reporting them as errors (refusal #%llu)\n",
                      unselectable.size(), static_cast<int>(FD_SETSIZE),
                      static_cast<unsigned long long>(n));
        }
    }

    struct timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

    int result = 0;
    if (n_added > 0) {
#ifdef _WIN32
        result = select(0, &fd_recv, &fd_send, &fd_error, &tv);
#else
        result = select(max_fd + 1, &fd_recv, &fd_send, &fd_error, &tv);
#endif
    }

    if (result < 0 || (result == 0 && unselectable.empty())) {
        recv_set.clear();
        send_set.clear();
        error_set.clear();
        return result;
    }

    // Filter to only ready sockets (never FD_ISSET an unselectable one)
    std::set<socket_t> ready_recv, ready_send, ready_error;

    if (result > 0) {
        for (socket_t sock : recv_set) {
            if (!unselectable.count(sock) && FD_ISSET(sock, &fd_recv)) ready_recv.insert(sock);
        }
        for (socket_t sock : send_set) {
            if (!unselectable.count(sock) && FD_ISSET(sock, &fd_send)) ready_send.insert(sock);
        }
        for (socket_t sock : error_set) {
            if (!unselectable.count(sock) && FD_ISSET(sock, &fd_error)) ready_error.insert(sock);
        }
    }
    for (socket_t sock : unselectable) ready_error.insert(sock);

    recv_set = std::move(ready_recv);
    send_set = std::move(ready_send);
    error_set = std::move(ready_error);

    return result + static_cast<int>(unselectable.size());
}

int CSock::GetLastError() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string CSock::GetErrorString(int error) {
    if (error == 0) {
        error = GetLastError();
    }

#ifdef _WIN32
    char buf[256] = {0};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, error, 0, buf, sizeof(buf), nullptr);
    return std::string(buf);
#else
    return std::string(strerror(error));
#endif
}

bool CSock::IsWouldBlock(int error) {
    if (error == 0) {
        error = GetLastError();
    }

#ifdef _WIN32
    return error == WSAEWOULDBLOCK;
#else
    return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

bool CSock::IsConnectionRefused(int error) {
    if (error == 0) {
        error = GetLastError();
    }

#ifdef _WIN32
    return error == WSAECONNREFUSED;
#else
    return error == ECONNREFUSED;
#endif
}

//-----------------------------------------------------------------------------
// IPv6 / dual-stack helpers
//-----------------------------------------------------------------------------

bool CSock::ParseEndpoint(const std::string& str, std::string& ip_out, uint16_t& port_out) {
    if (str.empty()) return false;

    // Reject leading/trailing whitespace
    if (std::isspace(static_cast<unsigned char>(str.front())) ||
        std::isspace(static_cast<unsigned char>(str.back()))) {
        return false;
    }

    if (str[0] == '[') {
        // IPv6 bracket notation: [addr]:port
        size_t close = str.find(']');
        if (close == std::string::npos) return false;
        ip_out = str.substr(1, close - 1);
        if (close + 2 > str.size() || str[close + 1] != ':') return false;
        try {
            int p = std::stoi(str.substr(close + 2));
            if (p <= 0 || p > 65535) return false;
            port_out = static_cast<uint16_t>(p);
        } catch (...) {
            return false;
        }
        return true;
    }

    // IPv4/hostname: addr:port (last colon)
    size_t colon = str.rfind(':');
    if (colon == std::string::npos || colon == 0) return false;
    ip_out = str.substr(0, colon);

    // Reject bare IPv6 without brackets (ambiguous — e.g. "::1:8444")
    if (ip_out.find(':') != std::string::npos) return false;

    try {
        int p = std::stoi(str.substr(colon + 1));
        if (p <= 0 || p > 65535) return false;
        port_out = static_cast<uint16_t>(p);
    } catch (...) {
        return false;
    }
    return true;
}

int CSock::DetectFamily(const std::string& ip_str) {
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &ipv4_addr) == 1) {
        return AF_INET;
    }
    struct in6_addr ipv6_addr;
    if (inet_pton(AF_INET6, ip_str.c_str(), &ipv6_addr) == 1) {
        return AF_INET6;
    }
    return 0;
}

bool CSock::FillSockAddr(const std::string& ip_str, uint16_t port,
                         struct sockaddr_storage& ss, socklen_t& ss_len) {
    memset(&ss, 0, sizeof(ss));

    // Try IPv4 first
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &ipv4_addr) == 1) {
        struct sockaddr_in* sa4 = reinterpret_cast<struct sockaddr_in*>(&ss);
        sa4->sin_family = AF_INET;
        sa4->sin_addr = ipv4_addr;
        sa4->sin_port = htons(port);
        ss_len = sizeof(struct sockaddr_in);
        return true;
    }

    // Try IPv6
    struct in6_addr ipv6_addr;
    if (inet_pton(AF_INET6, ip_str.c_str(), &ipv6_addr) == 1) {
        struct sockaddr_in6* sa6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_addr = ipv6_addr;
        sa6->sin6_port = htons(port);
        ss_len = sizeof(struct sockaddr_in6);
        return true;
    }

    return false;
}

bool CSock::ExtractAddress(const struct sockaddr_storage& ss,
                           std::string& ip_out, uint16_t& port_out) {
    char buf[INET6_ADDRSTRLEN];

    if (ss.ss_family == AF_INET) {
        const struct sockaddr_in* sa4 = reinterpret_cast<const struct sockaddr_in*>(&ss);
        if (inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof(buf)) == nullptr) return false;
        ip_out = buf;
        port_out = ntohs(sa4->sin_port);
        return true;
    }

    if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6* sa6 = reinterpret_cast<const struct sockaddr_in6*>(&ss);

        // Check if this is an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        // Unwrap to plain IPv4 for backward compatibility
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
            // Extract the IPv4 part (last 4 bytes of the 16-byte address)
            const uint8_t* addr_bytes = reinterpret_cast<const uint8_t*>(&sa6->sin6_addr);
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, addr_bytes + 12, 4);
            if (inet_ntop(AF_INET, &ipv4_addr, buf, sizeof(buf)) == nullptr) return false;
            ip_out = buf;
        } else {
            if (inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf)) == nullptr) return false;
            ip_out = buf;
        }
        port_out = ntohs(sa6->sin6_port);
        return true;
    }

    return false;
}

bool CSock::CreateListenSocket(uint16_t port, const std::string& bind_addr,
                               socket_t& sock_out, bool& is_ipv6) {
    is_ipv6 = false;

    // For loopback addresses, use IPv4 directly.
    // On Windows, IPv6 dual-stack binding to ::1 does NOT accept IPv4 connections
    // to 127.0.0.1, which breaks browsers, curl, and most tools.
    bool is_loopback = (bind_addr == "127.0.0.1" || bind_addr == "localhost" || bind_addr == "::1");

    // Try creating an IPv6 dual-stack socket first (skip for loopback)
    socket_t sock = is_loopback ? INVALID_SOCKET_VALUE : socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (IsValid(sock)) {
        // Set IPV6_V6ONLY=0 for dual-stack (accepts both IPv4 and IPv6)
        // Critical on Windows where this defaults to 1
        int v6only = 0;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
                       reinterpret_cast<const char*>(&v6only), sizeof(v6only)) == 0) {
            // Set SO_REUSEADDR
            int reuse = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#ifndef _WIN32
            setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
                       reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#endif

            // Bind
            struct sockaddr_in6 addr6;
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(port);

            if (bind_addr.empty() || bind_addr == "0.0.0.0" || bind_addr == "::") {
                addr6.sin6_addr = in6addr_any;
            } else if (bind_addr == "127.0.0.1" || bind_addr == "::1" || bind_addr == "localhost") {
                addr6.sin6_addr = in6addr_loopback;
            } else {
                // Try to parse as specific address
                inet_pton(AF_INET6, bind_addr.c_str(), &addr6.sin6_addr);
            }

            if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr6), sizeof(addr6)) == 0) {
                sock_out = sock;
                is_ipv6 = true;
                return true;
            }
        }
        // IPv6 setup failed — close and fall through to IPv4
        Close(sock);
    }

    // Fallback: IPv4-only socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!IsValid(sock)) return false;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#ifndef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#endif

    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(port);

    if (bind_addr.empty() || bind_addr == "0.0.0.0" || bind_addr == "::") {
        addr4.sin_addr.s_addr = INADDR_ANY;
    } else if (bind_addr == "127.0.0.1" || bind_addr == "::1" || bind_addr == "localhost") {
        addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        inet_pton(AF_INET, bind_addr.c_str(), &addr4.sin_addr);
    }

    if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr4), sizeof(addr4)) != 0) {
        Close(sock);
        return false;
    }

    sock_out = sock;
    is_ipv6 = false;
    return true;
}
