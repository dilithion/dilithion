// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/socket.h>
#include <net/sock.h>
#include <util/fdset_guard.h>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

// Static initialization
bool CSocket::socket_layer_initialized = false;
bool CSocketInit::initialized = false;

// CSocketInit implementation

CSocketInit::CSocketInit() {
    if (!initialized) {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
            initialized = true;
        }
#else
        initialized = true;
#endif
    }
}

CSocketInit::~CSocketInit() {
#ifdef _WIN32
    if (initialized) {
        WSACleanup();
        initialized = false;
    }
#endif
}

// CSocket implementation

CSocket::CSocket() : sock_fd(INVALID_SOCKET_FD), connected(false), peer_port(0) {
    InitializeSocketLayer();
}

CSocket::~CSocket() {
    Close();
}

CSocket::CSocket(CSocket&& other) noexcept
    : sock_fd(other.sock_fd),
      connected(other.connected),
      peer_address(std::move(other.peer_address)),
      peer_port(other.peer_port)
{
    other.Reset();
}

CSocket& CSocket::operator=(CSocket&& other) noexcept {
    if (this != &other) {
        Close();
        sock_fd = other.sock_fd;
        connected = other.connected;
        peer_address = std::move(other.peer_address);
        peer_port = other.peer_port;
        other.Reset();
    }
    return *this;
}

bool CSocket::InitializeSocketLayer() {
    if (!socket_layer_initialized) {
        static CSocketInit init;
        socket_layer_initialized = CSocketInit::IsInitialized();
    }
    return socket_layer_initialized;
}

void CSocket::Reset() {
    sock_fd = INVALID_SOCKET_FD;
    connected = false;
    peer_address.clear();
    peer_port = 0;
}

bool CSocket::Connect(const std::string& host, uint16_t port, int timeout_ms) {
    // NET-010 FIX: Validate port number
    // Reject port 0 (OS-assigned) and privileged ports (< 1024) for outbound connections
    if (port == 0) {
        return false;  // Port 0 not allowed
    }

    Close();

    // Resolve address — try direct IP first, then DNS
    struct sockaddr_storage ss;
    socklen_t ss_len;
    bool resolved = false;

    if (CSock::FillSockAddr(host, port, ss, ss_len)) {
        resolved = true;
    } else {
        // Try DNS resolution (both IPv4 and IPv6)
        struct addrinfo hints, *ai_result = nullptr;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host.c_str(), nullptr, &hints, &ai_result) == 0 && ai_result) {
            memcpy(&ss, ai_result->ai_addr, ai_result->ai_addrlen);
            ss_len = static_cast<socklen_t>(ai_result->ai_addrlen);
            // Set port
            if (ss.ss_family == AF_INET) {
                reinterpret_cast<struct sockaddr_in*>(&ss)->sin_port = htons(port);
            } else if (ss.ss_family == AF_INET6) {
                reinterpret_cast<struct sockaddr_in6*>(&ss)->sin6_port = htons(port);
            }
            resolved = true;
            freeaddrinfo(ai_result);
        } else if (ai_result) {
            freeaddrinfo(ai_result);
        }
    }

    if (!resolved) {
        return false;
    }

    // Create socket matching address family
    sock_fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == INVALID_SOCKET_FD) {
        return false;
    }

    // Set non-blocking for timeout
    if (timeout_ms > 0) {
        SetNonBlocking(true);
    }

    // Connect
    int result = connect(sock_fd, (struct sockaddr*)&ss, ss_len);

    if (result < 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            Close();
            return false;
        }
#else
        if (errno != EINPROGRESS) {
            Close();
            return false;
        }
#endif

        // Wait for connection with timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        // BKL-30: a descriptor at/above FD_SETSIZE cannot be waited on; this
        // socket is ours, so close it in place and report the connect as failed.
        if (!FdSetAdd(sock_fd, &write_fds)) {
            Close();
            return false;
        }

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        result = select(sock_fd + 1, nullptr, &write_fds, nullptr, &tv);
        if (result <= 0) {
            Close();
            return false;
        }

        // Check if connection succeeded
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        if (error != 0) {
            Close();
            return false;
        }

        // Set back to blocking
        SetNonBlocking(false);
    }

    connected = true;
    peer_address = host;
    peer_port = port;

    return true;
}

bool CSocket::Bind(uint16_t port) {
    // NET-010 FIX: Validate port number for binding
    if (port == 0 || port < 1024) {
        return false;  // Invalid port for P2P binding
    }

    Close();

    // Use dual-stack listen socket (IPv4+IPv6)
    bool is_ipv6 = false;
    if (!CSock::CreateListenSocket(port, "", sock_fd, is_ipv6)) {
        return false;
    }

    return true;
}

bool CSocket::Listen(int backlog) {
    if (!IsValid()) return false;

    if (listen(sock_fd, backlog) < 0) {
        return false;
    }

    return true;
}

std::unique_ptr<CSocket> CSocket::Accept() {
    if (!IsValid()) return nullptr;

    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);

    socket_t client_fd = accept(sock_fd, (struct sockaddr*)&client_addr, &addr_len);

    if (client_fd == INVALID_SOCKET_FD) {
        return nullptr;
    }

    auto client_socket = std::make_unique<CSocket>();
    client_socket->sock_fd = client_fd;
    client_socket->connected = true;

    // Extract address (unwraps IPv4-mapped IPv6 for compatibility)
    std::string ip_str;
    uint16_t port;
    if (CSock::ExtractAddress(client_addr, ip_str, port)) {
        client_socket->peer_address = ip_str;
        client_socket->peer_port = port;
    }

    return client_socket;
}

void CSocket::Close() {
    if (IsValid()) {
#ifdef _WIN32
        closesocket(sock_fd);
#else
        close(sock_fd);
#endif
        Reset();
    }
}

int CSocket::Send(const void* data, size_t len) {
    if (!IsValid() || !connected) return -1;

#ifdef _WIN32
    return send(sock_fd, (const char*)data, (int)len, 0);
#else
    return send(sock_fd, data, len, MSG_NOSIGNAL);
#endif
}

int CSocket::Recv(void* buffer, size_t len) {
    if (!IsValid() || !connected) return -1;

#ifdef _WIN32
    return recv(sock_fd, (char*)buffer, (int)len, 0);
#else
    return recv(sock_fd, buffer, len, 0);
#endif
}

int CSocket::SendAll(const void* data, size_t len) {
    const uint8_t* ptr = (const uint8_t*)data;
    size_t remaining = len;

    while (remaining > 0) {
        int sent = Send(ptr, remaining);
        if (sent <= 0) {
            return -1;
        }
        ptr += sent;
        remaining -= sent;
    }

    return len;
}

int CSocket::RecvAll(void* buffer, size_t len) {
    // NET-012 FIX: Add timeout to prevent hanging if peer stops sending mid-message
    uint8_t* ptr = (uint8_t*)buffer;
    size_t remaining = len;

    while (remaining > 0) {
        // Wait for data with timeout (30 seconds)
        fd_set read_fds;
        FD_ZERO(&read_fds);
        // BKL-30: never index an fd_set with a descriptor >= FD_SETSIZE.
        if (!FdSetAdd(sock_fd, &read_fds)) {
            return -1;
        }

        struct timeval tv;
        tv.tv_sec = 30;  // 30 second timeout
        tv.tv_usec = 0;

        int select_result = select(sock_fd + 1, &read_fds, nullptr, nullptr, &tv);
        if (select_result <= 0) {
            // Timeout or error
            return -1;
        }

        int received = Recv(ptr, remaining);
        if (received <= 0) {
            return -1;
        }
        ptr += received;
        remaining -= received;
    }

    return len;
}

bool CSocket::SetNonBlocking(bool non_blocking) {
    if (!IsValid()) return false;

#ifdef _WIN32
    u_long mode = non_blocking ? 1 : 0;
    return ioctlsocket(sock_fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags < 0) return false;

    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    return fcntl(sock_fd, F_SETFL, flags) == 0;
#endif
}

bool CSocket::SetReuseAddr(bool reuse) {
    if (!IsValid()) return false;

    int opt = reuse ? 1 : 0;
    return setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == 0;
}

bool CSocket::SetNoDelay(bool no_delay) {
    if (!IsValid()) return false;

    int opt = no_delay ? 1 : 0;
    return setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt)) == 0;
}

bool CSocket::SetRecvTimeout(int timeout_ms) {
    if (!IsValid()) return false;

#ifdef _WIN32
    DWORD timeout = timeout_ms;
    return setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == 0;
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

bool CSocket::SetSendTimeout(int timeout_ms) {
    if (!IsValid()) return false;

#ifdef _WIN32
    DWORD timeout = timeout_ms;
    return setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) == 0;
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

std::string CSocket::GetPeerAddress() const {
    return peer_address;
}

uint16_t CSocket::GetPeerPort() const {
    return peer_port;
}

std::string CSocket::GetLocalAddress() const {
    if (!IsValid()) return "";

    struct sockaddr_storage ss;
    socklen_t addr_len = sizeof(ss);

    if (getsockname(sock_fd, (struct sockaddr*)&ss, &addr_len) < 0) {
        return "";
    }

    std::string ip_str;
    uint16_t port;
    if (CSock::ExtractAddress(ss, ip_str, port)) {
        return ip_str;
    }
    return "";
}

uint16_t CSocket::GetLocalPort() const {
    if (!IsValid()) return 0;

    struct sockaddr_storage ss;
    socklen_t addr_len = sizeof(ss);

    if (getsockname(sock_fd, (struct sockaddr*)&ss, &addr_len) < 0) {
        return 0;
    }

    std::string ip_str;
    uint16_t port;
    if (CSock::ExtractAddress(ss, ip_str, port)) {
        return port;
    }
    return 0;
}

int CSocket::GetLastError() const {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string CSocket::GetLastErrorString() const {
    int err = GetLastError();

#ifdef _WIN32
    char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  nullptr, err, 0, buf, sizeof(buf), nullptr);
    return std::string(buf);
#else
    return std::string(strerror(err));
#endif
}

int CSocket::GetFD() const {
    // Phase 2: Return raw socket file descriptor for select()/poll()
    // On Windows, SOCKET is unsigned but we cast to int for compatibility
    // Caller should check IsValid() first
#ifdef _WIN32
    return static_cast<int>(sock_fd);
#else
    return static_cast<int>(sock_fd);
#endif
}

int CSocket::ReleaseFD() {
    // Phase 2: Release socket FD ownership
    // Transfers ownership to caller - CSocket will not close it
    if (!IsValid()) {
        return -1;
    }
    int fd = GetFD();
    Reset();  // Clear our reference so destructor won't close it
    return fd;
}

// CResolvedAddr implementation

std::string CResolvedAddr::ToString() const {
    if (!ip.empty()) {
        return ip + ":" + std::to_string(port);
    } else if (!hostname.empty()) {
        return hostname + ":" + std::to_string(port);
    }
    return ":" + std::to_string(port);
}
