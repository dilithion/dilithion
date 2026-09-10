// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/websocket.h>
#include <rpc/ssl_wrapper.h>
#include <net/sock.h>
#include <util/strencodings.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#ifndef _WIN32
#include <errno.h>
#endif

// OpenSSL for SHA-1 (required for WebSocket accept key)
#include <openssl/sha.h>

// Deferred reclamation: this thread resolves CBlockIndex*, so it checkpoints.
// g_chainstate is defined in src/core/globals.cpp and declared per-TU (the idiom
// used by headers_manager.cpp / block_processing.cpp / tx_index.cpp).
#include <consensus/chain.h>
extern CChainState g_chainstate;

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <intrin.h>  // For _byteswap_uint64
    // Windows already has closesocket - no need to redefine
    // Undef Windows API macros that conflict with our code
    #undef SendMessage
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

// Base64 encoding (simplified - for WebSocket accept key)
static std::string Base64Encode(const std::string& input) {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4) encoded.push_back('=');
    return encoded;
}

CWebSocketServer::CWebSocketServer(uint16_t port)
    : m_port(port), m_server_socket(INVALID_SOCKET), m_next_connection_id(1),
      m_ssl_wrapper(nullptr), m_ssl_enabled(false) {
}

CWebSocketServer::~CWebSocketServer() {
    Stop();
}

bool CWebSocketServer::Start() {
    if (m_running) {
        return false;
    }

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
#endif

    // Create dual-stack listen socket (localhost only for WebSocket)
    socket_t ws_sock;
    bool is_ipv6;
    if (!CSock::CreateListenSocket(m_port, "127.0.0.1", ws_sock, is_ipv6)) {
        std::cerr << "[WebSocket] Failed to create listen socket on port " << m_port << std::endl;
        return false;
    }
    m_server_socket = static_cast<int>(ws_sock);

    // Listen for connections
    if (listen(m_server_socket, 10) == SOCKET_ERROR) {
        std::cerr << "[WebSocket] Failed to listen on port " << m_port << std::endl;
        closesocket(m_server_socket);
        m_server_socket = INVALID_SOCKET;
        return false;
    }

    m_running = true;
    g_chainstate.DeclareEpochParticipant("websocket-server");
    m_server_thread = std::thread(&CWebSocketServer::ServerThread, this);
    
    return true;
}

void CWebSocketServer::Stop() {
    if (!m_running) {
        return;
    }

    m_running = false;

    // Close server socket
    if (m_server_socket != INVALID_SOCKET) {
#ifdef _WIN32
        shutdown(m_server_socket, SD_BOTH);
#else
        shutdown(m_server_socket, SHUT_RDWR);
#endif
        closesocket(m_server_socket);
        m_server_socket = INVALID_SOCKET;
    }

    // Close all connections
    {
        std::lock_guard<std::mutex> lock(m_connections_mutex);
        for (auto& pair : m_connections) {
            closesocket(pair.second->socket_fd);
            if (pair.second->ssl && m_ssl_wrapper) {
                m_ssl_wrapper->SSLFree(pair.second->ssl);
            }
        }
        m_connections.clear();
    }

    // Wait for server thread
    if (m_server_thread.joinable()) {
        m_server_thread.join();
    }
}

void CWebSocketServer::ServerThread() {
    // REGISTER AT ENTRY, THEN GO OFFLINE WHILE BLOCKED.
    //
    // ⚠️ THE OFFLINE SCOPE ALONE DOES NOT REGISTER THIS THREAD. A name reaches
    // the registry on its first NAMED checkpoint, and the scope's checkpoint is in
    // its DESTRUCTOR — which runs only when the wait RETURNS. On an idle node no
    // request ever arrives, so this thread would never register and the startup
    // census would refuse to start the node. Registering here, once, before the
    // first block, is what makes the census a statement about threads that EXIST
    // rather than threads that have been handed work.
    g_chainstate.EpochCheckpoint("websocket-server");

    while (m_running) {
        // DEFERRED-RECLAMATION CHECKPOINT — before accept(), which can wait
        // indefinitely. This thread handles the client inline and reaches
        // ExecuteRPC, i.e. the entire RPC handler table, so it resolves index
        // pointers. Checkpointing here means an idle websocket listener pins
        // nothing for the hours it may sit in accept(); pin bound is one request.
        struct sockaddr_storage clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket;
        {
        // OFFLINE WHILE BLOCKED. accept() can wait indefinitely; an epoch
        // published just before it FREEZES for the whole wait and pins every
        // entry unlinked meanwhile. The scope re-enters before the request is
        // handled, which is the first thing that can resolve a pointer.
            EpochOfflineScope offline(&g_chainstate);
            clientSocket = accept(m_server_socket, (struct sockaddr*)&clientAddr, &clientLen);
        }

        if (clientSocket == INVALID_SOCKET) {
            if (m_running) {
                continue;
            } else {
                break;
            }
        }

        // Handle client in this thread (for simplicity)
        // In production, use thread pool
        HandleClient(clientSocket);
    }
}

void CWebSocketServer::HandleClient(int clientSocket) {
    // Phase 3: Perform SSL handshake if SSL enabled
    SSL* ssl = nullptr;
    if (m_ssl_enabled && m_ssl_wrapper) {
        ssl = m_ssl_wrapper->AcceptSSL(clientSocket);
        if (!ssl) {
            closesocket(clientSocket);
            return;
        }
    }

    // Create connection
    auto connection = std::make_unique<WebSocketConnection>();
    connection->socket_fd = clientSocket;
    connection->ssl = ssl;
    connection->is_ssl = (ssl != nullptr);
    
    // Get client IP (supports both IPv4 and IPv6)
    struct sockaddr_storage clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    if (getpeername(clientSocket, (struct sockaddr*)&clientAddr, &addrLen) == 0) {
        std::string ip_str;
        uint16_t client_port;
        if (CSock::ExtractAddress(clientAddr, ip_str, client_port)) {
            connection->client_ip = ip_str;
        } else {
            connection->client_ip = "unknown";
        }
    } else {
        connection->client_ip = "unknown";
    }

    // Read HTTP request for handshake
    std::vector<char> buffer(4096);
    int bytesRead = SocketRead(*connection, buffer.data(), buffer.size() - 1);
    if (bytesRead <= 0) {
        closesocket(clientSocket);
        if (ssl && m_ssl_wrapper) {
            m_ssl_wrapper->SSLFree(ssl);
        }
        return;
    }
    buffer[bytesRead] = '\0';
    std::string request(buffer.data());

    // Perform WebSocket handshake
    if (!PerformHandshake(request, *connection)) {
        closesocket(clientSocket);
        if (ssl && m_ssl_wrapper) {
            m_ssl_wrapper->SSLFree(ssl);
        }
        return;
    }

    // Add connection to map
    int connection_id = m_next_connection_id++;
    {
        std::lock_guard<std::mutex> lock(m_connections_mutex);
        m_connections[connection_id] = std::move(connection);
    }

    // Message loop
    while (m_running) {
        std::string frame_data;
        Opcode opcode;
        
        // Get connection (with lock)
        WebSocketConnection* conn_ptr = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_connections_mutex);
            auto it = m_connections.find(connection_id);
            if (it == m_connections.end()) {
                break;  // Connection was closed
            }
            conn_ptr = it->second.get();
        }
        
        if (!ReadFrame(*conn_ptr, frame_data, opcode)) {
            break;  // Connection closed or error
        }

        switch (opcode) {
            case Opcode::TEXT:
            case Opcode::BINARY:
                if (m_message_callback) {
                    m_message_callback(connection_id, frame_data, opcode == Opcode::TEXT);
                }
                break;
                
            case Opcode::PING:
                // Respond with pong
                WriteFrame(*conn_ptr, frame_data, Opcode::PONG);
                break;
                
            case Opcode::CLOSE:
                // Close connection
                CloseConnection(connection_id);
                return;
                
            default:
                break;
        }
    }

    // Cleanup
    CloseConnection(connection_id);
}

bool CWebSocketServer::PerformHandshake(const std::string& request, WebSocketConnection& connection) {
    // Extract Sec-WebSocket-Key
    size_t key_pos = request.find("Sec-WebSocket-Key:");
    if (key_pos == std::string::npos) {
        return false;
    }
    
    size_t key_start = request.find_first_not_of(" \t", key_pos + 18);
    size_t key_end = request.find("\r\n", key_start);
    if (key_end == std::string::npos) {
        return false;
    }
    
    std::string client_key = request.substr(key_start, key_end - key_start);
    
    // Generate accept key
    std::string accept_key = GenerateAcceptKey(client_key);
    
    // Send handshake response
    std::ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n";
    response << "Upgrade: websocket\r\n";
    response << "Connection: Upgrade\r\n";
    response << "Sec-WebSocket-Accept: " << accept_key << "\r\n";
    response << "\r\n";
    
    std::string response_str = response.str();
    if (SocketWrite(connection, response_str.c_str(), response_str.size()) != static_cast<int>(response_str.size())) {
        return false;
    }
    
    connection.handshake_complete = true;
    return true;
}

std::string CWebSocketServer::GenerateAcceptKey(const std::string& client_key) {
    // WebSocket magic string (RFC 6455)
    const std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    
    // Concatenate client key + magic
    std::string combined = client_key + magic;
    
    // SHA-1 hash (WebSocket spec requires SHA-1)
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.data()), combined.size(), hash);
    
    // Base64 encode
    std::string hash_str(reinterpret_cast<const char*>(hash), SHA_DIGEST_LENGTH);
    return Base64Encode(hash_str);
}

bool CWebSocketServer::ReadFrame(WebSocketConnection& connection, std::string& frame_data, Opcode& opcode) {
    // Read frame header (2 bytes minimum)
    uint8_t header[2];
    if (SocketRead(connection, header, 2) != 2) {
        return false;
    }
    
    bool fin = (header[0] & 0x80) != 0;
    opcode = static_cast<Opcode>(header[0] & 0x0F);
    bool masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = header[1] & 0x7F;
    
    // Read extended payload length if needed
    if (payload_len == 126) {
        uint16_t len;
        if (SocketRead(connection, &len, 2) != 2) {
            return false;
        }
        payload_len = ntohs(len);
    } else if (payload_len == 127) {
        uint64_t len;
        if (SocketRead(connection, &len, 8) != 8) {
            return false;
        }
        // Network byte order conversion for 64-bit
        #ifdef _WIN32
            payload_len = _byteswap_uint64(len);
        #else
            payload_len = __builtin_bswap64(len);
        #endif
    }
    
    // Read masking key if present
    uint8_t masking_key[4] = {0};
    if (masked) {
        if (SocketRead(connection, masking_key, 4) != 4) {
            return false;
        }
    }
    
    // Read payload
    frame_data.resize(payload_len);
    if (SocketRead(connection, &frame_data[0], payload_len) != static_cast<int>(payload_len)) {
        return false;
    }
    
    // Unmask payload if masked
    if (masked) {
        for (size_t i = 0; i < payload_len; ++i) {
            frame_data[i] ^= masking_key[i % 4];
        }
    }
    
    return true;
}

bool CWebSocketServer::WriteFrame(WebSocketConnection& connection, const std::string& data, Opcode opcode) {
    std::vector<uint8_t> frame;
    
    // Frame header
    uint8_t byte1 = 0x80 | static_cast<uint8_t>(opcode);  // FIN=1
    frame.push_back(byte1);
    
    // Payload length
    size_t payload_len = data.size();
    if (payload_len < 126) {
        frame.push_back(static_cast<uint8_t>(payload_len));
    } else if (payload_len < 65536) {
        frame.push_back(126);
        uint16_t len = htons(static_cast<uint16_t>(payload_len));
        frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&len), 
                    reinterpret_cast<uint8_t*>(&len) + 2);
    } else {
        frame.push_back(127);
        uint64_t len = payload_len;
        // Network byte order conversion for 64-bit
        #ifdef _WIN32
            len = _byteswap_uint64(len);
        #else
            len = __builtin_bswap64(len);
        #endif
        frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&len), 
                    reinterpret_cast<uint8_t*>(&len) + 8);
    }
    
    // Payload
    frame.insert(frame.end(), data.begin(), data.end());
    
    // Send frame
    return SocketWrite(connection, frame.data(), frame.size()) == static_cast<int>(frame.size());
}

int CWebSocketServer::SocketRead(WebSocketConnection& connection, void* buffer, int size) {
    // OFFLINE ACROSS THE READ, symmetric with SocketWrite. HandleClient blocks here
    // for the whole life of a client connection waiting for the next frame, and an
    // online thread pins every eviction for that entire time -- unbounded, since a
    // client may simply never send. Reads hold no CBlockIndex* by construction: they
    // fill a byte buffer. (Round-4 panel, grok: the read side was wired nowhere.)
    EpochOfflineScope offline(&g_chainstate);
    if (connection.is_ssl && connection.ssl && m_ssl_wrapper) {
        return m_ssl_wrapper->SSLRead(connection.ssl, buffer, size);
    } else {
        return recv(connection.socket_fd, (char*)buffer, size, 0);
    }
}

int CWebSocketServer::SocketWrite(WebSocketConnection& connection, const void* buffer, int size) {
    // OFFLINE ACROSS THE WRITE, the same rule as the RPC server's socket_write: a
    // slow client stalls the send and an online thread pins every eviction for the
    // duration. Every websocket response leaves through here, which is why this one
    // helper covers the write side. Same CONTRACT as the RPC site and with the same
    // limit: it rests on no caller holding a resolved CBlockIndex* across the
    // write, which is a census of today's callers, not an enforced property.
    EpochOfflineScope offline(&g_chainstate);
    if (connection.is_ssl && connection.ssl && m_ssl_wrapper) {
        return m_ssl_wrapper->SSLWrite(connection.ssl, buffer, size);
    } else {
        return send(connection.socket_fd, (const char*)buffer, size, 0);
    }
}

bool CWebSocketServer::SendToClient(int connection_id, const std::string& message, bool is_text) {
    std::lock_guard<std::mutex> lock(m_connections_mutex);
    auto it = m_connections.find(connection_id);
    if (it == m_connections.end()) {
        return false;
    }
    
    Opcode opcode = is_text ? Opcode::TEXT : Opcode::BINARY;
    return WriteFrame(*it->second, message, opcode);
}

size_t CWebSocketServer::BroadcastMessage(const std::string& message, bool is_text) {
    std::lock_guard<std::mutex> lock(m_connections_mutex);
    size_t count = 0;
    
    Opcode opcode = is_text ? Opcode::TEXT : Opcode::BINARY;
    for (auto& pair : m_connections) {
        if (WriteFrame(*pair.second, message, opcode)) {
            count++;
        }
    }
    
    return count;
}

void CWebSocketServer::CloseConnection(int connection_id) {
    std::lock_guard<std::mutex> lock(m_connections_mutex);
    auto it = m_connections.find(connection_id);
    if (it == m_connections.end()) {
        return;
    }
    
    // Send close frame
    WriteFrame(*it->second, "", Opcode::CLOSE);
    
    // Close socket
    closesocket(it->second->socket_fd);
    if (it->second->ssl && m_ssl_wrapper) {
        m_ssl_wrapper->SSLFree(it->second->ssl);
    }
    
    m_connections.erase(it);
}

size_t CWebSocketServer::GetConnectionCount() const {
    std::lock_guard<std::mutex> lock(m_connections_mutex);
    return m_connections.size();
}

bool CWebSocketServer::InitializeSSL(const std::string& cert_file, const std::string& key_file) {
    m_ssl_wrapper = std::make_unique<CSSLWrapper>();
    if (!m_ssl_wrapper->InitializeServer(cert_file, key_file)) {
        m_ssl_wrapper.reset();
        m_ssl_enabled = false;
        return false;
    }
    
    m_ssl_enabled = true;
    return true;
}

