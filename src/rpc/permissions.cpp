// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/permissions.h>
#include <crypto/hmac_sha3.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <random>

// ============================================================================
// Constructor & Initialization
// ============================================================================

CRPCPermissions::CRPCPermissions()
    : m_legacyMode(false)
{
    InitializeMethodPermissions();
}

void CRPCPermissions::InitializeMethodPermissions() {
    // ========================================================================
    // Blockchain Read Methods (READ_BLOCKCHAIN = 0x0001)
    // ========================================================================

    uint32_t readBlockchain = static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN);

    m_methodPermissions["getblockcount"]      = readBlockchain;
    m_methodPermissions["getblock"]           = readBlockchain;
    m_methodPermissions["getblockhash"]       = readBlockchain;
    m_methodPermissions["getbestblockhash"]   = readBlockchain;
    m_methodPermissions["getblockchaininfo"]  = readBlockchain;
    m_methodPermissions["getchaintips"]       = readBlockchain;
    m_methodPermissions["gettxout"]           = readBlockchain;
    m_methodPermissions["getrawtransaction"]  = readBlockchain;
    m_methodPermissions["decoderawtransaction"] = readBlockchain;
    m_methodPermissions["getnetworkinfo"]     = readBlockchain;
    m_methodPermissions["getpeerinfo"]        = readBlockchain;

    // ========================================================================
    // Wallet Read Methods (READ_WALLET = 0x0002)
    // ========================================================================

    uint32_t readWallet = static_cast<uint32_t>(RPCPermission::READ_WALLET);

    m_methodPermissions["getbalance"]         = readWallet;
    m_methodPermissions["getaddresses"]       = readWallet;
    m_methodPermissions["listunspent"]        = readWallet;
    m_methodPermissions["gettransaction"]     = readWallet;
    m_methodPermissions["listtransactions"]   = readWallet;
    m_methodPermissions["gethdwalletinfo"]    = readWallet;
    m_methodPermissions["listhdaddresses"]    = readWallet;
    m_methodPermissions["rescanwallet"]       = readWallet;

    // ========================================================================
    // Mempool Read Methods (READ_MEMPOOL = 0x0004)
    // ========================================================================

    uint32_t readMempool = static_cast<uint32_t>(RPCPermission::READ_MEMPOOL);

    m_methodPermissions["getmempoolinfo"]     = readMempool;
    m_methodPermissions["getrawmempool"]      = readMempool;

    // ========================================================================
    // Mining Read Methods (READ_MINING = 0x0008)
    // ========================================================================

    uint32_t readMining = static_cast<uint32_t>(RPCPermission::READ_MINING);

    m_methodPermissions["getmininginfo"]      = readMining;

    // ========================================================================
    // Wallet Write Methods (WRITE_WALLET = 0x0010)
    // ========================================================================

    uint32_t writeWallet = static_cast<uint32_t>(RPCPermission::WRITE_WALLET);

    m_methodPermissions["getnewaddress"]      = writeWallet;
    m_methodPermissions["sendtoaddress"]      = writeWallet;
    m_methodPermissions["signrawtransaction"] = writeWallet;
    m_methodPermissions["createhdwallet"]     = writeWallet;
    m_methodPermissions["clearwallettxs"]     = writeWallet;
    m_methodPermissions["restorehdwallet"]    = writeWallet;

    // ========================================================================
    // Mempool Write Methods (WRITE_MEMPOOL = 0x0020)
    // ========================================================================

    uint32_t writeMempool = static_cast<uint32_t>(RPCPermission::WRITE_MEMPOOL);

    m_methodPermissions["sendrawtransaction"] = writeMempool;

    // ========================================================================
    // Mining Control Methods (CONTROL_MINING = 0x0040)
    // ========================================================================

    uint32_t controlMining = static_cast<uint32_t>(RPCPermission::CONTROL_MINING);

    m_methodPermissions["startmining"]        = controlMining;
    m_methodPermissions["stopmining"]         = controlMining;
    m_methodPermissions["generatetoaddress"]  = controlMining;

    // ========================================================================
    // Network Control Methods (CONTROL_NETWORK = 0x0080)
    // ========================================================================

    uint32_t controlNetwork = static_cast<uint32_t>(RPCPermission::CONTROL_NETWORK);

    m_methodPermissions["addnode"]            = controlNetwork;

    // ========================================================================
    // Admin Wallet Methods (ADMIN_WALLET = 0x0100)
    // ========================================================================

    uint32_t adminWallet = static_cast<uint32_t>(RPCPermission::ADMIN_WALLET);

    m_methodPermissions["encryptwallet"]      = adminWallet;
    m_methodPermissions["walletpassphrase"]   = adminWallet;
    m_methodPermissions["walletlock"]         = adminWallet;
    m_methodPermissions["walletpassphrasechange"] = adminWallet;
    m_methodPermissions["exportmnemonic"]     = adminWallet;
    m_methodPermissions["dumpprivkey"]        = adminWallet;
    m_methodPermissions["importprivkey"]      = adminWallet;

    // ========================================================================
    // Admin Server Methods (ADMIN_SERVER = 0x0200)
    // ========================================================================

    uint32_t adminServer = static_cast<uint32_t>(RPCPermission::ADMIN_SERVER);

    m_methodPermissions["stop"]               = adminServer;
    // v4.0.19: forcerebuild writes auto_rebuild marker and shuts down. Treated
    // as an admin-server operation alongside `stop` because it triggers shutdown.
    m_methodPermissions["forcerebuild"]       = adminServer;

    // ========================================================================
    // Public Methods (no permission required)
    // ========================================================================

    // "help" - deliberately not added (returns 0 from GetMethodPermissions)
    // Unknown methods also return 0, treated as public

    std::cout << "[RPC-PERMISSIONS] Initialized method permission map: "
              << m_methodPermissions.size() << " methods configured" << std::endl;
}

// ============================================================================
// Configuration Loading
// ============================================================================

bool CRPCPermissions::LoadFromFile(const std::string& configPath) {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_configPath = configPath;

    // Check if file exists
    std::ifstream file(configPath);
    if (!file.good()) {
        std::cout << "[RPC-PERMISSIONS] Config file not found: " << configPath
                  << " - falling back to legacy mode" << std::endl;
        return false;  // Caller will initialize legacy mode
    }

    // Read entire file
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json = buffer.str();
    file.close();

    // Parse JSON configuration
    if (!ParseJSONConfig(json)) {
        std::cerr << "[RPC-PERMISSIONS] ERROR: Failed to parse config file: "
                  << configPath << std::endl;
        return false;
    }

    m_legacyMode = false;
    std::cout << "[RPC-PERMISSIONS] Loaded " << m_users.size()
              << " users from " << configPath << std::endl;

    return true;
}

bool CRPCPermissions::ParseJSONConfig(const std::string& json) {
    // SIMPLIFIED JSON PARSER
    //
    // For production: Use jsoncpp or nlohmann::json library
    // This implementation handles basic parsing for demonstration
    //
    // Expected format:
    // {
    //   "version": 1,
    //   "users": {
    //     "username": {
    //       "password_hash": "hex_string",
    //       "salt": "hex_string",
    //       "role": "admin|wallet|readonly"
    //     }
    //   }
    // }

    // Find "users" section
    size_t usersPos = json.find("\"users\"");
    if (usersPos == std::string::npos) {
        std::cerr << "[RPC-PERMISSIONS] ERROR: Missing 'users' section in config" << std::endl;
        return false;
    }

    // Find opening brace of users object
    size_t usersObjStart = json.find('{', usersPos);
    if (usersObjStart == std::string::npos) {
        std::cerr << "[RPC-PERMISSIONS] ERROR: Malformed 'users' section" << std::endl;
        return false;
    }

    // Find matching closing brace (simplified - doesn't handle nested objects)
    size_t usersObjEnd = json.find('}', usersObjStart + 1);
    if (usersObjEnd == std::string::npos) {
        std::cerr << "[RPC-PERMISSIONS] ERROR: Malformed 'users' section (missing closing brace)" << std::endl;
        return false;
    }

    // Extract users section
    std::string usersSection = json.substr(usersObjStart + 1, usersObjEnd - usersObjStart - 1);

    // Parse each user entry (simplified parser)
    // For production: Use proper JSON library

    // Helper lambda to parse hex string
    auto hexToBytes = [](const std::string& hex) -> std::vector<uint8_t> {
        std::vector<uint8_t> bytes;
        bytes.reserve(hex.length() / 2);

        for (size_t i = 0; i + 1 < hex.length(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::strtol(byteStr.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }

        return bytes;
    };

    // Helper lambda to extract JSON string value
    auto extractStringValue = [](const std::string& json, const std::string& key) -> std::string {
        std::string keyPattern = "\"" + key + "\"";
        size_t keyPos = json.find(keyPattern);
        if (keyPos == std::string::npos) return "";

        size_t colonPos = json.find(':', keyPos);
        if (colonPos == std::string::npos) return "";

        size_t valueStart = json.find('"', colonPos);
        if (valueStart == std::string::npos) return "";

        size_t valueEnd = json.find('"', valueStart + 1);
        if (valueEnd == std::string::npos) return "";

        return json.substr(valueStart + 1, valueEnd - valueStart - 1);
    };

    // Simplified parsing: Extract username entries
    // For production implementation, use jsoncpp

    // JSON permissions file parsing is not yet implemented.
    // Return false so callers know the file was NOT loaded and will
    // fall back to legacy single-user authentication mode.
    std::cerr << "[RPC-PERMISSIONS] WARNING: JSON permissions file parsing not implemented. "
              << "Using legacy single-user authentication mode." << std::endl;

    return false;
}

bool CRPCPermissions::InitializeLegacyMode(const std::string& username,
                                           const std::string& password) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (username.empty() || password.empty()) {
        std::cerr << "[RPC-PERMISSIONS] ERROR: Empty username or password for legacy mode" << std::endl;
        return false;
    }

    // Generate random salt (32 bytes)
    std::vector<uint8_t> salt(32);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < salt.size(); i++) {
        salt[i] = static_cast<uint8_t>(dis(gen));
    }

    // Hash password with salt using PBKDF2-HMAC-SHA3
    // For simplicity, use HMAC-SHA3 directly (production: use PBKDF2 with iterations)
    std::vector<uint8_t> passwordHash(32);
    HMAC_SHA3_256(salt.data(), salt.size(),
                  reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
                  passwordHash.data());

    // Create admin user
    RPCUser user;
    user.username = username;
    user.passwordSalt = salt;
    user.passwordHash = passwordHash;
    user.permissions = static_cast<uint32_t>(RPCPermission::ROLE_ADMIN);

    m_users[username] = user;
    m_legacyMode = true;

    std::cout << "[RPC-PERMISSIONS] Initialized legacy mode (single user '"
              << username << "' with admin permissions)" << std::endl;

    return true;
}

// ============================================================================
// Authentication
// ============================================================================

bool CRPCPermissions::AuthenticateUser(const std::string& username,
                                      const std::string& password,
                                      uint32_t& permissionsOut) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Find user
    auto it = m_users.find(username);
    if (it == m_users.end()) {
        return false;  // User not found
    }

    const RPCUser& user = it->second;

    // Hash provided password with stored salt
    std::vector<uint8_t> computedHash(32);
    HMAC_SHA3_256(user.passwordSalt.data(), user.passwordSalt.size(),
                  reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
                  computedHash.data());

    // Constant-time comparison to prevent timing attacks
    bool match = (user.passwordHash.size() == computedHash.size());
    for (size_t i = 0; i < user.passwordHash.size() && i < computedHash.size(); i++) {
        match = match && (user.passwordHash[i] == computedHash[i]);
    }

    if (!match) {
        return false;  // Invalid password
    }

    // Return permissions
    permissionsOut = user.permissions;
    return true;
}

// ============================================================================
// Authorization
// ============================================================================

bool CRPCPermissions::CheckMethodPermission(const std::string& username,
                                           const std::string& method) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Find user
    auto it = m_users.find(username);
    if (it == m_users.end()) {
        return false;  // User not found
    }

    const RPCUser& user = it->second;

    // Check permission (no lock needed for GetMethodPermissions - read-only after init)
    return CheckMethodPermission(user.permissions, method);
}

bool CRPCPermissions::CheckMethodPermission(uint32_t userPermissions,
                                           const std::string& method) const {
    // CID 1675190 FIX: Use unlocked version since m_methodPermissions is read-only after init
    // This avoids double lock when called from CheckMethodPermission(username, method)
    uint32_t required = GetMethodPermissionsUnlocked(method);

    // If method not found (required = 0), allow (public method like "help")
    if (required == 0) {
        return true;
    }

    // Check if user has ALL required permissions (bitwise AND)
    // Example: user has 0x003F (ROLE_WALLET), method requires 0x0010 (WRITE_WALLET)
    //          (0x003F & 0x0010) = 0x0010, which equals required → TRUE
    return (userPermissions & required) == required;
}

// CID 1675190 FIX: Internal unlocked version - safe because m_methodPermissions
// is only written in constructor and read-only afterwards
uint32_t CRPCPermissions::GetMethodPermissionsUnlocked(const std::string& method) const {
    auto it = m_methodPermissions.find(method);
    if (it == m_methodPermissions.end()) {
        return 0;  // Unknown method, no permission required (public)
    }

    return it->second;
}

uint32_t CRPCPermissions::GetMethodPermissions(const std::string& method) const {
    // Public API acquires lock for thread safety
    std::lock_guard<std::mutex> lock(m_mutex);
    return GetMethodPermissionsUnlocked(method);
}

// ============================================================================
// Utility Methods
// ============================================================================

std::string CRPCPermissions::GetRoleName(uint32_t permissions) {
    if (permissions == static_cast<uint32_t>(RPCPermission::ROLE_ADMIN)) {
        return "admin";
    } else if (permissions == static_cast<uint32_t>(RPCPermission::ROLE_WALLET)) {
        return "wallet";
    } else if (permissions == static_cast<uint32_t>(RPCPermission::ROLE_READONLY)) {
        return "readonly";
    } else {
        return "custom";
    }
}
