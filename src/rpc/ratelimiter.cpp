// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/ratelimiter.h>

// Configuration constants
const std::chrono::seconds CRateLimiter::WINDOW_DURATION(60);  // 1 minute
const std::chrono::seconds CRateLimiter::AUTH_LOCKOUT_BASE(60);  // 1 minute base
const std::chrono::seconds CRateLimiter::AUTH_LOCKOUT_MAX(900);  // 15 minutes max

// FIX-013 (RPC-002): Default rate limit for unconfigured methods
// 1000/min = 16.67 tokens/sec, capacity 10 for burst
const CRateLimiter::MethodRateLimit CRateLimiter::DEFAULT_METHOD_LIMIT = {
    10.0,      // capacity (max burst)
    16.67,     // refillRate (1000/min = 16.67/sec)
    1.0        // costPerRequest
};

// FIX-013 (RPC-002): Per-method rate limit configuration
// Organized by risk level: CRITICAL → HIGH → MEDIUM → LOW
const std::map<std::string, CRateLimiter::MethodRateLimit> CRateLimiter::METHOD_LIMITS = {
    // === CRITICAL: Authentication/Security (5-10/min) ===
    {"walletpassphrase",       {5.0,  0.083, 1.0}},  // 5/min - brute force target
    {"walletpassphrasechange", {5.0,  0.083, 1.0}},  // 5/min - credential manipulation
    {"encryptwallet",          {5.0,  0.083, 1.0}},  // 5/min - critical state change

    // === CRITICAL: Transaction Sending (10/min) ===
    {"sendtoaddress",          {10.0, 0.167, 1.0}},  // 10/min - financial operations
    {"sendrawtransaction",     {10.0, 0.167, 1.0}},  // 10/min - financial operations

    // === HIGH: Wallet State Changes (20/min) ===
    // P3-R3 FIX: Reduced getnewaddress from 100/min to 20/min
    // Prevents address enumeration attacks (probing wallet for addresses)
    {"getnewaddress",          {20.0, 0.333, 1.0}},  // 20/min - address enumeration protection
    {"createhdwallet",         {20.0, 0.333, 1.0}},  // 20/min - wallet state manipulation
    {"restorehdwallet",        {20.0, 0.333, 1.0}},  // 20/min - wallet state manipulation
    {"exportmnemonic",         {20.0, 0.333, 1.0}},  // 20/min - sensitive data export
    {"dumpprivkey",            {5.0,  0.083, 1.0}},  // 5/min - sensitive key export
    {"importprivkey",          {5.0,  0.083, 1.0}},  // 5/min - wallet key import
    // v4.0.19: forcerebuild triggers wipe + IBD; 1/min is intentionally conservative.
    {"forcerebuild",           {1.0,  0.0167, 1.0}}, // 1/min - destructive operator action

    // === HIGH: Mining Control (20/min) ===
    {"startmining",            {20.0, 0.333, 1.0}},  // 20/min - resource intensive
    {"stopmining",             {20.0, 0.333, 1.0}},  // 20/min - service disruption
    {"generatetoaddress",      {20.0, 0.333, 1.0}},  // 20/min - computationally expensive

    // === MEDIUM: Transaction/Wallet Queries (200/min) ===
    {"signrawtransaction",     {200.0, 3.33, 1.0}},  // 200/min - CPU intensive
    {"gettransaction",         {200.0, 3.33, 1.0}},  // 200/min
    {"listtransactions",       {200.0, 3.33, 1.0}},  // 200/min
    {"listunspent",            {200.0, 3.33, 1.0}},  // 200/min
    {"getaddresses",           {200.0, 3.33, 1.0}},  // 200/min
    {"listhdaddresses",        {200.0, 3.33, 1.0}},  // 200/min

    // === MEDIUM: Blockchain Queries (500/min) ===
    {"getblock",               {500.0, 8.33, 1.0}},  // 500/min - I/O intensive
    {"getrawtransaction",      {500.0, 8.33, 1.0}},  // 500/min
    {"decoderawtransaction",   {500.0, 8.33, 1.0}},  // 500/min

    // === REST API Endpoints (Light Wallet API) ===
    // These are public endpoints for light wallet clients
    {"api_balance",            {500.0, 8.33, 1.0}},   // 500/min - address balance lookup
    {"api_utxos",              {200.0, 3.33, 1.0}},   // 200/min - UTXO iteration (CPU intensive)
    {"api_tx",                 {500.0, 8.33, 1.0}},   // 500/min - transaction lookup
    {"api_broadcast",          {10.0,  0.167, 1.0}},  // 10/min - CRITICAL (same as sendrawtransaction)
    {"api_info",               {1000.0, 16.67, 1.0}}, // 1000/min - lightweight read
    {"api_fee",                {1000.0, 16.67, 1.0}}, // 1000/min - lightweight read

    // === LOW: Read-Only Info (default 1000/min applies to unconfigured methods) ===
    // getbalance, getblockchaininfo, getblockcount, etc. - use DEFAULT_METHOD_LIMIT
};

bool CRateLimiter::AllowRequest(const std::string& ipAddress) {
    // Exempt localhost from rate limiting (local services like block explorer)
    if (ipAddress == "127.0.0.1" || ipAddress == "::1") {
        return true;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Get or create record for this IP
    RequestRecord& record = GetRecord(ipAddress);

    // RPC-008 FIX: Token bucket rate limiting with burst control
    // Refill tokens based on time elapsed since last refill
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - record.lastRefill).count();

    // Add tokens based on elapsed time (1 token per second)
    record.tokens += elapsed * TOKEN_REFILL_RATE;

    // Cap at bucket capacity (prevent token hoarding)
    if (record.tokens > TOKEN_BUCKET_CAPACITY) {
        record.tokens = TOKEN_BUCKET_CAPACITY;
    }

    record.lastRefill = now;

    // Check if we have enough tokens for this request
    if (record.tokens < TOKEN_COST_PER_REQUEST) {
        return false;  // Rate limit exceeded (burst or sustained)
    }

    // Deduct token cost and allow request
    record.tokens -= TOKEN_COST_PER_REQUEST;

    // Legacy counter (for monitoring)
    if (IsWindowExpired(record)) {
        record.count = 0;
        record.windowStart = now;
    }
    record.count++;

    return true;
}

bool CRateLimiter::AllowMethodRequest(const std::string& ipAddress, const std::string& method) {
    // Exempt localhost from rate limiting (local services like block explorer)
    if (ipAddress == "127.0.0.1" || ipAddress == "::1") {
        return true;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // Get or create record for this IP
    RequestRecord& record = GetRecord(ipAddress);

    // Get rate limit for this method
    const MethodRateLimit& limit = GetMethodLimit(method);

    // Get or initialize method token bucket
    auto& methodTokens = record.methodTokens;
    auto& methodRefillTimes = record.methodRefillTimes;

    // Initialize if first request for this method from this IP
    if (methodTokens.find(method) == methodTokens.end()) {
        methodTokens[method] = limit.capacity;
        methodRefillTimes[method] = std::chrono::steady_clock::now();
    }

    // Calculate elapsed time and refill tokens
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - methodRefillTimes[method]).count();

    methodTokens[method] += elapsed * limit.refillRate;

    // Cap at capacity (prevent token hoarding)
    if (methodTokens[method] > limit.capacity) {
        methodTokens[method] = limit.capacity;
    }

    methodRefillTimes[method] = now;

    // Check if sufficient tokens available
    if (methodTokens[method] < limit.costPerRequest) {
        return false;  // Rate limited for this method
    }

    // Deduct token cost and allow request
    methodTokens[method] -= limit.costPerRequest;
    return true;
}

void CRateLimiter::RecordAuthFailure(const std::string& ipAddress) {
    std::lock_guard<std::mutex> lock(m_mutex);

    RequestRecord& record = GetRecord(ipAddress);

    record.failedAttempts++;
    record.lastFailedTime = std::chrono::steady_clock::now();

    // RPC-006 FIX: Increment lockout count when reaching threshold
    // This tracks how many times this IP has been locked out for exponential backoff
    if (record.failedAttempts >= MAX_FAILED_AUTH_ATTEMPTS) {
        record.lockoutCount++;
    }
}

void CRateLimiter::RecordAuthSuccess(const std::string& ipAddress) {
    std::lock_guard<std::mutex> lock(m_mutex);

    RequestRecord& record = GetRecord(ipAddress);

    // RPC-006 FIX: Reset both failed attempts and lockout count on successful auth
    // This gives the user a fresh start after successful authentication
    record.failedAttempts = 0;
    record.lockoutCount = 0;  // Reset exponential backoff
}

bool CRateLimiter::IsLockedOut(const std::string& ipAddress) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_records.find(ipAddress);
    if (it == m_records.end()) {
        return false;  // No record = not locked out
    }

    const RequestRecord& record = it->second;

    // Check if exceeded max failed attempts
    if (record.failedAttempts < MAX_FAILED_AUTH_ATTEMPTS) {
        return false;
    }

    // RPC-006 FIX: Exponential backoff calculation
    // Lockout duration = BASE * 2^(lockoutCount - 1), capped at MAX
    // 1st lockout: 60s * 2^0 = 60s (1 minute)
    // 2nd lockout: 60s * 2^1 = 120s (2 minutes)
    // 3rd lockout: 60s * 2^2 = 240s (4 minutes)
    // 4th lockout: 60s * 2^3 = 480s (8 minutes)
    // 5th+ lockout: capped at 900s (15 minutes)

    size_t exponent = (record.lockoutCount > 0) ? (record.lockoutCount - 1) : 0;
    if (exponent > 10) exponent = 10;  // Prevent overflow (2^10 = 1024)

    int64_t lockoutSeconds = AUTH_LOCKOUT_BASE.count() * (1 << exponent);

    // Cap at maximum lockout duration
    if (lockoutSeconds > AUTH_LOCKOUT_MAX.count()) {
        lockoutSeconds = AUTH_LOCKOUT_MAX.count();
    }

    std::chrono::seconds lockoutDuration(lockoutSeconds);

    // Check if lockout period has expired
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastFail = std::chrono::duration_cast<std::chrono::seconds>(
        now - record.lastFailedTime
    );

    if (timeSinceLastFail >= lockoutDuration) {
        return false;  // Lockout expired
    }

    return true;  // Still locked out
}

size_t CRateLimiter::GetRequestCount(const std::string& ipAddress) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_records.find(ipAddress);
    if (it == m_records.end()) {
        return 0;
    }

    const RequestRecord& record = it->second;

    // If window expired, return 0
    if (IsWindowExpired(record)) {
        return 0;
    }

    return record.count;
}

void CRateLimiter::CleanupOldRecords() {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto now = std::chrono::steady_clock::now();
    const std::chrono::hours ONE_HOUR(1);

    // Remove records older than 1 hour
    for (auto it = m_records.begin(); it != m_records.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::hours>(
            now - it->second.windowStart
        );

        if (age >= ONE_HOUR) {
            it = m_records.erase(it);
        } else {
            ++it;
        }
    }
}

// Private methods

CRateLimiter::RequestRecord& CRateLimiter::GetRecord(const std::string& ipAddress) {
    // If record doesn't exist, create it
    if (m_records.find(ipAddress) == m_records.end()) {
        RequestRecord newRecord;

        // RPC-008 FIX: Initialize token bucket with full capacity
        newRecord.tokens = TOKEN_BUCKET_CAPACITY;
        newRecord.lastRefill = std::chrono::steady_clock::now();

        // RPC-006 FIX: Initialize exponential backoff tracking
        newRecord.failedAttempts = 0;
        newRecord.lockoutCount = 0;
        newRecord.lastFailedTime = std::chrono::steady_clock::time_point::min();

        // Legacy fields
        newRecord.count = 0;
        newRecord.windowStart = std::chrono::steady_clock::now();

        m_records[ipAddress] = newRecord;
    }

    return m_records[ipAddress];
}

bool CRateLimiter::IsWindowExpired(const RequestRecord& record) const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - record.windowStart
    );

    return elapsed >= WINDOW_DURATION;
}

const CRateLimiter::MethodRateLimit& CRateLimiter::GetMethodLimit(const std::string& method) const {
    // Look up method-specific limit
    auto it = METHOD_LIMITS.find(method);

    if (it != METHOD_LIMITS.end()) {
        return it->second;  // Return configured limit
    }

    // Return default limit for unconfigured methods
    return DEFAULT_METHOD_LIMIT;
}
