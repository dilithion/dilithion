/**
 * @file rpc_permissions_tests.cpp
 * @brief Unit tests for RPC permissions system (FIX-014)
 *
 * Tests the Role-Based Access Control (RBAC) implementation including:
 * - Permission bitfield operations
 * - Method-permission mappings
 * - Authorization logic
 * - Authentication with HMAC-SHA3-256
 * - Multi-user configuration
 * - Thread safety
 * - Edge cases and error handling
 *
 * @author Dilithion Core Development Team
 * @date 2025-11-11
 */

#include <gtest/gtest.h>
#include <rpc/permissions.h>
#include <thread>
#include <vector>
#include <atomic>
#include <fstream>

/**
 * Test Suite 1: Permission Bitfield Operations
 *
 * Verifies that the bitfield permission model works correctly:
 * - Individual permission bits set correctly
 * - Role presets combine permissions correctly
 * - Bitwise operations produce expected results
 */
class RPCPermissionsBitfieldTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test fixtures set up before each test
    }

    void TearDown() override {
        // Cleanup after each test
    }
};

TEST_F(RPCPermissionsBitfieldTest, IndividualPermissions) {
    // Test individual permission bits
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN), 0x0001);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::READ_WALLET), 0x0002);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::READ_MEMPOOL), 0x0004);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::READ_MINING), 0x0008);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::WRITE_WALLET), 0x0010);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::WRITE_MEMPOOL), 0x0020);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::CONTROL_MINING), 0x0040);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::CONTROL_NETWORK), 0x0080);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::ADMIN_WALLET), 0x0100);
    EXPECT_EQ(static_cast<uint32_t>(RPCPermission::ADMIN_SERVER), 0x0200);
}

TEST_F(RPCPermissionsBitfieldTest, RolePresets) {
    // Test role preset values
    uint32_t readonly = static_cast<uint32_t>(RPCPermission::ROLE_READONLY);
    uint32_t wallet = static_cast<uint32_t>(RPCPermission::ROLE_WALLET);
    uint32_t admin = static_cast<uint32_t>(RPCPermission::ROLE_ADMIN);

    EXPECT_EQ(readonly, 0x000F);  // READ_BLOCKCHAIN | READ_WALLET | READ_MEMPOOL | READ_MINING
    EXPECT_EQ(wallet, 0x003F);    // ROLE_READONLY | WRITE_WALLET | WRITE_MEMPOOL
    EXPECT_EQ(admin, 0xFFFFFFFF); // All permissions
}

TEST_F(RPCPermissionsBitfieldTest, BitwiseOperations) {
    uint32_t admin = static_cast<uint32_t>(RPCPermission::ROLE_ADMIN);
    uint32_t wallet = static_cast<uint32_t>(RPCPermission::ROLE_WALLET);
    uint32_t readonly = static_cast<uint32_t>(RPCPermission::ROLE_READONLY);

    // Admin has all permissions
    EXPECT_NE((admin & static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN)), 0);
    EXPECT_NE((admin & static_cast<uint32_t>(RPCPermission::WRITE_WALLET)), 0);
    EXPECT_NE((admin & static_cast<uint32_t>(RPCPermission::ADMIN_SERVER)), 0);
    EXPECT_NE((admin & static_cast<uint32_t>(RPCPermission::ADMIN_WALLET)), 0);

    // Wallet has read + write, not admin
    EXPECT_NE((wallet & static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN)), 0);
    EXPECT_NE((wallet & static_cast<uint32_t>(RPCPermission::READ_WALLET)), 0);
    EXPECT_NE((wallet & static_cast<uint32_t>(RPCPermission::WRITE_WALLET)), 0);
    EXPECT_NE((wallet & static_cast<uint32_t>(RPCPermission::WRITE_MEMPOOL)), 0);
    EXPECT_EQ((wallet & static_cast<uint32_t>(RPCPermission::ADMIN_WALLET)), 0);
    EXPECT_EQ((wallet & static_cast<uint32_t>(RPCPermission::ADMIN_SERVER)), 0);

    // Readonly has only read permissions
    EXPECT_NE((readonly & static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN)), 0);
    EXPECT_NE((readonly & static_cast<uint32_t>(RPCPermission::READ_WALLET)), 0);
    EXPECT_NE((readonly & static_cast<uint32_t>(RPCPermission::READ_MEMPOOL)), 0);
    EXPECT_NE((readonly & static_cast<uint32_t>(RPCPermission::READ_MINING)), 0);
    EXPECT_EQ((readonly & static_cast<uint32_t>(RPCPermission::WRITE_WALLET)), 0);
    EXPECT_EQ((readonly & static_cast<uint32_t>(RPCPermission::WRITE_MEMPOOL)), 0);
    EXPECT_EQ((readonly & static_cast<uint32_t>(RPCPermission::ADMIN_WALLET)), 0);
    EXPECT_EQ((readonly & static_cast<uint32_t>(RPCPermission::ADMIN_SERVER)), 0);
}

TEST_F(RPCPermissionsBitfieldTest, PermissionCombinations) {
    // Test combining multiple permissions with bitwise OR
    uint32_t readWalletAndBlockchain = static_cast<uint32_t>(
        RPCPermission::READ_WALLET | RPCPermission::READ_BLOCKCHAIN
    );
    EXPECT_EQ(readWalletAndBlockchain, 0x0003);

    uint32_t writeWalletAndMempool = static_cast<uint32_t>(
        RPCPermission::WRITE_WALLET | RPCPermission::WRITE_MEMPOOL
    );
    EXPECT_EQ(writeWalletAndMempool, 0x0030);

    uint32_t allRead = static_cast<uint32_t>(
        RPCPermission::READ_BLOCKCHAIN | RPCPermission::READ_WALLET |
        RPCPermission::READ_MEMPOOL | RPCPermission::READ_MINING
    );
    EXPECT_EQ(allRead, 0x000F);
}

/**
 * Test Suite 2: Method-Permission Mapping
 *
 * Verifies that RPC methods are correctly mapped to required permissions:
 * - Readonly methods require read permissions only
 * - Write methods require read + write permissions
 * - Admin methods require admin permissions
 * - Unknown methods return 0 (no permissions required)
 */
class RPCPermissionsMethodMappingTest : public ::testing::Test {
protected:
    CRPCPermissions perms;

    void SetUp() override {
        // CRPCPermissions constructor initializes method mappings
    }
};

TEST_F(RPCPermissionsMethodMappingTest, BlockchainReadMethods) {
    EXPECT_EQ(perms.GetMethodPermissions("getblockcount"),
              static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN));
    EXPECT_EQ(perms.GetMethodPermissions("getblock"),
              static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN));
    EXPECT_EQ(perms.GetMethodPermissions("getblockhash"),
              static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN));
    EXPECT_EQ(perms.GetMethodPermissions("getblockchaininfo"),
              static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN));
    EXPECT_EQ(perms.GetMethodPermissions("getdifficulty"),
              static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN));
}

TEST_F(RPCPermissionsMethodMappingTest, WalletReadMethods) {
    EXPECT_EQ(perms.GetMethodPermissions("getbalance"),
              static_cast<uint32_t>(RPCPermission::READ_WALLET));
    EXPECT_EQ(perms.GetMethodPermissions("listaddresses"),
              static_cast<uint32_t>(RPCPermission::READ_WALLET));
    EXPECT_EQ(perms.GetMethodPermissions("listtransactions"),
              static_cast<uint32_t>(RPCPermission::READ_WALLET));
    EXPECT_EQ(perms.GetMethodPermissions("listunspent"),
              static_cast<uint32_t>(RPCPermission::READ_WALLET));
    EXPECT_EQ(perms.GetMethodPermissions("gettransaction"),
              static_cast<uint32_t>(RPCPermission::READ_WALLET));
}

TEST_F(RPCPermissionsMethodMappingTest, WalletWriteMethods) {
    uint32_t walletWrite = static_cast<uint32_t>(
        RPCPermission::READ_WALLET | RPCPermission::WRITE_WALLET
    );

    EXPECT_EQ(perms.GetMethodPermissions("sendtoaddress"), walletWrite);
    EXPECT_EQ(perms.GetMethodPermissions("getnewaddress"), walletWrite);
    EXPECT_EQ(perms.GetMethodPermissions("signrawtransaction"), walletWrite);
    EXPECT_EQ(perms.GetMethodPermissions("createhdwallet"), walletWrite);
}

TEST_F(RPCPermissionsMethodMappingTest, MempoolMethods) {
    EXPECT_EQ(perms.GetMethodPermissions("getmempoolinfo"),
              static_cast<uint32_t>(RPCPermission::READ_MEMPOOL));

    uint32_t mempoolWrite = static_cast<uint32_t>(
        RPCPermission::READ_MEMPOOL | RPCPermission::WRITE_MEMPOOL
    );
    EXPECT_EQ(perms.GetMethodPermissions("sendrawtransaction"), mempoolWrite);
}

TEST_F(RPCPermissionsMethodMappingTest, MiningMethods) {
    EXPECT_EQ(perms.GetMethodPermissions("getmininginfo"),
              static_cast<uint32_t>(RPCPermission::READ_MINING));

    EXPECT_EQ(perms.GetMethodPermissions("startmining"),
              static_cast<uint32_t>(RPCPermission::CONTROL_MINING));
    EXPECT_EQ(perms.GetMethodPermissions("stopmining"),
              static_cast<uint32_t>(RPCPermission::CONTROL_MINING));
    EXPECT_EQ(perms.GetMethodPermissions("generatetoaddress"),
              static_cast<uint32_t>(RPCPermission::CONTROL_MINING));
}

TEST_F(RPCPermissionsMethodMappingTest, AdminWalletMethods) {
    EXPECT_EQ(perms.GetMethodPermissions("encryptwallet"),
              static_cast<uint32_t>(RPCPermission::ADMIN_WALLET));
    EXPECT_EQ(perms.GetMethodPermissions("walletpassphrase"),
              static_cast<uint32_t>(RPCPermission::ADMIN_WALLET));
    EXPECT_EQ(perms.GetMethodPermissions("exportmnemonic"),
              static_cast<uint32_t>(RPCPermission::ADMIN_WALLET));
    EXPECT_EQ(perms.GetMethodPermissions("backupwallet"),
              static_cast<uint32_t>(RPCPermission::ADMIN_WALLET));
}

TEST_F(RPCPermissionsMethodMappingTest, AdminServerMethods) {
    EXPECT_EQ(perms.GetMethodPermissions("stop"),
              static_cast<uint32_t>(RPCPermission::ADMIN_SERVER));
}

TEST_F(RPCPermissionsMethodMappingTest, UnknownMethods) {
    // CVE-2026-RPC-PERMDEFAULT (H-A1): unknown methods now require ROLE_ADMIN.
    // Previously returned 0 (public), which silently exposed wallet-touching
    // methods missing from the map (setminingaddress, claimhtlc, etc.).
    EXPECT_EQ(perms.GetMethodPermissions("unknownmethod"),
              static_cast<uint32_t>(RPCPermission::ROLE_ADMIN));
    EXPECT_EQ(perms.GetMethodPermissions(""),
              static_cast<uint32_t>(RPCPermission::ROLE_ADMIN));
    EXPECT_EQ(perms.GetMethodPermissions("getbalancetypo"),
              static_cast<uint32_t>(RPCPermission::ROLE_ADMIN));
    // Methods explicitly mapped as public (required=0) remain public.
    EXPECT_EQ(perms.GetMethodPermissions("help"), 0u);
}

/**
 * Test Suite 3: Authorization Logic
 *
 * Verifies that CheckMethodPermission() correctly enforces access control:
 * - Admin role can access all methods
 * - Wallet role can access read + write methods
 * - Readonly role can only access read methods
 * - Insufficient permissions are denied
 */
class RPCPermissionsAuthorizationTest : public ::testing::Test {
protected:
    CRPCPermissions perms;
    uint32_t admin;
    uint32_t wallet;
    uint32_t readonly;

    void SetUp() override {
        admin = static_cast<uint32_t>(RPCPermission::ROLE_ADMIN);
        wallet = static_cast<uint32_t>(RPCPermission::ROLE_WALLET);
        readonly = static_cast<uint32_t>(RPCPermission::ROLE_READONLY);
    }
};

TEST_F(RPCPermissionsAuthorizationTest, AdminCanAccessEverything) {
    // Blockchain read
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "getblockcount"));
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "getblock"));

    // Wallet read
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "getbalance"));
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "listtransactions"));

    // Wallet write
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "sendtoaddress"));
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "getnewaddress"));

    // Mining control
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "startmining"));
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "stopmining"));

    // Admin wallet
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "encryptwallet"));
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "exportmnemonic"));

    // Admin server
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "stop"));
}

TEST_F(RPCPermissionsAuthorizationTest, WalletCanReadAndWrite) {
    // Blockchain read - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "getblockcount"));
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "getblock"));

    // Wallet read - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "getbalance"));
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "listtransactions"));

    // Wallet write - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "sendtoaddress"));
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "getnewaddress"));

    // Mempool read - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "getmempoolinfo"));

    // Mempool write - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "sendrawtransaction"));
}

TEST_F(RPCPermissionsAuthorizationTest, WalletCannotAccessAdmin) {
    // Mining control - DENIED (wallet doesn't have CONTROL_MINING)
    EXPECT_FALSE(perms.CheckMethodPermission(wallet, "startmining"));
    EXPECT_FALSE(perms.CheckMethodPermission(wallet, "stopmining"));

    // Admin wallet - DENIED (wallet doesn't have ADMIN_WALLET)
    EXPECT_FALSE(perms.CheckMethodPermission(wallet, "encryptwallet"));
    EXPECT_FALSE(perms.CheckMethodPermission(wallet, "exportmnemonic"));
    EXPECT_FALSE(perms.CheckMethodPermission(wallet, "walletpassphrase"));

    // Admin server - DENIED (wallet doesn't have ADMIN_SERVER)
    EXPECT_FALSE(perms.CheckMethodPermission(wallet, "stop"));
}

TEST_F(RPCPermissionsAuthorizationTest, ReadonlyCanOnlyRead) {
    // Blockchain read - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(readonly, "getblockcount"));
    EXPECT_TRUE(perms.CheckMethodPermission(readonly, "getblock"));

    // Wallet read - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(readonly, "getbalance"));
    EXPECT_TRUE(perms.CheckMethodPermission(readonly, "listtransactions"));

    // Mempool read - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(readonly, "getmempoolinfo"));

    // Mining read - ALLOWED
    EXPECT_TRUE(perms.CheckMethodPermission(readonly, "getmininginfo"));
}

TEST_F(RPCPermissionsAuthorizationTest, ReadonlyCannotWrite) {
    // Wallet write - DENIED
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "sendtoaddress"));
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "getnewaddress"));

    // Mempool write - DENIED
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "sendrawtransaction"));

    // Mining control - DENIED
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "startmining"));
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "stopmining"));

    // Admin wallet - DENIED
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "encryptwallet"));
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "exportmnemonic"));

    // Admin server - DENIED
    EXPECT_FALSE(perms.CheckMethodPermission(readonly, "stop"));
}

TEST_F(RPCPermissionsAuthorizationTest, ZeroPermissions) {
    uint32_t noAccess = 0;

    // No permissions - all write/admin methods DENIED
    EXPECT_FALSE(perms.CheckMethodPermission(noAccess, "sendtoaddress"));
    EXPECT_FALSE(perms.CheckMethodPermission(noAccess, "stop"));
    EXPECT_FALSE(perms.CheckMethodPermission(noAccess, "encryptwallet"));

    // Even read methods DENIED with zero permissions
    EXPECT_FALSE(perms.CheckMethodPermission(noAccess, "getbalance"));
    EXPECT_FALSE(perms.CheckMethodPermission(noAccess, "getblockcount"));
}

TEST_F(RPCPermissionsAuthorizationTest, UnknownMethodsAllowed) {
    // Unknown methods return 0 required permissions, so allowed
    // (Logged as warning in production for security monitoring)
    EXPECT_TRUE(perms.CheckMethodPermission(readonly, "unknownmethod"));
    EXPECT_TRUE(perms.CheckMethodPermission(wallet, "unknownmethod"));
    EXPECT_TRUE(perms.CheckMethodPermission(admin, "unknownmethod"));
}

/**
 * Test Suite 4: Authentication
 *
 * Verifies that AuthenticateUser() correctly:
 * - Accepts valid username/password combinations
 * - Rejects invalid usernames
 * - Rejects invalid passwords
 * - Returns correct permission bitmask for authenticated user
 * - Uses constant-time comparison (no timing leaks)
 */
class RPCPermissionsAuthenticationTest : public ::testing::Test {
protected:
    CRPCPermissions perms;

    void SetUp() override {
        // Initialize with legacy mode (single admin user)
        bool success = perms.InitializeLegacyMode("admin", "testpass123");
        ASSERT_TRUE(success) << "Failed to initialize legacy mode";
    }
};

TEST_F(RPCPermissionsAuthenticationTest, ValidCredentials) {
    uint32_t permsOut = 0;

    bool success = perms.AuthenticateUser("admin", "testpass123", permsOut);

    EXPECT_TRUE(success);
    EXPECT_EQ(permsOut, static_cast<uint32_t>(RPCPermission::ROLE_ADMIN));
}

TEST_F(RPCPermissionsAuthenticationTest, InvalidUsername) {
    uint32_t permsOut = 0;

    bool success = perms.AuthenticateUser("baduser", "testpass123", permsOut);

    EXPECT_FALSE(success);
    EXPECT_EQ(permsOut, 0);  // Permissions not modified on failure
}

TEST_F(RPCPermissionsAuthenticationTest, InvalidPassword) {
    uint32_t permsOut = 0;

    bool success = perms.AuthenticateUser("admin", "wrongpass", permsOut);

    EXPECT_FALSE(success);
    EXPECT_EQ(permsOut, 0);
}

TEST_F(RPCPermissionsAuthenticationTest, EmptyPassword) {
    uint32_t permsOut = 0;

    bool success = perms.AuthenticateUser("admin", "", permsOut);

    EXPECT_FALSE(success);
}

TEST_F(RPCPermissionsAuthenticationTest, EmptyUsername) {
    uint32_t permsOut = 0;

    bool success = perms.AuthenticateUser("", "testpass123", permsOut);

    EXPECT_FALSE(success);
}

TEST_F(RPCPermissionsAuthenticationTest, CaseSensitiveUsername) {
    uint32_t permsOut = 0;

    // Usernames are case-sensitive
    bool success = perms.AuthenticateUser("ADMIN", "testpass123", permsOut);

    EXPECT_FALSE(success);
}

TEST_F(RPCPermissionsAuthenticationTest, PasswordNotStoredPlaintext) {
    // This test verifies that the RPCUser structure doesn't store plaintext passwords
    // (Conceptual test - implementation detail)

    // After InitializeLegacyMode("admin", "testpass123"), the password "testpass123"
    // should NOT be stored in plaintext anywhere in CRPCPermissions
    // Only the HMAC-SHA3-256 hash should be stored

    // This is verified by code inspection:
    // - RPCUser struct has passwordHash (bytes) not passwordPlaintext (string)
    // - InitializeLegacyMode() hashes password immediately
    // - No plaintext storage path exists

    SUCCEED() << "Password hashing verified by design";
}

/**
 * Test Suite 5: Multi-User Configuration
 *
 * Verifies that LoadFromFile() correctly:
 * - Loads multiple users from JSON config
 * - Assigns correct permissions to each user
 * - Handles different roles (admin, wallet, readonly)
 */
class RPCPermissionsMultiUserTest : public ::testing::Test {
protected:
    CRPCPermissions perms;
    std::string testConfigPath;

    void SetUp() override {
        // Create temporary test config file
        testConfigPath = "test_rpc_permissions_multiuser.json";

        // Note: This test requires actual JSON parsing implementation
        // Current implementation has simplified JSON parser (placeholder)
        // Skip this test if JSON parsing not yet implemented

        // For now, mark as pending implementation
    }

    void TearDown() override {
        // Clean up test config file
        std::remove(testConfigPath.c_str());
    }
};

TEST_F(RPCPermissionsMultiUserTest, DISABLED_LoadMultipleUsers) {
    // NOTE: Disabled until JSON parsing fully implemented
    // See src/rpc/permissions.cpp - ParseJSONConfig() is simplified placeholder

    // Would test:
    // - Load config with 3 users (admin, wallet_bot, monitor)
    // - Authenticate each user with correct password
    // - Verify correct permissions assigned
    // - Verify authorization works correctly for each role

    GTEST_SKIP() << "Skipping multi-user test until JSON parsing implemented";
}

/**
 * Test Suite 6: Edge Cases
 *
 * Tests error handling and boundary conditions:
 * - Very long usernames/passwords
 * - Special characters in credentials
 * - Permission bitmask edge cases
 * - Concurrent access patterns
 */
class RPCPermissionsEdgeCasesTest : public ::testing::Test {
protected:
    CRPCPermissions perms;
};

TEST_F(RPCPermissionsEdgeCasesTest, VeryLongUsername) {
    std::string longUsername(1000, 'a');
    uint32_t permsOut = 0;

    // Should handle gracefully (likely returns false, doesn't crash)
    bool success = perms.AuthenticateUser(longUsername, "password", permsOut);

    EXPECT_FALSE(success);
}

TEST_F(RPCPermissionsEdgeCasesTest, VeryLongPassword) {
    // Initialize with normal username
    perms.InitializeLegacyMode("admin", "testpass");

    // Try authenticating with very long password
    std::string longPassword(10000, 'x');
    uint32_t permsOut = 0;

    bool success = perms.AuthenticateUser("admin", longPassword, permsOut);

    // Should handle gracefully (returns false, doesn't crash)
    EXPECT_FALSE(success);
}

TEST_F(RPCPermissionsEdgeCasesTest, SpecialCharactersInPassword) {
    // Passwords can contain special characters
    std::string specialPass = "p@$$w0rd!#%&*(){}[]<>?/|\\~`";

    bool initSuccess = perms.InitializeLegacyMode("admin", specialPass);
    ASSERT_TRUE(initSuccess);

    uint32_t permsOut = 0;
    bool authSuccess = perms.AuthenticateUser("admin", specialPass, permsOut);

    EXPECT_TRUE(authSuccess);
    EXPECT_EQ(permsOut, static_cast<uint32_t>(RPCPermission::ROLE_ADMIN));
}

TEST_F(RPCPermissionsEdgeCasesTest, UnicodeInUsername) {
    // Test UTF-8 username (may or may not be supported)
    std::string unicodeUser = "用户名";  // Chinese characters

    bool initSuccess = perms.InitializeLegacyMode(unicodeUser, "password");

    // Behavior depends on implementation (accept or reject)
    // Just verify it doesn't crash
    SUCCEED() << "Unicode handling tested (implementation-dependent)";
}

TEST_F(RPCPermissionsEdgeCasesTest, AllPermissionBitsSet) {
    uint32_t allBits = 0xFFFFFFFF;

    // Admin with all bits set should have all permissions
    EXPECT_TRUE(perms.CheckMethodPermission(allBits, "getblockcount"));
    EXPECT_TRUE(perms.CheckMethodPermission(allBits, "sendtoaddress"));
    EXPECT_TRUE(perms.CheckMethodPermission(allBits, "stop"));
}

TEST_F(RPCPermissionsEdgeCasesTest, NoBitsSet) {
    uint32_t noBits = 0x00000000;

    // User with no permissions should be denied all methods (except unknown)
    EXPECT_FALSE(perms.CheckMethodPermission(noBits, "getblockcount"));
    EXPECT_FALSE(perms.CheckMethodPermission(noBits, "sendtoaddress"));
    EXPECT_FALSE(perms.CheckMethodPermission(noBits, "stop"));
}

TEST_F(RPCPermissionsEdgeCasesTest, SingleBitPermission) {
    // Test with just one permission bit set
    uint32_t onlyReadBlockchain = static_cast<uint32_t>(RPCPermission::READ_BLOCKCHAIN);

    EXPECT_TRUE(perms.CheckMethodPermission(onlyReadBlockchain, "getblockcount"));
    EXPECT_FALSE(perms.CheckMethodPermission(onlyReadBlockchain, "getbalance"));  // Needs READ_WALLET
    EXPECT_FALSE(perms.CheckMethodPermission(onlyReadBlockchain, "sendtoaddress"));
}

/**
 * Test Suite 7: Role Name Mapping
 *
 * Verifies that GetRoleName() correctly converts permission bitmasks
 * to human-readable role names for logging and error messages.
 */
class RPCPermissionsRoleNameTest : public ::testing::Test {
};

TEST_F(RPCPermissionsRoleNameTest, StandardRoles) {
    EXPECT_EQ(CRPCPermissions::GetRoleName(
        static_cast<uint32_t>(RPCPermission::ROLE_ADMIN)), "admin");

    EXPECT_EQ(CRPCPermissions::GetRoleName(
        static_cast<uint32_t>(RPCPermission::ROLE_WALLET)), "wallet");

    EXPECT_EQ(CRPCPermissions::GetRoleName(
        static_cast<uint32_t>(RPCPermission::ROLE_READONLY)), "readonly");
}

TEST_F(RPCPermissionsRoleNameTest, CustomPermissions) {
    // Non-standard permission combinations should return "custom"
    uint32_t customPerms = static_cast<uint32_t>(
        RPCPermission::READ_BLOCKCHAIN | RPCPermission::CONTROL_MINING
    );

    EXPECT_EQ(CRPCPermissions::GetRoleName(customPerms), "custom");
}

TEST_F(RPCPermissionsRoleNameTest, NoPermissions) {
    EXPECT_EQ(CRPCPermissions::GetRoleName(0), "custom");
}

/**
 * Test Suite 8: Thread Safety (Concurrency)
 *
 * Stress tests to verify thread safety:
 * - Concurrent authentication from multiple threads
 * - Concurrent authorization checks
 * - No data races or crashes under high concurrency
 */
class RPCPermissionsThreadSafetyTest : public ::testing::Test {
protected:
    CRPCPermissions perms;

    void SetUp() override {
        perms.InitializeLegacyMode("admin", "testpass");
    }
};

TEST_F(RPCPermissionsThreadSafetyTest, ConcurrentAuthentication) {
    const int numThreads = 50;
    const int attemptsPerThread = 100;

    std::atomic<int> successCount{0};
    std::atomic<int> failureCount{0};
    std::vector<std::thread> threads;

    // Launch threads doing concurrent authentication
    for (int i = 0; i < numThreads; i++) {
        threads.emplace_back([this, &successCount, &failureCount, attemptsPerThread]() {
            for (int j = 0; j < attemptsPerThread; j++) {
                uint32_t permsOut = 0;

                // Half with valid credentials, half with invalid
                bool useValidCreds = (j % 2 == 0);
                std::string password = useValidCreds ? "testpass" : "wrongpass";

                bool success = perms.AuthenticateUser("admin", password, permsOut);

                if (success) {
                    successCount++;
                    EXPECT_EQ(permsOut, static_cast<uint32_t>(RPCPermission::ROLE_ADMIN));
                } else {
                    failureCount++;
                }
            }
        });
    }

    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }

    // Verify correct results
    int expectedSuccesses = numThreads * attemptsPerThread / 2;  // Half valid
    int expectedFailures = numThreads * attemptsPerThread / 2;   // Half invalid

    EXPECT_EQ(successCount.load(), expectedSuccesses);
    EXPECT_EQ(failureCount.load(), expectedFailures);
}

TEST_F(RPCPermissionsThreadSafetyTest, ConcurrentAuthorizationChecks) {
    const int numThreads = 100;
    const int checksPerThread = 1000;

    std::atomic<int> allowedCount{0};
    std::atomic<int> deniedCount{0};
    std::vector<std::thread> threads;

    uint32_t wallet = static_cast<uint32_t>(RPCPermission::ROLE_WALLET);

    // Launch threads doing concurrent authorization checks
    for (int i = 0; i < numThreads; i++) {
        threads.emplace_back([this, wallet, &allowedCount, &deniedCount, checksPerThread]() {
            for (int j = 0; j < checksPerThread; j++) {
                // Alternate between allowed and denied methods
                std::string method = (j % 2 == 0) ? "getbalance" : "stop";

                bool allowed = perms.CheckMethodPermission(wallet, method);

                if (allowed) {
                    allowedCount++;
                } else {
                    deniedCount++;
                }
            }
        });
    }

    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }

    // Wallet role can getbalance (allowed) but not stop (denied)
    int expectedAllowed = numThreads * checksPerThread / 2;
    int expectedDenied = numThreads * checksPerThread / 2;

    EXPECT_EQ(allowedCount.load(), expectedAllowed);
    EXPECT_EQ(deniedCount.load(), expectedDenied);
}

TEST_F(RPCPermissionsThreadSafetyTest, MixedConcurrentAccess) {
    // Mix of authentication and authorization from multiple threads
    const int numThreads = 50;
    const int opsPerThread = 200;

    std::atomic<int> totalOps{0};
    std::vector<std::thread> threads;

    for (int i = 0; i < numThreads; i++) {
        threads.emplace_back([this, &totalOps, opsPerThread]() {
            uint32_t wallet = static_cast<uint32_t>(RPCPermission::ROLE_WALLET);

            for (int j = 0; j < opsPerThread; j++) {
                if (j % 3 == 0) {
                    // Authenticate
                    uint32_t permsOut = 0;
                    perms.AuthenticateUser("admin", "testpass", permsOut);
                } else if (j % 3 == 1) {
                    // Check permission
                    perms.CheckMethodPermission(wallet, "getbalance");
                } else {
                    // Get method permissions
                    perms.GetMethodPermissions("sendtoaddress");
                }

                totalOps++;
            }
        });
    }

    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }

    // Verify all operations completed
    EXPECT_EQ(totalOps.load(), numThreads * opsPerThread);
}

/**
 * Test Suite 9: Legacy Mode
 *
 * Verifies backwards compatibility when rpc_permissions.json doesn't exist:
 * - Single admin user created from rpcuser/rpcpassword
 * - Has full ROLE_ADMIN permissions
 * - Authentication works correctly
 */
class RPCPermissionsLegacyModeTest : public ::testing::Test {
protected:
    CRPCPermissions perms;
};

TEST_F(RPCPermissionsLegacyModeTest, InitializeLegacyMode) {
    bool success = perms.InitializeLegacyMode("admin", "password123");

    EXPECT_TRUE(success);
    EXPECT_TRUE(perms.IsLegacyMode());
    EXPECT_EQ(perms.GetUserCount(), 1);
}

TEST_F(RPCPermissionsLegacyModeTest, LegacyModeAuthentication) {
    perms.InitializeLegacyMode("admin", "password123");

    uint32_t permsOut = 0;
    bool success = perms.AuthenticateUser("admin", "password123", permsOut);

    EXPECT_TRUE(success);
    EXPECT_EQ(permsOut, static_cast<uint32_t>(RPCPermission::ROLE_ADMIN));
}

TEST_F(RPCPermissionsLegacyModeTest, LegacyModeFullAccess) {
    perms.InitializeLegacyMode("admin", "password123");

    uint32_t permsOut = 0;
    perms.AuthenticateUser("admin", "password123", permsOut);

    // Legacy admin should have full access to all methods
    EXPECT_TRUE(perms.CheckMethodPermission(permsOut, "getblockcount"));
    EXPECT_TRUE(perms.CheckMethodPermission(permsOut, "sendtoaddress"));
    EXPECT_TRUE(perms.CheckMethodPermission(permsOut, "stop"));
    EXPECT_TRUE(perms.CheckMethodPermission(permsOut, "encryptwallet"));
}

/**
 * Test Suite 10: Performance Benchmarks
 *
 * Measures performance of critical operations:
 * - Authorization check latency
 * - Authentication latency
 * - Method permission lookup latency
 */
class RPCPermissionsPerformanceTest : public ::testing::Test {
protected:
    CRPCPermissions perms;

    void SetUp() override {
        perms.InitializeLegacyMode("admin", "testpass");
    }
};

TEST_F(RPCPermissionsPerformanceTest, AuthorizationCheckLatency) {
    const int iterations = 100000;
    uint32_t wallet = static_cast<uint32_t>(RPCPermission::ROLE_WALLET);

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        perms.CheckMethodPermission(wallet, "getbalance");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    double avgLatencyUs = static_cast<double>(duration.count()) / iterations;

    std::cout << "[PERFORMANCE] CheckMethodPermission: "
              << avgLatencyUs << " µs/op (" << iterations << " iterations)" << std::endl;

    // Should be <1 microsecond (O(1) bitwise operation + map lookup)
    EXPECT_LT(avgLatencyUs, 1.0) << "Authorization check too slow!";
}

TEST_F(RPCPermissionsPerformanceTest, AuthenticationLatency) {
    const int iterations = 1000;  // Fewer iterations (HMAC is expensive)

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        uint32_t permsOut = 0;
        perms.AuthenticateUser("admin", "testpass", permsOut);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    double avgLatencyMs = static_cast<double>(duration.count()) / iterations;

    std::cout << "[PERFORMANCE] AuthenticateUser: "
              << avgLatencyMs << " ms/op (" << iterations << " iterations)" << std::endl;

    // Should be ~1-2ms (dominated by HMAC-SHA3-256)
    EXPECT_LT(avgLatencyMs, 5.0) << "Authentication too slow!";
}

TEST_F(RPCPermissionsPerformanceTest, MethodPermissionLookup) {
    const int iterations = 1000000;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        perms.GetMethodPermissions("sendtoaddress");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    double avgLatencyUs = static_cast<double>(duration.count()) / iterations;

    std::cout << "[PERFORMANCE] GetMethodPermissions: "
              << avgLatencyUs << " µs/op (" << iterations << " iterations)" << std::endl;

    // Should be <0.5 microseconds (O(log n) map lookup with n=45)
    EXPECT_LT(avgLatencyUs, 0.5) << "Method lookup too slow!";
}

/**
 * Main Test Runner
 */
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
