// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Wallet Persistence Tests
 *
 * Tests wallet Save/Load functionality
 */

#include <wallet/wallet.h>
#include <iostream>
#include <fstream>
#include <filesystem>

// ANSI colors
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_BLUE "\033[34m"
#define COLOR_RESET "\033[0m"

int main() {
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "   Wallet Persistence Tests            " << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;

    // Platform-specific temp path
#ifdef _WIN32
    const std::string testFile = "test_wallet_persist.dat";
#else
    const std::string testFile = "/tmp/test_wallet.dat";
#endif

    // Test 1: Save and load unencrypted wallet
    std::cout << COLOR_BLUE << "\n=== Test 1: Save/Load Unencrypted Wallet ===" << COLOR_RESET << std::endl;
    {
        CWallet wallet1;
        wallet1.SetWalletFile(testFile);

        // Generate keys
        wallet1.GenerateNewKey();
        wallet1.GenerateNewKey();

        CDilithiumAddress addr1 = wallet1.GetNewAddress();
        std::cout << COLOR_GREEN << "✓ Generated 2 keys" << COLOR_RESET << std::endl;

        // Save wallet
        if (!wallet1.Save()) {
            std::cout << COLOR_RED << "✗ Failed to save wallet" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Saved wallet" << COLOR_RESET << std::endl;

        // Load into new wallet
        CWallet wallet2;
        if (!wallet2.Load(testFile)) {
            std::cout << COLOR_RED << "✗ Failed to load wallet" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Loaded wallet" << COLOR_RESET << std::endl;

        // Verify key count
        if (wallet2.GetKeyPoolSize() != 2) {
            std::cout << COLOR_RED << "✗ Key count mismatch" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ All keys loaded" << COLOR_RESET << std::endl;
    }

    // Test 2: Save and load encrypted wallet
    std::cout << COLOR_BLUE << "\n=== Test 2: Save/Load Encrypted Wallet ===" << COLOR_RESET << std::endl;
    {
        CWallet wallet1;
        wallet1.SetWalletFile(testFile);

        // Generate keys before encryption
        wallet1.GenerateNewKey();

        // Encrypt wallet
        if (!wallet1.EncryptWallet("MyStr0ng!T3st#P@ss")) {
            std::cout << COLOR_RED << "✗ Failed to encrypt wallet" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Encrypted wallet" << COLOR_RESET << std::endl;

        // Generate key in encrypted wallet
        wallet1.GenerateNewKey();
        std::cout << COLOR_GREEN << "✓ Generated key in encrypted wallet" << COLOR_RESET << std::endl;

        // Explicitly save encrypted wallet
        if (!wallet1.Save()) {
            std::cout << COLOR_RED << "✗ Failed to save encrypted wallet" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Saved encrypted wallet" << COLOR_RESET << std::endl;

        // Load into new wallet
        CWallet wallet2;
        if (!wallet2.Load(testFile)) {
            std::cout << COLOR_RED << "✗ Failed to load encrypted wallet" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Loaded encrypted wallet" << COLOR_RESET << std::endl;

        // Verify it's encrypted
        if (!wallet2.IsCrypted()) {
            std::cout << COLOR_RED << "✗ Wallet not encrypted after load" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Wallet is encrypted" << COLOR_RESET << std::endl;

        // Verify it's locked
        if (!wallet2.IsLocked()) {
            std::cout << COLOR_RED << "✗ Wallet not locked after load" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Wallet is locked" << COLOR_RESET << std::endl;

        // Unlock with correct passphrase
        if (!wallet2.Unlock("MyStr0ng!T3st#P@ss")) {
            std::cout << COLOR_RED << "✗ Failed to unlock" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ Unlocked with correct passphrase" << COLOR_RESET << std::endl;

        // Verify key count
        if (wallet2.GetKeyPoolSize() != 2) {
            std::cout << COLOR_RED << "✗ Key count mismatch (expected 2, got " << wallet2.GetKeyPoolSize() << ")" << COLOR_RESET << std::endl;
            return 1;
        }
        std::cout << COLOR_GREEN << "✓ All keys loaded and accessible" << COLOR_RESET << std::endl;
    }

    // Cleanup
    std::filesystem::remove(testFile);

    std::cout << "\n" << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << "✓ ALL TESTS PASSED" << COLOR_RESET << std::endl;
    std::cout << COLOR_BLUE << "========================================" << COLOR_RESET << std::endl;

    return 0;
}
