// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/system.h>
#include <core/chainparams.h>
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>

#ifdef _WIN32
    #include <direct.h>
    #include <windows.h>
    #include <shlobj.h>
    #define mkdir(path, mode) _mkdir(path)

    /**
     * Convert a wide (UTF-16) path to its 8.3 short form, then to std::string.
     * Short paths are always ASCII, so they work with ANSI file APIs and LevelDB.
     * If short path conversion fails, falls back to narrow conversion (best effort).
     */
    static std::string WidePathToSafeString(const wchar_t* widePath) {
        // Get required buffer size for short path
        DWORD shortLen = GetShortPathNameW(widePath, NULL, 0);
        if (shortLen > 0) {
            std::wstring shortPath(shortLen, L'\0');
            DWORD result = GetShortPathNameW(widePath, &shortPath[0], shortLen);
            if (result > 0 && result < shortLen) {
                shortPath.resize(result);
                // Short path is ASCII-safe, direct narrow conversion works
                return std::string(shortPath.begin(), shortPath.end());
            }
        }
        // Fallback: use WideCharToMultiByte with UTF-8 encoding
        int len = WideCharToMultiByte(CP_UTF8, 0, widePath, -1, NULL, 0, NULL, NULL);
        if (len > 0) {
            std::string result(len - 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, widePath, -1, &result[0], len, NULL, NULL);
            return result;
        }
        return "";
    }
#else
    #include <unistd.h>
    #include <pwd.h>
    #include <fcntl.h>      // For open() flags: O_CREAT, O_EXCL, O_WRONLY
    #include <errno.h>      // For errno and EEXIST
    #include <cstring>      // For strerror()
#endif

/**
 * Get home directory in a cross-platform way
 */
static std::string GetHomeDir() {
#ifdef _WIN32
    // Windows: Use wide API to handle Unicode usernames (e.g., Cyrillic, CJK)
    // SHGetFolderPathW returns the full UTF-16 path, then we convert to 8.3 short
    // path which is always ASCII-safe for LevelDB and ANSI file APIs.
    wchar_t widePath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, widePath))) {
        std::string result = WidePathToSafeString(widePath);
        if (!result.empty()) {
            return result;
        }
    }

    // Fallback: try narrow API (works for ASCII usernames)
    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        return std::string(appdata);
    }

    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        return std::string(userprofile);
    }

    return "C:\\";
#else
    // Linux/Mac: Use HOME environment variable
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home);
    }

    // Fallback: Get from passwd database
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir) {
        return std::string(pw->pw_dir);
    }

    return "/tmp";
#endif
}

/**
 * DB-MED-001 FIX: Validate path for security issues
 * Prevents path traversal attacks via malicious environment variables
 */
static bool IsPathSafe(const std::string& path) {
    // Check for null bytes (path truncation attack)
    if (path.find('\0') != std::string::npos) {
        std::cerr << "ERROR: Path contains null byte - potential injection attack" << std::endl;
        return false;
    }

    // Check for relative path traversal sequences
    if (path.find("..") != std::string::npos) {
        std::cerr << "ERROR: Path contains '..' - potential path traversal attack" << std::endl;
        return false;
    }

    // Check for control characters
    for (char c : path) {
        if (c < 32 && c != '\t') {
            std::cerr << "ERROR: Path contains control characters" << std::endl;
            return false;
        }
    }

    // Path length sanity check (prevent DoS via extremely long paths)
    if (path.length() > 4096) {
        std::cerr << "ERROR: Path too long (max 4096 characters)" << std::endl;
        return false;
    }

    return true;
}

std::string GetDataDir() {
    // Check for environment variable override
    const char* env_datadir = std::getenv("DILITHION_DATADIR");
    if (env_datadir) {
        std::string path(env_datadir);
        // DB-MED-001 FIX: Validate environment variable path
        if (!IsPathSafe(path)) {
            std::cerr << "WARNING: DILITHION_DATADIR contains unsafe path, ignoring" << std::endl;
            // Fall through to default path
        } else {
            return path;
        }
    }

    // Default: ~/.dilithion (or %USERPROFILE%\.dilithion on Windows)
    std::string home = GetHomeDir();

#ifdef _WIN32
    return home + "\\.dilithion";
#else
    return home + "/.dilithion";
#endif
}

std::string GetDataDir(bool testnet) {
    if (!testnet) {
        return GetDataDir();
    }

    // Check for environment variable override
    const char* env_datadir = std::getenv("DILITHION_DATADIR");
    if (env_datadir) {
        std::string path(env_datadir);
        // DB-MED-001 FIX: Validate environment variable path
        if (!IsPathSafe(path)) {
            std::cerr << "WARNING: DILITHION_DATADIR contains unsafe path, ignoring" << std::endl;
            // Fall through to default path
        } else {
            return path + "-testnet";
        }
    }

    // Default: ~/.dilithion-testnet
    std::string home = GetHomeDir();

#ifdef _WIN32
    return home + "\\.dilithion-testnet";
#else
    return home + "/.dilithion-testnet";
#endif
}

std::string GetDataDir(Dilithion::Network network) {
    if (network == Dilithion::TESTNET) {
        return GetDataDir(true);
    }
    if (network == Dilithion::DILV) {
        // Check for environment variable override
        const char* env_datadir = std::getenv("DILITHION_DATADIR");
        if (env_datadir) {
            std::string path(env_datadir);
            if (IsPathSafe(path)) {
                return path + "-dilv";
            }
            std::cerr << "WARNING: DILITHION_DATADIR contains unsafe path, ignoring" << std::endl;
        }

        std::string home = GetHomeDir();
#ifdef _WIN32
        return home + "\\.dilv";
#else
        return home + "/.dilv";
#endif
    }
    // MAINNET (default)
    return GetDataDir();
}

bool EnsureDataDirExists(const std::string& path) {
    // CID 1675201 FIX: Prevent TOCTOU (Time-Of-Check Time-Of-Use) race condition
    // Instead of checking then creating, we attempt to create atomically and verify
    // This prevents an attacker from replacing the directory with a symlink between check and use
    
    // Attempt to create directory atomically (mkdir fails if directory already exists)
#ifdef _WIN32
    int mkdir_result = mkdir(path.c_str(), 0);
    bool created = (mkdir_result == 0);
    
    if (mkdir_result != 0) {
        // Directory might already exist, or creation failed
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            std::cerr << "ERROR: Failed to create directory: " << path << " (error: " << error << ")" << std::endl;
            return false;
        }
        // ERROR_ALREADY_EXISTS means directory exists - verify it's actually a directory
    }
#else
    int mkdir_result = mkdir(path.c_str(), 0700);
    bool created = (mkdir_result == 0);
    
    if (mkdir_result != 0) {
        // Directory might already exist, or creation failed
        if (errno != EEXIST) {
            std::cerr << "ERROR: Failed to create directory: " << path << " (" << strerror(errno) << ")" << std::endl;
            return false;
        }
        // EEXIST means directory exists - verify it's actually a directory (not symlink/file)
    }
#endif

    // CID 1675201 FIX: Verify directory attributes AFTER creation/check to prevent TOCTOU
    // Use lstat on Unix to detect symlinks (doesn't follow symlinks), stat on Windows
    struct stat info;
#ifdef _WIN32
    if (stat(path.c_str(), &info) != 0) {
        std::cerr << "ERROR: Cannot access directory: " << path << std::endl;
        return false;
    }
    
    // On Windows, verify it's actually a directory (not a file)
    if (!(info.st_mode & S_IFDIR)) {
        std::cerr << "ERROR: " << path << " exists but is not a directory" << std::endl;
        return false;
    }
#else
    // Use lstat to detect symlinks (doesn't follow symlinks)
    if (lstat(path.c_str(), &info) != 0) {
        std::cerr << "ERROR: Cannot access directory: " << path << std::endl;
        return false;
    }
    
    // CID 1675201 FIX: Reject symlinks for security (prevent symlink attacks)
    if (S_ISLNK(info.st_mode)) {
        std::cerr << "ERROR: " << path << " is a symlink - not allowed for security reasons" << std::endl;
        return false;
    }
    
    // Verify it's actually a directory (not a file)
    if (!S_ISDIR(info.st_mode)) {
        std::cerr << "ERROR: " << path << " exists but is not a directory" << std::endl;
        return false;
    }
#endif

    if (created) {
        std::cout << "Created data directory: " << path << std::endl;
    }
    return true;
}

/**
 * PERSIST-004 FIX: Atomically create a file with exclusive access
 *
 * This function prevents TOCTOU (Time-Of-Check Time-Of-Use) race conditions
 * by using atomic file creation primitives:
 *
 * - POSIX: open() with O_CREAT | O_EXCL
 *   - O_CREAT: Create file if it doesn't exist
 *   - O_EXCL: Fail if file already exists
 *   - Combined: Atomic test-and-create operation
 *
 * - Windows: CreateFile() with CREATE_NEW disposition
 *   - CREATE_NEW: Create only if file doesn't exist
 *   - Fails with ERROR_FILE_EXISTS if file already exists
 *
 * Security Properties:
 * 1. Atomicity: Check-and-create happens in single kernel operation
 * 2. Exclusivity: Only ONE process can successfully create the file
 * 3. Race-free: No window between check and creation
 *
 * Use Case Example:
 *   Process A                    Process B
 *   ----------                   ----------
 *   AtomicCreateFile(...)        AtomicCreateFile(...)
 *     -> returns true              -> returns false (file exists)
 *   Safe to proceed              Must abort
 *
 * @param file_path Path to file to create
 * @return true if this process successfully created the file
 * @return false if file already exists (another process won)
 */
bool AtomicCreateFile(const std::string& file_path) {
#ifdef _WIN32
    // Windows: Use CreateFileW with CREATE_NEW disposition
    // Convert to wide string for Unicode path support
    std::wstring wFilePath(file_path.begin(), file_path.end());
    HANDLE hFile = CreateFileW(
        wFilePath.c_str(),
        GENERIC_WRITE,              // Desired access
        0,                          // No sharing (exclusive)
        NULL,                       // Default security
        CREATE_NEW,                 // Create only if doesn't exist (atomic!)
        FILE_ATTRIBUTE_NORMAL,      // Normal file
        NULL                        // No template
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_EXISTS) {
            // Another process already created the file
            return false;
        }
        // Other error (permissions, disk full, etc.)
        std::cerr << "ERROR: Failed to create file atomically: " << file_path << std::endl;
        std::cerr << "       Windows error code: " << error << std::endl;
        return false;
    }

    // Successfully created file - close handle
    CloseHandle(hFile);
    return true;

#else
    // POSIX: Use open() with O_CREAT | O_EXCL
    int fd = open(file_path.c_str(),
                  O_CREAT | O_EXCL | O_WRONLY,  // Create exclusively, write-only
                  0600);                         // rw------- permissions

    if (fd == -1) {
        if (errno == EEXIST) {
            // Another process already created the file
            return false;
        }
        // Other error (permissions, disk full, etc.)
        std::cerr << "ERROR: Failed to create file atomically: " << file_path << std::endl;
        std::cerr << "       errno: " << errno << " (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    // Successfully created file - close descriptor
    close(fd);
    return true;
#endif
}
