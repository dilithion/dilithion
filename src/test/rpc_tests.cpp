// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/server.h>
#include <rpc/auth.h>
#include <wallet/wallet.h>
#include <miner/controller.h>
#include <node/utxo_set.h>
#include <consensus/chain.h>
#include <net/sock.h>

#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <filesystem>  // MEM-MED-001 FIX: Replace system() with std::filesystem

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #define closesocket close
#endif

using namespace std;

// ONE definition of the test credentials. They are needed in two places that
// must agree -- the server's auth/permissions init and the client's
// Authorization header -- and a silent disagreement between them would present
// as "Unauthorized", i.e. as a server bug rather than a test bug.
static const char* kTestRpcUser = "testuser";
static const char* kTestRpcPass = "testpassword123";

// Header controls exist so the suite can PIN the two security gates, not just
// satisfy them. Before this, no test anywhere asserted that a request WITHOUT
// the CSRF header or with bad credentials is REJECTED -- so deleting the CSRF
// check in server.cpp, or inverting the auth gate, left every suite green.
enum class Csrf { Send, Omit };
enum class Creds { Good, Bad, Omit };

// Helper: Send JSON-RPC request over HTTP
string SendRPCRequest(uint16_t port, const string& method, const string& params = "[]", const string& id = "1",
                      Csrf csrf = Csrf::Send, Creds creds = Creds::Good) {
    // Create socket and connect to localhost
    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (!CSock::FillSockAddr("127.0.0.1", port, ss, ss_len)) {
        return "";
    }

    int sock = socket(ss.ss_family, SOCK_STREAM, 0);
    if (sock < 0) {
        return "";
    }

    if (connect(sock, (struct sockaddr*)&ss, ss_len) < 0) {
        closesocket(sock);
        return "";
    }

    // Build JSON-RPC request
    ostringstream jsonBody;
    jsonBody << "{";
    jsonBody << "\"jsonrpc\":\"2.0\",";
    jsonBody << "\"method\":\"" << method << "\",";
    jsonBody << "\"params\":" << params << ",";
    jsonBody << "\"id\":" << id;
    jsonBody << "}";

    string body = jsonBody.str();

    // Build HTTP request
    ostringstream httpReq;
    httpReq << "POST / HTTP/1.1\r\n";
    httpReq << "Host: localhost\r\n";
    // CSRF protection: the server rejects any request without this header
    // ("Missing X-Dilithion-RPC header", code -32600). This suite never sent
    // it, but the omission was invisible for as long as the server refused to
    // start at all -- fixing the auth/permissions init is what surfaced it.
    // Every RPC caller must send it; it is part of the documented contract.
    if (csrf == Csrf::Send) httpReq << "X-Dilithion-RPC: 1\r\n";
    // Auth is configured now (it was not before), so the server also requires
    // HTTP Basic credentials: "Unauthorized - Invalid or missing credentials".
    // Third layer down -- the server refusing to start hid the CSRF gap, which
    // in turn hid this one. Each fix revealed the next real requirement.
    if (creds != Creds::Omit) {
        const std::string pass = (creds == Creds::Good) ? kTestRpcPass : "wrong-password";
        const std::string pair = std::string(kTestRpcUser) + ":" + pass;
        httpReq << "Authorization: Basic "
                << RPCAuth::Base64Encode(reinterpret_cast<const uint8_t*>(pair.data()),
                                         pair.size())
                << "\r\n";
    }
    httpReq << "Content-Type: application/json\r\n";
    httpReq << "Content-Length: " << body.size() << "\r\n";
    httpReq << "\r\n";
    httpReq << body;

    string request = httpReq.str();

    // Send request
    send(sock, request.c_str(), request.size(), 0);

    // Read response. A SINGLE 4096-byte recv truncates: RPC_Help's body is
    // already ~4.4 KB, so the `help` assertion was passing only because
    // "getnewaddress" happens to be emitted first -- one reordering of
    // RPC_Help away from a false pass. Drain the socket instead, as
    // tx_index_integration_tests.cpp does.
    string response;
    {
        char buffer[8192];
        for (;;) {
            int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (n <= 0) break;
            response.append(buffer, static_cast<size_t>(n));
            if (n < static_cast<int>(sizeof(buffer) - 1)) break;
        }
    }
    closesocket(sock);

    if (response.empty()) {
        return "";
    }

    // Extract JSON body from HTTP response
    size_t pos = response.find("\r\n\r\n");
    if (pos == string::npos) {
        pos = response.find("\n\n");
        if (pos == string::npos) {
            return "";
        }
        return response.substr(pos + 2);
    }
    return response.substr(pos + 4);
}

// CVE-2026-RPC-AUTH: Start() refuses unless BOTH RPCAuth::InitializeAuth()
// has run (global) and InitializePermissions() has populated m_permissions
// (per server). Production does both (dilithion-node.cpp:7656); this harness
// did neither, so every Start() here returned false and this whole suite was
// quarantined in run_test_suites.sh rather than ported forward. The refusal is
// correct behaviour -- the test was wrong. Mirrors the pattern already used by
// tx_index_integration_tests.cpp:347.
static bool PrepareServer(CRPCServer& server, const std::string& tag) {
    static bool auth_done = false;
    if (!auth_done) {
        if (!RPCAuth::InitializeAuth(kTestRpcUser, kTestRpcPass)) {
            cout << "  ✗ RPCAuth::InitializeAuth failed" << endl;
            return false;
        }
        auth_done = true;
    }
    // A FIXED path here is a greenness gate held by anyone who can write /tmp.
    // InitializePermissions -> LoadFromFile succeeds if the file merely EXISTS
    // and returns without installing the legacy credentials, so a stale or
    // planted file turns every request into a 401 and reds the suite
    // deterministically, with a log that cheerfully says "Loaded N users".
    const std::string perms =
        (std::filesystem::temp_directory_path()
         / ("dil_rpc_perms_" + tag + "_" + std::to_string(static_cast<long>(::getpid())) + ".json")).string();
    std::error_code perms_ec;
    std::filesystem::remove(perms, perms_ec);
    if (!server.InitializePermissions(perms, kTestRpcUser, kTestRpcPass)) {
        cout << "  ✗ InitializePermissions failed (" << perms << ")" << endl;
        return false;
    }
    return true;
}

// A Start() failure is reported with the reason it actually had, never a guess.
// The old text blamed "port conflict or system limitation" while the server had
// just printed the real cause on the line above -- a message that misdiagnoses
// its own failure is worse than no message.
static void ReportStartFailure() {
    cout << "  ✗ Failed to start RPC server" << endl;
    cout << "    auth configured : " << (RPCAuth::IsAuthConfigured() ? "yes" : "NO") << endl;
    cout << "    (a bind failure would be reported by Start() above; if auth"
            " says yes, suspect the port)" << endl;
}

// NEGATIVE CONTROLS. The happy path proves the suite can talk to the server;
// only these prove the server still REFUSES. Without them, deleting the CSRF
// block or inverting the auth gate in server.cpp leaves the whole roster green
// -- and given the CVE-2026-RPC-AUTH history that put those gates there, an
// unpinned gate is the part that matters.
bool TestSecurityGatesReject() {
    cout << "\nTesting RPC security gates REJECT (negative controls)..." << endl;

    CWallet wallet;
    wallet.GenerateNewKey();
    CRPCServer server(18436);
    server.RegisterWallet(&wallet);

    if (!PrepareServer(server, "gates")) return false;
    if (!server.Start()) { ReportStartFailure(); return false; }
    this_thread::sleep_for(chrono::milliseconds(100));

    bool ok = true;

    // 1. No CSRF header -> must be refused.
    string r = SendRPCRequest(18436, "getnewaddress", "[]", "1", Csrf::Omit, Creds::Good);
    if (r.find("X-Dilithion-RPC") == string::npos) {
        cout << "  ✗ CSRF gate did NOT reject a request without the header" << endl;
        cout << "    response: " << r.substr(0, 160) << endl;
        ok = false;
    } else {
        cout << "  ✓ CSRF gate rejects a request without X-Dilithion-RPC" << endl;
    }

    // 2. Wrong password -> must be refused.
    r = SendRPCRequest(18436, "getnewaddress", "[]", "2", Csrf::Send, Creds::Bad);
    if (r.find("Unauthorized") == string::npos) {
        cout << "  ✗ Auth gate did NOT reject bad credentials" << endl;
        cout << "    response: " << r.substr(0, 160) << endl;
        ok = false;
    } else {
        cout << "  ✓ Auth gate rejects bad credentials" << endl;
    }

    // 3. No credentials at all -> must be refused.
    r = SendRPCRequest(18436, "getnewaddress", "[]", "3", Csrf::Send, Creds::Omit);
    if (r.find("Unauthorized") == string::npos) {
        cout << "  ✗ Auth gate did NOT reject a request with no credentials" << endl;
        cout << "    response: " << r.substr(0, 160) << endl;
        ok = false;
    } else {
        cout << "  ✓ Auth gate rejects a request with no credentials" << endl;
    }

    server.Stop();
    return ok;
}

bool TestServerStartStop() {
    cout << "Testing RPC server start/stop..." << endl;

    // Use a unique port to avoid conflicts (18432 instead of 18332)
    CRPCServer server(18432);

    if (!PrepareServer(server, "startstop")) return false;

    if (!server.Start()) {
        ReportStartFailure();
        return false;  // A server that will not start is a FAILURE, not a skip.
    }
    cout << "  ✓ Server started on port " << server.GetPort() << endl;

    if (!server.IsRunning()) {
        cout << "  ✗ Server not running after start" << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ Server is running" << endl;

    // Give server time to start
    this_thread::sleep_for(chrono::milliseconds(100));

    server.Stop();

    // Give server time to stop
    this_thread::sleep_for(chrono::milliseconds(100));

    if (server.IsRunning()) {
        cout << "  ✗ Server still running after stop" << endl;
        return false;
    }
    cout << "  ✓ Server stopped" << endl;

    return true;
}

bool TestWalletRPCs() {
    cout << "\nTesting wallet RPC endpoints..." << endl;

    // Create wallet and server
    CWallet wallet;
    wallet.GenerateNewKey();

    // Create UTXO set and chain state for getbalance test
    // The return was discarded, so a failed Open() let getbalance be asserted
    // against an unopened UTXO set. And remove_all ran ONLY on the success
    // path, so every early return leaked .test_rpc_utxo into the CWD (the repo
    // root under run_test_suites.sh) for the NEXT run to pick up -- a cross-run
    // state channel that only starts mattering now the suite actually runs.
    CUTXOSet utxo_set;
    std::error_code ec_pre;
    std::filesystem::remove_all(".test_rpc_utxo", ec_pre);
    if (!utxo_set.Open(".test_rpc_utxo")) {
        cout << "  ✗ Failed to open test UTXO set" << endl;
        return false;
    }
    CChainState chain_state;

    CRPCServer server(18333);
    server.RegisterWallet(&wallet);
    server.RegisterUTXOSet(&utxo_set);
    server.RegisterChainState(&chain_state);

    if (!PrepareServer(server, "wallet")) return false;

    if (!server.Start()) {
        ReportStartFailure();
        return false;
    }

    // Give server time to start
    this_thread::sleep_for(chrono::milliseconds(100));

    // Test getnewaddress
    string response = SendRPCRequest(18333, "getnewaddress");
    if (response.find("result") == string::npos || response.find("\"D") == string::npos) {
        cout << "  ✗ getnewaddress failed" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ getnewaddress works" << endl;

    // Test getbalance
    response = SendRPCRequest(18333, "getbalance");
    if (response.find("result") == string::npos || response.find("0") == string::npos) {
        cout << "  ✗ getbalance failed" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ getbalance works (balance: 0)" << endl;

    // Test getaddresses
    response = SendRPCRequest(18333, "getaddresses");
    if (response.find("result") == string::npos || response.find("[") == string::npos) {
        cout << "  ✗ getaddresses failed" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ getaddresses works" << endl;

    server.Stop();

    // MEM-MED-001 FIX: Clean up test UTXO directory using std::filesystem
    std::error_code ec;
    std::filesystem::remove_all(".test_rpc_utxo", ec);

    return true;
}

bool TestMiningRPCs() {
    cout << "\nTesting mining RPC endpoints..." << endl;

    CMiningController miner(2);
    CRPCServer server(18334);
    server.RegisterMiner(&miner);

    if (!PrepareServer(server, "mining")) return false;

    if (!server.Start()) {
        ReportStartFailure();
        return false;
    }

    // Give server time to start
    this_thread::sleep_for(chrono::milliseconds(100));

    // Test getmininginfo
    string response = SendRPCRequest(18334, "getmininginfo");
    if (response.find("result") == string::npos || response.find("mining") == string::npos) {
        cout << "  ✗ getmininginfo failed" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ getmininginfo works" << endl;

    // Test stopmining (should work even if not mining)
    response = SendRPCRequest(18334, "stopmining");
    if (response.find("result") == string::npos) {
        cout << "  ✗ stopmining failed" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ stopmining works" << endl;

    server.Stop();
    return true;
}

bool TestGeneralRPCs() {
    cout << "\nTesting general RPC endpoints..." << endl;

    CRPCServer server(18335);

    if (!PrepareServer(server, "general")) return false;

    if (!server.Start()) {
        ReportStartFailure();
        return false;
    }

    // Give server time to start
    this_thread::sleep_for(chrono::milliseconds(100));

    // Test help
    string response = SendRPCRequest(18335, "help");
    if (response.find("result") == string::npos || response.find("getnewaddress") == string::npos) {
        cout << "  ✗ help failed" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ help works" << endl;

    // Test getnetworkinfo
    response = SendRPCRequest(18335, "getnetworkinfo");
    if (response.find("result") == string::npos || response.find("version") == string::npos) {
        cout << "  ✗ getnetworkinfo failed" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ getnetworkinfo works" << endl;

    // Test invalid method
    response = SendRPCRequest(18335, "invalidmethod");
    if (response.find("error") == string::npos || response.find("Method not found") == string::npos) {
        cout << "  ✗ Invalid method should return error" << endl;
        cout << "  Response: " << response << endl;
        server.Stop();
        return false;
    }
    cout << "  ✓ Invalid methods correctly rejected" << endl;

    server.Stop();
    return true;
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    cout << "======================================" << endl;
    cout << "Phase 4 RPC Server Tests" << endl;
    cout << "JSON-RPC 2.0 over HTTP" << endl;
    cout << "======================================" << endl;
    cout << endl;

    bool allPassed = true;

    allPassed &= TestServerStartStop();
    allPassed &= TestWalletRPCs();
    allPassed &= TestMiningRPCs();
    allPassed &= TestGeneralRPCs();
    allPassed &= TestSecurityGatesReject();

    cout << endl;
    cout << "======================================" << endl;
    if (allPassed) {
        cout << "✅ All RPC tests passed!" << endl;
    } else {
        cout << "❌ Some tests failed" << endl;
    }
    cout << "======================================" << endl;
    cout << endl;

    // This block used to print unconditionally. On a failing run it emitted six
    // green ticks for components that had NOT been validated -- while the server
    // had refused to start and nothing had been exercised at all. A summary that
    // claims coverage the run did not achieve is the most expensive kind of lie
    // in a test, because it is the part a human reads.
    if (allPassed) {
        cout << "Phase 4 RPC Components Validated:" << endl;
        cout << "  ✓ JSON-RPC 2.0 protocol" << endl;
        cout << "  ✓ HTTP/1.1 transport" << endl;
        cout << "  ✓ Wallet endpoints (getnewaddress, getbalance, getaddresses)" << endl;
        cout << "  ✓ Mining endpoints (getmininginfo, stopmining)" << endl;
        cout << "  ✓ General endpoints (help, getnetworkinfo)" << endl;
        cout << "  ✓ Error handling (invalid methods)" << endl;
    } else {
        cout << "NOTHING above is validated -- the run failed. Do not read the" << endl;
        cout << "component list from a failing run; there isn't one." << endl;
    }
    cout << endl;

#ifdef _WIN32
    WSACleanup();
#endif

    return allPassed ? 0 : 1;
}
