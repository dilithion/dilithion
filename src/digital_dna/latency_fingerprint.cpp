#include "latency_fingerprint.h"
#include <net/sock.h>

#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <thread>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <poll.h>
#endif

namespace digital_dna {

LatencyFingerprintCollector::LatencyFingerprintCollector() {
    // NOTE: Winsock init/cleanup is NOT done here.
    // The node process already calls WSAStartup() at startup.
    // Calling WSACleanup() in the destructor would terminate ALL sockets
    // in the process (P2P connections), causing a crash.
    // Standalone test tools should call WSAStartup() themselves before
    // creating a LatencyFingerprintCollector.
}

LatencyFingerprintCollector::~LatencyFingerprintCollector() {
}

double LatencyFingerprintCollector::measure_rtt(const std::string& ip, uint16_t port) {
    // Prepare address (supports both IPv4 and IPv6)
    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (!CSock::FillSockAddr(ip, port, ss, ss_len)) return -1.0;

    // Create TCP socket matching address family
#ifdef _WIN32
    SOCKET sock = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return -1.0;

    // Set non-blocking
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int sock = socket(ss.ss_family, SOCK_STREAM, 0);
    if (sock < 0) return -1.0;

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Attempt connection
    int result = connect(sock, (struct sockaddr*)&ss, ss_len);

#ifdef _WIN32
    if (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        // Wait for connection with timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms_ / 1000;
        tv.tv_usec = (timeout_ms_ % 1000) * 1000;

        result = select(0, NULL, &write_fds, NULL, &tv);
        if (result <= 0) {
            closesocket(sock);
            return -1.0;  // Timeout or error
        }

        // Check if connection succeeded
        int error = 0;
        int len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        if (error != 0) {
            closesocket(sock);
            return -1.0;
        }
    }
#else
    if (result < 0 && errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;

        result = poll(&pfd, 1, timeout_ms_);
        if (result <= 0) {
            close(sock);
            return -1.0;
        }

        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
        if (error != 0) {
            close(sock);
            return -1.0;
        }
    }
#endif

    // Stop timing
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Close socket
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    // Return RTT in milliseconds (TCP handshake = 1 RTT)
    return duration.count() / 1000.0;
}

LatencyStats LatencyFingerprintCollector::measure_seed(const SeedNode& seed) {
    LatencyStats stats;
    stats.seed_name = seed.name;
    stats.samples = 0;
    stats.failures = 0;

    // Collect samples
    for (uint32_t i = 0; i < samples_per_seed_; i++) {
        double rtt = measure_rtt(seed.ip, seed.port);
        if (rtt > 0) {
            stats.measurements.push_back(rtt);
            stats.samples++;
        } else {
            stats.failures++;
        }

        // Small delay between measurements to avoid overwhelming
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Compute statistics
    if (!stats.measurements.empty()) {
        stats.median_ms = compute_median(stats.measurements);
        stats.p10_ms = compute_percentile(stats.measurements, 10.0);
        stats.p90_ms = compute_percentile(stats.measurements, 90.0);
        stats.mean_ms = compute_mean(stats.measurements);
        stats.stddev_ms = compute_stddev(stats.measurements, stats.mean_ms);
    }

    return stats;
}

LatencyFingerprint LatencyFingerprintCollector::collect() {
    LatencyFingerprint fp;
    fp.measurement_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    fp.measurement_height = 0;  // Caller should set this

    // Measure each seed
    fp.seed_stats.reserve(MAINNET_SEEDS.size());
    for (size_t i = 0; i < MAINNET_SEEDS.size(); i++) {
        fp.seed_stats.push_back(measure_seed(MAINNET_SEEDS[i]));
    }

    return fp;
}

double LatencyFingerprintCollector::compute_median(std::vector<double>& values) {
    if (values.empty()) return 0.0;

    std::sort(values.begin(), values.end());
    size_t n = values.size();
    if (n % 2 == 0) {
        return (values[n/2 - 1] + values[n/2]) / 2.0;
    }
    return values[n/2];
}

double LatencyFingerprintCollector::compute_percentile(std::vector<double>& values, double p) {
    if (values.empty()) return 0.0;

    std::sort(values.begin(), values.end());
    double index = (p / 100.0) * (values.size() - 1);
    size_t lower = static_cast<size_t>(std::floor(index));
    size_t upper = static_cast<size_t>(std::ceil(index));

    if (lower == upper) return values[lower];

    double fraction = index - lower;
    return values[lower] * (1.0 - fraction) + values[upper] * fraction;
}

double LatencyFingerprintCollector::compute_mean(const std::vector<double>& values) {
    if (values.empty()) return 0.0;

    double sum = 0.0;
    for (double v : values) sum += v;
    return sum / values.size();
}

double LatencyFingerprintCollector::compute_stddev(const std::vector<double>& values, double mean) {
    if (values.size() < 2) return 0.0;

    double sum_sq = 0.0;
    for (double v : values) {
        double diff = v - mean;
        sum_sq += diff * diff;
    }
    return std::sqrt(sum_sq / (values.size() - 1));
}

// Fingerprint comparison using Wasserstein distance
double LatencyFingerprint::wasserstein_distance(const std::vector<double>& a, const std::vector<double>& b) {
    if (a.empty() || b.empty()) return 1000.0;  // Large distance for missing data

    std::vector<double> a_sorted = a;
    std::vector<double> b_sorted = b;
    std::sort(a_sorted.begin(), a_sorted.end());
    std::sort(b_sorted.begin(), b_sorted.end());

    // Interpolate to same number of points
    size_t n = std::max(a_sorted.size(), b_sorted.size());
    double sum = 0.0;

    for (size_t i = 0; i < n; i++) {
        double t = static_cast<double>(i) / (n - 1);

        // Get value from each distribution at quantile t
        size_t idx_a = static_cast<size_t>(t * (a_sorted.size() - 1));
        size_t idx_b = static_cast<size_t>(t * (b_sorted.size() - 1));

        double val_a = a_sorted[std::min(idx_a, a_sorted.size() - 1)];
        double val_b = b_sorted[std::min(idx_b, b_sorted.size() - 1)];

        sum += std::abs(val_a - val_b);
    }

    return sum / n;
}

double LatencyFingerprint::distance(const LatencyFingerprint& a, const LatencyFingerprint& b) {
    // Compare per-seed median latency, matched POSITIONALLY.
    //
    // serialize() (digital_dna.cpp) persists only seed_stats[i].median_ms — neither
    // seed_name nor the raw measurements vector survive the wire/registry round-trip.
    // The previous implementation matched seeds by seed_name and ran Wasserstein over
    // the raw measurements; on any deserialized DNA both are empty, so every stored
    // identity collapsed to the 1000.0 "no data" sentinel and latency contributed
    // nothing to clustering. Seeds are probed in a deterministic, network-fixed order,
    // so positional median comparison is well-defined and round-trips correctly.
    //
    // A median_ms of 0.0 is the "no measurement" sentinel: LatencyStats default-
    // initializes its doubles to 0.0, and measure_seed only populates median_ms for a
    // reachable seed (real RTT medians are always > 0). Skip any positional pair where
    // either side is 0.0 — comparing a real median against a 0.0 default would yield a
    // spurious large distance and mis-cluster otherwise-similar nodes.
    size_t n = std::min(a.seed_stats.size(), b.seed_stats.size());
    double total_distance = 0.0;
    size_t matched = 0;
    for (size_t i = 0; i < n; i++) {
        double ma = a.seed_stats[i].median_ms;
        double mb = b.seed_stats[i].median_ms;
        if (ma == 0.0 || mb == 0.0) continue;  // 0.0 = no measurement for this seed
        total_distance += std::abs(ma - mb);
        matched++;
    }
    if (matched == 0) return 1000.0;  // No comparable seeds = maximum distance
    return total_distance / static_cast<double>(matched);
}

std::string LatencyFingerprint::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "{\n";
    oss << "  \"timestamp\": " << measurement_timestamp << ",\n";
    oss << "  \"height\": " << measurement_height << ",\n";
    oss << "  \"seeds\": [\n";

    for (size_t i = 0; i < seed_stats.size(); i++) {
        const auto& s = seed_stats[i];
        oss << "    {\n";
        oss << "      \"name\": \"" << s.seed_name << "\",\n";
        oss << "      \"median_ms\": " << s.median_ms << ",\n";
        oss << "      \"p10_ms\": " << s.p10_ms << ",\n";
        oss << "      \"p90_ms\": " << s.p90_ms << ",\n";
        oss << "      \"mean_ms\": " << s.mean_ms << ",\n";
        oss << "      \"stddev_ms\": " << s.stddev_ms << ",\n";
        oss << "      \"samples\": " << s.samples << ",\n";
        oss << "      \"failures\": " << s.failures << "\n";
        oss << "    }";
        if (i < seed_stats.size() - 1) oss << ",";
        oss << "\n";
    }

    oss << "  ]\n";
    oss << "}\n";

    return oss.str();
}

} // namespace digital_dna
