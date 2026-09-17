#include "dna_registry_db.h"
#include <iostream>
#include <filesystem>
#include <thread>
#include <chrono>

using namespace digital_dna;

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { std::cout << "  [PASS] " << msg << std::endl; passed++; } \
    else { std::cout << "  [FAIL] " << msg << std::endl; failed++; } \
} while(0)

int main() {
    std::string dbPath = "./test_dna_hist_db";
    std::filesystem::remove_all(dbPath);

    DNARegistryDB db;
    CHECK(db.Open(dbPath), "Open DB");

    // Create a DNA identity
    DigitalDNA dna1;
    dna1.address.fill(0x01);
    dna1.mik_identity.fill(0xAA);
    dna1.registration_height = 100;
    dna1.registration_time = 1000;
    dna1.is_valid = true;
    dna1.timing.iterations_per_second = 500000;

    // Register
    auto r = db.register_identity(dna1);
    CHECK(r == IDNARegistry::RegisterResult::SUCCESS, "Register identity");

    // History should be empty after initial registration
    auto hist = db.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 0, "History empty after register");

    // Update with new DNA (different speed = new hardware).
    //
    // EXPECTATION CORRECTED 2026-09-10 — the PRODUCTION CODE IS RIGHT, this file
    // was stranded. It asserted UPDATED, which was the only success code when
    // this test was last touched (14b779e1, 2026-03-09). DNA_CHANGED was added
    // SIX DAYS LATER by e5ed5acb (2026-03-15, "DNA rotation detection + trust
    // penalties"), and nothing came back to update the expectation, so the suite
    // has been red ever since -- unnoticed, because it was in no roster row
    // until PR #188 registered it.
    //
    // 500000 -> 750000 is a 1.5x IPS jump. core_dimensions_changed (digital_dna.h)
    // treats >10% as a hardware change, so DNA_CHANGED is the CORRECT and more
    // specific verdict, and every production consumer already treats it as
    // success alongside UPDATED (dilithion-node.cpp / dilv-node.cpp accept both).
    //
    // Asserting DNA_CHANGED here rather than "either" is deliberate: it is the
    // stronger claim. `UPDATED` would also be returned by a no-op enrichment, so
    // accepting either would stop distinguishing a hardware rotation from a
    // timestamp bump -- which is the whole point of the Phase 5 split.
    std::this_thread::sleep_for(std::chrono::seconds(1));
    DigitalDNA dna2 = dna1;
    dna2.timing.iterations_per_second = 750000;
    dna2.registration_height = 200;
    r = db.update_identity(dna2);
    CHECK(r == IDNARegistry::RegisterResult::DNA_CHANGED,
          "Update 1 returns DNA_CHANGED (1.5x IPS = hardware rotation, not enrichment)");

    hist = db.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 1, "History has 1 entry after first update");
    if (!hist.empty()) {
        CHECK(hist[0].second.timing.iterations_per_second == 500000,
              "Archived DNA has original IPS (500000)");
        CHECK(hist[0].first > 0, "Archived timestamp is nonzero");
    }

    // Update again (another hardware change)
    std::this_thread::sleep_for(std::chrono::seconds(1));
    DigitalDNA dna3 = dna1;
    dna3.timing.iterations_per_second = 1000000;
    dna3.registration_height = 300;
    r = db.update_identity(dna3);
    CHECK(r == IDNARegistry::RegisterResult::DNA_CHANGED,
          "Update 2 returns DNA_CHANGED (2.0x IPS = hardware rotation)");

    hist = db.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 2, "History has 2 entries after second update");
    if (hist.size() >= 2) {
        CHECK(hist[0].second.timing.iterations_per_second == 500000,
              "Archived[0] has IPS 500000 (first version)");
        CHECK(hist[1].second.timing.iterations_per_second == 750000,
              "Archived[1] has IPS 750000 (second version)");
        CHECK(hist[0].first < hist[1].first,
              "History is chronologically ordered");
    }

    // Verify current identity is the latest
    auto current = db.get_identity_by_mik(dna1.mik_identity);
    CHECK(current.has_value(), "Current identity exists");
    if (current) {
        CHECK(current->timing.iterations_per_second == 1000000,
              "Current DNA has latest IPS (1000000)");
    }

    // Check that a different MIK has no history
    std::array<uint8_t, 20> otherMik{};
    otherMik.fill(0xBB);
    auto otherHist = db.get_dna_history(otherMik);
    CHECK(otherHist.empty(), "Unknown MIK has empty history");

    // Test persistence: close and reopen
    db.Close();
    DNARegistryDB db2;
    CHECK(db2.Open(dbPath), "Reopen DB");

    hist = db2.get_dna_history(dna1.mik_identity);
    CHECK(hist.size() == 2, "History survives DB reopen");
    if (hist.size() >= 2) {
        CHECK(hist[0].second.timing.iterations_per_second == 500000,
              "Persisted history[0] correct after reopen");
        CHECK(hist[1].second.timing.iterations_per_second == 750000,
              "Persisted history[1] correct after reopen");
    }

    // ---- The other side of the discriminator, and the reason this file is not
    // just "flip UPDATED to DNA_CHANGED". Both assertions above would still pass
    // if core_dimensions_changed were replaced by `return true;`. This one goes
    // RED in that case: an update that changes NO core dimension must come back
    // UPDATED, not DNA_CHANGED. Together the two pin the split; either alone
    // pins only half of it.
    DigitalDNA dna4 = dna3;                       // same IPS, same latency
    dna4.registration_height = 400;               // pure enrichment
    auto r4 = db2.update_identity(dna4);
    CHECK(r4 == IDNARegistry::RegisterResult::UPDATED,
          "A no-core-change update returns UPDATED, NOT DNA_CHANGED");

    // And it must still be a real write, or the line above could pass for the
    // wrong reason (an early return that never touched the record).
    auto after = db2.get_identity_by_mik(dna1.mik_identity);
    CHECK(after.has_value() && after->registration_height == 400,
          "the no-core-change update actually persisted");

    // Cleanup
    db2.Close();
    std::filesystem::remove_all(dbPath);

    std::cout << "\n=============================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    return failed > 0 ? 1 : 0;
}
