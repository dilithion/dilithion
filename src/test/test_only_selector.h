// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// test_only_selector.h — a `--only=<scenario>` selector for hand-written test
// main()s.
//
// WHY THIS EXISTS
// ---------------
// A census of every suite in scripts/run_test_suites.sh (2026-09-07, 51 rows)
// found ZERO Boost suites. Every one is a hand-written main() that calls
// scenario functions in sequence, and 24 of them assert(). assert() aborts the
// PROCESS. So on any failing suite:
//
//   * only the FIRST failing scenario is ever observed, which makes every
//     quarantine reason of the form "N assertions fail" an undercount -- N is
//     what was seen before the abort, not what fails; and
//   * every LATER scenario in the file has never executed at all, in any run,
//     quarantined or not.
//
// chain_case_2_5_equivalence_tests.cpp is the worked example. Its main()
// carries a hand-written comment explaining that scenario_5 was MOVED ahead of
// scenario_2 so that scenario_5 would still run past the known scenario_2
// abort. That is the right instinct implemented as source reordering: it
// rescued one scenario, left scenarios 3 and 4 unreached, and left no record in
// the roster that anything was being skipped. This header is the general form
// of that manoeuvre, with the scope written down where the gate can read it.
//
// CONTRACT
//   * With NO --only argument, every scenario runs. A suite that adopts this
//     header behaves exactly as it did before -- that is the whole point, and
//     is what makes adoption safe across 24 files.
//   * --only=<name> may be repeated; the union runs, in the order the source
//     calls them (this is a filter, not a scheduler -- it never reorders).
//   * An --only name that matches NO registered scenario is a HARD ERROR, exit
//     non-zero, listing the names that do exist. A typo must never quietly run
//     nothing and exit 0; a green gate covering nothing is worse than a red one.
//   * Any unrecognised argument is likewise a hard error. Silently ignoring an
//     argument is how a roster ARGS field rots into a decoration.
//   * --list-scenarios prints the registered names and exits 0, running none.
//     It exists so a roster ARGS field can be written from observed names
//     rather than from memory.
//
// USAGE
//     int main(int argc, char** argv) {
//         test_only::Selector only(argc, argv);
//         if (only.ShouldRun("scenario_1")) test_scenario_1();
//         if (only.ShouldRun("scenario_2")) test_scenario_2();
//         return only.Finish();
//     }
//
// Finish() returns 0 only if every requested name was registered AND at least
// one scenario actually ran. Call it on the success path; leave the existing
// failure paths returning what they already return.

#ifndef DILITHION_TEST_ONLY_SELECTOR_H
#define DILITHION_TEST_ONLY_SELECTOR_H

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace test_only {

class Selector {
public:
    Selector(int argc, char** argv)
    {
        for (int i = 1; i < argc; ++i) {
            const std::string a(argv[i] ? argv[i] : "");
            if (a.rfind("--only=", 0) == 0) {
                const std::string name = a.substr(7);
                if (name.empty()) {
                    std::cerr << "[selector] --only= requires a scenario name\n";
                    m_arg_error = true;
                } else {
                    m_requested.push_back(name);
                }
            } else if (a == "--list-scenarios") {
                m_list_only = true;
            } else {
                // Not "unknown flags are ignored". An ignored argument means
                // the process ran a different scope than the caller asked for
                // and said nothing about it.
                std::cerr << "[selector] unknown argument: " << a << "\n"
                          << "[selector] accepted: --only=<scenario> (repeatable), "
                             "--list-scenarios\n";
                m_arg_error = true;
            }
        }
    }

    // Registers `name` as a scenario this binary knows about, and reports
    // whether it should run now. Registration happens even when the answer is
    // false -- that is what makes an unknown --only name detectable at all.
    bool ShouldRun(const std::string& name)
    {
        m_known.push_back(name);
        if (m_arg_error) return false;
        if (m_list_only) return false;
        if (m_requested.empty()) { ++m_ran; return true; }
        for (const auto& r : m_requested) {
            if (r == name) { ++m_ran; return true; }
        }
        return false;
    }

    int Finish()
    {
        if (m_list_only) {
            std::cout << "scenarios in this binary:\n";
            for (const auto& k : m_known) std::cout << "  " << k << "\n";
            return 0;
        }
        if (m_arg_error) return 2;

        int rc = 0;
        for (const auto& r : m_requested) {
            bool found = false;
            for (const auto& k : m_known) {
                if (k == r) { found = true; break; }
            }
            if (!found) {
                std::cerr << "[selector] no such scenario: " << r << "\n";
                rc = 2;
            }
        }
        if (rc != 0) {
            std::cerr << "[selector] scenarios in this binary:\n";
            for (const auto& k : m_known) std::cerr << "  " << k << "\n";
            return rc;
        }
        // There was a second backstop here -- `if (m_ran == 0) return 2;` --
        // and mutation testing removed it without a single self-test arm
        // noticing. It could not fire: ShouldRun registers a name and returns
        // true in the same call, so a name that is both requested and
        // registered has necessarily run, and m_ran == 0 therefore implies an
        // unrequested-name error the loop above has already returned on. It was
        // a guard that read as defence-in-depth and was in fact unreachable
        // code on the path that decides which tests run.
        //
        // The implication it rested on is now asserted directly, in the
        // self-test: any argument set that returns 0 here must have run at
        // least one scenario. A refactor that breaks the implication (filtering
        // by tag, say, or registering names without running them) fails there
        // rather than silently passing here.
        if (!m_requested.empty()) {
            std::cout << "[selector] ran " << m_ran << " of " << m_known.size()
                      << " scenarios (PARTIAL -- the rest were not executed)\n";
        }
        return 0;
    }

private:
    std::vector<std::string> m_requested;
    std::vector<std::string> m_known;
    bool m_list_only = false;
    bool m_arg_error = false;
    int m_ran = 0;
};

} // namespace test_only

#endif // DILITHION_TEST_ONLY_SELECTOR_H
