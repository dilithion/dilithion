// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Self-test for test_only_selector.h.
//
// WHY IT IS A SEPARATE BINARY. The selector is about to decide WHICH TEST CASES
// RUN across 24 hand-written suites. A defect in it does not produce a red
// suite -- it produces a green one that covered less than the roster says. That
// is the same shape as the stale-binary defect the roster staleness guard
// exists for, and it is exactly the class that cannot be caught by the suites
// it governs, because they are the thing being silenced.
//
// The load-bearing arms are the ones where a WRONG selector still exits 0:
//   * an unknown --only name running nothing and exiting 0,
//   * a valid --only name matching nothing after a refactor renames a scenario,
//   * an unrecognised argument being ignored.
// Each of those turns a gate into a decoration without changing its colour.
//
// This binary is self-contained: it includes only the header under test, so it
// builds and runs without the node objects.

#include <test/test_only_selector.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

void chk(const std::string& what, bool ok)
{
    if (ok) { std::cout << "   PASS  " << what << "\n"; ++g_pass; }
    else    { std::cout << "   FAIL  " << what << "\n"; ++g_fail; }
}

// Drive the selector exactly as a main() would, and report which scenarios ran
// plus the exit code it would have returned.
struct Outcome {
    std::vector<std::string> ran;
    int rc = -1;
};

Outcome Drive(const std::vector<std::string>& args,
              const std::vector<std::string>& scenarios)
{
    std::vector<char*> argv;
    std::string prog = "selftest";
    argv.push_back(&prog[0]);
    std::vector<std::string> owned(args);
    for (auto& a : owned) argv.push_back(&a[0]);

    test_only::Selector sel(static_cast<int>(argv.size()), argv.data());
    Outcome o;
    for (const auto& s : scenarios) {
        if (sel.ShouldRun(s)) o.ran.push_back(s);
    }
    o.rc = sel.Finish();
    return o;
}

const std::vector<std::string> kScenarios = {"alpha", "beta", "gamma"};

bool RanExactly(const Outcome& o, const std::vector<std::string>& want)
{
    return o.ran == want;
}

} // namespace

int main()
{
    std::cout << "== no --only: every scenario runs (adoption must be a no-op) ==\n";
    {
        Outcome o = Drive({}, kScenarios);
        chk("all three scenarios run", RanExactly(o, kScenarios));
        chk("exit 0", o.rc == 0);
    }

    std::cout << "\n== --only selects, and does not reorder ==\n";
    {
        Outcome o = Drive({"--only=gamma", "--only=alpha"}, kScenarios);
        // Requested gamma-then-alpha; SOURCE order is alpha-then-gamma. A
        // selector that honoured the argument order would silently change
        // execution order, and these suites share global state -- ordering is
        // not cosmetic here.
        chk("only the selected scenarios run", o.ran.size() == 2);
        chk("they run in SOURCE order, not argument order",
            RanExactly(o, {"alpha", "gamma"}));
        chk("exit 0", o.rc == 0);
    }

    std::cout << "\n== an UNKNOWN --only name is a hard error ==\n";
    {
        // The defect this prevents: a typo, or a scenario renamed by a
        // refactor, silently runs NOTHING and exits 0. The roster would show a
        // green partial row covering zero cases.
        Outcome o = Drive({"--only=delta"}, kScenarios);
        chk("nothing ran", o.ran.empty());
        chk("exit is NON-ZERO (a typo must not pass as green)", o.rc != 0);
    }
    {
        // A valid name beside an invalid one must still fail. Otherwise a
        // rename inside a multi-name selection degrades coverage silently.
        Outcome o = Drive({"--only=alpha", "--only=delta"}, kScenarios);
        chk("one good name does not rescue one bad name", o.rc != 0);
    }

    std::cout << "\n== an unrecognised ARGUMENT is a hard error ==\n";
    {
        Outcome o = Drive({"--onlyy=alpha"}, kScenarios);
        chk("nothing ran", o.ran.empty());
        chk("exit is NON-ZERO", o.rc != 0);
    }
    {
        Outcome o = Drive({"--only="}, kScenarios);
        chk("--only= with an empty name is an error", o.rc != 0);
    }

    std::cout << "\n== --list-scenarios enumerates and runs nothing ==\n";
    {
        Outcome o = Drive({"--list-scenarios"}, kScenarios);
        chk("no scenario ran", o.ran.empty());
        chk("exit 0 (it is a query, not a failure)", o.rc == 0);
    }

    std::cout << "\n== PROPERTY: rc == 0 implies at least one scenario ran ==\n";
    {
        // This replaces a `if (m_ran == 0) return 2;` backstop that mutation
        // testing proved unreachable -- deleting it changed nothing, because
        // ShouldRun registers and runs in the same call, so any requested name
        // that is known has necessarily run. Rather than ship an unfirable
        // guard, the IMPLICATION it rested on is asserted here over every
        // argument shape, including the empty selection. A refactor that
        // separates registration from execution breaks this arm immediately.
        const std::vector<std::vector<std::string>> arg_sets = {
            {},
            {"--only=alpha"},
            {"--only=alpha", "--only=beta"},
            {"--only=gamma"},
            {"--only=alpha", "--only=alpha"},   // duplicate request
        };
        bool held = true;
        for (const auto& a : arg_sets) {
            Outcome o = Drive(a, kScenarios);
            if (o.rc == 0 && o.ran.empty()) held = false;
        }
        chk("no argument set returns 0 having run nothing", held);

        // And with nothing registered at all, any selection must fail.
        Outcome empty = Drive({"--only=alpha"}, {});
        chk("empty scenario list plus a selection is non-zero", empty.rc != 0);
    }

    std::cout << "\n   ===== test_only_selector: " << g_pass << " passed, "
              << g_fail << " failed =====\n";
    return g_fail == 0 ? 0 : 1;
}
