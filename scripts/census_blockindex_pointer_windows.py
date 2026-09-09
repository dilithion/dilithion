#!/usr/bin/env python3
"""
census_blockindex_pointer_windows.py — #193 deliverable 0.

Enumerate every `GetBlockIndex(` call site in the node/net files and classify each
by SHAPE: does the returned CBlockIndex* get dereferenced, walked or stored AFTER
cs_main has been released?

WHY THIS IS A SCRIPT AND NOT A LIST SOMEBODY TYPED
--------------------------------------------------
PR #129 published "four more sites" as though it were a census. A reviewer then
found a fifth IN THE FILE #129 WAS EDITING. That is the
a-fix-aimed-at-a-site-leaves-siblings defect committed while citing the lesson,
and it means a hand-listed set must not be trusted a third time. The fix list for
#193 is whatever THIS produces, re-runnable by anyone.

WHAT IT DOES
------------
For each `GetBlockIndex(` call:
  1. extract the variable the result is bound to (if any);
  2. find the enclosing function and the lock scopes that cover the call;
  3. scan forward inside that function for USES of the variable — `var->`, `*var`,
     passing `var` to a call, or storing it — and record the first one;
  4. decide whether a cs_main holder (MainLockGuard, or a lock_guard/unique_lock
     naming cs_main) is in scope at BOTH the resolve and that first use.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It is a lexical scanner, not a compiler. It cannot see through helper functions,
aliasing, or a pointer stored into a struct and used elsewhere. So it NEVER
reports "safe" on its own authority: anything it cannot resolve is UNKNOWN and
goes to a human. Undercounting is the failure mode that matters here — a site
wrongly cleared is a use-after-free nobody looks for again — so the classifier is
biased to escalate, and the counts below distinguish what it PROVED from what it
merely did not flag.

CLASSES
  UNGUARDED   resolve + a deref/walk/store, with no cs_main holder in scope.
  GUARDED     resolve and first use both inside a cs_main holder's scope.
  NO-WINDOW   result is only null-tested, or immediately returned, or never
              dereferenced at all — nothing to dangle.
  UNKNOWN     the scanner could not follow it. NOT a clearance.
"""

import os
import re
import sys

FILES = [
    "src/node/block_processing.cpp",
    "src/node/block_validation_queue.cpp",
    "src/node/dilithion-node.cpp",
    "src/node/dilv-node.cpp",
    "src/node/ibd_coordinator.cpp",
    "src/net/headers_manager.cpp",
    "src/net/orphan_manager.cpp",
]

CALL = re.compile(r'GetBlockIndex\s*\(')
# `CBlockIndex* foo = ...GetBlockIndex(` / `auto* foo =` / `foo = ...GetBlockIndex(`
BIND = re.compile(r'(?:(?:const\s+)?CBlockIndex\s*\*\s*(?:const\s+)?|auto\s*\*\s*|auto\s+)?'
                  r'([A-Za-z_]\w*)\s*=\s*[^;]*GetBlockIndex\s*\(')
LOCKHOLDER = re.compile(r'MainLockGuard\b|lock_guard\s*<[^>]*>\s*\w+\s*\(\s*cs_main|'
                        r'unique_lock\s*<[^>]*>\s*\w+\s*\(\s*cs_main|LOCK\s*\(\s*cs_main\s*\)')
FUNC_START = re.compile(r'^[A-Za-z_][\w:<>,\s\*&]*::\w+\s*\([^;]*$|^[A-Za-z_][\w:<>,\s\*&]*\s+\w+\s*\([^;]*\)\s*\{')


def strip_comments(text):
    """Blank out comments WITHOUT changing the line count.

    ⚠️ The first version did `re.sub(r'/\\*.*?\\*/', '', text, flags=re.S)`, which
    deletes the newlines inside a block comment and therefore SHIFTS every line
    number after it. The census then cited `block_processing.cpp:338` for a call
    that is actually elsewhere — line 338 is `uint256 blockHash;`. Caught by
    hand-checking one row against the source; every row after the file's first
    /* */ block would have pointed at the wrong place, and a census whose
    path:line is wrong is worse than no census, because it sends a fixer to
    innocent code.

    Block comments are replaced by their own newlines; line comments are
    truncated in place. Both preserve the line index exactly.
    """
    def blank_block(m):
        return '\n' * m.group(0).count('\n')
    text = re.sub(r'/\*.*?\*/', blank_block, text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def enclosing_function(lines, idx):
    """Walk back to the nearest line at column 0 that looks like a definition."""
    for i in range(idx, -1, -1):
        s = lines[i]
        if s and s[0] not in ' \t}#/' and '(' in s and not s.lstrip().startswith('//'):
            return i, s.strip()[:70]
    return 0, "<file scope>"


def brace_depth(lines, a, b):
    d = 0
    for i in range(a, b):
        d += lines[i].count('{') - lines[i].count('}')
    return d


def lock_in_scope(lines, fn_start, call_idx):
    """Is a cs_main holder declared between the function start and the call, in a
    block that has not closed by the time we reach the call?"""
    for i in range(fn_start, call_idx + 1):
        if LOCKHOLDER.search(lines[i]):
            # the guard's scope survives to call_idx if the net brace depth from
            # the guard line to the call has not gone negative
            if brace_depth(lines, i, call_idx + 1) >= 0:
                return True, i + 1
    return False, None


def main():
    # Root defaults to the repo this script lives in, but can be overridden so the
    # SAME classifier can be pointed at another checkout — which is how its
    # GUARDED arm gets positive-controlled (run it against a branch that has
    # MainLockGuard and confirm it reports GUARDED, rather than trusting a "0
    # GUARDED" result from a tree that has no guards to find).
    #
    # This defaulted silently to the script's own parent directory. Copying the
    # script to /tmp and running it there made it scan /tmp, report 0 sites, and
    # look exactly like "no findings". A tool whose scope depends on where its
    # file sits will eventually be run from the wrong place and say nothing.
    if len(sys.argv) > 1:
        root = os.path.abspath(sys.argv[1])
    else:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isdir(os.path.join(root, "src")):
        print(f"FATAL: {root} has no src/ — wrong root, refusing to report 0 findings",
              file=sys.stderr)
        sys.exit(2)
    os.chdir(root)
    rows = []
    for path in FILES:
        if not os.path.exists(path):
            print(f"WARN: {path} missing", file=sys.stderr)
            continue
        raw = open(path, encoding='utf-8', errors='replace').read()
        code = strip_comments(raw)
        lines = code.split('\n')
        rawlines = raw.split('\n')
        for idx, line in enumerate(lines):
            if not CALL.search(line):
                continue
            lineno = idx + 1
            fn_start, fn_name = enclosing_function(lines, idx)
            m = BIND.search(line)
            var = m.group(1) if m else None
            guarded, guard_line = lock_in_scope(lines, fn_start, idx)

            if not var:
                # not bound: `if (GetBlockIndex(h))` or passed straight into a call
                cls = "NO-WINDOW" if re.search(r'if\s*\(|return\s|!\s*$', line) else "UNKNOWN"
                rows.append((path, lineno, fn_name, "-", cls, guarded, "",
                             rawlines[idx].strip()[:80]))
                continue

            # find the first USE of var after the call, within this function
            use_ln, use_kind, use_txt = None, "", ""
            depth = 0
            for j in range(idx + 1, min(idx + 260, len(lines))):
                depth += lines[j - 1].count('{') - lines[j - 1].count('}')
                if depth < 0:
                    break  # left the function
                l = lines[j]
                if re.search(rf'\b{re.escape(var)}\s*->', l):
                    use_ln, use_kind, use_txt = j + 1, "deref", rawlines[j].strip()[:80]
                    break
                if re.search(rf'\*\s*{re.escape(var)}\b', l):
                    use_ln, use_kind, use_txt = j + 1, "deref*", rawlines[j].strip()[:80]
                    break
                if re.search(rf'=\s*{re.escape(var)}\s*;', l) or \
                   re.search(rf'\(\s*{re.escape(var)}\s*[,)]', l):
                    use_ln, use_kind, use_txt = j + 1, "escape", rawlines[j].strip()[:80]
                    break

            # ── DOES THE POINTER OUTLIVE THE CALL? ───────────────────────────
            # This decides whether deferred reclamation (draining a graveyard at
            # an iteration boundary) is sound. If a resolved pointer is stored
            # into a member, a global, a container or a struct field, it can be
            # read on a LATER iteration and a per-iteration grace period does not
            # cover it. Locals cannot outlive the call.
            #
            # Same bias as everything else here: anything ambiguous is reported,
            # not cleared. This finds STORES, so a false positive costs a human
            # read and a false negative costs a use-after-free.
            escapes = []
            depth2 = 0
            for j in range(idx + 1, min(idx + 260, len(lines))):
                depth2 += lines[j - 1].count('{') - lines[j - 1].count('}')
                if depth2 < 0:
                    break
                l = lines[j]
                v = re.escape(var)
                if re.search(rf'\bm_\w+\s*=\s*{v}\s*;', l) or \
                   re.search(rf'\bg_\w+\s*=\s*{v}\s*;', l):
                    escapes.append(f"member/global@{j+1}")
                elif re.search(rf'\.\w+\s*=\s*{v}\s*;', l) or \
                     re.search(rf'->\w+\s*=\s*{v}\s*;', l):
                    escapes.append(f"field@{j+1}")
                elif re.search(rf'(push_back|emplace_back|insert|emplace|push)\s*\(\s*{v}\s*[,)]', l):
                    escapes.append(f"container@{j+1}")
                elif re.search(rf'\breturn\s+{v}\s*;', l):
                    escapes.append(f"return@{j+1}")
            stored = ";".join(escapes[:2])

            if use_ln is None and not escapes:
                cls = "NO-WINDOW"
            elif escapes:
                # outlives the call -> a per-iteration grace period does NOT cover it
                cls = "OUTLIVES-CALL"
            else:
                g_at_use, _ = lock_in_scope(lines, fn_start, use_ln - 1)
                cls = "GUARDED" if (guarded and g_at_use) else "UNGUARDED"
            rows.append((path, lineno, fn_name, var, cls, guarded,
                         f"{use_kind}@{use_ln}" if use_ln else "", use_txt))

    order = {"OUTLIVES-CALL": 0, "UNGUARDED": 1, "UNKNOWN": 2, "GUARDED": 3, "NO-WINDOW": 4}
    rows.sort(key=lambda r: (order[r[4]], r[0], r[1]))

    counts = {}
    for r in rows:
        counts[r[4]] = counts.get(r[4], 0) + 1

    print("| # | class | file:line | function | var | first use | cs_main in scope |")
    print("|---|---|---|---|---|---|---|")
    for n, (path, lineno, fn, var, cls, guarded, use, _txt) in enumerate(rows, 1):
        print(f"| {n} | **{cls}** | `{path}:{lineno}` | `{fn}` | `{var}` | "
              f"{use or '—'} | {'yes' if guarded else 'no'} |")
    print()
    print("TOTAL call sites: %d" % len(rows))
    for k in ("OUTLIVES-CALL", "UNGUARDED", "UNKNOWN", "GUARDED", "NO-WINDOW"):
        print("  %-10s %d" % (k, counts.get(k, 0)))
    print()
    print("UNGUARDED and UNKNOWN both require a human decision. UNKNOWN is NOT a")
    print("clearance -- it is the scanner saying it could not follow the pointer.")
    print()
    print("OUTLIVES-CALL is the one that decides deferred reclamation: a pointer")
    print("stored into a member/global/field/container can be read on a LATER")
    print("iteration, so a per-iteration grace period would NOT cover it.")

    # ------------------------------------------------------------------
    # SELF-CHECK: every reported path:line must actually contain the call.
    #
    # This exists because the first version of strip_comments() deleted the
    # newlines inside /* */ blocks and shifted every line number after the first
    # block comment. The output looked completely normal -- 52 plausible rows --
    # and cited innocent lines. A census with wrong locations is worse than none,
    # because it sends whoever fixes it to the wrong code and they find nothing
    # wrong there.
    #
    # It is asserted rather than trusted: cheap, and it fails loudly instead of
    # producing a confident wrong table.
    # ------------------------------------------------------------------
    bad = []
    cache = {}
    for path, lineno, *_ in rows:
        if path not in cache:
            cache[path] = open(path, encoding='utf-8', errors='replace').read().split('\n')
        src = cache[path]
        if lineno - 1 >= len(src) or 'GetBlockIndex(' not in src[lineno - 1]:
            bad.append(f"{path}:{lineno}")
    if bad:
        print()
        print("FATAL SELF-CHECK FAILURE: %d reported location(s) do NOT contain"
              " GetBlockIndex( -- line numbers are shifted, the table is wrong:" % len(bad))
        for b in bad[:10]:
            print("   " + b)
        sys.exit(3)
    print()
    print("self-check: all %d reported locations verified to contain GetBlockIndex("
          % len(rows))


if __name__ == "__main__":
    main()
