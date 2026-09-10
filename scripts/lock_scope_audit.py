#!/usr/bin/env python3
"""Audit: is a private mutex held across a call into the chainstate?

Every chainstate accessor that takes cs_main is one half of an AB-BA when a
class holds its own mutex across the call (register P2P-17). This finds them.

SCOPE, so it is not over-trusted: this detects a LOCK HELD ACROSS A CALL. It
does NOT detect the released-pointer/lifetime class (P2P-16), where the accessor
is called holding nothing and the returned pointer is dereferenced later.
Verified: run against the pre-P2P-16 head it reports CLEAN for GetLocator.

Review fixes folded (COORD reader on 732eb9e8):
  * `.lock()` now RE-MARKS a released lock as held. The first version only ever
    set released=True on `.unlock()` and never cleared it, so a chainstate call
    placed after a re-take reported CLEAN -- the exact shape of the fix this
    instrument exists to protect. That mutant is now the guard's RED arm.
  * The accessor list is GENERATED from chain.cpp (every CChainState method whose
    body takes cs_main) instead of a hand-written six. Lock-free accessors such
    as GetHeight (an atomic read, BUG #74) are therefore correctly excluded.
"""
import io, re, sys, os

LOCK   = re.compile(r'\b(?:std::)?(?:lock_guard|unique_lock|scoped_lock)\s*<[^>]*>\s+(\w+)\s*\(\s*([A-Za-z_][A-Za-z0-9_:.>-]*)\s*\)')
UNLOCK = re.compile(r'\b(\w+)\s*\.unlock\s*\(\s*\)')
RELOCK = re.compile(r'\b(\w+)\s*\.lock\s*\(\s*\)')
FUNC   = re.compile(r'^[A-Za-z_][A-Za-z0-9_:<>,&*\s]*::(\w+)\s*\(')

# ---------------------------------------------------------------------------
# ALLOWLIST - (file, function, call, mutex) -> exact expected count.
#
# REVIEW FIX (#197 confirming reader): this was a per-FILE allowlist in the shell
# wrapper, so a NEW violation appended to an already-listed file passed silently
# - and the three listed files are the three largest TUs in the tree. "A new site
# fails until someone classifies it" was FALSE exactly where it mattered most.
# It is now a TUPLE with an exact count, so BOTH a different-shaped site AND one
# MORE of an allowed shape fail.
#
# It lives here rather than in the wrapper because an allowlist is DATA, not
# string manipulation - expressing it in shell cost two quoting bugs.
#
# Each entry carries its ARGUMENT, not just its name.
ALLOWED = {
    # P2P-14/15 removed the cs_main -> cs_headers direction (chain.cpp:2637), so
    # only one direction exists and there is no cycle to close.
    ('src/net/headers_manager.cpp', 'OnBlockActivated', 'GetBlockHeightByHash', 'cs_headers'): 1,

    # EVERY other holder of g_pendingMinerWinsMutex is a bare push_back touching
    # no chainstate, so no thread ever waits on cs_main while holding it unless it
    # ALREADY owns cs_main - the only holder that reaches the chainstate is itself
    # inside a block-connect callback, where cs_main is held and recursive. No
    # thread can supply the opposite order.
    ('src/node/dilithion-node.cpp', '?', 'GetTip', 'g_pendingMinerWinsMutex'): 1,
    ('src/node/dilithion-node.cpp', '?', 'GetBlockIndex', 'g_pendingMinerWinsMutex'): 1,
    ('src/node/dilv-node.cpp', '?', 'GetTip', 'g_pendingMinerWinsMutex'): 1,
    ('src/node/dilv-node.cpp', '?', 'GetBlockIndex', 'g_pendingMinerWinsMutex'): 1,
}


def cs_main_accessors(chain_cpp):
    """Every CChainState method whose body acquires cs_main. Generated, not guessed."""
    src = io.open(chain_cpp, encoding='utf-8', errors='replace').read().split('\n')
    names, cur, depth, seen = set(), None, 0, False
    for raw in src:
        line = re.sub(r'//.*$', '', raw)
        m = re.match(r'^[A-Za-z_][\w:<>,&*\s]*\bCChainState::(\w+)\s*\(', raw)
        if m and depth == 0:
            cur, seen = m.group(1), False
        if cur and re.search(r'<std::recursive_mutex>\s+\w+\(cs_main\)', line):
            seen = True
        depth += line.count('{') - line.count('}')
        if cur and depth <= 0 and seen:
            names.add(cur); cur, seen = None, False
    return names

def scan(path, accessors):
    call_re = re.compile(r'g_chainstate\.(' + '|'.join(sorted(accessors)) + r')\s*\(')
    src = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
    depth, held, func, out = 0, [], '?', []
    for i, raw in enumerate(src, 1):
        line = re.sub(r'//.*$', '', raw)
        m = FUNC.match(raw)
        if m and depth == 0:
            func = m.group(1)
        lk = LOCK.search(line)
        if lk:
            held.append({'d': depth, 'var': lk.group(1), 'mx': lk.group(2), 'rel': False})
        for h in held:
            u = UNLOCK.search(line)
            if u and h['var'] == u.group(1):
                h['rel'] = True
            r = RELOCK.search(line)
            if r and h['var'] == r.group(1):
                h['rel'] = False          # <-- the fix: a re-take is held again
        c = call_re.search(line)
        if c:
            live = [h['mx'] for h in held if not h['rel'] and 'cs_main' not in h['mx']]
            if live:
                out.append((i, func, c.group(1), sorted(set(live))))
        depth += line.count('{') - line.count('}')
        held = [h for h in held if h['d'] <= depth]
    return out

def main(argv):
    root = argv[1] if argv[1:] else '.'
    chain = os.path.join(root, 'src', 'consensus', 'chain.cpp')
    if not os.path.isfile(chain):
        print("ERROR: cannot find src/consensus/chain.cpp under " + root); return 2
    acc = cs_main_accessors(chain)
    if not acc:
        print("ERROR: generated an EMPTY cs_main accessor list — refusing to report CLEAN")
        return 2
    print(f"cs_main-taking CChainState accessors generated from chain.cpp: {len(acc)}")

    targets = []
    for dirpath, _dirs, files in os.walk(os.path.join(root, 'src')):
        if os.sep + 'test' in dirpath:
            continue
        for f in files:
            if f.endswith('.cpp') and f != 'chain.cpp':
                targets.append(os.path.join(dirpath, f))

    total, counts = 0, {}
    for t in sorted(targets):
        f = scan(t, acc)
        if f:
            total += len(f)
            rel = os.path.relpath(t, root).replace(os.sep, '/')
            print(f"\n*** {rel}: {len(f)} chainstate call(s) inside a PRIVATE-mutex scope")
            for ln, fn, call, mxs in f:
                print(f"   :{ln:<6} {fn:<30} g_chainstate.{call}()   holding: {','.join(mxs)}")
                for mx in mxs:
                    k = (rel, fn, call, mx)
                    counts[k] = counts.get(k, 0) + 1
    print(f"\nfiles scanned: {len(targets)}   sites found: {total}")

    unclassified, overcount = [], []
    for key, got in counts.items():
        want = ALLOWED.get(key, 0)
        if want == 0:   unclassified.append((key, got))
        elif got > want: overcount.append((key, got, want))

    if unclassified or overcount:
        print('')
        for (f, fn, call, mx), got in unclassified:
            print(f'FAIL: UNCLASSIFIED - {f} :: {fn} holds {mx} across g_chainstate.{call}()  x{got}')
            print( '      One half of an AB-BA with the cs_main -> <private mutex> edge the block')
            print( '      connect/disconnect callbacks create (P2P-17). Fix with unique_lock +')
            print( '      unlock() across the call, as CCoinStatsIndex::WriteBlock, its Init(),')
            print( '      and tx_index.cpp:520 do. If genuinely safe add the TUPLE to ALLOWED')
            print( '      **with the argument**.')
        for (f, fn, call, mx), got, want in overcount:
            print(f'FAIL: {f} has {got} sites of shape ({fn}/{call}/{mx}), expected {want}.')
            print( '      An EXTRA site of an allowed shape is still a new site - classify it.')
        return 1

    print('OK: every site is classified (tuple + exact count)')
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
