#!/usr/bin/env python3
"""Audit: is a private mutex held across a call into the chainstate?

Every chainstate accessor that takes cs_main is one half of an AB-BA when a
class holds its own mutex across the call (register P2P-17). This finds them.

SCOPE, so it is not over-trusted. Three limits, each stated because a reader
would otherwise have to infer them from a green line:

1. This detects a LOCK HELD ACROSS A CALL. It does NOT detect the
   released-pointer/lifetime class (P2P-16), where the accessor is called
   holding nothing and the returned pointer is dereferenced later. Verified: run
   against the pre-P2P-16 head it reports CLEAN for GetLocator.

2. L-4 (#197 reader): an `unlock()` is treated as UNCONDITIONAL. Written as
       if (cond) lk.unlock();
       ... g_chainstate.GetTip() ...
   this auditor believes the mutex is released on every path, so it would report
   CLEAN while the !cond path still holds it. [measured] no such instance exists
   in the tree today - the reader's M9 mutant confirmed the blind spot rather
   than a live defect - but it is a real blind spot, not a theoretical one, and
   it fails in the SILENT direction.

3. Matching is textual. A lock taken inside a helper this file calls, or hidden
   behind a macro, is invisible; and because the receiver is now any identifier,
   a same-named method on an unrelated class can be over-reported. Over-reporting
   is loud and gets classified; under-reporting is what the widening fixed.

4. D-8 (#197 fold read): two more spellings escape SILENTLY, and they are listed
   here rather than left to be rediscovered.
     (a) A lock ACQUIRED by a bare call - `m_mutex.lock();` with no RAII guard -
         is not seen at all. `.lock()` is recognised only as a RE-take on a
         variable this auditor already knows about, so a mutex first acquired
         that way never enters the held set and a chainstate call under it
         reports CLEAN.
         [measured] TWO such sites exist: registration_manager.cpp:498 and :550,
         both `stateMutex_.lock();`. Neither is a live miss - that file makes ZERO
         chainstate accessor calls, so there is nothing for the auditor to have
         missed there. (An earlier version of this note claimed "no instance in
         the tree"; that was wrong, and the grep that produced it also counted
         comments. Corrected by measuring, which is the whole point of the
         paragraph above it.)
     (c) F3 (external panel round 1): an accessor CALL split across lines -
             CBlockIndex* t = g_chainstate
                 .GetTip();
         - is invisible, because matching is per line. Same for the census, so
         the coverage number under-reports by the same amount.
     (d) F3: `auto lk = std::lock_guard(m);` (CTAD via copy-init) is not matched;
         LOCK expects the type to be followed by the VARIABLE name, not by `=`.
         The generator's GUARD pattern has the same single-spelling fragility -
         it recognises `<std::recursive_mutex> name(cs_main)` and nothing else,
         so an accessor that took cs_main by any other spelling would never
         enter the generated list at all.
         [measured] neither (c) nor (d) occurs in production .cpp today.
     (b) A guard whose DECLARATION spans lines -
             std::lock_guard<std::recursive_mutex>
                 lock(cs_main);
         - does not match, because LOCK is applied per line. Same consequence.
         [measured] ZERO instances in production .cpp.
   Both are under-reporting, i.e. the direction that reads as success. They are
   left unhandled deliberately: handling them means either joining lines (which
   would break the per-line reporting this guard's output depends on) or tracking
   bare lock/unlock pairs across scopes, which is the half-a-parser this file has
   twice refused to become. Stated, measured as absent, and revisited if either
   spelling appears - the accessor COUNT printed on every run is the tripwire for
   the tree changing underneath that claim.

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

# M-2 (#197 reader): the first version required explicit template arguments and
# a parenthesised initialiser, so THREE legal spellings walked straight past it -
# CTAD (`std::lock_guard lock(m);`, valid since C++17 and used in this tree),
# brace-init (`std::lock_guard<std::mutex> lock{m};`), and scoped_lock over
# several mutexes (only the first was ever captured). Each one is a lock this
# auditor would not have seen a chainstate call held across.
#   <...>  optional          -> CTAD
#   [({]   either bracket    -> brace-init
#   ([^)}]*) all arguments   -> every mutex in a scoped_lock, split by the caller
LOCK   = re.compile(r'\b(?:std::)?(?:lock_guard|unique_lock|scoped_lock)\s*'
                    r'(?:<[^>]*>)?\s+(\w+)\s*[({]\s*([^)}]*?)\s*[)}]')
UNLOCK = re.compile(r'\b(\w+)\s*\.unlock\s*\(\s*\)')
RELOCK = re.compile(r'\b(\w+)\s*\.lock\s*\(\s*\)')
# M-3 (#197 reader): attribution used to require a `Class::method(` signature, so
# a site inside a FREE function - or inside a lambda within one - was reported as
# function '?', and '?' was then used as an allowlist KEY. That key is
# location-agnostic: it says "one unattributed site of this shape somewhere in
# this file", so removing the classified site and adding a different one
# elsewhere keeps the count at 1 and passes silently.
#
# The four allowlisted node sites are exactly that shape - they sit in a lambda
# passed to RegisterBlockConnectCallback inside main(). Matching plain function
# definitions as well as methods attributes them to `main`, and '?' is now
# REFUSED as an allowlist key (see the check in main()).
FUNC   = re.compile(r'^[A-Za-z_][A-Za-z0-9_:<>,&*\s]*?\b(\w+)\s*\(')

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
    # P2P-14/15 removed the cs_main -> cs_headers direction, so only one
    # direction exists and there is no cycle to close.
    #
    # L-1 (#197 reader): this used to cite "chain.cpp:2637", which is
    # `m_chainTipsCacheDirty = true;` - an unrelated line. The real mechanism is
    # the TipNotifyDrain DECLARATION-ORDER block in CChainState::ActivateBestChain
    # and its twin in DisconnectTip: `drain` is declared BEFORE the lock_guard, so
    # it is destroyed AFTER it and the tip callbacks fire with cs_main already
    # released. Named by SYMBOL, not by line: the reader's own replacement line
    # numbers had already shifted by the time this was folded, because #194
    # merged into the branch in between. That is the whole argument for symbols.
    # `scripts/check-tip-notify-drain.sh` is what actually holds that order.
    ('src/net/headers_manager.cpp', 'OnBlockActivated', 'GetBlockHeightByHash', 'cs_headers'): 1,

    # F9 (external panel round 1), because these four entries' safety argument
    # depends on it: the body also calls tip->GetAncestor(...), and
    # CBlockIndex::GetAncestor takes NO lock - [measured] src/node/block_index.cpp
    # contains no cs_main acquisition at all, only a comment mentioning it; the
    # function is a plain pprev walk. So it adds no edge of its own and needs no
    # entry here. What makes THESE two safe is stated at the definition of
    # SettlePendingMinerWinsOnConnect: its only caller is a block-connect
    # callback, which already holds cs_main (recursive), so no thread can supply
    # the opposite order.
    #
    # D-1 (external review of #197): keying on 'main' was only PARTLY the fix.
    # main() in the node files runs from its opening line to end of file, so every
    # lambda inside it shares the key - and a NEW chainstate call under this mutex
    # in a DIFFERENT lambda would inherit this classification and pass silently.
    # The four callback bodies are hoisted to named statics
    # (SettlePendingMinerWinsOnConnect) so each entry names one specific body.
    #
    # M-3: these were keyed on '?' - the attribution placeholder - which is
    # location-agnostic: it means "one unattributed site of this shape SOMEWHERE
    # in this file", so deleting the classified site and adding a different one
    # elsewhere kept the count at 1 and passed silently. They sit inside a lambda
    # passed to RegisterBlockConnectCallback within main(); FUNC now names that
    # enclosing function, and '?' is refused as a key outright.
    #
    # EVERY other holder of g_pendingMinerWinsMutex is a bare push_back touching
    # no chainstate, so no thread ever waits on cs_main while holding it unless it
    # ALREADY owns cs_main - the only holder that reaches the chainstate is itself
    # inside a block-connect callback, where cs_main is held and recursive. No
    # thread can supply the opposite order.
    ('src/node/dilithion-node.cpp', 'SettlePendingMinerWinsOnConnect', 'GetTip', 'g_pendingMinerWinsMutex'): 1,
    ('src/node/dilithion-node.cpp', 'SettlePendingMinerWinsOnConnect', 'GetBlockIndex', 'g_pendingMinerWinsMutex'): 1,
    ('src/node/dilv-node.cpp', 'SettlePendingMinerWinsOnConnect', 'GetTip', 'g_pendingMinerWinsMutex'): 1,
    ('src/node/dilv-node.cpp', 'SettlePendingMinerWinsOnConnect', 'GetBlockIndex', 'g_pendingMinerWinsMutex'): 1,
}


# Out-of-line definitions in chain.cpp: `... CChainState::Name(` at column 0.
DEF_CPP = re.compile(r'^[A-Za-z_][\w:<>,&*\s]*\bCChainState::(\w+)\s*\(')
# Inline definitions in chain.h: an INDENTED member signature that OPENS a body
# on the same line. The brace is what separates a definition from a declaration.
DEF_H = re.compile(r'^\s+[A-Za-z_][\w:<>,&*\s]*?\b(\w+)\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{')
GUARD = re.compile(r'<std::recursive_mutex>\s+\w+\(cs_main\)')
NOT_A_METHOD = {'if', 'for', 'while', 'switch', 'catch', 'return', 'else'}


def _scan_cpp(path):
    """Out-of-line CChainState methods in a .cpp whose body acquires cs_main."""
    src = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
    names, cur, depth, seen = set(), None, 0, False
    for raw in src:
        line = re.sub(r'//.*$', '', raw)
        m = DEF_CPP.match(raw)
        if m and depth == 0:
            cur, seen = m.group(1), False
        if cur and GUARD.search(line):
            seen = True
        depth += line.count('{') - line.count('}')
        if cur and depth <= 0 and seen:
            names.add(cur); cur, seen = None, False
    return names


def _scan_header(path):
    """Methods defined INLINE in the class body whose body acquires cs_main.

    These never start at brace-depth 0 - they sit inside `class CChainState {` -
    which is exactly why requiring depth 0 excluded all of them.
    """
    src = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
    names, cur, seen, want = set(), None, False, 0
    depth = 0
    for raw in src:
        line = re.sub(r'//.*$', '', raw)
        if cur is None:
            m = DEF_H.match(raw)
            if m and m.group(1) not in NOT_A_METHOD:
                cur, seen, want = m.group(1), False, depth
        if cur is not None and GUARD.search(line):
            seen = True
        depth += line.count('{') - line.count('}')
        if cur is not None and depth <= want:
            if seen:
                names.add(cur)
            cur, seen = None, False
    return names


def cs_main_accessors(chain_cpp):
    """Every CChainState method whose body acquires cs_main. GENERATED, not guessed.

    L-3 (#197 reader): this read chain.cpp ONLY, so three cs_main takers defined
    INLINE in chain.h were absent from the list, and a call to any of them was
    invisible to the audit - GetBlockIndexSize, InvalidateChainTipsCache and
    HasPendingBlockHashProvider. No caller holds a private mutex across them
    today, so nothing was actually being missed; the list was simply narrower
    than "every accessor that takes cs_main" claimed of it.

    Folded into the GENERATOR rather than hand-listed, deliberately: a
    hand-written list is the drift this function exists to prevent, and it is how
    the original six-entry list went stale in the first place. The accessor COUNT
    is printed on every run, so the list growing or shrinking is visible.
    """
    names = _scan_cpp(chain_cpp)
    chain_h = os.path.splitext(chain_cpp)[0] + '.h'
    if os.path.isfile(chain_h):
        names |= _scan_header(chain_h)
    return names


def _innermost(held, m, at, before):
    """The entries an unlock()/lock() on `m` actually names.

    F11(b): ownership used to be matched on the variable NAME alone, so two
    guards both called `lk` in nested scopes shared one entry and the inner
    unlock released the outer. C++ resolves the identifier to its INNERMOST
    binding, so pick the greatest scope depth among the matching entries and
    move only those (a scoped_lock records one entry per mutex at the same
    depth, and those must still move together).
    """
    if m is None or at is None or not (at < before):
        return []
    same = [h for h in held if h['var'] == m.group(1)]
    if not same:
        return []
    deepest = max(h['d'] for h in same)
    return [h for h in same if h['d'] == deepest]


call_re_global = None   # set by main() once the accessor list exists

def scan(path, accessors):
    # M-1 (#197 reader): this matched ONLY `g_chainstate.`, so every chainstate
    # call made through any other receiver was invisible - and there are many:
    # `m_chainstate->` in rpc/server.cpp and rpc/rest_api.cpp, plus the classes
    # that hold a `CChainState&` member (block_validation_queue,
    # chain_selector_impl, ...). The audit's "every site is classified" line was
    # therefore true only of direct calls on the global.
    #
    # Now ANY receiver counts: `<ident>.` or `<ident>->` followed by one of the
    # generated accessor names. A receiver is REQUIRED (no bare call), which
    # keeps CChainState's own internal calls out - chain.cpp is excluded from the
    # scan anyway - and the receiver is reported so a reader can judge it.
    #
    # This can over-report: another class with a method of the same name, called
    # under a private mutex, will be listed. That is the fail-LOUD direction and
    # the allowlist is the place to classify it. Under-reporting was the bug.
    call_re = re.compile(r'\b(\w+)\s*(?:\.|->)\s*(' + '|'.join(sorted(accessors)) + r')\s*\(')
    src = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
    depth, held, func, out = 0, [], '?', []
    for i, raw in enumerate(src, 1):
        line = re.sub(r'//.*$', '', raw)
        m = FUNC.match(raw)
        if m and depth == 0:
            func = m.group(1)

        # F11(a) (external panel round 2): only the FIRST guard on a line was
        # recorded. `std::lock_guard a(m1); std::lock_guard b(m2);` registered `a`
        # and dropped `b` entirely - so unlocking `a` read as "nothing held" while
        # `b` still owned its mutex, and a chainstate call after that reported
        # CLEAN. Record every declaration on the line.
        for lk in LOCK.finditer(line):
            # group(2) may hold SEVERAL mutexes (std::scoped_lock a(m1, m2)).
            # Record one entry per mutex under the same variable name, so an
            # unlock()/lock() on that variable moves all of them together.
            for mx in [m.strip() for m in lk.group(2).split(',') if m.strip()]:
                held.append({'d': depth, 'var': lk.group(1), 'mx': mx, 'rel': False})
        # F2(a) (external panel round 1, gpt6 HIGH): unlock/relock used to be
        # applied to the WHOLE line before the accessor call was examined, so
        #     g_chainstate.GetTip(); lk.unlock();
        # was read as "released" even though the call happens while the mutex is
        # still held - the exact direction that hides a site. Position within the
        # line decides now: a release only counts if it appears BEFORE the call.
        u = UNLOCK.search(line)
        r = RELOCK.search(line)
        u_at = u.start() if u else None
        r_at = r.start() if r else None

        # F2(c): this used to classify only the FIRST accessor on a line, while
        # the census below counts every one with finditer - so a line with two
        # accessor calls was half-audited and the two numbers disagreed by
        # construction. Every call on the line is classified now.
        for c in call_re.finditer(line):
            c_at = c.start()
            # F11(b): ownership was matched by variable TEXT alone, so two guards
            # both called `lk` in nested scopes were the same entry - the inner
            # unlock() marked the OUTER one released, and a call after the inner
            # scope closed reported CLEAN while the outer mutex was still held.
            # An unlock names the INNERMOST binding of that identifier, so resolve
            # to the deepest matching entry instead of all of them.
            for h in _innermost(held, u, u_at, c_at):
                h['rel'] = True
            for h in _innermost(held, r, r_at, c_at):
                h['rel'] = False          # a re-take before the call is held again
            # F2(b): this exemption was a SUBSTRING test - `'cs_main' not in mx` -
            # so any mutex whose NAME merely contains the text, such as
            # `private_cs_main_mutex`, was silently treated as the global lock and
            # its sites never reported. Match the identifier, optionally qualified
            # (`CChainState::cs_main`), and nothing else.
            live = [h['mx'] for h in held
                    if not h['rel'] and h['mx'].split('::')[-1] != 'cs_main']
            if live:
                out.append((i, func, c.group(2), sorted(set(live)), c.group(1)))

        # Apply the line's release/re-take to the carried state REGARDLESS of
        # position, so a line that only unlocks (no accessor call on it) still
        # updates the held set for the lines that follow. The positional test
        # above governs only whether THIS line's calls see it.
        for h in _innermost(held, u, 0, 1):
            h['rel'] = True
        for h in _innermost(held, r, 0, 1):
            h['rel'] = False

        prev_depth = depth
        depth += line.count('{') - line.count('}')
        # D-3 (external review of #197): `func` was never CLEARED, so anything at
        # namespace scope AFTER a function closed - a lambda initialising a global,
        # say - inherited that function's name. A mis-key is quieter than a refusal:
        # it can match an ALLOWED entry written for a different body. Clear at the
        # CLOSE of the body, not merely at depth 0, because a signature whose brace
        # sits on the next line is still at depth 0 and must keep its name.
        if prev_depth > 0 and depth <= 0:
            func = '?'
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
    print(f"cs_main-taking CChainState accessors generated from chain.cpp + chain.h: {len(acc)}")
    global call_re_global
    call_re_global = re.compile(r'\b(\w+)\s*(?:\.|->)\s*(' + '|'.join(sorted(acc)) + r')\s*\(')

    targets = []
    for dirpath, _dirs, files in os.walk(os.path.join(root, 'src')):
        if os.sep + 'test' in dirpath:
            continue
        for f in files:
            # F8 (external panel round 1): this excluded by BASENAME, so ANY file
            # called chain.cpp anywhere in the tree was skipped - not merely the
            # one whose accessors are being generated. Compare the path.
            if f.endswith('.cpp') and os.path.join(dirpath, f) != chain:
                targets.append(os.path.join(dirpath, f))

    total, counts, unattributed, receivers = 0, {}, [], {}
    for t in sorted(targets):
        f = scan(t, acc)
        if f:
            total += len(f)
            rel = os.path.relpath(t, root).replace(os.sep, '/')
            print(f"\n*** {rel}: {len(f)} chainstate call(s) inside a PRIVATE-mutex scope")
            for ln, fn, call, mxs, recv in f:
                print(f"   :{ln:<6} {fn:<30} {recv}.{call}()   holding: {','.join(mxs)}")
                for mx in mxs:
                    k = (rel, fn, call, mx)
                    counts[k] = counts.get(k, 0) + 1
                    receivers[k] = recv      # D-5: report the ACTUAL receiver
                    if fn == '?':
                        unattributed.append((rel, ln, call, mx))
    print(f"\nfiles scanned: {len(targets)}   sites found: {total}")

    # M-1: state the POPULATION this auditor can see, not only what it flagged.
    # Before the receiver was widened this matched `g_chainstate.` alone, so the
    # "every site is classified" line below was true only of DIRECT calls on the
    # global.
    #
    # ⚠️ THE SNAPSHOT BELOW MOVES WITH main, AND HAS ALREADY BEEN STALE TWICE.
    # It read 86/319 at the L-3 fold, 98/332 after it, and 108/344 after #198
    # merged - each time because the accessor list or the tree grew underneath a
    # number written into a comment. The LIVE figures are printed on every run by
    # the block just below; treat those as authoritative and this as dated
    # context. It is kept only because the RATIO is the point (roughly a third of
    # accessor calls do not go through the global, so a g_chainstate-only matcher
    # was never auditing what its output implied), and that survives the drift.
    #
    # [censused at main 0683b3f2] 108 of 344 accessor calls in production .cpp
    # (31.4%) reach the chainstate through another receiver - 90 via
    # `m_chainstate`, 10 via `cs`, 8
    # via a plain `chainstate`. None of those 98 sits inside a private-mutex
    # scope, so the old verdict was accidentally right while its coverage claim
    # was a quarter short. Printing the split lets the next reader see that
    # difference instead of inferring it.
    by_recv = {}
    for t in sorted(targets):
        for raw in io.open(t, encoding='utf-8', errors='replace').read().split('\n'):
            for mm in call_re_global.finditer(re.sub(r'//.*$', '', raw)):
                by_recv[mm.group(1)] = by_recv.get(mm.group(1), 0) + 1
    tot_calls = sum(by_recv.values())
    direct = by_recv.get('g_chainstate', 0)
    print("accessor CALLS visible to this auditor: %d (%d via g_chainstate, %d via another receiver)"
          % (tot_calls, direct, tot_calls - direct))
    if tot_calls - direct:
        others = ', '.join("%s x%d" % (k, v) for k, v in sorted(by_recv.items()) if k != 'g_chainstate')
        print("  non-global receivers: " + others)
        print("  (a receiver-based match can over-report a same-named method on another class;")
        print("   that is the fail-LOUD direction, and ALLOWED is where such a site gets classified)")

    if unattributed:
        print('')
        for rel, ln, call, mx in unattributed:
            print(f'FAIL: UNATTRIBUTED - {rel}:{ln} holds {mx} across {call}() but this')
            print( '      auditor could not name the enclosing function, so the site cannot be')
            print( '      keyed in ALLOWED except by a wildcard - and a wildcard key is')
            print( '      location-agnostic: delete the classified site, add a different one')
            print( '      elsewhere in the file, and the count stays 1 and passes silently.')
            print( '      Fix the attribution (FUNC) or restructure the code so it has a name.')
        return 1

    unclassified, overcount = [], []
    for key, got in counts.items():
        want = ALLOWED.get(key, 0)
        if want == 0:     unclassified.append((key, got))
        elif got != want: overcount.append((key, got, want))

    # D-2 (#197 fold read), and the first fix for it was COSMETIC. Changing the
    # comparison from `got > want` to `got != want` is not enough on its own,
    # because this loop iterates over the sites that were FOUND - a classified
    # site that DISAPPEARS is simply absent from `counts`, so `got` is never 0 and
    # nothing is compared. Measured: deleting a classified call still exited 0.
    #
    # An allowlist entry is a claim that a site EXISTS and is safe for a stated
    # reason. When the site goes away the claim is stale, and a stale entry is how
    # an allowlist silently starts authorising something else later. So walk the
    # ALLOWED side too and fail on any entry with no matching site.
    #
    # F1 (external panel round 1, gpt6 BLOCKER — and it was a real one): the first
    # version of this walk demanded EVERY allowlist entry have a site under the
    # scanned root, unconditionally. That is true of the repository and false of
    # any other tree, so it broke the auditor's own fixtures: they build a
    # throwaway src/consensus + src/probe, none of the five production files
    # exist there, and all five entries reported "expected 1, found 0" — turning
    # four NEGATIVE controls red and the self-test's exit into 1.
    #
    # The refinement is NOT a fixture-sniff and NOT a flag (either would be a
    # hole the wrapper could inherit). It is a statement of what the check can
    # actually know: an allowlist entry names a FILE, and an entry whose file is
    # not present in the tree being scanned says nothing about that tree. Where
    # the file IS present — which is every entry in the repository — the rule
    # keeps its full force, so D-2 stays load-bearing exactly where it matters.
    for key, want in ALLOWED.items():
        if want <= 0 or key in counts:
            continue
        entry_file = os.path.join(root, key[0].replace('/', os.sep))
        if not os.path.isfile(entry_file):
            continue        # not this tree's file; unknowable, not a violation
        overcount.append((key, 0, want))

    if unclassified or overcount:
        print('')
        for (f, fn, call, mx), got in unclassified:
            recv = receivers.get((f, fn, call, mx), '<receiver>')
            print(f'FAIL: UNCLASSIFIED - {f} :: {fn} holds {mx} across {recv}.{call}()  x{got}')
            print( '      One half of an AB-BA with the cs_main -> <private mutex> edge the block')
            print( '      connect/disconnect callbacks create (P2P-17). Fix with unique_lock +')
            print( '      unlock() across the call, as CCoinStatsIndex::WriteBlock, its Init(),')
            print( '      and tx_index.cpp:520 do. If genuinely safe add the TUPLE to ALLOWED')
            print( '      **with the argument**.')
        for (f, fn, call, mx), got, want in overcount:
            print(f'FAIL: {f} has {got} sites of shape ({fn}/{call}/{mx}), expected {want}.')
            if got > want:
                print( '      An EXTRA site of an allowed shape is still a new site - classify it.')
            else:
                print( '      FEWER sites than the allowlist claims. An ALLOWED entry asserts a site')
                print( '      EXISTS and is safe for a stated reason; with the site gone the entry is')
                print( '      stale, and a stale entry is how an allowlist quietly starts authorising')
                print( '      a DIFFERENT site later. Delete the entry in the same change that')
                print( '      removed the call.')
        return 1

    print('OK: every site is classified (tuple + exact count)')
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
