#!/usr/bin/env python3
"""Fixtures for lock_scope_audit.py - one per RECEIVER form and one per LOCK form.

Why this exists. The auditor's two regexes were each too narrow, and neither
narrowness was visible from its output:

  * M-1 - `call_re` matched only `g_chainstate.`, so a chainstate call through
    any other receiver was invisible. [censused] 98 of 332 accessor calls in
    production .cpp reach the chainstate as `m_chainstate->` (90) or a plain
    `chainstate.` (8). None of them happened to sit under a private mutex, so
    widening the regex changed no verdict - which is exactly why the gap could
    have survived indefinitely. A regex that finds nothing new is
    indistinguishable from a regex that finds nothing, unless something proves
    it CAN find.

  * M-2 - `LOCK` required explicit template arguments and a parenthesised
    initialiser, so CTAD, brace-init and multi-mutex scoped_lock were all
    invisible: a chainstate call held across one of those locks was not seen.

  * M-3 - a site the auditor could not attribute was reported as function '?',
    and '?' was used as an ALLOWLIST KEY. That key is location-agnostic.

Each fixture builds a throwaway tree, runs the real auditor over it, and asserts
what it must and must NOT find. The negative fixtures matter as much: a matcher
that flags everything classifies nothing.
"""
import io, os, subprocess, sys, tempfile, shutil

AUDIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lock_scope_audit.py')

# A minimal chain.cpp the generator can read: two accessors that take cs_main,
# and one that does not (so the generated list is not simply "every method").
CHAIN_CPP = '''
#include <chain.h>
CBlockIndex* CChainState::GetTip() const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    return pindexTip;
}
CBlockIndex* CChainState::GetBlockIndex(const uint256& h) const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    return nullptr;
}
int CChainState::GetHeight() const {
    return m_height.load();
}
'''

def build(tmp, body, name='probe.cpp'):
    os.makedirs(os.path.join(tmp, 'src', 'consensus'), exist_ok=True)
    os.makedirs(os.path.join(tmp, 'src', 'probe'), exist_ok=True)
    io.open(os.path.join(tmp, 'src', 'consensus', 'chain.cpp'), 'w', encoding='utf-8').write(CHAIN_CPP)
    io.open(os.path.join(tmp, 'src', 'probe', name), 'w', encoding='utf-8').write(body)

def run(tmp):
    r = subprocess.run([sys.executable, AUDIT, tmp], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr

FAILURES = []

def case(label, body, must_find, must_not_find=(), expect_rc=None):
    tmp = tempfile.mkdtemp(prefix='lsa_fix_')
    try:
        build(tmp, body)
        rc, out = run(tmp)
        ok = True
        for needle in must_find:
            if needle not in out:
                ok = False
                FAILURES.append('%s: expected to FIND %r' % (label, needle))
        for needle in must_not_find:
            if needle in out:
                ok = False
                FAILURES.append('%s: expected NOT to find %r' % (label, needle))
        if expect_rc is not None and rc != expect_rc:
            ok = False
            FAILURES.append('%s: exit %d, expected %d' % (label, rc, expect_rc))
        print('  %-58s %s' % (label, 'ok' if ok else 'FAIL'))
        if not ok:
            print('    ---- auditor output ----')
            for l in out.strip().split('\n')[:14]:
                print('    ' + l)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

print('RECEIVER FORMS (M-1) - each must be SEEN inside a private-mutex scope:')

case('R1 g_chainstate.  (the only form the old regex matched)', '''
void Probe1() {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['g_chainstate.GetTip()', 'm_privateMutex'], expect_rc=1)

case('R2 m_chainstate->  (90 such calls in production)', '''
void Probe2() {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    CBlockIndex* t = m_chainstate->GetTip();
    (void)t;
}
''', must_find=['m_chainstate.GetTip()', 'm_privateMutex'], expect_rc=1)

case('R3 chainstate.  (a reference parameter or member)', '''
void Probe3(CChainState& chainstate) {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    CBlockIndex* t = chainstate.GetBlockIndex(uint256());
    (void)t;
}
''', must_find=['chainstate.GetBlockIndex()', 'm_privateMutex'], expect_rc=1)

print('LOCK FORMS (M-2) - each must be recognised as a HELD private mutex:')

case('L1 CTAD: std::lock_guard lk(m)  (no template arguments)', '''
void Probe4() {
    std::lock_guard lk(m_privateMutex);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['m_privateMutex'], expect_rc=1)

case('L2 brace-init: std::lock_guard<std::mutex> lk{m}', '''
void Probe5() {
    std::lock_guard<std::mutex> lk{m_privateMutex};
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['m_privateMutex'], expect_rc=1)

case('L3 scoped_lock over TWO mutexes (second was dropped before)', '''
void Probe6() {
    std::scoped_lock lk(m_firstMutex, m_secondMutex);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['m_firstMutex', 'm_secondMutex'], expect_rc=1)


print('GENERATOR SOURCES (L-3) - an inline cs_main taker in chain.h must count:')

CHAIN_H_INLINE = (
    'class CChainState {\n'
    'public:\n'
    '    size_t InlineOnlyAccessor() const {\n'
    '        std::lock_guard<std::recursive_mutex> lock(cs_main);\n'
    '        return mapBlockIndex.size();\n'
    '    }\n'
    '    int NoLockHere() const { return 0; }\n'
    '};\n'
)

PROBE_H = (
    'void ProbeH() {\n'
    '    std::lock_guard<std::mutex> lk(m_privateMutex);\n'
    '    size_t n = g_chainstate.InlineOnlyAccessor();\n'
    '    (void)n;\n'
    '}\n'
)

def header_case():
    # chain.h defines some accessors INLINE, inside the class body. The generator
    # read chain.cpp only, so those never entered the accessor list and any call
    # to them was invisible to the audit. The cause was a depth-0 requirement: an
    # inline method never starts at brace depth 0.
    #
    # The second method (NoLockHere) is the control: a method WITHOUT a cs_main
    # guard must not become an accessor, or the list would be "every method".
    tmp = tempfile.mkdtemp(prefix='lsa_fix_h_')
    try:
        os.makedirs(os.path.join(tmp, 'src', 'consensus'), exist_ok=True)
        os.makedirs(os.path.join(tmp, 'src', 'probe'), exist_ok=True)
        io.open(os.path.join(tmp, 'src', 'consensus', 'chain.cpp'), 'w', encoding='utf-8').write(CHAIN_CPP)
        io.open(os.path.join(tmp, 'src', 'consensus', 'chain.h'), 'w', encoding='utf-8').write(CHAIN_H_INLINE)
        io.open(os.path.join(tmp, 'src', 'probe', 'probe.cpp'), 'w', encoding='utf-8').write(PROBE_H)
        rc, out = run(tmp)
        # F9: NoLockHere is the CONTROL and must be asserted, not merely present -
        # if the generator listed every method rather than every cs_main taker, H1
        # would still pass on the first two conditions alone.
        ok = (('InlineOnlyAccessor' in out) and ('m_privateMutex' in out)
              and ('NoLockHere' not in out) and rc == 1)
        if not ok:
            FAILURES.append('H1: an inline chain.h cs_main taker was not treated as an accessor')
        print('  %-58s %s' % ('H1 inline accessor defined in chain.h is generated', 'ok' if ok else 'FAIL'))
        if not ok:
            for l in out.strip().split('\n')[:12]:
                print('    ' + l)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

header_case()

print('NEGATIVE CONTROLS - a matcher that flags everything classifies nothing:')

case('N1 no lock held at all -> NOT a site', '''
void Probe7() {
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['sites found: 0'], must_not_find=['PRIVATE-mutex scope'], expect_rc=0)

case('N2 only cs_main held -> NOT a site (that is the correct order)', '''
void Probe8() {
    std::lock_guard<std::recursive_mutex> lk(cs_main);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['sites found: 0'], must_not_find=['PRIVATE-mutex scope'], expect_rc=0)

case('N3 released before the call (unlock) -> NOT a site', '''
void Probe9() {
    std::unique_lock<std::mutex> lk(m_privateMutex);
    lk.unlock();
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['sites found: 0'], must_not_find=['PRIVATE-mutex scope'], expect_rc=0)

case('N4 RE-TAKEN after unlock -> IS a site again (the original RED arm)', '''
void Probe10() {
    std::unique_lock<std::mutex> lk(m_privateMutex);
    lk.unlock();
    lk.lock();
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['m_privateMutex'], expect_rc=1)

case('N5 a non-accessor method under a lock -> NOT a site', '''
void Probe11() {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    int h = g_chainstate.GetHeight();
    (void)h;
}
''', must_find=['sites found: 0'], must_not_find=['PRIVATE-mutex scope'], expect_rc=0)


print('SILENT ESCAPES (F2, external panel round 1) - each was invisible, and')
print('each failed in the direction that reads as CLEAN:')

# F2(a) order on one line: the release comes AFTER the call, so the call happens
# while the mutex is still held. Processing the whole line first read it as
# released and dropped the site.
case('F2a unlock AFTER the call on the same line -> still a site', '''
void ProbeF2a() {
    std::unique_lock<std::mutex> lk(m_privateMutex);
    CBlockIndex* t = g_chainstate.GetTip(); lk.unlock();
    (void)t;
}
''', must_find=['m_privateMutex'], expect_rc=1)

# ...and the mirror, so the fix is not just "always report": a release BEFORE
# the call on the same line must still exempt it.
case('F2a unlock BEFORE the call on the same line -> NOT a site', '''
void ProbeF2a2() {
    std::unique_lock<std::mutex> lk(m_privateMutex);
    lk.unlock(); CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['sites found: 0'], must_not_find=['PRIVATE-mutex scope'], expect_rc=0)

# F2(b) the cs_main exemption was a SUBSTRING test, so a private mutex whose
# name merely contains the text was treated as the global lock and never
# reported.
case('F2b a mutex NAMED private_cs_main_mutex is not cs_main', '''
void ProbeF2b() {
    std::lock_guard<std::mutex> lk(private_cs_main_mutex);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['private_cs_main_mutex'], expect_rc=1)

# ...control: the REAL cs_main must still be exempt, or the widening would turn
# every correct call into a finding.
case('F2b the real cs_main is still exempt', '''
void ProbeF2b2() {
    std::lock_guard<std::recursive_mutex> lk(cs_main);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
''', must_find=['sites found: 0'], must_not_find=['PRIVATE-mutex scope'], expect_rc=0)

# F2(c) only the FIRST accessor on a line was classified, while the census
# counted every one with finditer - so a two-call line was half-audited and the
# two numbers disagreed by construction.
case('F2c TWO accessor calls on one line -> both classified', '''
void ProbeF2c() {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    CBlockIndex* a = g_chainstate.GetTip(); CBlockIndex* b = g_chainstate.GetBlockIndex(uint256());
    (void)a; (void)b;
}
''', must_find=['GetTip()', 'GetBlockIndex()'], expect_rc=1)

print('ALLOWLIST WALK, BOTH DIRECTIONS (D-2 / F1) - the check that a classified')
print('site still EXISTS, exercised as a fixture rather than by hand:')

def walk_case(label, allowed, body, expect_rc, needle=None):
    """Run the REAL auditor as a library with a synthetic allowlist.

    Not a flag and not a root-sniff: the self-test imports the module and
    substitutes ALLOWED, so production keeps exactly one allowlist and there is
    nothing a wrapper could inherit to weaken the check.
    """
    import importlib.util
    tmp = tempfile.mkdtemp(prefix='lsa_walk_')
    try:
        build(tmp, body)
        spec = importlib.util.spec_from_file_location('lsa_under_test', AUDIT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.ALLOWED = allowed
        import io as _io, contextlib
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = mod.main(['lock_scope_audit.py', tmp])
        out = buf.getvalue()
        ok = (rc == expect_rc) and (needle is None or needle in out)
        if not ok:
            FAILURES.append('%s: exit %s (expected %s)%s' %
                            (label, rc, expect_rc,
                             '' if needle is None or needle in out else ' / missing %r' % needle))
        print('  %-58s %s' % (label, 'ok' if ok else 'FAIL'))
        if not ok:
            for l in out.strip().split('\n')[:12]:
                print('    ' + l)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

PROBE_SITE = '''
void ProbeW() {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
'''

# W1: the entry MATCHES a real site in this tree -> classified, exit 0.
walk_case('W1 allowlist entry with a matching site -> OK',
          {('src/probe/probe.cpp', 'ProbeW', 'GetTip', 'm_privateMutex'): 1},
          PROBE_SITE, 0)

# W2: the entry's FILE exists but the site does NOT -> the walk must FAIL.
#     This is the D-2 regression encoded: before the ALLOWED-side walk existed,
#     a vanished classified site left counts empty and the run exited 0.
walk_case('W2 entry whose file exists but site is GONE -> FAIL',
          {('src/probe/probe.cpp', 'NoSuchFunction', 'GetTip', 'm_privateMutex'): 1,
           ('src/probe/probe.cpp', 'ProbeW', 'GetTip', 'm_privateMutex'): 1},
          PROBE_SITE, 1, needle='expected 1')

# W3: the entry names a file NOT PRESENT in this tree -> unknowable, not a
#     violation. This is the F1 fix itself: without it the auditor's own
#     fixtures turned four negative controls red.
walk_case('W3 entry for a file absent from this tree -> not a violation',
          {('src/net/headers_manager.cpp', 'OnBlockActivated', 'GetTip', 'cs_headers'): 1,
           ('src/probe/probe.cpp', 'ProbeW', 'GetTip', 'm_privateMutex'): 1},
          PROBE_SITE, 0)

# W4 (D-1 encoded): an allowlist keyed on ONE function does not cover a site in
#     a DIFFERENT function of the same file. Before the callback bodies were
#     hoisted to named statics, every lambda in main() shared one key and a
#     relocated site inherited its classification.
TWO_FUNCS = '''
void ProbeW() {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}

void ProbeOther() {
    std::lock_guard<std::mutex> lk(m_privateMutex);
    CBlockIndex* t = g_chainstate.GetTip();
    (void)t;
}
'''
walk_case('W4 a site in a DIFFERENT function is not covered -> FAIL',
          {('src/probe/probe.cpp', 'ProbeW', 'GetTip', 'm_privateMutex'): 1},
          TWO_FUNCS, 1, needle='UNCLASSIFIED')

print('')
if FAILURES:
    print('FAILURES (%d):' % len(FAILURES))
    for f in FAILURES:
        print('  - ' + f)
    sys.exit(1)
print('OK: every receiver form, every lock form, and every negative control behaves as claimed')
