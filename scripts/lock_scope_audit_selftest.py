#!/usr/bin/env python3
"""Fixtures for lock_scope_audit.py - one per RECEIVER form and one per LOCK form.

Why this exists. The auditor's two regexes were each too narrow, and neither
narrowness was visible from its output:

  * M-1 - `call_re` matched only `g_chainstate.`, so a chainstate call through
    any other receiver was invisible. [censused] 86 of 319 accessor calls in
    production .cpp reach the chainstate as `m_chainstate->` (81) or a plain
    `chainstate.` (5). None of them happened to sit under a private mutex, so
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

case('R2 m_chainstate->  (81 such calls in production)', '''
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
        ok = ('InlineOnlyAccessor' in out) and ('m_privateMutex' in out) and rc == 1
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

print('')
if FAILURES:
    print('FAILURES (%d):' % len(FAILURES))
    for f in FAILURES:
        print('  - ' + f)
    sys.exit(1)
print('OK: every receiver form, every lock form, and every negative control behaves as claimed')
