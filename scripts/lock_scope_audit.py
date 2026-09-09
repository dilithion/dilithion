import io,re,sys

CHAINSTATE = re.compile(r'g_chainstate\.(GetTip|GetBlockIndex|GetHeight|GetBlocksAtHeight|GetBlockHeightByHash|GetChainTips)\s*\(')
LOCK       = re.compile(r'\b(?:std::)?(?:lock_guard|unique_lock)\s*<[^>]*>\s+(\w+)\s*\(\s*([A-Za-z_][A-Za-z0-9_:.>-]*)\s*\)')
UNLOCK     = re.compile(r'\b(\w+)\s*\.unlock\s*\(\s*\)')
FUNC       = re.compile(r'^[A-Za-z_][A-Za-z0-9_:<>,&*\s]*::(\w+)\s*\(')

def scan(path):
    src = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
    depth = 0
    # stack of (depth_at_open, varname, mutexname, released_bool_holder)
    held = []
    func = '?'
    findings = []
    for i, raw in enumerate(src, 1):
        line = re.sub(r'//.*$', '', raw)
        m = FUNC.match(raw)
        if m and depth == 0:
            func = m.group(1)
        # drop locks whose scope has closed
        opens  = line.count('{')
        closes = line.count('}')
        lk = LOCK.search(line)
        if lk:
            held.append({'d': depth, 'var': lk.group(1), 'mx': lk.group(2), 'rel': False})
        ul = UNLOCK.search(line)
        if ul:
            for h in held:
                if h['var'] == ul.group(1):
                    h['rel'] = True
        cm = CHAINSTATE.search(line)
        if cm:
            live = [h for h in held if not h['rel'] and 'cs_main' not in h['mx']]
            if live:
                findings.append((i, func, cm.group(1), [h['mx'] for h in live]))
        depth += opens - closes
        held = [h for h in held if h['d'] <= depth]
    return findings

for path in sys.argv[1:]:
    f = scan(path)
    if not f:
        print(f"CLEAN  {path}")
        continue
    print(f"\n*** {path}: {len(f)} chainstate call(s) inside a PRIVATE-mutex scope")
    for ln, fn, call, mxs in f:
        print(f"   :{ln:<5} {fn:<28} g_chainstate.{call}()   holding: {','.join(sorted(set(mxs)))}")
