#!/usr/bin/env python3
"""chain_concentration.py — reusable TRUE-OPERATOR concentration analysis for DIL / DilV.

WHY THIS EXISTS
    `gettopholders` counts ADDRESSES, and miners mint a fresh address per coin
    (rotation), so address-level reads understate concentration AND inflate the
    apparent holder count. This tool clusters addresses into real operators so
    "how concentrated is the chain / how many real participants" can be answered
    honestly and RE-RUN at any time.

CLUSTERING (union-find), in increasing aggressiveness:
    (1) shared-input heuristic   — all input addresses co-spent in one tx are the
                                   same owner. The SAFE backbone (no false merges
                                   barring a custodial co-spend, which the hub
                                   guard below catches).
    (2) MIK -> payout-address    — a mining identity's payout addresses are one
                                   operator.
    (3) consolidation out-links  — a single-output (non-OP_RETURN) tx is a sweep /
                                   self-send, so its output belongs to the input
                                   owner. This is the "linked wallets between
                                   transactions" merge. APPLIED ONLY when the
                                   output is NOT a hub.

HUB GUARD (the make-or-break correctness control)
    Bridge / dev-fund / dev-reward / exchange addresses are touched by MANY
    distinct operators. Merging through them collapses everyone into one false
    mega-entity. Hubs are TERMINALS: never unioned into an operator cluster.
    Hubs come from (a) a seed list (defaults below + --hubs file) and (b) AUTO
    detection: any address receiving from more than --hub-indegree distinct
    pre-clusters is flagged a hub and excluded, then clustering is re-run. This
    catches unknown exchanges without a hand-maintained list.

CACHING
    Pass 1 (the slow verbosity=2 chain scan) is cached to <chain>_concentration
    _cache.json. Clustering + reporting run from the cache instantly, so you can
    re-cluster with different hub lists / thresholds without re-scanning. --rescan
    forces a fresh pull.

USAGE (run ON a seed node against localhost RPC — 60k+ getblock calls; do NOT run
       over the network):
    python3 chain_concentration.py --chain dil  --rpc-port 8332
    python3 chain_concentration.py --chain dilv --rpc-port 9332 --rescan
    python3 chain_concentration.py --chain dil  --hubs extra_hubs.txt --hub-indegree 40

Reuses RPC / UnionFind / ChainScanner from chain_forensics.py (same dir).
Read-only: only getblockchaininfo / getblockhash / getblock / gettopholders.

LIMITATIONS (read before trusting a number):
  - total_miks UNDERCOUNTS. The scanner records ONE mik per payout address, but an
    operator can point many MIKs at one address (e.g. lzmz: 14 MIKs -> 1 address counts
    as 1). The true-operator clustering + concentration are UNAFFECTED (they are
    tx-graph-driven, not mik-driven); only the reported mik tally is low. Proper fix =
    capture a set of miks per address in chain_forensics.ChainScanner (needs a re-scan).
  - holdings %s are over the gettopholders top-N CAPTURED balance = an UPPER bound on
    true supply share, not a share of total supply.
  - operator merging is ON-CHAIN-EVIDENCE-based (shared-input + single-output
    consolidation + MIK->payout). An operator that never co-spends or consolidates its
    distinct address-clusters stays split (a floor on concentration, not a ceiling).
  - auto-hub excludes NON-mining high-indegree addresses; a mining address is never a
    hub (a large self-consolidating operator must not be mistaken for an exchange).
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict

# Reuse the proven building blocks (same directory).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain_forensics import RPC, UnionFind, ChainScanner, log  # noqa: E402


# ── Known hub addresses (seed list; extend via --hubs <file>, one address/line) ──
# Coinbase tax destinations (every mainnet miner pays into these — params.h):
DEV_FUND_ADDR   = "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq"
DEV_REWARD_ADDR = "DRne9ygVbQJFKma1pyEMPpyRbjmVKNcbWe"
# Bridge custody / deposit addresses (from prior forensics — verify before trusting):
BRIDGE_ADDRS = [
    "DESyLBcZYDU1jrE2o1GuQkdiuiwk2An6Sn",   # old DilV bridge
    "DTHGN3XiZ9LRxHVPUWMumX8B9q6B4BuPdp",   # current DilV bridge
]
DEFAULT_HUBS = set([DEV_FUND_ADDR, DEV_REWARD_ADDR] + BRIDGE_ADDRS)

# Prior-baseline entity figures for trend reporting.
BASELINES = {
    "dil":  {"date": "2026-03-28", "operators": 237, "top10_blocks": 31.8, "nakamoto": 28},
    "dilv": {"date": "2026-03-28", "operators": 174, "top10_blocks": 38.3, "nakamoto": 15},
}


def scan_to_cache(rpc, cache_path, max_height=None):
    """Pass 1: full verbosity=2 scan -> cache the raw graph + per-address metadata.

    Reuses ChainScanner._process_block per block; --max-height caps the scan
    (for smoke-tests and height-bounded snapshots, e.g. the migration height).
    """
    scanner = ChainScanner(rpc)
    scanner.height, scanner.chain = rpc.get_height()
    if max_height:
        scanner.height = min(scanner.height, max_height)
    log(f"Chain {scanner.chain}: scanning {scanner.height} blocks (verbosity=2)...")
    t0 = time.time()
    for h in range(1, scanner.height + 1):
        if h % 1000 == 0:
            log(f"  ...block {h}/{scanner.height} ({time.time() - t0:.0f}s)")
        try:
            bhash = rpc.get_block_hash(h)
            block = rpc.get_block(bhash, verbosity=2)
            scanner._process_block(block, h)
        except Exception as e:
            log(f"  ERROR at block {h}: {e}")
    log(f"Scan took {time.time() - t0:.0f}s; {len(scanner.addr_info)} addresses, "
        f"{len(scanner.tx_graph)} non-coinbase txs")
    # Persist only what clustering/reporting needs (NOT the giant txid_index).
    cache = {
        "chain": scanner.chain,
        "height": scanner.height,
        "addr_info": {a: {"mined_blocks": i["mined_blocks"],
                          "mined_value": i["mined_value"],
                          "mik": i["mik"]}
                      for a, i in scanner.addr_info.items()},
        "tx_graph": scanner.tx_graph,   # [{inputs:[addr], outputs:[{address,value,is_op_return}]}]
    }
    with open(cache_path, "w") as f:
        json.dump(cache, f)
    log(f"Cached scan -> {cache_path}")
    return cache


def cluster(cache, hubs, hub_indegree):
    """Pass 2 (fast, re-runnable): build operator clusters from the cached graph.

    Two clustering rounds: round 1 with the seed hub list, then auto-detect
    high-indegree hubs and re-cluster so unknown exchanges/bridges don't
    over-merge.
    """
    tx_graph = cache["tx_graph"]
    addr_info = cache["addr_info"]

    def build(hub_set):
        uf = UnionFind()
        # (1) shared-input + (3) single-output consolidation
        for tx in tx_graph:
            ins = [a for a in tx["inputs"] if a and a not in hub_set]
            for i in range(1, len(ins)):
                uf.union(ins[0], ins[i])
            outs = [o for o in tx["outputs"]
                    if o["address"] and not o["is_op_return"]]
            # single spendable output => sweep/self-send => output belongs to input owner
            if len(outs) == 1 and ins:
                o = outs[0]["address"]
                if o not in hub_set:
                    uf.union(ins[0], o)
        # (2) MIK -> payout addresses
        mik_addrs = defaultdict(list)
        for a, info in addr_info.items():
            if info["mik"] and a not in hub_set:
                mik_addrs[info["mik"]].append(a)
        for addrs in mik_addrs.values():
            for i in range(1, len(addrs)):
                uf.union(addrs[0], addrs[i])
        return uf

    uf = build(hubs)

    # AUTO-HUB: a NON-MINING address receiving from > hub_indegree distinct owner-
    # clusters is a hub (exchange / service). A MINING address is by definition a
    # participant, not a hub — a large operator that self-consolidates from many of
    # its own rotation addresses would otherwise be falsely flagged and excluded,
    # dropping a real top operator (and its MIKs) from the count. So mined addresses
    # are never auto-hubs; indegree is over post-first-cluster roots (own rotation
    # addresses already merged count as one source).
    indeg = defaultdict(set)
    for tx in tx_graph:
        src_roots = {uf.find(a) for a in tx["inputs"] if a and a not in hubs}
        for o in tx["outputs"]:
            a = o["address"]
            if a and not o["is_op_return"] and a not in hubs:
                indeg[a] |= src_roots
    auto = {a for a, roots in indeg.items()
            if len(roots) > hub_indegree
            and addr_info.get(a, {}).get("mined_blocks", 0) == 0}
    if auto:
        log(f"AUTO-HUB: flagged {len(auto)} high-indegree addresses (> {hub_indegree} "
            f"distinct sources); re-clustering. Examples: {sorted(auto)[:5]}")
        hubs = set(hubs) | auto
        uf = build(hubs)

    return uf, hubs


def report(cache, uf, hubs, top_holders, chain):
    addr_info = cache["addr_info"]
    H = cache["height"]

    # mining blocks per operator (cluster root)
    op_blocks = defaultdict(int)
    op_addrs = defaultdict(set)
    op_miks = defaultdict(set)
    for a, info in addr_info.items():
        if a in hubs:
            continue
        root = uf.find(a) if a in uf.parent else a
        op_blocks[root] += info["mined_blocks"]
        op_addrs[root].add(a)
        if info["mik"]:
            op_miks[root].add(info["mik"])

    miners = {r: b for r, b in op_blocks.items() if b > 0}
    total_blk = sum(miners.values())
    ranked = sorted(miners.items(), key=lambda x: -x[1])

    def cum(n):
        return sum(b for _, b in ranked[:n]) / total_blk * 100 if total_blk else 0
    shares = [b / total_blk for _, b in ranked] if total_blk else []
    hhi = sum(s * s for s in shares)
    c = 0
    nak = 0
    for s in shares:
        c += s
        nak += 1
        if c > 0.5:
            break
    total_miks = sum(len(op_miks[r]) for r in miners)
    total_addr = sum(len(op_addrs[r]) for r in miners)

    out = {
        "chain": chain, "height": H,
        "true_operators": len(miners),
        "total_miks": total_miks, "total_mining_addresses": total_addr,
        "address_inflation_x": round(total_addr / len(miners), 1) if miners else 0,
        "sustained_operators_100blk": sum(1 for _, b in ranked if b >= 100),
        "mining": {"hhi": round(hhi, 4), "nakamoto": nak,
                   "top1": round(cum(1), 2), "top5": round(cum(5), 1),
                   "top10": round(cum(10), 1), "top20": round(cum(20), 1),
                   "top50": round(cum(50), 1)},
        "hubs_excluded": sorted(hubs),
    }

    # holdings per operator (join gettopholders to clusters)
    if top_holders:
        bal = defaultdict(float)
        for h in top_holders:
            a, b = h["address"], float(h["balance"])
            if a in hubs:
                continue
            root = uf.find(a) if a in uf.parent else a
            bal[root] += b
        bvals = sorted(bal.values(), reverse=True)
        tot = sum(bvals)
        if tot:
            hc = 0
            hnak = 0
            for v in bvals:
                hc += v
                hnak += 1
                if hc > tot * 0.5:
                    break
            out["holdings"] = {
                "captured_entities": len(bvals),
                "note": "% of captured top-N balance (UPPER bound on supply share)",
                "top1": round(bvals[0] / tot * 100, 2),
                "top10": round(sum(bvals[:10]) / tot * 100, 1),
                "nakamoto": hnak,
            }

    base = BASELINES.get(chain)
    if base:
        out["baseline_trend"] = {
            "since": base["date"],
            "operators": f'{base["operators"]} -> {len(miners)}',
            "top10_blocks": f'{base["top10_blocks"]}% -> {round(cum(10), 1)}%',
            "nakamoto": f'{base["nakamoto"]} -> {nak}',
        }
    return out


def main():
    ap = argparse.ArgumentParser(description="True-operator concentration analysis (DIL/DilV).")
    ap.add_argument("--chain", required=True, choices=["dil", "dilv"])
    ap.add_argument("--rpc-host", default="127.0.0.1")
    ap.add_argument("--rpc-port", type=int)
    ap.add_argument("--rpc-user", default="rpc")
    ap.add_argument("--rpc-pass", default="rpc")
    ap.add_argument("--rescan", action="store_true", help="Force a fresh chain scan.")
    ap.add_argument("--max-height", type=int, help="Cap the scan at this height (smoke-test / bounded snapshot).")
    ap.add_argument("--hubs", help="File of extra hub addresses (one per line).")
    ap.add_argument("--hub-indegree", type=int, default=40,
                    help="Auto-flag an address as a hub if it receives from > N distinct clusters.")
    ap.add_argument("--out", help="Write JSON report to this path.")
    args = ap.parse_args()

    port = args.rpc_port or (8332 if args.chain == "dil" else 9332)
    rpc = RPC(host=args.rpc_host, port=port, user=args.rpc_user, password=args.rpc_pass)

    cache_path = f"{args.chain}_concentration_cache.json"
    if args.rescan or not os.path.exists(cache_path):
        cache = scan_to_cache(rpc, cache_path, max_height=args.max_height)
    else:
        log(f"Loading cached scan {cache_path} (use --rescan to refresh)")
        cache = json.load(open(cache_path))

    hubs = set(DEFAULT_HUBS)
    if args.hubs and os.path.exists(args.hubs):
        for line in open(args.hubs):
            line = line.strip()
            if line and not line.startswith("#"):
                hubs.add(line)

    top_holders = None
    try:
        th = rpc.get_top_holders(500)
        top_holders = th.get("top") if isinstance(th, dict) else th
    except Exception as e:
        log(f"gettopholders unavailable ({e}); skipping holdings view.")

    uf, hubs = cluster(cache, hubs, args.hub_indegree)
    rep = report(cache, uf, hubs, top_holders, args.chain)

    print(json.dumps(rep, indent=2))
    out_path = args.out or f"{args.chain}_concentration_report.json"
    with open(out_path, "w") as f:
        json.dump(rep, f, indent=2)
    log(f"Report -> {out_path}")


if __name__ == "__main__":
    main()
