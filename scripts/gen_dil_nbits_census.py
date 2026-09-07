"""Generate the DIL nBits census header from a raw seed dump. WRITE-GATED.

Why this exists
---------------
The LP-10 red-team found that DIL's nMinimumChainWork was pinned only
literal-against-literal: the KAT compared a constant in chainparams.cpp to the
same constant retyped in the test. That detects an EDIT but cannot detect an
ERROR, and there was no committed artifact behind the number. DilV's constant is
re-derived in-repo by summation (its nBits never retargeted, so the sum is
closed-form); DIL retargets on roughly half its blocks and cannot be re-derived
from a formula, so the per-block data has to be committed.

This script turns a raw `<height> <hash> <nBits>` dump into a compiled census
table, so `minimum_chain_work_kat_tests` can RE-DERIVE the DIL constant by
summing work over the census rather than restating it.

The gate
--------
A census artifact that is silently wrong is worse than none: it looks like
evidence. An earlier round of this mission committed two "census" files that
were actually Python tracebacks, because the script ran from the wrong directory
and the shell redirect captured the error as data. So this script writes NOTHING
unless every check passes, and exits non-zero with the reason on stderr:

  * the input ends with the producer's DONE marker (a file copied while still
    being written parses as a perfectly well-formed SHORT table -- this actually
    happened: a first read saw 19,242 of 54,001 rows, truncated mid-hash);
  * heights are contiguous 0..EXPECT_TIP with no duplicates and no gaps;
  * the row count is exactly EXPECT_TIP + 1;
  * no nBits is zero (a zero mantissa makes ComputeChainWork saturate to MAX
    work -- a spectacular and completely invisible wrong answer);
  * the emitted table's own counts re-sum to the row count.

The output deliberately does NOT contain the expected chain-work sum. The test
must derive that from the census and compare it to chainparams; baking the
answer into the artifact would make the assertion circular.

Usage:
  python scripts/gen_dil_nbits_census.py <dump.tsv> src/test/dil_nbits_census.h
"""
import collections
import hashlib
import io
import os
import sys

EXPECT_TIP = 54000          # DIL's most recent checkpoint height
EXPECT_ROWS = EXPECT_TIP + 1

# Consensus anchors, both from src/core/chainparams.cpp Mainnet(). A sha256 of
# the dump proves only that the bytes have not changed since we read them -- it
# says NOTHING about whether those bytes are DIL's real history. These two
# hashes are what tie the census to consensus: the genesis the chain starts
# from, and the checkpoint the threshold is measured at. Without them a dump
# from the wrong chain, the wrong network, or a fork would sail through every
# structural check and produce an authoritative-looking wrong constant.
EXPECT_GENESIS_HASH = "0000009eaa5e7781ba6d14525c3f75c35444045b21ddafbbea61090db99b0bc3"
EXPECT_TIP_HASH = "0000000bb44c964b4e3c6fec8c15941738cd74b434bafbfe4aadce898140b993"


def die(msg):
    sys.stderr.write("CENSUS ABORTED (nothing written): %s\n" % msg)
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        die("usage: gen_dil_nbits_census.py <dump.tsv> <out.h>")
    src, out = sys.argv[1], sys.argv[2]
    if not os.path.isfile(src):
        die("input %s does not exist" % src)

    raw = io.open(src, "rb").read()
    sha = hashlib.sha256(raw).hexdigest()

    text = raw.decode("utf-8", "replace")
    lines = text.replace("\r\n", "\n").split("\n")

    saw_done = False
    seen = {}
    hashes = {}
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper() == "DONE":
            saw_done = True
            continue
        if saw_done:
            die("line %d: data row AFTER the DONE marker" % lineno)
        parts = line.split()
        if len(parts) < 2:
            die("line %d: expected '<height> [hash] <nBits>', got %r" % (lineno, line))
        try:
            height = int(parts[0])
        except ValueError:
            die("line %d: first column is not a height: %r" % (lineno, parts[0]))
        tok = parts[-1]
        body = tok[2:] if tok[:2].lower() == "0x" else tok
        try:
            nbits = int(body, 16)
        except ValueError:
            die("line %d: unparseable nBits: %r" % (lineno, tok))
        if nbits == 0:
            die("line %d: nBits is zero (would saturate work to MAX)" % lineno)
        if nbits > 0xFFFFFFFF:
            die("line %d: nBits does not fit in 32 bits: %r" % (lineno, tok))
        if height in seen:
            die("duplicate row for height %d" % height)
        seen[height] = nbits
        if len(parts) >= 3:
            hashes[height] = parts[1].lower()

    # ---- WRITE GATE -----------------------------------------------------
    if not saw_done:
        die("no DONE marker: %s may be TRUNCATED (copied while still being "
            "written). Refusing -- a short census yields a plausible, wrong "
            "chain work." % src)
    if len(seen) != EXPECT_ROWS:
        die("expected %d rows (heights 0..%d), found %d"
            % (EXPECT_ROWS, EXPECT_TIP, len(seen)))
    missing = [h for h in range(0, EXPECT_ROWS) if h not in seen]
    if missing:
        die("heights are not contiguous 0..%d; %d missing, first few: %s"
            % (EXPECT_TIP, len(missing), missing[:5]))

    # Consensus anchors. Structural checks above prove the table is well-formed;
    # these prove it is the RIGHT CHAIN. A dump from a fork or the wrong network
    # passes every other gate and yields an authoritative-looking wrong number.
    for h, want in ((0, EXPECT_GENESIS_HASH), (EXPECT_TIP, EXPECT_TIP_HASH)):
        got = hashes.get(h)
        if got is None:
            die("row at height %d carries no block hash; cannot anchor the census "
                "to consensus. Re-dump with the hash column." % h)
        if got != want:
            die("height %d hash does not match chainparams: got %s, want %s. "
                "This dump is not DIL mainnet history." % (h, got, want))

    agg = collections.Counter(seen[h] for h in range(0, EXPECT_ROWS))
    if sum(agg.values()) != EXPECT_ROWS:
        die("aggregate counts re-sum to %d, expected %d"
            % (sum(agg.values()), EXPECT_ROWS))

    body_lines = []
    for nbits in sorted(agg):
        body_lines.append("    {0x%08xu, %d}," % (nbits, agg[nbits]))

    header = """// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// GENERATED FILE -- do not edit by hand.
//   generator: scripts/gen_dil_nbits_census.py
//   source:    a read-only DIL seed dump of <height> <hash> <nBits>
//   sha256:    %(sha)s
//   coverage:  heights 0..%(tip)d inclusive (%(rows)d blocks), verified contiguous,
//              no duplicates, no zero nBits, producer DONE marker present
//   anchored:  height 0 and height %(tip)d hashes matched against chainparams
//              Mainnet() genesisHash and its highest checkpoint -- the sha256
//              proves the bytes are unchanged, these prove they are DIL
//
// DIL retargets on roughly half of all blocks (%(distinct)d distinct nBits over %(rows)d),
// so its nMinimumChainWork cannot be re-derived from a closed form the way
// DilV's can. This census is the per-block evidence, aggregated by nBits --
// chain work is a SUM, so grouping equal nBits together is exact.
//
// This file deliberately does NOT contain the expected chain-work total.
// minimum_chain_work_kat_tests derives it from this table and compares it to
// chainparams; baking the answer in here would make that assertion circular.

#ifndef DILITHION_TEST_DIL_NBITS_CENSUS_H
#define DILITHION_TEST_DIL_NBITS_CENSUS_H

#include <cstdint>
#include <cstddef>

namespace dilithion {
namespace test {

struct DilNBitsCensusRow {
    uint32_t nBits;
    uint32_t count;
};

// Highest height covered, inclusive.
static const int DIL_CENSUS_TIP_HEIGHT = %(tip)d;
// Total blocks censused; must equal DIL_CENSUS_TIP_HEIGHT + 1.
static const long long DIL_CENSUS_TOTAL_BLOCKS = %(rows)d;

static const DilNBitsCensusRow DIL_NBITS_CENSUS[] = {
%(body)s
};

static const size_t DIL_NBITS_CENSUS_LEN =
    sizeof(DIL_NBITS_CENSUS) / sizeof(DIL_NBITS_CENSUS[0]);

}  // namespace test
}  // namespace dilithion

#endif  // DILITHION_TEST_DIL_NBITS_CENSUS_H
""" % {"sha": sha, "tip": EXPECT_TIP, "rows": EXPECT_ROWS,
       "distinct": len(agg), "body": "\n".join(body_lines)}

    if "Traceback" in header:
        die("output contains a traceback -- refusing to write")

    io.open(out, "w", encoding="utf-8", newline="\n").write(header)
    sys.stdout.write("WROTE %s\n" % out)
    sys.stdout.write("  source sha256   %s\n" % sha)
    sys.stdout.write("  blocks censused %d (heights 0..%d, contiguous)\n"
                     % (EXPECT_ROWS, EXPECT_TIP))
    sys.stdout.write("  distinct nBits  %d\n" % len(agg))


if __name__ == "__main__":
    main()
