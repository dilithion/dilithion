# Enabling large pages for mining

RandomX mining in full mode walks a 2 GB dataset. On standard 4 KB memory pages that
working set needs roughly 500,000 TLB entries, far more than any current CPU holds, so
the processor spends much of its time on address translation instead of hashing.

Backing the dataset and the per-thread scratchpads with large pages (2 MB on x86-64)
removes most of that overhead. **The difference is about 2x.** A Ryzen 9 9950X measured
~12,650 H/s at 32 threads on standard pages and ~25,000 H/s with large pages enabled.

A mining node requests large pages automatically. If the operating system refuses, it
falls back to standard pages and keeps mining — you lose the speed, never the ability to
mine. Every node that mines prints exactly one status line, so you can always tell which
path you got:

```
  [MINING] Large pages: ENABLED (2GB dataset)
  [MINING] Large pages: UNAVAILABLE - mining on standard 4KB pages, expect roughly half
           the achievable hashrate.
  [MINING] Large pages: IGNORED - the 2GB dataset was already allocated on standard
           pages before mining started, and cannot be moved.
  [MINING] Large pages: REQUESTED - the 2GB dataset is being allocated now; the
           ENABLED/UNAVAILABLE result follows.
  [MINING] Large pages: N/A - LIGHT mode only (the 2GB FULL-mode dataset that large
           pages back needs >= 3072 MB RAM).
```

`REQUESTED` is transient — the `ENABLED` or `UNAVAILABLE` line follows within a minute or
two, once the dataset has been allocated.

A node that is **not** mining prints none of these. That is deliberate: a relay node never
requests large pages (see *Why it might still say UNAVAILABLE* below), so it has nothing to
report.

If you see `UNAVAILABLE`, follow the section for your platform below. If you see
`IGNORED`, restart the node with `--mine`.

Large pages are not free: the memory is reserved up front and cannot be swapped. Do not
allocate so much that the rest of the system starves.

## How many pages you actually need

Getting this wrong is the most common reason large pages silently do nothing, so the exact
counts (2 MiB pages) are worth stating:

| Allocation | Size | 2 MiB pages |
|---|---|---|
| RandomX dataset | 2,181,038,016 B (rounded up by the kernel) | **1040** |
| Per-thread scratchpad | 2,097,152 B | **1 per mining thread** |

So a 32-thread miner needs **1040 + 32 = 1072** pages, about **2.2 GB** — not 2 GB, and
noticeably more than the `1024` that circulates in most guides.

Falling short degrades in two distinct steps, which is why the exact number matters:

- **Fewer than 1040 pages** — the dataset allocation fails and falls back to 4 KB pages.
  This is the failure that costs you half your hashrate, and it is the one `1024` causes:
  1024 is **16 pages short** of the 1040 the dataset needs.
- **1040 to 1071 pages** (with 32 threads) — the dataset gets large pages, but the pool
  runs out partway through the per-thread scratchpads. Each scratchpad falls back on its
  own, so some threads get large pages and the rest do not. Most of the win is kept.

The node does *not* request large pages for its 256 MB cache, precisely so the cache
cannot consume pages the dataset needs.

Round up. The examples below use **1152**, which covers 32 threads with headroom.

## Linux

Reserve the pages:

```bash
sudo sysctl -w vm.nr_hugepages=1152
```

Make it survive reboots:

```bash
echo 'vm.nr_hugepages=1152' | sudo tee -a /etc/sysctl.conf
```

Confirm the reservation took effect — `HugePages_Total` should read 1152 and
`Hugepagesize` should read `2048 kB`:

```bash
grep -E 'HugePages_|Hugepagesize' /proc/meminfo
```

**Transparent hugepages are not a substitute.** RandomX allocates with
`mmap(MAP_HUGETLB)`, which draws from the explicitly reserved hugetlb pool above and
ignores THP completely. Setting `transparent_hugepage=always` will not enable this and the
node will keep reporting `UNAVAILABLE`.

**Keep the page size at 2 MiB.** If the kernel is booted with `default_hugepagesz=1G`,
`MAP_HUGETLB` hands out 1 GiB pages, and each 2 MiB scratchpad then consumes an entire
1 GiB page. Worse, freeing one fails, so a node leaks 1 GiB every time it recreates its
mining VMs — which it does on every mining restart. If `Hugepagesize` above is not
`2048 kB`, fix that before enabling this.

Reserve huge pages soon after boot if you can. On a long-running machine, physical memory
fragments and the kernel may be unable to assemble enough contiguous 2 MB regions.

## Windows

Windows requires the **Lock pages in memory** privilege (`SeLockMemoryPrivilege`), which
no account holds by default.

1. Run `secpol.msc` (Local Security Policy).
2. Go to **Local Policies → User Rights Assignment**.
3. Open **Lock pages in memory**.
4. Add the account the miner runs as.
5. **Log out and back in** — the privilege is attached to the logon token, so it does not
   apply to an existing session.
6. Restart the node.

Windows Home does not ship `secpol.msc`. Grant it from an administrator PowerShell
instead, substituting the account name:

```powershell
$account = "$env:COMPUTERNAME\$env:USERNAME"
$sid = (New-Object Security.Principal.NTAccount($account)).Translate([Security.Principal.SecurityIdentifier]).Value
secedit /export /areas USER_RIGHTS /cfg "$env:TEMP\rights.cfg" | Out-Null
$cfg = Get-Content "$env:TEMP\rights.cfg"
if ($cfg -match 'SeLockMemoryPrivilege') {
    $cfg = $cfg -replace '(SeLockMemoryPrivilege\s*=.*)', "`$1,*$sid"
} else {
    $cfg = $cfg -replace '(\[Privilege Rights\])', "`$1`r`nSeLockMemoryPrivilege = *$sid"
}
$cfg | Set-Content "$env:TEMP\rights.cfg" -Encoding Unicode
secedit /configure /db "$env:TEMP\rights.sdb" /cfg "$env:TEMP\rights.cfg" /areas USER_RIGHTS
```

Then log out, log back in, and restart the node.

Note that once the node makes its first large-page attempt it enables
`SeLockMemoryPrivilege` on its own process token and leaves it enabled for the life of the
process, whether or not the allocation succeeded. That is upstream RandomX behaviour, not
something the node chooses per-allocation.

Windows cannot always satisfy a large-page request on a machine that has been running for
a long time, because it needs contiguous physical memory. If `UNAVAILABLE` persists after
the privilege is granted and you have logged back in, reboot and start the miner early.

## macOS

Supported, using 2 MB superpages, with no configuration required — the node requests them
and the OS grants or refuses per allocation.

## Why it might still say UNAVAILABLE

- **The pool is too small.** See the sizing table above; the dataset alone needs 1040
  pages, so the widely-copied `1024` is 16 pages short and the dataset falls back.
- **You set transparent hugepages instead of the hugetlb pool** (Linux) — see above.
- **You granted the Windows privilege but did not log out and back in.** The privilege is
  attached to the logon token.
- **The node was not started with `--mine`.** Large pages are requested only by nodes that
  actually mine, so a relay node will neither request them nor report on them. On a host
  with 8 GB or more of RAM the node builds the 2 GB dataset at startup regardless, to
  speed up initial block download — so if a node started without `--mine` later begins
  mining, that dataset has already been built on standard pages and cannot be moved. The
  node reports `Large pages: IGNORED` in that case; restart it with `--mine`.
- **Memory is too fragmented.** Reserve early in the machine's uptime, or reboot.
