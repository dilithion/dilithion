# Enabling large pages for mining

RandomX mining in full mode walks a 2 GB dataset. On standard 4 KB memory pages that
working set needs roughly 500,000 TLB entries, far more than any current CPU holds, so
the processor spends much of its time on address translation instead of hashing.

Backing the dataset and the per-thread scratchpads with large pages (2 MB on x86-64)
removes most of that overhead. **The difference is about 2x.** A Ryzen 9 9950X measured
~12,650 H/s at 32 threads on standard pages and ~25,000 H/s with large pages enabled.

The node requests large pages automatically. If the operating system refuses, it falls
back to standard pages and keeps mining — you lose the speed, never the ability to mine.
Check which path you got at startup:

```
[MINING] Large pages: ENABLED
[MINING] Large pages: UNAVAILABLE - mining on standard 4KB pages, expect roughly half
         the achievable hashrate.
```

If you see `UNAVAILABLE`, follow the section for your platform below.

Large pages are not free: the memory is reserved up front and cannot be swapped. Budget
about 2.1 GB per mining node, and do not allocate so much that the rest of the system
starves.

## Linux

Reserve 1280 huge pages (2.5 GB, leaving headroom above the 2 GB dataset):

```bash
sudo sysctl -w vm.nr_hugepages=1280
```

Make it survive reboots:

```bash
echo 'vm.nr_hugepages=1280' | sudo tee -a /etc/sysctl.conf
```

Confirm the reservation took effect — `HugePages_Free` should be non-zero:

```bash
grep HugePages /proc/meminfo
```

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

Windows cannot always satisfy a large-page request on a machine that has been running for
a long time, because it needs contiguous physical memory. If `UNAVAILABLE` persists after
the privilege is granted and you have logged back in, reboot and start the miner early.

## macOS

RandomX does not support large pages on macOS. Miners there run on standard pages; this
is expected and there is no configuration to change.
