# ==============================================================================
# check_participant_waits.awk — a thread that BLOCKS must not do it ONLINE.
# ==============================================================================
#
# Prints one verdict line per blocking call found in a participant file:
#
#   OK      <file> <line> <call>        inside an EpochOfflineScope
#   EXEMPT  <file> <line> <call>        carries a declared per-site exclusion
#   BAD     <file> <line> <call>        ONLINE across a blocking call
#   PARSE   <file> <line> <reason>      unreadable -> the caller FAILS
#
# ⚠️ WHY. An epoch scheme's whole bound is "a thread passes its checkpoint
# promptly". A thread that publishes an epoch and then BLOCKS freezes
# DrainGraveyard's minimum for the entire block, so nothing unlinked meanwhile can
# ever be freed. This has now been found FOUR times on this branch, each time in a
# different file, each time by a human noticing rather than by a check:
#   round 1  the RPC server parked in accept()          47.60 MB / 15 s, 0 freed
#   round 4  two paused validation threads              10 ms at a time, unbounded
#   round 7  the idle headers processor (F45)           the state an idle node is IN
#   round 8  the VDF miner in cooldown (F46)            TWO MINUTES, on the miners
#
# ⚠️ AND THE THING THAT HID THE LAST TWO WAS A COMMENT STATING A BOUND. F46's
# checkpoint said "Pin bound: one VDF round" directly above eight waits totalling
# up to two minutes. A prose bound is not checkable; this is.
#
# ⚠️ POINTER-FREE IS NOT PIN-FREE. Every one of the four looked safe because the
# thread held nothing at the wait. A thread pins by its PUBLISHED EPOCH, not by
# holding a pointer -- which is exactly why this needs a machine and not a reviewer.
#
# A participant file is one containing `EpochCheckpoint(`. Within it, every
# blocking call must be inside an `EpochOfflineScope` (or an `EpochOnlineWindow`,
# whose destructor quiesces), or carry an exclusion on the line before:
#
#     // EPOCH-WAIT-EXEMPT: <reason this thread cannot pin here>
#
# An exemption REQUIRES a reason. The point is not to allow opting out; it is to
# force the argument to be written where the next reader will find it.

function reset() { src = ""; delete inbody; delete fn_start; delete fn_end; delete fn_cp; delete fn_name; delete sc_depth; delete sc_online; delete call_at; delete call_tx }

FNR == 1 && NR > 1 { finish() }
FNR == 1 { reset(); fname = FILENAME }
{ src = src $0 "\n" }
END { finish() }

function strip(s,   out, i, n, c, c2, state, prev, delim, endtok, at, at2, k, run, runstart) {
    out = ""; n = length(s); state = "code"
    for (i = 1; i <= n; i++) {
        c  = substr(s, i, 1); c2 = substr(s, i, 2)
        if (state == "code") {
            if (c2 == "//") { state = "line"; i++; continue }
            if (c2 == "/*") { state = "block"; out = out "  "; i++; continue }
            if (c == "R" && substr(s, i + 1, 1) == "\"") {
                prev = (i > 1) ? substr(s, i - 1, 1) : " "
                if (prev !~ /[A-Za-z0-9_]/ || prev ~ /[LuU8]/) {
                    delim = ""; at = i + 2
                    while (at <= n && substr(s, at, 1) != "(") { delim = delim substr(s, at, 1); at++ }
                    endtok = ")" delim "\""
                    k = index(substr(s, at), endtok)
                    if (k == 0) return ""
                    for (at2 = i; at2 < at + k + length(endtok) - 1; at2++)
                        out = out ((substr(s, at2, 1) == "\n") ? "\n" : " ")
                    i = at + k + length(endtok) - 2
                    continue
                }
            }
            if (c == "\"") { state = "str"; out = out "\""; continue }
            if (c == "'") {
                if (substr(s, i + 1, 1) ~ /[0-9A-Fa-f]/) {
                    runstart = i - 1
                    while (runstart >= 1 && substr(s, runstart, 1) ~ /[0-9A-Fa-f.xXbB']/) runstart--
                    run = substr(s, runstart + 1, i - runstart - 1)
                    prev = (runstart >= 1) ? substr(s, runstart, 1) : " "
                    if (run ~ /^[0-9]/ && prev !~ /[A-Za-z_]/) { out = out "0"; continue }
                }
                state = "chr"; out = out "'"; continue
            }
            out = out c
        } else if (state == "line") {
            if (c == "\n") { state = "code"; out = out "\n" }
        } else if (state == "block") {
            if (c2 == "*/") { state = "code"; out = out "  "; i++; continue }
            out = out ((c == "\n") ? "\n" : " ")
        } else if (state == "str" || state == "chr") {
            if (c == "\\") { out = out "  "; i++; continue }
            if ((state == "str" && c == "\"") || (state == "chr" && c == "'")) { state = "code"; out = out c; continue }
            out = out ((c == "\n") ? "\n" : " ")
        }
    }
    if (state == "block" || state == "str" || state == "chr") return ""
    return out
}

function finish(   code, ncl, cl, raw, nraw, i, j, ln, call, call_col, scope_col, depth, k, ch, exempt, fstart, hascp, nfn, f, g, nm, body, fname_line, nsc, ncall, ci, rest, base, scope_online, covered, first_stmt) {
    if (src == "") return
    code = strip(src)
    if (code == "") { print "PARSE " fname " 0 unterminated comment, string or raw-string literal"; reset(); return }

    # only participant files are in scope
    if (code !~ /EpochCheckpoint[ \t]*\(/) { reset(); return }

    ncl  = split(code, cl,  "\n")
    nraw = split(src,  raw, "\n")

    # ⚠️ THE UNIT IS THE THREAD BODY AND WHAT IT CALLS, NOT THE FILE AND NOT ONE
    # FUNCTION (round-8 F47 triage). Three versions of this, each wrong in a
    # different direction, and the third was found by ADDING a check rather than
    # by reading:
    #   * by FILE      -> 50 findings, nearly all on threads that are not
    #                     participants but share a file with one. A guard nobody
    #                     will action is a guard that gets switched off.
    #   * by FUNCTION  -> 27 findings, all real candidates -- but it could not see
    #                     `send()` in CHttpServer::HandleRequest, because the
    #                     checkpoint is in WorkerThread and HandleRequest merely
    #                     RUNS ON that thread. The pin belongs to the THREAD; the
    #                     blocking call can be any number of frames down.
    #   * by THREAD BODY + ONE HOP -> what this does.
    #
    # ⚠️ ONE HOP IS A STATED LIMIT, NOT A CLAIM OF COMPLETENESS. A blocking call
    # two frames below a checkpointing function, or in another translation unit,
    # is NOT seen. Closing that needs a real call graph, which is not an awk job;
    # what it must not do is let the PASS line imply a coverage it does not have,
    # so the driver prints the depth with the result.
    depth = 0; fstart = 0; hascp = 0; nfn = 0
    for (i = 1; i <= ncl; i++) {
        ln = cl[i]
        for (k = 1; k <= length(ln); k++) {
            ch = substr(ln, k, 1)
            if (ch == "{") { if (depth == 0) { fstart = i; hascp = 0; fname_line = (i > 1 ? cl[i-1] " " ln : ln) } depth++ }
            else if (ch == "}") {
                depth--
                if (depth == 0 && fstart > 0) {
                    nfn++
                    fn_start[nfn] = fstart; fn_end[nfn] = i; fn_cp[nfn] = hascp
                    # the declarator name: last identifier before the '(' of the
                    # signature, taken from the line that opened the body (or the
                    # one above it, for a brace on its own line)
                    fn_name[nfn] = ""
                    if (match(fname_line, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
                        nm = substr(fname_line, RSTART, RLENGTH)
                        sub(/[ \t]*\($/, "", nm)
                        fn_name[nfn] = nm
                    }
                    fstart = 0; hascp = 0
                }
            }
        }
        if (fstart > 0 && ln ~ /EpochCheckpoint[ \t]*\(/) hascp = 1
    }

    # step 1: the checkpointing functions themselves
    for (f = 1; f <= nfn; f++)
        if (fn_cp[f]) for (j = fn_start[f]; j <= fn_end[f]; j++) inbody[j] = 1

    # step 2: ONE HOP -- any function in this file whose name is called from a
    # checkpointing function's body
    for (f = 1; f <= nfn; f++) {
        if (!fn_cp[f]) continue
        body = ""
        for (j = fn_start[f]; j <= fn_end[f]; j++) body = body " " cl[j]
        for (g = 1; g <= nfn; g++) {
            if (fn_cp[g] || fn_name[g] == "") continue
            if (body ~ ("(^|[^A-Za-z0-9_])" fn_name[g] "[ \t]*\\(")) {
                for (j = fn_start[g]; j <= fn_end[g]; j++) inbody[j] = 1
            }
        }
    }

    # ⚠️ ROUND 8 (F49) FOUND SIX WAYS TO SATISFY THIS GUARD WITHOUT THE PROPERTY.
    # All six are now rejected, each with its own negative fixture, because a
    # guard that can be satisfied without the property is a guard that certifies
    # nothing:
    #
    #  (a) A MARKER ANYWHERE IN THE PRECEDING THREE LINES exempted the call -- and
    #      exempted anything ADDED into that window later. A marker must now sit on
    #      the IMMEDIATELY PRECEDING line, or name the call token it excuses.
    #  (b) `if (x) EpochOfflineScope o(&cs);` -- braceless. The object dies at the
    #      semicolon, but the depth tracker only cleared on `}`, so the NEXT call
    #      read as covered. A scope now registers ONLY as the first statement of a
    #      braced block.
    #  (c) `EpochOnlineWindow` was treated as equivalent to an offline scope. IT IS
    #      THE OPPOSITE: its BODY IS ONLINE. A wait inside one -- even nested in an
    #      offline scope -- was wrongly accepted. Modelled as ONLINE, so it masks
    #      any offline scope enclosing it.
    #  (d) ONE `scopedepth` counter could not represent nesting. Now a stack.
    #  (e) Only the FIRST blocking call on a line was checked, so `f(); g();` hid
    #      `g()`. Every call on the line is checked now.
    #  (f) The taxonomy missed `->wait(`, `sleep_until`, `join()`, `read`/`write`,
    #      `SSLWrite`, and the Win32 forms. Widened; what is still missing is named
    #      in the header rather than left to be discovered.
    #
    # The tell for (b) and (c) is the same one this file has hit twice before: a
    # FALSE OK is the dangerous direction, and only a fixture finds it.
    depth = 0; nsc = 0
    for (i = 1; i <= ncl; i++) {
        ln = cl[i]
        if (!(i in inbody)) {
            # still track braces, or the depth is wrong when we re-enter scope
            for (k = 1; k <= length(ln); k++) {
                ch = substr(ln, k, 1)
                if (ch == "{") depth++
                else if (ch == "}") { depth--; while (nsc > 0 && sc_depth[nsc] > depth) nsc-- }
            }
            continue
        }

        # Positions of every blocking call on this line, and of a scope decl.
        ncall = 0
        rest = ln; base = 0
        while (match(rest, /(\.|->)(wait|wait_for|wait_until)[ \t]*\(|this_thread::sleep_(for|until)[ \t]*\(|(^|[^A-Za-z0-9_])(accept|recv|send|select|poll|epoll_wait|SSLRead|SSLWrite|WaitForSingleObject|WaitForMultipleObjects)[ \t]*\(|(^|[^A-Za-z0-9_])(Sleep)[ \t]*\(|\.join[ \t]*\(/)) {
            ncall++
            call_at[ncall] = base + RSTART
            call_tx[ncall] = substr(rest, RSTART, RLENGTH)
            gsub(/^[^A-Za-z_.>-]+|[ \t]*\($/, "", call_tx[ncall])
            base += RSTART + RLENGTH - 1
            rest = substr(rest, RSTART + RLENGTH)
        }

        scope_col = 0; scope_online = 0
        if (match(ln, /EpochOfflineScope[ \t]+[A-Za-z_]/)) scope_col = RSTART
        else if (match(ln, /EpochOnlineWindow[ \t]+[A-Za-z_]/)) { scope_col = RSTART; scope_online = 1 }

        ci = 1
        # `first_stmt` is set by a '{' and cleared by the first token after it, so
        # a scope only registers when it is that first token -- which is what makes
        # the braceless form (b) fail.
        for (k = 1; k <= length(ln) + 1; k++) {
            while (ci <= ncall && k == call_at[ci]) {
                exempt = 0
                # (a) immediately-preceding line only, OR the marker names the call
                if (raw[i-1] ~ /EPOCH-WAIT-EXEMPT:[ \t]*[^ \t]/) exempt = 1
                else {
                    for (j = i - 1; j >= 1 && j >= i - 3; j--)
                        if (raw[j] ~ /EPOCH-WAIT-EXEMPT:/ && raw[j] ~ call_tx[ci]) exempt = 1
                }
                # covered only if the INNERMOST scope is an OFFLINE one (c)+(d)
                covered = (nsc > 0 && sc_online[nsc] == 0)
                if (exempt)      print "EXEMPT " fname " " i " " call_tx[ci]
                else if (covered) print "OK "    fname " " i " " call_tx[ci]
                else              print "BAD "   fname " " i " " call_tx[ci]
                ci++
            }
            if (scope_col > 0 && k == scope_col) {
                if (first_stmt) {
                    nsc++; sc_depth[nsc] = depth; sc_online[nsc] = scope_online
                } else {
                    print "PARSE " fname " " i " a scope that is not the first statement of a braced block cannot be tracked (braceless `if (x) EpochOfflineScope o(...);` dies at the semicolon); brace it"
                }
                scope_col = -1
            }
            if (k > length(ln)) break
            ch = substr(ln, k, 1)
            if (ch == "{") { depth++; first_stmt = 1 }
            else if (ch == "}") { depth--; first_stmt = 0; while (nsc > 0 && sc_depth[nsc] > depth) nsc-- }
            else if (ch != " " && ch != "\t") first_stmt = 0
        }
    }

    reset()
}
