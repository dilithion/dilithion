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

function reset() { src = ""; delete inbody; delete fn_start; delete fn_end; delete fn_cp; delete fn_name }

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

function finish(   code, ncl, cl, raw, nraw, i, j, ln, call, call_col, scope_col, scopedepth, depth, k, ch, exempt, fstart, hascp, nfn, f, g, nm, body, fname_line) {
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

    # ⚠️ BRACE DEPTH, NOT A LINE WINDOW. The heuristic that FOUND F46 was "is there
    # an EpochOfflineScope within 25 lines above" -- good enough to find
    # candidates, not good enough to clear one: it accepts a scope that closed
    # before the call and a scope in a different block entirely. Track the depth at
    # which each scope is declared, and treat the call as covered only while the
    # depth is still inside it.
    # ⚠️ COLUMN ORDER WITHIN THE LINE MATTERS, AND THE FIRST VERSION GOT IT
    # WRONG -- caught by its own fixtures, which is the argument for writing them
    # before trusting the check. It processed a whole line's braces and THEN
    # evaluated the call, so `cv.wait(lk); }` retroactively closed the scope that
    # covered it (false BAD), and `{ EpochOfflineScope o(...); }` on one line
    # registered a scope that had already closed (false OK -- the dangerous one).
    # Walk the characters in order and act at each token's own column.
    depth = 0; scopedepth = -1
    for (i = 1; i <= ncl; i++) {
        ln = cl[i]

        scope_col = 0
        if (match(ln, /Epoch(OfflineScope|OnlineWindow)[ 	]+[A-Za-z_]/)) scope_col = RSTART

        call = ""; call_col = 0
        if (!(i in inbody)) { }   # not in a checkpointing function: out of scope
        else if (match(ln, /\.(wait|wait_for|wait_until)[ 	]*\(/))        { call = "cv.wait";   call_col = RSTART }
        else if (match(ln, /this_thread::sleep_for[ 	]*\(/))          { call = "sleep_for"; call_col = RSTART }
        else if (match(ln, /(^|[^A-Za-z0-9_])accept[ 	]*\(/))         { call = "accept";    call_col = RSTART }
        else if (match(ln, /(^|[^A-Za-z0-9_])recv[ 	]*\(/))           { call = "recv";      call_col = RSTART }
        else if (match(ln, /(^|[^A-Za-z0-9_])select[ 	]*\(/))         { call = "select";    call_col = RSTART }
        else if (match(ln, /(^|[^A-Za-z0-9_])send[ 	]*\(/))           { call = "send";      call_col = RSTART }
        else if (match(ln, /(^|[^A-Za-z0-9_])poll[ 	]*\(/))           { call = "poll";      call_col = RSTART }

        for (k = 1; k <= length(ln) + 1; k++) {
            if (call_col > 0 && k == call_col) {
                exempt = 0
                for (j = i - 1; j >= 1 && j >= i - 3; j--)
                    if (raw[j] ~ /EPOCH-WAIT-EXEMPT:[ 	]*[^ 	]/) exempt = 1
                if (exempt)               print "EXEMPT " fname " " i " " call
                else if (scopedepth >= 0) print "OK "     fname " " i " " call
                else                      print "BAD "    fname " " i " " call
                call_col = -1
            }
            if (scope_col > 0 && k == scope_col) { scopedepth = depth; scope_col = -1 }
            if (k > length(ln)) break
            ch = substr(ln, k, 1)
            if (ch == "{") depth++
            else if (ch == "}") { depth--; if (scopedepth >= 0 && depth < scopedepth) scopedepth = -1 }
        }
    }
    reset()
}
