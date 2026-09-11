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

function reset() { src = ""; delete inbody; delete fn_start; delete fn_end; delete fn_cp; delete fn_name; delete sc_depth; delete sc_online; delete call_at; delete call_tx; delete sd_at; delete sd_online; delete fn_unnamed; delete fn_reach; delete fn_new }

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

# ⚠️ A SIGNATURE CAN SPAN SIX LINES, AND LOOKING AT ONE LOST IT (round-9 F57f).
# CHttpServer::SendResponse declares four parameters across four lines, so the line
# above its opening brace is `const std::string& body) {` -- no name in sight. The
# block was therefore unnamed, could never be matched as a one-hop callee, and the
# TWELVE sends inside it were invisible to this guard. Join back far enough to find
# the declarator.
function sigwindow(cl, i, ln,   w, k) {
    w = ""
    for (k = (i > 6 ? i - 6 : 1); k < i; k++) w = w " " cl[k]
    return w " " ln
}

function finish(   code, ncl, cl, raw, nraw, i, j, ln, call, call_col, scope_col, depth, k, ch, exempt, fstart, hascp, nfn, f, g, nm, body, fname_line, nsc, ncall, ci, rest, base, covered, first_stmt, nsd, si, sd_rest, sd_base, nm_rest, hascp_line, hasblock, h, HOPS) {
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
        # ⚠️ EVALUATED BEFORE *AND* AFTER THE BRACE WALK (round-9 F57b). Checking
        # only afterwards lost `void f(){ cs.EpochCheckpoint("x"); cv.wait(lk); }`:
        # the closing brace cleared fstart on the same line, so the function was
        # recorded as NOT checkpointing and its wait was never examined. Checking
        # only before lost the opening-brace-on-the-same-line form. Both, and the
        # flag is set on the LINE not the position, which is what a one-liner needs.
        if (ln ~ /EpochCheckpoint[ \t]*\(/) hascp_line = 1; else hascp_line = 0
        for (k = 1; k <= length(ln); k++) {
            ch = substr(ln, k, 1)
            if (ch == "{") { if (depth == 0) { fstart = i; hascp = hascp_line; fname_line = sigwindow(cl, i, ln) } depth++ }
            else if (ch == "}") {
                depth--
                if (depth == 0 && fstart > 0) {
                    nfn++
                    fn_start[nfn] = fstart; fn_end[nfn] = i; fn_cp[nfn] = (hascp || hascp_line)
                    # the declarator name: last identifier before the '(' of the
                    # signature, taken from the line that opened the body (or the
                    # one above it, for a brace on its own line)
                    # ⚠️ THE *LAST* identifier before the '(', NOT THE FIRST
                    # (round-9 F57f). Taking the first named `CHttpServer` in
                    # `void CHttpServer::AcceptThread(` and `std` in a
                    # constructor-initializer definition -- so those functions were
                    # misnamed and lost their one-hop callees silently. A wrong name
                    # does not fail; it just stops finding things.
                    fn_name[nfn] = ""
                    nm_rest = fname_line
                    while (match(nm_rest, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
                        nm = substr(nm_rest, RSTART, RLENGTH)
                        sub(/[ \t]*\($/, "", nm)
                        if (nm !~ /^(if|for|while|switch|return|sizeof|catch)$/) fn_name[nfn] = nm
                        nm_rest = substr(nm_rest, RSTART + RLENGTH)
                    }
                    # ⚠️ REPORTED ONLY WHEN THE MISSING NAME COSTS COVERAGE. The
                    # first version printed PARSE for every unnamed top-level block
                    # and buried the run in 25 findings -- namespaces, struct
                    # bodies, initializer lists, anything opening a brace at depth
                    # 0 without an `identifier(` above it. None of those can be a
                    # one-hop callee, so naming them buys nothing.
                    #
                    # It matters in exactly one case: a block that CONTAINS a
                    # blocking call and is NOT itself a checkpointing function. That
                    # block might be reachable from a participant, and an unnamed
                    # block cannot be matched as a callee -- so its calls would be
                    # invisible. That is a coverage hole and it fails.
                    fn_unnamed[nfn] = (fn_name[nfn] == "")
                    fstart = 0; hascp = 0
                }
            }
        # ⚠️ ACCUMULATE ACROSS THE BODY. Setting hascp only at the opening brace
        # works for a one-liner and loses every MULTI-LINE function, whose
        # checkpoint is on a later line -- which collapsed the whole population to
        # zero and made the guard report a clean tree it had not examined. The
        # counts printing 0 scoped / 0 exempt is what surfaced it; a guard that
        # reports nothing must never read as PASS.
        if (fstart > 0 && hascp_line) hascp = 1
        }
    }

    # the unnamed blocks that could cost coverage -- see the note in pass 1
    for (f = 1; f <= nfn; f++) {
        if (!fn_unnamed[f] || fn_cp[f]) continue
        hasblock = 0
        for (j = fn_start[f]; j <= fn_end[f]; j++)
            if (cl[j] ~ /(\.|->)(wait|wait_for|wait_until|join)[ 	]*\(|this_thread::sleep_(for|until)[ 	]*\(|(^|[^A-Za-z0-9_])(accept|recv|send|select|poll)[ 	]*\(/) hasblock = 1
        if (hasblock)
            print "PARSE " fname " " fn_start[f] " a block containing a blocking call could not be NAMED, so it can never be matched as a one-hop callee -- its calls are invisible to this guard"
    }

    # step 1: the checkpointing functions themselves
    for (f = 1; f <= nfn; f++)
        if (fn_cp[f]) for (j = fn_start[f]; j <= fn_end[f]; j++) inbody[j] = 1

    # step 2: TWO HOPS, and the second was earned rather than chosen (round-9).
    # One hop covered `WorkerThread -> HandleRequest`. It did NOT cover
    # `WorkerThread -> HandleRequest -> SendResponse`, and SendResponse holds TWELVE
    # of http_server's eighteen `send()` calls -- so a dozen blocking calls on a
    # participant thread sat outside the population while the guard printed PASS.
    #
    # That is the concrete answer to "can a two-hop case matter in this tree?": YES,
    # and it surfaced by widening the signature window far enough to NAME
    # SendResponse and then noticing the count did NOT move -- nameable, still
    # unreachable. A number that does not move when it should is the cheapest tell
    # there is, and only visible because the guard prints its population.
    #
    # ⚠️ THE LIMIT IS NOW TWO, NOT NONE. Three hops is still invisible, as is any
    # callee in another translation unit. HOPS is a constant so the depth is one
    # number to change and one number to report.
    HOPS = 2
    for (h = 1; h <= HOPS; h++) {
        for (f = 1; f <= nfn; f++) {
            if (!fn_cp[f] && !fn_reach[f]) continue
            body = ""
            for (j = fn_start[f]; j <= fn_end[f]; j++) body = body " " cl[j]
            for (g = 1; g <= nfn; g++) {
                if (fn_cp[g] || fn_reach[g] || fn_name[g] == "") continue
                if (body ~ ("(^|[^A-Za-z0-9_])" fn_name[g] "[ \\t]*\\(")) fn_new[g] = 1
            }
        }
        for (g = 1; g <= nfn; g++) {
            if (!fn_new[g]) continue
            fn_reach[g] = 1; fn_new[g] = 0
            for (j = fn_start[g]; j <= fn_end[g]; j++) inbody[j] = 1
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
#
# ⚠️ THE SEND ACCOUNTING, RECONCILED (round-9 F51). Three artifacts on this branch
# said "18 sends", "4 markers" and "five sites by hand", and none agreed because
# each counted a different thing. The real decomposition in http_server.cpp:
#     12  CALL SITES of SendResponse(...)          -- not sends themselves
#      2  actual send() inside SendResponse        -- one per platform branch
#      6  raw send() in HandleRequest              -- three per platform branch
# So "18" was call sites; the blocking calls the guard must cover are the 2 + 6 = 8
# textual send() calls, of which each build compiles half. All are now marked, and
# the two inside SendResponse were invisible until the guard reached TWO hops.
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
        while (match(rest, /(\.|->)(wait|wait_for|wait_until)[ \t]*\(|this_thread::sleep_(for|until)[ \t]*\(|(^|[^A-Za-z0-9_])(accept|recv|send|select|poll|epoll_wait|SSLRead|SSLWrite|WaitForSingleObject|WaitForMultipleObjects)[ \t]*\(|(^|[^A-Za-z0-9_])(Sleep)[ \t]*\(|(\.|->)join[ \t]*\(/)) {
            ncall++
            call_at[ncall] = base + RSTART
            call_tx[ncall] = substr(rest, RSTART, RLENGTH)
            # Normalise to the BARE IDENTIFIER (`join`, `wait`, `recv`). The
            # marker-names-the-call test is a literal substring search, and a human
            # writing "the join below is shutdown-only" writes `join`, not `.join`.
            # Leaving the punctuation on made every NAMED exemption fail -- caught
            # by fixture g5, which is precisely why the accept cases exist.
            gsub(/^[^A-Za-z_]+|[ \t]*\($/, "", call_tx[ncall])
            base += RSTART + RLENGTH - 1
            rest = substr(rest, RSTART + RLENGTH)
        }

        # ⚠️ EVERY SCOPE ON THE LINE, IN COLUMN ORDER (round-9 F57a). Taking one --
        # and preferring EpochOfflineScope when both appeared -- meant
        # `{ EpochOfflineScope o(&cs); { EpochOnlineWindow w(&cs); cv.wait(lk); } }`
        # written on ONE line reported OK for a wait that is ONLINE. A false OK, on
        # the construct the guard exists to catch.
        nsd = 0
        sd_rest = ln; sd_base = 0
        while (match(sd_rest, /Epoch(OfflineScope|OnlineWindow)[ \t]+[A-Za-z_]/)) {
            nsd++
            sd_at[nsd] = sd_base + RSTART
            sd_online[nsd] = (substr(sd_rest, RSTART, RLENGTH) ~ /OnlineWindow/) ? 1 : 0
            sd_base += RSTART + RLENGTH - 1
            sd_rest = substr(sd_rest, RSTART + RLENGTH)
        }
        si = 1

        ci = 1
        # `first_stmt` is set by a '{' and cleared by the first token after it, so
        # a scope only registers when it is that first token -- which is what makes
        # the braceless form (b) fail.
        for (k = 1; k <= length(ln) + 1; k++) {
            while (ci <= ncall && k == call_at[ci]) {
                # ⚠️ A PRECEDING-LINE MARKER EXEMPTS EXACTLY ONE CALL (round-9
                # F57c). It used to exempt EVERY call on the following line, so
                # `cv.wait(a); cv.wait(b);` was excused by one reason that had
                # considered one of them. Only the FIRST call on the line may take
                # the bare preceding-line marker; any other call on that line must
                # be named.
                #
                # ⚠️ AND THE NAME TEST IS LITERAL, NOT A REGEX (round-9 F57d).
                # `raw[j] ~ call_tx[ci]` treated the call token as a pattern, so
                # `cv.wait` "named" `cvXwait` -- `.` matching any character. index()
                # is a substring test and cannot do that.
                exempt = 0
                if (ci == 1 && raw[i-1] ~ /EPOCH-WAIT-EXEMPT:[ \t]*[^ \t]/) exempt = 1
                else {
                    for (j = i - 1; j >= 1 && j >= i - 3; j--)
                        if (raw[j] ~ /EPOCH-WAIT-EXEMPT:/ && index(raw[j], call_tx[ci]) > 0) exempt = 1
                }
                # covered only if the INNERMOST scope is an OFFLINE one (c)+(d)
                covered = (nsc > 0 && sc_online[nsc] == 0)
                if (exempt)      print "EXEMPT " fname " " i " " call_tx[ci]
                else if (covered) print "OK "    fname " " i " " call_tx[ci]
                else              print "BAD "   fname " " i " " call_tx[ci]
                ci++
            }
            while (si <= nsd && k == sd_at[si]) {
                if (first_stmt) {
                    nsc++; sc_depth[nsc] = depth; sc_online[nsc] = sd_online[si]
                } else {
                    print "PARSE " fname " " i " a scope that is not the first statement of a braced block cannot be tracked (braceless `if (x) EpochOfflineScope o(...);` dies at the semicolon); brace it"
                }
                si++
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
