# ==============================================================================
# check_thread_local_guard.awk — the parsing half of the thread_local guard.
# ==============================================================================
#
# Prints one verdict line per `thread_local` token found:
#
#   OK    <file> <line> <type>
#   BAD   <file> <line> <type> <reason>
#   PARSE <file> <line> <reason>          (unparsable -> the caller FAILS)
#
# ⚠️ EVERY `thread_local` TOKEN PRODUCES A LINE. There is no silent skip. A token
# the parser cannot account for is PARSE, never dropped -- round 7 (F37c) found
# that the previous version `continue`d on any statement it did not recognise as a
# declaration, so a `#define` containing the token, or a specifier it had not been
# taught, vanished from the population rather than failing. A declaration that is
# never counted is worse than one reported unguarded: it cannot be seen at all.
#
# ⚠️ THE HISTORY, because this file has failed open twice and the pattern is the
# lesson. Round 6 found five bypasses (`inline`/`constexpr`/`static inline`,
# line-split declarations, a COMMENT in the window, an assert on a DIFFERENT type)
# -- all of them consequences of matching LINES with regexes. Round 7 found the
# rewrite still failing open in five more ways (F37): the window keyed on a bare
# TOKEN so `using Check = std::is_trivially_destructible<T>;` and
# `static_assert(!std::is_trivially_destructible<T>::value)` both satisfied it;
# multiple declarators were unhandled; unrecognised statements were skipped; awk
# and find failures did not reach the exit code; and the floor could be overridden
# by an env var. A guard that can be satisfied by a NEGATED assert is not a guard.
#
# So the rules here are deliberately narrow and the default is refusal:
#   * the assert must be a real `static_assert(` call,
#   * its first argument must be POSITIVE (no leading `!`),
#   * and must name EXACTLY the declared type,
#   * one declarator per declaration,
#   * anything else is PARSE.
#
# ⚠️ IT IS ALSO CORRECT WHEN GIVEN SEVERAL FILES AT ONCE. The previous version
# accumulated into one buffer and reported everything under the LAST filename in
# the END block; it was correct only because the driver happened to call it once
# per file. Found by running it on two files by hand. State resets per file.

function reset() { src = ""; nl = 0 }

FNR == 1 && NR > 1 { finish() }
FNR == 1 { reset(); fname = FILENAME }
{ src = src $0 "\n"; nl = FNR }
END { finish() }

# ---------------------------------------------------------------------------
# Strip comments and the CONTENTS of string/char literals, preserving newlines
# and therefore line numbers. Returns "" on an unterminated construct.
# ---------------------------------------------------------------------------
function strip(s,   out, i, n, c, c2, state, prev, delim, endtok, at, at2, k, run, runstart) {
    out = ""; n = length(s); state = "code"
    for (i = 1; i <= n; i++) {
        c  = substr(s, i, 1)
        c2 = substr(s, i, 2)
        if (state == "code") {
            if (c2 == "//") { state = "line"; i++; continue }
            if (c2 == "/*") { state = "block"; out = out "  "; i++; continue }

            # RAW STRING LITERALS: R"DELIM( ... )DELIM". src/api/*_html.h embed
            # whole HTML documents this way, full of quotes and `//`.
            if (c == "R" && substr(s, i + 1, 1) == "\"") {
                prev = (i > 1) ? substr(s, i - 1, 1) : " "
                if (prev !~ /[A-Za-z0-9_]/ || prev ~ /[LuU8]/) {
                    delim = ""; at = i + 2
                    while (at <= n && substr(s, at, 1) != "(") {
                        delim = delim substr(s, at, 1); at++
                    }
                    endtok = ")" delim "\""
                    k = index(substr(s, at), endtok)
                    if (k == 0) return ""
                    for (at2 = i; at2 < at + k + length(endtok) - 1; at2++) {
                        out = out ((substr(s, at2, 1) == "\n") ? "\n" : " ")
                    }
                    i = at + k + length(endtok) - 2
                    continue
                }
            }

            if (c == "\"")  { state = "str";  out = out "\""; continue }
            if (c == "'") {
                # ⚠️ A DIGIT SEPARATOR IS NOT A CHARACTER LITERAL -- AND A CHARACTER
                # LITERAL WITH AN ENCODING PREFIX IS NOT A DIGIT SEPARATOR (F43).
                # The first version tested only "hex digit on both sides", which
                # makes `u8'A'` look like a separator: `8` and `A` are both hex
                # digits, so the opening quote was swallowed and the CLOSING quote
                # then opened a literal that ran to the end of the file. a8's
                # scanner had the identical bug tonight, independently -- one more
                # argument for the ruled consolidation onto a single lexer.
                #
                # A separator only occurs INSIDE a numeric literal. Walk back over
                # the numeric run; it must start with a DIGIT, and the character
                # before it must not be an identifier character. `u8'A'` fails that
                # (the run is "8", preceded by `u`); `200'000` and `0x1F'FF` pass.
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
            if ((state == "str" && c == "\"") || (state == "chr" && c == "'")) {
                state = "code"; out = out c; continue
            }
            out = out ((c == "\n") ? "\n" : " ")
        }
    }
    if (state == "block" || state == "str" || state == "chr") return ""
    return out
}

function squash(s) { gsub(/[ \t\n]+/, " ", s); gsub(/^ | $/, "", s); return s }

function normtype(s) {
    s = squash(s)
    gsub(/ \*/, "*", s); gsub(/\* /, "*", s)
    gsub(/ &/, "&", s);  gsub(/& /, "&", s)
    gsub(/ </, "<", s);  gsub(/< /, "<", s)
    gsub(/ >/, ">", s);  gsub(/> /, ">", s)
    gsub(/ ,/, ",", s);  gsub(/, /, ",", s)
    gsub(/ ::/, "::", s); gsub(/:: /, "::", s)
    sub(/^std::/, "", s)
    gsub(/<std::/, "<", s)
    gsub(/,std::/, ",", s)
    return s
}

# Extract the balanced argument list of a call whose '(' is at position `at` in s.
function balanced(s, at,   d, k, ch, o) {
    d = 0; o = ""
    for (k = at; k <= length(s); k++) {
        ch = substr(s, k, 1)
        if (ch == "(") { d++; if (d == 1) continue }
        else if (ch == ")") { d--; if (d == 0) return o }
        o = o ch
    }
    return ""      # unbalanced
}

# ⚠️ THE ASSERT CHECK, AND IT IS DELIBERATELY STRICT (F37a). It must be a real
# `static_assert(` whose FIRST argument is a POSITIVE trait check on exactly the
# declared type. Rejected on purpose, each with a fixture:
#     using Check = std::is_trivially_destructible<T>;   (not an assert)
#     static_assert(!std::is_trivially_destructible<T>::value, "");   (negated)
#     if constexpr (std::is_trivially_destructible<T>::value) {...}   (not an assert)
function has_assert(win, want,   pos, rest, args, first, d, k, ch, arg) {
    rest = win
    while ((pos = index(rest, "static_assert")) > 0) {
        rest = substr(rest, pos + length("static_assert"))
        # the '(' must follow, modulo whitespace
        k = 1
        while (k <= length(rest) && substr(rest, k, 1) ~ /[ \t\n]/) k++
        if (substr(rest, k, 1) != "(") continue
        args = balanced(rest, k)
        if (args == "") continue
        # first argument = up to the first top-level comma
        first = ""; d = 0
        for (k = 1; k <= length(args); k++) {
            ch = substr(args, k, 1)
            if (ch == "(" || ch == "<" || ch == "[") d++
            else if (ch == ")" || ch == ">" || ch == "]") d--
            else if (ch == "," && d <= 0) break
            first = first ch
        }
        first = squash(first)
        if (first ~ /^!/) continue                       # NEGATED: not a guarantee
        if (first !~ /is_trivially_destructible/) continue
        # the trait's template argument must be the declared type
        k = index(first, "<")
        if (k == 0) continue
        arg = ""; d = 0
        for (; k <= length(first); k++) {
            ch = substr(first, k, 1)
            if (ch == "<") { d++; if (d == 1) continue }
            else if (ch == ">") { d--; if (d == 0) break }
            arg = arg ch
        }
        if (normtype(arg) == want) return 1
    }
    return 0
}

function finish(   code, ncl, cl, ln, line, stmt, j, depth, k, done, ch,
                   head, hcopy, body, cut, d1, d2, nt, tok, name, ptr, type,
                   want, win, i, ndecl) {
    if (src == "") return
    code = strip(src)
    if (code == "") {
        print "PARSE " fname " 0 unterminated comment, string or raw-string literal"
        reset(); return
    }
    ncl = split(code, cl, "\n")

    for (ln = 1; ln <= ncl; ln++) {
        line = cl[ln]
        if (line !~ /(^|[^A-Za-z0-9_])thread_local([^A-Za-z0-9_]|$)/) continue

        # (F37c) A preprocessor line carrying the token is not a declaration and
        # must not be silently skipped -- it is exactly the "macro-wrapped
        # declaration" bypass, still unfixed and unfixtured before this change.
        if (line ~ /^[ \t]*#/) {
            print "PARSE " fname " " ln " `thread_local` inside a preprocessor directive: the guard cannot certify a macro-defined declaration"
            continue
        }

        # Join forward to the terminating ';' at bracket depth 0.
        stmt = line; j = ln; done = 0
        while (j <= ncl) {
            if (j > ln) stmt = stmt " " cl[j]
            depth = 0
            for (k = 1; k <= length(stmt); k++) {
                ch = substr(stmt, k, 1)
                if (ch == "(" || ch == "[" || ch == "{") depth++
                else if (ch == ")" || ch == "]" || ch == "}") depth--
                else if (ch == ";" && depth <= 0) { done = 1; break }
            }
            if (done) { stmt = substr(stmt, 1, k); break }
            j++
            if (j > ln + 8) break
        }
        if (!done) {
            print "PARSE " fname " " ln " could not find the end of this thread_local statement"
            continue
        }

        # Everything before `thread_local` must be storage specifiers only.
        head = stmt
        sub(/thread_local.*$/, "", head)
        head = squash(head)
        if (head != "") {
            hcopy = head
            gsub(/(^|[^A-Za-z0-9_])(static|extern|inline|mutable|const|volatile)([^A-Za-z0-9_]|$)/, " ", hcopy)
            gsub(/(^|[^A-Za-z0-9_])(static|extern|inline|mutable|const|volatile)([^A-Za-z0-9_]|$)/, " ", hcopy)
            if (squash(hcopy) != "") {
                print "PARSE " fname " " ln " unrecognised tokens before `thread_local` (" head "): refusing rather than skipping"
                continue
            }
        }

        body = stmt
        sub(/^.*thread_local/, "", body)
        gsub(/(^|[^A-Za-z0-9_])(static|extern|inline|mutable)([^A-Za-z0-9_]|$)/, " ", body)

        cut = ""; d1 = 0; d2 = 0
        for (k = 1; k <= length(body); k++) {
            ch = substr(body, k, 1)
            if (ch == "<") d2++
            else if (ch == ">") { if (d2 > 0) d2-- }
            else if (ch == "(" || ch == "[") { if (d1 <= 0 && d2 <= 0 && ch == "(") break; d1++ }
            else if (ch == ")" || ch == "]") d1--
            else if (d1 <= 0 && d2 <= 0 && (ch == "=" || ch == ";" || ch == "{")) break
            cut = cut ch
        }
        cut = squash(cut)
        if (cut == "") {
            print "PARSE " fname " " ln " empty declarator after `thread_local`"
            continue
        }

        # (F37b) MULTIPLE DECLARATORS. `thread_local std::string *p = nullptr, s;`
        # declares a POINTER and a STRING; one assert cannot describe both, and
        # silently certifying the first would be the failing-open direction.
        # Refused, with the fix in the message.
        if (index(cut, ",") > 0 || index(body, ",") > 0) {
            ndecl = index(body, ",")
            if (ndecl > 0 && d2 == 0) {
                print "PARSE " fname " " ln " multiple declarators in one thread_local declaration: split them, so each carries its own static_assert"
                continue
            }
        }

        nt = split(cut, tok, " ")
        if (nt < 2) {
            print "PARSE " fname " " ln " cannot separate type from name in: " cut
            continue
        }
        name = tok[nt]; ptr = ""
        while (substr(name, 1, 1) == "*" || substr(name, 1, 1) == "&") {
            ptr = ptr substr(name, 1, 1); name = substr(name, 2)
        }
        type = ""
        for (k = 1; k < nt; k++) type = type " " tok[k]
        type = squash(type) ptr
        if (type == "") {
            print "PARSE " fname " " ln " no type before the declarator in: " cut
            continue
        }
        want = normtype(type)

        win = ""
        for (k = ln; k <= ln + 6 && k <= ncl; k++) win = win " " cl[k]

        if (has_assert(win, want)) print "OK " fname " " ln " " type
        else print "BAD " fname " " ln " " type " no positive static_assert(std::is_trivially_destructible<" type ">::value) in code within 6 lines"
    }
    reset()
}
