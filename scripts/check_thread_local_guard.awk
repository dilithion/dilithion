# ==============================================================================
# check_thread_local_guard.awk — the parsing half of the thread_local guard.
# ==============================================================================
#
# Invoked once per file by scripts/check_thread_local_guard.sh. Prints one line
# per declaration found:
#
#   OK    <file> <line> <type>
#   BAD   <file> <line> <type> <reason>
#   PARSE <file> <line> <reason>          (unparsable -> the caller FAILS)
#
# ⚠️ WHY awk AND NOT grep. Round 6 of the external panel found the first version
# of this guard bypassable in five ways, and every one of them came from matching
# lines with regexes instead of parsing declarations:
#
#   1. the specifier alternation was `(static|extern)? thread_local`, so
#      `inline thread_local`, `constexpr thread_local` and `static inline
#      thread_local` were NEVER COUNTED -- not flagged, not even seen;
#   2. a declaration split across lines (`thread_local` on one, the type on the
#      next) was likewise invisible;
#   3. the six-line window grepped the BARE STRING `is_trivially_destructible`,
#      so a COMMENT mentioning it satisfied the guard;
#   4. and so did a `static_assert` on a COMPLETELY DIFFERENT TYPE;
#   5. a macro-wrapped declaration was invisible for the same reason as 1.
#
# A guard that can be satisfied by a comment is not a guard. So: strip comments
# and string literals with a character scanner, join the declaration to its
# terminating `;`, extract the declared TYPE, and require the assert to name
# THAT type. See lessons_learned.md, "A COMMENT EDIT CAN BREAK A STRUCTURAL
# GUARD", which is the same defect class from the other direction.
#
# ⚠️ AND IT FAILS CLOSED. Anything this cannot parse is reported as PARSE and the
# caller treats it as a failure. A stripper that cannot parse its input must
# never report CLEAN -- that is the direction that ships a false PASS.

BEGIN { src = ""; nlines = 0 }

{ raw[NR] = $0; src = src $0 "\n"; nlines = NR }

# ---------------------------------------------------------------------------
# Strip comments and the CONTENTS of string/char literals, preserving newlines
# and therefore line numbers. Returns "" on an unterminated construct.
# ---------------------------------------------------------------------------
function strip(s,   out, i, n, c, c2, state, prev, delim, endtok, at, k) {
    out = ""; n = length(s); state = "code"
    for (i = 1; i <= n; i++) {
        c  = substr(s, i, 1)
        c2 = substr(s, i, 2)
        if (state == "code") {
            if (c2 == "//") { state = "line"; i++; continue }
            if (c2 == "/*") { state = "block"; out = out "  "; i++; continue }

            # ⚠️ RAW STRING LITERALS. R"DELIM( ... )DELIM" — the embedded HTML in
            # src/api/*_html.h is full of quotes, apostrophes and `//` inside the
            # payload, so treating it as ordinary text made the whole file
            # unparsable. Found by running the guard, not by reading it: four
            # files came back PARSE-FAIL on the first run of the hardened parser,
            # which is the fail-closed behaviour working exactly as intended.
            if (c == "R" && substr(s, i + 1, 1) == "\"") {
                prev = (i > 1) ? substr(s, i - 1, 1) : " "
                if (prev !~ /[A-Za-z0-9_]/ || prev ~ /[LuU8]/) {
                    delim = ""; at = i + 2
                    while (at <= n && substr(s, at, 1) != "(") {
                        delim = delim substr(s, at, 1); at++
                    }
                    endtok = ")" delim "\""
                    k = index(substr(s, at), endtok)
                    if (k == 0) return ""          # unterminated raw string
                    # keep the newlines so line numbers survive
                    for (at2 = i; at2 < at + k + length(endtok) - 1; at2++) {
                        out = out ((substr(s, at2, 1) == "\n") ? "\n" : " ")
                    }
                    i = at + k + length(endtok) - 2
                    continue
                }
            }

            if (c == "\"")  { state = "str";  out = out "\""; continue }
            if (c == "'") {
                # ⚠️ A DIGIT SEPARATOR IS NOT A CHARACTER LITERAL. `200'000`
                # (mempool_persist.h:90) sent the scanner into char-literal state
                # for the rest of the file. Same discovery route as the raw
                # strings above.
                prev = (i > 1) ? substr(s, i - 1, 1) : " "
                if (prev ~ /[0-9A-Fa-f]/ && substr(s, i + 1, 1) ~ /[0-9A-Fa-f]/) {
                    out = out "0"; continue
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

# The type text a `static_assert(std::is_trivially_destructible<X>::value, ...)`
# names, normalised the same way as a declared type so the two can be compared.
function normtype(s) {
    s = squash(s)
    gsub(/ \*/, "*", s); gsub(/\* /, "*", s)
    gsub(/ &/, "&", s);  gsub(/& /, "&", s)
    gsub(/ </, "<", s);  gsub(/< /, "<", s)
    gsub(/ >/, ">", s);  gsub(/> /, ">", s)
    gsub(/ ,/, ",", s);  gsub(/, /, ",", s)
    gsub(/ ::/, "::", s); gsub(/:: /, "::", s)
    sub(/^std::/, "", s)          # std::string and string are the same type here
    gsub(/<std::/, "<", s)
    gsub(/,std::/, ",", s)
    return s
}

END {
    code = strip(src)
    if (code == "") {
        print "PARSE " FILENAME " 0 unterminated comment or string literal"
        exit 0
    }

    # Rebuild a line index over the stripped text so a match position maps back
    # to a line number in the ORIGINAL file.
    ncl = split(code, cl, "\n")

    for (ln = 1; ln <= ncl; ln++) {
        line = cl[ln]
        if (line !~ /(^|[^A-Za-z0-9_])thread_local([^A-Za-z0-9_]|$)/) continue

        # Join forward to the terminating ';' at bracket depth 0 (a declaration
        # may be split across lines, which the regex version could not see).
        stmt = line; j = ln; depth = 0; done = 0
        while (j <= ncl) {
            if (j > ln) stmt = stmt " " cl[j]
            depth = 0; k = 0
            for (k = 1; k <= length(stmt); k++) {
                ch = substr(stmt, k, 1)
                if (ch == "(" || ch == "[" || ch == "{") depth++
                else if (ch == ")" || ch == "]" || ch == "}") depth--
                else if (ch == ";" && depth <= 0) { done = 1; break }
            }
            if (done) { stmt = substr(stmt, 1, k); break }
            j++
            if (j > ln + 8) break        # a declaration spanning >8 lines: give up loudly
        }
        if (!done) {
            print "PARSE " FILENAME " " ln " could not find the end of this thread_local declaration"
            continue
        }

        # Only a DECLARATION, not a mention. After stripping, `thread_local` must
        # be a declaration specifier: nothing but other specifiers before it.
        head = stmt
        sub(/thread_local.*$/, "", head)
        head = squash(head)
        if (head != "") {
            hcopy = head
            gsub(/\<(static|extern|inline|constexpr|mutable|const|volatile)\>/, "", hcopy)
            if (squash(hcopy) != "") continue     # e.g. a using-decl or a comment-free mention
        }

        body = stmt
        sub(/^.*thread_local/, "", body)
        gsub(/\<(static|extern|inline|constexpr|mutable)\>/, " ", body)

        # Cut at the first top-level '=', '(', '{' or ';' — whichever ends the
        # declarator — tracking (), [] and <> so a template argument list or a
        # constructor-argument list does not terminate it early.
        cut = ""; d1 = 0; d2 = 0
        for (k = 1; k <= length(body); k++) {
            ch = substr(body, k, 1)
            if (ch == "<") d2++
            else if (ch == ">") { if (d2 > 0) d2-- }
            else if (ch == "(" || ch == "[") d1++
            else if (ch == ")" || ch == "]") d1--
            else if (d1 <= 0 && d2 <= 0 && (ch == "=" || ch == ";" || ch == "{")) break
            else if (d1 <= 0 && d2 <= 0 && ch == "(") break
            cut = cut ch
        }
        cut = squash(cut)
        if (cut == "") {
            print "PARSE " FILENAME " " ln " empty declarator after thread_local"
            continue
        }

        # The last token is the declarator name; everything before it is the
        # type. A leading '*' or '&' belongs to the type, not the name.
        nt = split(cut, tok, " ")
        if (nt < 2) {
            print "PARSE " FILENAME " " ln " cannot separate type from name in: " cut
            continue
        }
        name = tok[nt]
        ptr = ""
        while (substr(name, 1, 1) == "*" || substr(name, 1, 1) == "&") {
            ptr = ptr substr(name, 1, 1); name = substr(name, 2)
        }
        type = ""
        for (k = 1; k < nt; k++) type = type " " tok[k]
        type = squash(type) ptr
        if (type == "") {
            print "PARSE " FILENAME " " ln " no type before the declarator in: " cut
            continue
        }
        want = normtype(type)

        # The assert must be within 6 lines of the declaration, in CODE (the
        # window comes from the stripped text, so a comment cannot satisfy it),
        # and must name THIS type.
        found = 0
        win = ""
        for (k = ln; k <= ln + 6 && k <= ncl; k++) win = win " " cl[k]
        w = win
        while (match(w, /is_trivially_destructible[ \t]*</)) {
            rest = substr(w, RSTART + RLENGTH)
            # take up to the matching '>' at depth 0
            d = 0; arg = ""
            for (k = 1; k <= length(rest); k++) {
                ch = substr(rest, k, 1)
                if (ch == "<") d++
                else if (ch == ">") { if (d == 0) break; d-- }
                arg = arg ch
            }
            if (normtype(arg) == want) { found = 1; break }
            w = substr(rest, k + 1)
        }

        if (found) print "OK " FILENAME " " ln " " type
        else       print "BAD " FILENAME " " ln " " type " no static_assert(is_trivially_destructible<" type ">) in code within 6 lines"
    }
}
