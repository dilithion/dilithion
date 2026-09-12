# Blank out C++ comments and string/char-literal CONTENTS, preserving line
# numbers and every other character, so a grep-based structural guard sees CODE
# only. Written in awk on purpose: the guard it serves already depends on awk,
# and adding a python dependency to a CI-wired guard means the guard can vanish
# on an image that lacks it.
#
# WHY, concretely. The stripper this replaced was `sed 's://.*::'`. It deleted
# from the FIRST // on a line to end of line, string literals included, so
#     const char* u = "see http://x"; auto* t = g_chainstate.GetTip();
# lost the real GetTip() call before the grep ever saw it. That is a FALSE PASS:
# the guard reports the invariant holds while the violation sits in the file.
#
# THEN THIS SCANNER REOPENED THE SAME CLASS, and an external round-3 seat found
# it unanimously. C++14 digit separators are apostrophes:
#     int64_t v = 5'000; auto* t = g_chainstate.GetTip();
# The first version treated that ' as a char-literal opener, blanked forward to
# the next ', and swallowed the call. Same false PASS, new spelling. The lesson
# is that a hand-rolled lexer's DEFAULT must be to refuse, not to guess: every
# construct below either has an explicit rule or exits 3.
#
# HANDLED: // to end of line; /* */ inline and multi-line; "..." and '...' with
# backslash escapes; C++14 digit separators (a ' between two hex digits is a
# token character, not a literal).
#
# REFUSED, loudly (exit 3, which fails the calling guard):
#   - a raw string literal R"delim(...)delim"
#   - ANY line whose last character is a backslash. That one rule covers
#     backslash-continued line comments, backslash-continued string and char
#     literals, and line-spliced tokens (`GetT\` + newline + `ip()`), all of
#     which would otherwise be mis-tokenised into a false PASS. Neither file
#     this guard checks contains one.
#   - a trigraph introducer ??/ (an alternative spelling of backslash; inert
#     under -std=c++17, refused anyway rather than assumed inert)
#   - a string or char literal still OPEN at end of line
# A scanner that cannot parse its input must never report CLEAN.
#
# Comment and literal bytes become spaces, so no two tokens are joined and no
# column moves.
BEGIN { inblock = 0 }

function refuse(why) { print "STRIPPER-REFUSES: " why > "/dev/stderr"; exit 3 }

# A ' that sits between two hex digits is a C++14 digit separator, not a
# literal. Checked at the quote itself, where any ' inside an earlier literal
# has already been consumed by the literal scanner.
# NB: the locals are prev/nxt - `next` is an awk RESERVED WORD and naming a
# parameter that is a syntax error, which makes the whole guard exit 1.
# A char literal may carry an encoding prefix: u8'a', u'a', U'a', L'a'.
# ONLY u8' can fool the digit-separator test - because 8 is a hex digit and so is
# a typical literal body, so `u8'a'` reads as <hexdigit>'<hexdigit> - and that is
# not theoretical: with one further apostrophe later on the line (a digit
# separator, say) the quote that should have CLOSED the char literal instead
# opens a run that blanks everything between, and
#     char c = u8'a'; auto* t = g_chainstate.GetTip(); int z = 1'000;
# came out of the scanner with the real GetTip() call erased and exit 0. A FALSE
# PASS, the exact class this scanner exists to prevent, found by an in-house read
# after the round-3 fold had already closed one instance of it.
#
# u'/U'/L' cannot fool it (u, U and L are not hex digits, so the separator test
# already fails), but they are matched here anyway: the header claims every
# construct has a rule or exits 3, and that claim should be true by construction
# rather than by luck.
function is_char_literal_prefix(line, i,    p1, p2, p3) {
    if (i < 2) return 0
    p1 = substr(line, i - 1, 1)
    p2 = (i >= 3) ? substr(line, i - 2, 1) : ""
    p3 = (i >= 4) ? substr(line, i - 3, 1) : ""
    if (p1 == "8" && (p2 == "u" || p2 == "U")) {
        if (p3 == "" || p3 !~ /[A-Za-z0-9_]/) return 1
    }
    if (p1 == "u" || p1 == "U" || p1 == "L") {
        if (p2 == "" || p2 !~ /[A-Za-z0-9_]/) return 1
    }
    return 0
}

function is_digit_separator(line, i,    prev, nxt) {
    if (i <= 1 || i >= length(line)) return 0
    prev = substr(line, i - 1, 1)
    nxt = substr(line, i + 1, 1)
    return (prev ~ /[0-9a-fA-F]/ && nxt ~ /[0-9a-fA-F]/)
}

{
    line = $0
    lastc = substr(line, length(line), 1)
    if (lastc == "\r") { lastc = substr(line, length(line) - 1, 1) }
    if (lastc == "\\") refuse("line ends in a backslash (continuation or token splice)")
    if (index(line, "??/") > 0) refuse("trigraph introducer ??/")

    out = ""; i = 1; n = length(line)
    while (i <= n) {
        c = substr(line, i, 1)
        d = substr(line, i, 2)
        if (inblock) {
            if (d == "*/") { inblock = 0; out = out "  "; i += 2 } else { out = out " "; i++ }
            continue
        }
        if (d == "//") { while (i <= n) { out = out " "; i++ } continue }
        if (d == "/*") { inblock = 1; out = out "  "; i += 2; continue }
        if (c == "\"" || c == "'") {
            if (c == "'" && !is_char_literal_prefix(line, i) && is_digit_separator(line, i)) { out = out c; i++; continue }
            # Raw string literals are refused, and the test is made HERE rather
            # than by scanning the line for the two characters R" - chain.cpp has
            # literals ending in R ("ERROR") and a line-level test cannot tell
            # those from a raw-string prefix. It refused a clean chain.cpp on
            # exactly that.
            if (c == "\"" && i > 1 && substr(line, i - 1, 1) == "R") refuse("raw string literal")
            q = c; out = out c; i++
            closed = 0
            while (i <= n) {
                c2 = substr(line, i, 1)
                if (c2 == "\\") { out = out "  "; i += 2; continue }
                if (c2 == q)    { out = out c2; i++; closed = 1; break }
                out = out " "; i++
            }
            if (!closed) {
                if (q == "\"") refuse("unterminated string literal")
                refuse("unterminated char literal")
            }
            continue
        }
        out = out c; i++
    }
    print out
}
END { if (inblock) refuse("unterminated block comment at end of file") }
