# Blank out C++ comments and string/char-literal CONTENTS, preserving line
# numbers and every other character, so a grep-based structural guard sees CODE
# only. Written in awk on purpose: the guard it serves already depends on awk,
# and adding a python dependency to a CI-wired guard means the guard can vanish
# on an image that lacks it.
#
# WHY, concretely. The previous stripper was `sed 's://.*::'`. It deleted from
# the FIRST `//` on a line to end of line — so a line carrying a URL in a string
# literal, e.g.
#     const char* u = "see http://x"; auto* t = g_chainstate.GetTip();
# had the real GetTip() call deleted before the grep ever saw it. That is a
# FALSE PASS: the guard reports the invariant holds while the violation sits in
# the file (mutant S10). It also could not see an inline /* */ (S11).
#
# Handled: // to end of line, /* */ inline and multi-line, "..." and '...' with
# backslash escapes. Comment and literal bytes become spaces, so no two tokens
# are joined and column positions do not move.
#
# REFUSED, loudly: raw string literals R"delim(...)delim" and a // comment
# continued onto the next line by a trailing backslash. Neither appears in the
# files this guard checks. Rather than mis-parse them silently — which is how a
# stripper manufactures a false PASS — emit a marker and exit 3 so the caller
# fails closed. A stripper that cannot parse its input must never report CLEAN.
BEGIN { inblock = 0 }
{
    line = $0
    out = ""; i = 1; n = length(line)
    while (i <= n) {
        c = substr(line, i, 1)
        d = substr(line, i, 2)
        if (inblock) {
            if (d == "*/") { inblock = 0; out = out "  "; i += 2 } else { out = out " "; i++ }
            continue
        }
        if (d == "//") {
            # Trailing-backslash test uses substr, NOT a regex. These files are
            # CRLF, so $0 ends with a CR and a plain /\$/ can never match — a
            # refusal that silently never fires is worse than no refusal. (The
            # first version here shipped a mangled pattern and accepted the very
            # file it was written to reject; running it is what caught that.)
            lastc = substr(line, length(line), 1)
            if (lastc == "\r") lastc = substr(line, length(line) - 1, 1)
            if (lastc == "\\") {
                print "STRIPPER-REFUSES: backslash-continued line comment" > "/dev/stderr"; exit 3
            }
            while (i <= n) { out = out " "; i++ }
            continue
        }
        if (d == "/*") { inblock = 1; out = out "  "; i += 2; continue }
        if (c == "\"" || c == "'") {
            # Raw string literals are refused, but the test has to be made HERE,
            # in normal state, not by scanning the line for the two characters
            # R" - chain.cpp contains string literals ending in R (`"ERROR"`),
            # and a line-level test cannot tell those from a raw-string prefix.
            # It refused a clean chain.cpp on exactly that. At this point any R
            # inside an earlier literal has already been blanked, so a preceding
            # R here really is a prefix.
            if (i > 1 && substr(line, i - 1, 1) == "R") {
                print "STRIPPER-REFUSES: raw string literal" > "/dev/stderr"; exit 3
            }
            q = c; out = out c; i++
            while (i <= n) {
                c2 = substr(line, i, 1)
                if (c2 == "\\") { out = out "  "; i += 2; continue }
                if (c2 == q)    { out = out c2; i++; break }
                out = out " "; i++
            }
            continue
        }
        out = out c; i++
    }
    print out
}
