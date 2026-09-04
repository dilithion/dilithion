// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_DELIBERATE_WRAP_H
#define DILITHION_UTIL_DELIBERATE_WRAP_H

// ---------------------------------------------------------------------------
// DILITHION_DELIBERATE_SIGNED_WRAP — a NARROW, function-scoped opt-out from
// UBSan's `signed-integer-overflow` check.
//
// WHY THIS EXISTS
// ---------------
// A handful of legacy DFMP consensus functions deliberately let an int64_t
// exponential overflow and rely on the wrapped-negative result being caught by
// the floor in CalculateEffectiveTarget(). That is intentional, it is the LIVE
// consensus rule below the C-3 gate, and the project makes it well-defined by
// compiling with -fwrapv ($(CONSENSUS_CXXFLAGS); see the CONSENSUS-CRITICAL
// block in the Makefile).
//
// Those sites are the ONLY known deliberate signed wraps in the tree. When a
// build is instrumented with `-fsanitize=undefined` they are the only expected
// signed-integer-overflow reports, and silencing them the cheap way — adding
// -fwrapv to the whole sanitized build — switches the check OFF EVERYWHERE and
// buys silence at the price of a whole bug class. That is precisely the failure
// mode this macro exists to prevent: it moves the exemption from the build
// (global, invisible, unbounded) to the source (per-function, greppable, and
// documented at the site it applies to).
//
// SEMANTICS
// ---------
// The attribute affects INSTRUMENTATION ONLY. It emits no code, changes no
// arithmetic, and is a no-op in any non-sanitized build. Consensus behaviour is
// byte-identical with and without it. It does NOT make the overflow defined —
// -fwrapv is what does that, and it is still required.
//
// RULES FOR USE
// -------------
//  * ONLY on a function whose signed overflow is deliberate, documented, and
//    already made defined by -fwrapv.
//  * NEVER as a way to quiet a UBSan report you have not explained.
//  * NEVER on a whole file or translation unit.
//  * Every use must carry a comment saying which overflow it covers and why.
//
// Applying this to a function you have not proven is a deliberate wrap is the
// same defect as the global -fwrapv, only smaller — grep for this macro when
// auditing what UBSan is no longer watching.
// ---------------------------------------------------------------------------

#if defined(__has_attribute)
#  if __has_attribute(no_sanitize)
#    define DILITHION_HAS_NO_SANITIZE_ATTR 1
#  endif
#endif

#if defined(DILITHION_HAS_NO_SANITIZE_ATTR)
#  define DILITHION_DELIBERATE_SIGNED_WRAP \
       __attribute__((no_sanitize("signed-integer-overflow")))
#else
// MSVC and any toolchain without the attribute: no-op. Those toolchains do not
// build with -fsanitize=undefined here either, so nothing is lost.
#  define DILITHION_DELIBERATE_SIGNED_WRAP
#endif

#endif // DILITHION_UTIL_DELIBERATE_WRAP_H
