// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// UBSan leg positive control. See ubsan_positive_control.sh for why it exists.
//
// The exponent comes from argv so no compiler can constant-fold the undefined
// shift away. `3` is the clean arm, `40` is undefined behaviour on a 32-bit int.
// A shift is used rather than signed overflow because project code is built with
// -fwrapv, which makes signed overflow defined.

#include <cstdio>
#include <cstdlib>

static int shift_left(int value, int exponent) { return value << exponent; }

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <exponent>\n", argv[0]);
        return 2;
    }
    const int exponent = std::atoi(argv[1]);
    std::printf("1 << %d = %d\n", exponent, shift_left(1, exponent));
    return 0;
}
