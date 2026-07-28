/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
module minicrypto.finite_field;

import minicrypto.utils;

// field element
alias fe = i32[10];

// field constants
//
// fe_one      : 1
// sqrtm1      : sqrt(-1)
// d           :     -121665 / 121666
// D2          : 2 * -121665 / 121666
// lop_x, lop_y: low order point in Edwards coordinates
// ufactor     : -sqrt(-1) * 2
// A2          : 486662^2  (A squared)
immutable(fe) fe_one = 1;

immutable(fe) sqrtm1 = [
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482,
];

immutable(fe) d = [
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116,
];

immutable(fe) D2 = [
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199,
];

immutable(fe) lop_x = [
    21352778, 5345713, 4660180, -8347857, 24143090,
    14568123, 30185756, -12247770, -33528939, 8345319,
];

immutable(fe) lop_y = [
    -6952922, -1265500, 6862341, -7057498, -4037696,
    -5447722, 31680899, -15325402, -19365852, 1569102,
];

immutable(fe) ufactor = [
    -1917299, 15887451, -18755900, -7000830, -24778944,
    544946, -16816446, 4011309, -653372, 10741468,
];

immutable(fe) A2 = [
    12721188, 3529, 0, 0, 0, 0, 0, 0, 0, 0,
];

pragma(inline, true)
void fe_0(ref fe h) @nogc nothrow
{
    // ZERO(h, 10);
    for(size_t i = 0; i < 10; i++)
        h[i] = 0;
}

pragma(inline, true)
void fe_1(ref fe h) @nogc nothrow
{
    h[0] = 1;
    // ZERO(h+1, 9);
    for(size_t i = 1; i < 10; i++)
        h[i] = 0;
}

pragma(inline, true)
void fe_copy(ref fe h, const ref fe f) @nogc nothrow
{
    for (size_t i = 0; i < 10; i++)
        h[i] = f[i];
}

pragma(inline, true)
void fe_neg(ref fe h, const ref fe f) @nogc nothrow
{
    for (size_t i = 0; i < 10; i++)
        h[i] = -f[i];
}

pragma(inline, true)
void fe_add(ref fe h, const ref fe f, const ref fe g) @nogc nothrow
{
    for (size_t i = 0; i < 10; i++)
        h[i] = f[i] + g[i];
}

pragma(inline, true)
void fe_sub(ref fe h, const ref fe f, const ref fe g) @nogc nothrow
{
    for (size_t i = 0; i < 10; i++)
        h[i] = f[i] - g[i];
}

void fe_cswap(ref fe f, ref fe g, int b) @nogc nothrow
{
    /*volatile*/ i32 mask = -b; // -1 = 0xffffffff
    i32 x0 = (f[0] ^ g[0]) & mask;    f[0] = f[0] ^ x0;    g[0] = g[0] ^ x0;
    i32 x1 = (f[1] ^ g[1]) & mask;    f[1] = f[1] ^ x1;    g[1] = g[1] ^ x1;
    i32 x2 = (f[2] ^ g[2]) & mask;    f[2] = f[2] ^ x2;    g[2] = g[2] ^ x2;
    i32 x3 = (f[3] ^ g[3]) & mask;    f[3] = f[3] ^ x3;    g[3] = g[3] ^ x3;
    i32 x4 = (f[4] ^ g[4]) & mask;    f[4] = f[4] ^ x4;    g[4] = g[4] ^ x4;
    i32 x5 = (f[5] ^ g[5]) & mask;    f[5] = f[5] ^ x5;    g[5] = g[5] ^ x5;
    i32 x6 = (f[6] ^ g[6]) & mask;    f[6] = f[6] ^ x6;    g[6] = g[6] ^ x6;
    i32 x7 = (f[7] ^ g[7]) & mask;    f[7] = f[7] ^ x7;    g[7] = g[7] ^ x7;
    i32 x8 = (f[8] ^ g[8]) & mask;    f[8] = f[8] ^ x8;    g[8] = g[8] ^ x8;
    i32 x9 = (f[9] ^ g[9]) & mask;    f[9] = f[9] ^ x9;    g[9] = g[9] ^ x9;
}

void fe_ccopy(ref fe f, const ref fe g, int b) @nogc nothrow
{
    /*volatile*/ i32 mask = -b; // -1 = 0xffffffff
    i32 x0 = (f[0] ^ g[0]) & mask;    f[0] = f[0] ^ x0;
    i32 x1 = (f[1] ^ g[1]) & mask;    f[1] = f[1] ^ x1;
    i32 x2 = (f[2] ^ g[2]) & mask;    f[2] = f[2] ^ x2;
    i32 x3 = (f[3] ^ g[3]) & mask;    f[3] = f[3] ^ x3;
    i32 x4 = (f[4] ^ g[4]) & mask;    f[4] = f[4] ^ x4;
    i32 x5 = (f[5] ^ g[5]) & mask;    f[5] = f[5] ^ x5;
    i32 x6 = (f[6] ^ g[6]) & mask;    f[6] = f[6] ^ x6;
    i32 x7 = (f[7] ^ g[7]) & mask;    f[7] = f[7] ^ x7;
    i32 x8 = (f[8] ^ g[8]) & mask;    f[8] = f[8] ^ x8;
    i32 x9 = (f[9] ^ g[9]) & mask;    f[9] = f[9] ^ x9;
}


// Signed carry propagation
// ------------------------
//
// Let t be a number.  It can be uniquely decomposed thus:
//
//    t = h*2^26 + l
//    such that -2^25 <= l < 2^25
//
// Let c = (t + 2^25) / 2^26            (rounded down)
//     c = (h*2^26 + l + 2^25) / 2^26   (rounded down)
//     c =  h   +   (l + 2^25) / 2^26   (rounded down)
//     c =  h                           (exactly)
// Because 0 <= l + 2^25 < 2^26
//
// Let u = t          - c*2^26
//     u = h*2^26 + l - h*2^26
//     u = l
// Therefore, -2^25 <= u < 2^25
//
// Additionally, if |t| < x, then |h| < x/2^26 (rounded down)
//
// Notations:
// - In C, 1<<25 means 2^25.
// - In C, x>>25 means floor(x / (2^25)).
// - All of the above applies with 25 & 24 as well as 26 & 25.
//
//
// Note on negative right shifts
// -----------------------------
//
// In C, x >> n, where x is a negative integer, is implementation
// defined.  In practice, all platforms do arithmetic shift, which is
// equivalent to division by 2^26, rounded down.  Some compilers, like
// GCC, even guarantee it.
//
// If we ever stumble upon a platform that does not propagate the sign
// bit (we won't), visible failures will show at the slightest test, and
// the signed shifts can be replaced by the following:
//
//     typedef struct { i64 x:39; } s25;
//     typedef struct { i64 x:38; } s26;
//     i64 shift25(i64 x) { s25 s; s.x = ((u64)x)>>25; return s.x; }
//     i64 shift26(i64 x) { s26 s; s.x = ((u64)x)>>26; return s.x; }
//
// Current compilers cannot optimise this, causing a 30% drop in
// performance.  Fairly expensive for something that never happens.
//
//
// Precondition
// ------------
//
// |t0|       < 2^63
// |t1|..|t9| < 2^62
//
// Algorithm
// ---------
// c   = t0 + 2^25 / 2^26   -- |c|  <= 2^36
// t0 -= c * 2^26           -- |t0| <= 2^25
// t1 += c                  -- |t1| <= 2^63
//
// c   = t4 + 2^25 / 2^26   -- |c|  <= 2^36
// t4 -= c * 2^26           -- |t4| <= 2^25
// t5 += c                  -- |t5| <= 2^63
//
// c   = t1 + 2^24 / 2^25   -- |c|  <= 2^38
// t1 -= c * 2^25           -- |t1| <= 2^24
// t2 += c                  -- |t2| <= 2^63
//
// c   = t5 + 2^24 / 2^25   -- |c|  <= 2^38
// t5 -= c * 2^25           -- |t5| <= 2^24
// t6 += c                  -- |t6| <= 2^63
//
// c   = t2 + 2^25 / 2^26   -- |c|  <= 2^37
// t2 -= c * 2^26           -- |t2| <= 2^25        < 1.1 * 2^25  (final t2)
// t3 += c                  -- |t3| <= 2^63
//
// c   = t6 + 2^25 / 2^26   -- |c|  <= 2^37
// t6 -= c * 2^26           -- |t6| <= 2^25        < 1.1 * 2^25  (final t6)
// t7 += c                  -- |t7| <= 2^63
//
// c   = t3 + 2^24 / 2^25   -- |c|  <= 2^38
// t3 -= c * 2^25           -- |t3| <= 2^24        < 1.1 * 2^24  (final t3)
// t4 += c                  -- |t4| <= 2^25 + 2^38 < 2^39
//
// c   = t7 + 2^24 / 2^25   -- |c|  <= 2^38
// t7 -= c * 2^25           -- |t7| <= 2^24        < 1.1 * 2^24  (final t7)
// t8 += c                  -- |t8| <= 2^63
//
// c   = t4 + 2^25 / 2^26   -- |c|  <= 2^13
// t4 -= c * 2^26           -- |t4| <= 2^25        < 1.1 * 2^25  (final t4)
// t5 += c                  -- |t5| <= 2^24 + 2^13 < 1.1 * 2^24  (final t5)
//
// c   = t8 + 2^25 / 2^26   -- |c|  <= 2^37
// t8 -= c * 2^26           -- |t8| <= 2^25        < 1.1 * 2^25  (final t8)
// t9 += c                  -- |t9| <= 2^63
//
// c   = t9 + 2^24 / 2^25   -- |c|  <= 2^38
// t9 -= c * 2^25           -- |t9| <= 2^24        < 1.1 * 2^24  (final t9)
// t0 += c * 19             -- |t0| <= 2^25 + 2^38*19 < 2^44
//
// c   = t0 + 2^25 / 2^26   -- |c|  <= 2^18
// t0 -= c * 2^26           -- |t0| <= 2^25        < 1.1 * 2^25  (final t0)
// t1 += c                  -- |t1| <= 2^24 + 2^18 < 1.1 * 2^24  (final t1)
//
// Postcondition
// -------------
//   |t0|, |t2|, |t4|, |t6|, |t8|  <  1.1 * 2^25
//   |t1|, |t3|, |t5|, |t7|, |t9|  <  1.1 * 2^24
enum FE_CARRY = `
    i64 c;
    c = (t0 + (cast(i64)1<<25)) >> 26;  t0 -= c * (cast(i64)1 << 26);  t1 += c;
    c = (t4 + (cast(i64)1<<25)) >> 26;  t4 -= c * (cast(i64)1 << 26);  t5 += c;
    c = (t1 + (cast(i64)1<<24)) >> 25;  t1 -= c * (cast(i64)1 << 25);  t2 += c;
    c = (t5 + (cast(i64)1<<24)) >> 25;  t5 -= c * (cast(i64)1 << 25);  t6 += c;
    c = (t2 + (cast(i64)1<<25)) >> 26;  t2 -= c * (cast(i64)1 << 26);  t3 += c;
    c = (t6 + (cast(i64)1<<25)) >> 26;  t6 -= c * (cast(i64)1 << 26);  t7 += c;
    c = (t3 + (cast(i64)1<<24)) >> 25;  t3 -= c * (cast(i64)1 << 25);  t4 += c;
    c = (t7 + (cast(i64)1<<24)) >> 25;  t7 -= c * (cast(i64)1 << 25);  t8 += c;
    c = (t4 + (cast(i64)1<<25)) >> 26;  t4 -= c * (cast(i64)1 << 26);  t5 += c;
    c = (t8 + (cast(i64)1<<25)) >> 26;  t8 -= c * (cast(i64)1 << 26);  t9 += c;
    c = (t9 + (cast(i64)1<<24)) >> 25;  t9 -= c * (cast(i64)1 << 25);  t0 += c * 19;
    c = (t0 + (cast(i64)1<<25)) >> 26;  t0 -= c * (cast(i64)1 << 26);  t1 += c;
    h[0]=cast(i32)t0;  h[1]=cast(i32)t1;  h[2]=cast(i32)t2;  h[3]=cast(i32)t3;  h[4]=cast(i32)t4;
    h[5]=cast(i32)t5;  h[6]=cast(i32)t6;  h[7]=cast(i32)t7;  h[8]=cast(i32)t8;  h[9]=cast(i32)t9;
`;

// Decodes a field element from a byte buffer.
// mask specifies how many bits we ignore.
// Traditionally we ignore 1. It's useful for EdDSA,
// which uses that bit to denote the sign of x.
// Elligator however uses positive representatives,
// which means ignoring 2 bits instead.
void fe_frombytes_mask(ref fe h, const(u8)* s, uint nb_mask) @nogc nothrow
{
    u32 mask = 0xffffff >> nb_mask;
    i64 t0 = load32_le(s);                    // t0 < 2^32
    i64 t1 = load24_le(s +  4) << 6;          // t1 < 2^30
    i64 t2 = load24_le(s +  7) << 5;          // t2 < 2^29
    i64 t3 = load24_le(s + 10) << 3;          // t3 < 2^27
    i64 t4 = load24_le(s + 13) << 2;          // t4 < 2^26
    i64 t5 = load32_le(s + 16);               // t5 < 2^32
    i64 t6 = load24_le(s + 20) << 7;          // t6 < 2^31
    i64 t7 = load24_le(s + 23) << 5;          // t7 < 2^29
    i64 t8 = load24_le(s + 26) << 4;          // t8 < 2^28
    i64 t9 = (load24_le(s + 29) & mask) << 2;  // t9 < 2^25
    mixin(FE_CARRY); // Carry precondition OK
}

void fe_frombytes(ref fe h, const(u8)* s) @nogc nothrow
{
    fe_frombytes_mask(h, s, 1);
}

// Precondition
//   |h[0]|, |h[2]|, |h[4]|, |h[6]|, |h[8]|  <  1.1 * 2^25
//   |h[1]|, |h[3]|, |h[5]|, |h[7]|, |h[9]|  <  1.1 * 2^24
//
// Therefore, |h| < 2^255-19
// There are two possibilities:
//
// - If h is positive, all we need to do is reduce its individual
//   limbs down to their tight positive range.
// - If h is negative, we also need to add 2^255-19 to it.
//   Or just remove 19 and chop off any excess bit.
void fe_tobytes(u8* s, const ref fe h) @nogc nothrow
{
    i32[10] t = void;
    COPY(t.ptr, h.ptr, 10);
    i32 q = (19 * t[9] + ((cast(i32) 1) << 24)) >> 25;
    //                 |t9|                    < 1.1 * 2^24
    //  -1.1 * 2^24  <  t9                     < 1.1 * 2^24
    //  -21  * 2^24  <  19 * t9                < 21  * 2^24
    //  -2^29        <  19 * t9 + 2^24         < 2^29
    //  -2^29 / 2^25 < (19 * t9 + 2^24) / 2^25 < 2^29 / 2^25
    //  -16          < (19 * t9 + 2^24) / 2^25 < 16
    // FOR(i, 0, 5)
    for(size_t i = 0; i < 5; i++)
    {
        q += t[2*i  ]; q >>= 26; // q = 0 or -1
        q += t[2*i+1]; q >>= 25; // q = 0 or -1
    }
    // q =  0 iff h >= 0
    // q = -1 iff h <  0
    // Adding q * 19 to h reduces h to its proper range.
    q *= 19;  // Shift carry back to the beginning
    // FOR(i, 0, 5)
    for(size_t i = 0; i < 5; i++)
    {
        t[i*2  ] += q;  q = t[i*2  ] >> 26;  t[i*2  ] -= q * (cast(i32)1 << 26);
        t[i*2+1] += q;  q = t[i*2+1] >> 25;  t[i*2+1] -= q * (cast(i32)1 << 25);
    }
    // h is now fully reduced, and q represents the excess bit.

    store32_le(s +  0, (cast(u32)t[0] >>  0) | (cast(u32)t[1] << 26));
    store32_le(s +  4, (cast(u32)t[1] >>  6) | (cast(u32)t[2] << 19));
    store32_le(s +  8, (cast(u32)t[2] >> 13) | (cast(u32)t[3] << 13));
    store32_le(s + 12, (cast(u32)t[3] >> 19) | (cast(u32)t[4] <<  6));
    store32_le(s + 16, (cast(u32)t[5] >>  0) | (cast(u32)t[6] << 25));
    store32_le(s + 20, (cast(u32)t[6] >>  7) | (cast(u32)t[7] << 19));
    store32_le(s + 24, (cast(u32)t[7] >> 13) | (cast(u32)t[8] << 12));
    store32_le(s + 28, (cast(u32)t[8] >> 20) | (cast(u32)t[9] <<  6));

    //WIPE_BUFFER(t);
    crypto_wipe(t.ptr, t.length * i32.sizeof);
}

// Precondition
// -------------
//   |f0|, |f2|, |f4|, |f6|, |f8|  <  1.65 * 2^26
//   |f1|, |f3|, |f5|, |f7|, |f9|  <  1.65 * 2^25
//
//   |g0|, |g2|, |g4|, |g6|, |g8|  <  1.65 * 2^26
//   |g1|, |g3|, |g5|, |g7|, |g9|  <  1.65 * 2^25
void fe_mul_small(ref fe h, const ref fe f, i32 g) @nogc nothrow
{
    i64 t0 = f[0] * cast(i64) g;  i64 t1 = f[1] * cast(i64) g;
    i64 t2 = f[2] * cast(i64) g;  i64 t3 = f[3] * cast(i64) g;
    i64 t4 = f[4] * cast(i64) g;  i64 t5 = f[5] * cast(i64) g;
    i64 t6 = f[6] * cast(i64) g;  i64 t7 = f[7] * cast(i64) g;
    i64 t8 = f[8] * cast(i64) g;  i64 t9 = f[9] * cast(i64) g;
    // |t0|, |t2|, |t4|, |t6|, |t8|  <  1.65 * 2^26 * 2^31  < 2^58
    // |t1|, |t3|, |t5|, |t7|, |t9|  <  1.65 * 2^25 * 2^31  < 2^57

    mixin(FE_CARRY); // Carry precondition OK
}

// Precondition
// -------------
//   |f0|, |f2|, |f4|, |f6|, |f8|  <  1.65 * 2^26
//   |f1|, |f3|, |f5|, |f7|, |f9|  <  1.65 * 2^25
//
//   |g0|, |g2|, |g4|, |g6|, |g8|  <  1.65 * 2^26
//   |g1|, |g3|, |g5|, |g7|, |g9|  <  1.65 * 2^25
void fe_mul(ref fe h, const ref fe f, const ref fe g) @nogc nothrow
{
    // Everything is unrolled and put in temporary variables.
    // We could roll the loop, but that would make curve25519 twice as slow.
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 g0 = g[0]; i32 g1 = g[1]; i32 g2 = g[2]; i32 g3 = g[3]; i32 g4 = g[4];
    i32 g5 = g[5]; i32 g6 = g[6]; i32 g7 = g[7]; i32 g8 = g[8]; i32 g9 = g[9];
    i32 F1 = f1*2; i32 F3 = f3*2; i32 F5 = f5*2; i32 F7 = f7*2; i32 F9 = f9*2;
    i32 G1 = g1*19;  i32 G2 = g2*19;  i32 G3 = g3*19;
    i32 G4 = g4*19;  i32 G5 = g5*19;  i32 G6 = g6*19;
    i32 G7 = g7*19;  i32 G8 = g8*19;  i32 G9 = g9*19;
    
    // |F1|, |F3|, |F5|, |F7|, |F9|  <  1.65 * 2^26
    // |G0|, |G2|, |G4|, |G6|, |G8|  <  2^31
    // |G1|, |G3|, |G5|, |G7|, |G9|  <  2^30

    i64 t0 = f0*cast(i64)g0 + F1*cast(i64)G9 + f2*cast(i64)G8 + F3*cast(i64)G7 + f4*cast(i64)G6
           + F5*cast(i64)G5 + f6*cast(i64)G4 + F7*cast(i64)G3 + f8*cast(i64)G2 + F9*cast(i64)G1;
    i64 t1 = f0*cast(i64)g1 + f1*cast(i64)g0 + f2*cast(i64)G9 + f3*cast(i64)G8 + f4*cast(i64)G7
           + f5*cast(i64)G6 + f6*cast(i64)G5 + f7*cast(i64)G4 + f8*cast(i64)G3 + f9*cast(i64)G2;
    i64 t2 = f0*cast(i64)g2 + F1*cast(i64)g1 + f2*cast(i64)g0 + F3*cast(i64)G9 + f4*cast(i64)G8
           + F5*cast(i64)G7 + f6*cast(i64)G6 + F7*cast(i64)G5 + f8*cast(i64)G4 + F9*cast(i64)G3;
    i64 t3 = f0*cast(i64)g3 + f1*cast(i64)g2 + f2*cast(i64)g1 + f3*cast(i64)g0 + f4*cast(i64)G9
           + f5*cast(i64)G8 + f6*cast(i64)G7 + f7*cast(i64)G6 + f8*cast(i64)G5 + f9*cast(i64)G4;
    i64 t4 = f0*cast(i64)g4 + F1*cast(i64)g3 + f2*cast(i64)g2 + F3*cast(i64)g1 + f4*cast(i64)g0
           + F5*cast(i64)G9 + f6*cast(i64)G8 + F7*cast(i64)G7 + f8*cast(i64)G6 + F9*cast(i64)G5;
    i64 t5 = f0*cast(i64)g5 + f1*cast(i64)g4 + f2*cast(i64)g3 + f3*cast(i64)g2 + f4*cast(i64)g1
           + f5*cast(i64)g0 + f6*cast(i64)G9 + f7*cast(i64)G8 + f8*cast(i64)G7 + f9*cast(i64)G6;
    i64 t6 = f0*cast(i64)g6 + F1*cast(i64)g5 + f2*cast(i64)g4 + F3*cast(i64)g3 + f4*cast(i64)g2
           + F5*cast(i64)g1 + f6*cast(i64)g0 + F7*cast(i64)G9 + f8*cast(i64)G8 + F9*cast(i64)G7;
    i64 t7 = f0*cast(i64)g7 + f1*cast(i64)g6 + f2*cast(i64)g5 + f3*cast(i64)g4 + f4*cast(i64)g3
           + f5*cast(i64)g2 + f6*cast(i64)g1 + f7*cast(i64)g0 + f8*cast(i64)G9 + f9*cast(i64)G8;
    i64 t8 = f0*cast(i64)g8 + F1*cast(i64)g7 + f2*cast(i64)g6 + F3*cast(i64)g5 + f4*cast(i64)g4
           + F5*cast(i64)g3 + f6*cast(i64)g2 + F7*cast(i64)g1 + f8*cast(i64)g0 + F9*cast(i64)G9;
    i64 t9 = f0*cast(i64)g9 + f1*cast(i64)g8 + f2*cast(i64)g7 + f3*cast(i64)g6 + f4*cast(i64)g5
           + f5*cast(i64)g4 + f6*cast(i64)g3 + f7*cast(i64)g2 + f8*cast(i64)g1 + f9*cast(i64)g0;
    
    // t0 < 0.67 * 2^61
    // t1 < 0.41 * 2^61
    // t2 < 0.52 * 2^61
    // t3 < 0.32 * 2^61
    // t4 < 0.38 * 2^61
    // t5 < 0.22 * 2^61
    // t6 < 0.23 * 2^61
    // t7 < 0.13 * 2^61
    // t8 < 0.09 * 2^61
    // t9 < 0.03 * 2^61

    mixin(FE_CARRY); // Everything below 2^62, Carry precondition OK
}

// Precondition
// -------------
//   |f0|, |f2|, |f4|, |f6|, |f8|  <  1.65 * 2^26
//   |f1|, |f3|, |f5|, |f7|, |f9|  <  1.65 * 2^25
//
// Note: we could use fe_mul() for this, but this is significantly faster
void fe_sq(ref fe h, const ref fe f) @nogc nothrow
{
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 f0_2 = f0*2;   i32 f1_2 = f1*2;   i32 f2_2 = f2*2;   i32 f3_2 = f3*2;
    i32 f4_2 = f4*2;   i32 f5_2 = f5*2;   i32 f6_2 = f6*2;   i32 f7_2 = f7*2;
    i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
    i32 f8_19 = f8*19;  i32 f9_38 = f9*38;
    
    // |f0_2| , |f2_2| , |f4_2| , |f6_2| , |f8_2|  <  1.65 * 2^27
    // |f1_2| , |f3_2| , |f5_2| , |f7_2| , |f9_2|  <  1.65 * 2^26
    // |f5_38|, |f6_19|, |f7_38|, |f8_19|, |f9_38| <  2^31

    i64 t0 = f0  *cast(i64)f0    + f1_2*cast(i64)f9_38 + f2_2*cast(i64)f8_19
           + f3_2*cast(i64)f7_38 + f4_2*cast(i64)f6_19 + f5  *cast(i64)f5_38;
    i64 t1 = f0_2*cast(i64)f1    + f2  *cast(i64)f9_38 + f3_2*cast(i64)f8_19
           + f4  *cast(i64)f7_38 + f5_2*cast(i64)f6_19;
    i64 t2 = f0_2*cast(i64)f2    + f1_2*cast(i64)f1    + f3_2*cast(i64)f9_38
           + f4_2*cast(i64)f8_19 + f5_2*cast(i64)f7_38 + f6  *cast(i64)f6_19;
    i64 t3 = f0_2*cast(i64)f3    + f1_2*cast(i64)f2    + f4  *cast(i64)f9_38
           + f5_2*cast(i64)f8_19 + f6  *cast(i64)f7_38;
    i64 t4 = f0_2*cast(i64)f4    + f1_2*cast(i64)f3_2  + f2  *cast(i64)f2
           + f5_2*cast(i64)f9_38 + f6_2*cast(i64)f8_19 + f7  *cast(i64)f7_38;
    i64 t5 = f0_2*cast(i64)f5    + f1_2*cast(i64)f4    + f2_2*cast(i64)f3
           + f6  *cast(i64)f9_38 + f7_2*cast(i64)f8_19;
    i64 t6 = f0_2*cast(i64)f6    + f1_2*cast(i64)f5_2  + f2_2*cast(i64)f4
           + f3_2*cast(i64)f3    + f7_2*cast(i64)f9_38 + f8  *cast(i64)f8_19;
    i64 t7 = f0_2*cast(i64)f7    + f1_2*cast(i64)f6    + f2_2*cast(i64)f5
           + f3_2*cast(i64)f4    + f8  *cast(i64)f9_38;
    i64 t8 = f0_2*cast(i64)f8    + f1_2*cast(i64)f7_2  + f2_2*cast(i64)f6
           + f3_2*cast(i64)f5_2  + f4  *cast(i64)f4    + f9  *cast(i64)f9_38;
    i64 t9 = f0_2*cast(i64)f9    + f1_2*cast(i64)f8    + f2_2*cast(i64)f7
           + f3_2*cast(i64)f6    + f4  *cast(i64)f5_2;
    
    // t0 < 0.67 * 2^61
    // t1 < 0.41 * 2^61
    // t2 < 0.52 * 2^61
    // t3 < 0.32 * 2^61
    // t4 < 0.38 * 2^61
    // t5 < 0.22 * 2^61
    // t6 < 0.23 * 2^61
    // t7 < 0.13 * 2^61
    // t8 < 0.09 * 2^61
    // t9 < 0.03 * 2^61

    mixin(FE_CARRY);
}

//  Parity check.  Returns 0 if even, 1 if odd
int fe_isodd(const ref fe f) @nogc nothrow
{
    u8[32] s = void;
    fe_tobytes(s.ptr, f);
    u8 isodd = s[0] & 1;
    //WIPE_BUFFER(s);
    crypto_wipe(s.ptr, s.length * u8.sizeof);
    return isodd;
}

// Returns 1 if equal, 0 if not equal
int fe_isequal(const ref fe f, const ref fe g) @nogc nothrow
{
    u8[32] fs = void;
    u8[32] gs = void;
    fe_tobytes(fs.ptr, f);
    fe_tobytes(gs.ptr, g);
    int isdifferent = crypto_verify32(fs.ptr, gs.ptr);
    //WIPE_BUFFER(fs);
    crypto_wipe(fs.ptr, fs.length * u8.sizeof);
    //WIPE_BUFFER(gs);
    crypto_wipe(gs.ptr, gs.length * u8.sizeof);
    return 1 + isdifferent;
}

// Inverse square root.
// Returns true if x is a square, false otherwise.
// After the call:
//   isr = sqrt(1/x)        if x is a non-zero square.
//   isr = sqrt(sqrt(-1)/x) if x is not a square.
//   isr = 0                if x is zero.
// We do not guarantee the sign of the square root.
//
// Notes:
// Let quartic = x^((p-1)/4)
//
// x^((p-1)/2) = chi(x)
// quartic^2   = chi(x)
// quartic     = sqrt(chi(x))
// quartic     = 1 or -1 or sqrt(-1) or -sqrt(-1)
//
// Note that x is a square if quartic is 1 or -1
// There are 4 cases to consider:
//
// if   quartic         = 1  (x is a square)
// then x^((p-1)/4)     = 1
//      x^((p-5)/4) * x = 1
//      x^((p-5)/4)     = 1/x
//      x^((p-5)/8)     = sqrt(1/x) or -sqrt(1/x)
//
// if   quartic                = -1  (x is a square)
// then x^((p-1)/4)            = -1
//      x^((p-5)/4) * x        = -1
//      x^((p-5)/4)            = -1/x
//      x^((p-5)/8)            = sqrt(-1)   / sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = sqrt(-1)^2 / sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = -1/sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = -sqrt(1/x) or sqrt(1/x)
//
// if   quartic         = sqrt(-1)  (x is not a square)
// then x^((p-1)/4)     = sqrt(-1)
//      x^((p-5)/4) * x = sqrt(-1)
//      x^((p-5)/4)     = sqrt(-1)/x
//      x^((p-5)/8)     = sqrt(sqrt(-1)/x) or -sqrt(sqrt(-1)/x)
//
// Note that the product of two non-squares is always a square:
//   For any non-squares a and b, chi(a) = -1 and chi(b) = -1.
//   Since chi(x) = x^((p-1)/2), chi(a)*chi(b) = chi(a*b) = 1.
//   Therefore a*b is a square.
//
//   Since sqrt(-1) and x are both non-squares, their product is a
//   square, and we can compute their square root.
//
// if   quartic                = -sqrt(-1)  (x is not a square)
// then x^((p-1)/4)            = -sqrt(-1)
//      x^((p-5)/4) * x        = -sqrt(-1)
//      x^((p-5)/4)            = -sqrt(-1)/x
//      x^((p-5)/8)            = sqrt(-sqrt(-1)/x)
//      x^((p-5)/8)            = sqrt( sqrt(-1)/x) * sqrt(-1)
//      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * sqrt(-1)^2
//      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * -1
//      x^((p-5)/8) * sqrt(-1) = -sqrt(sqrt(-1)/x) or sqrt(sqrt(-1)/x)
int invsqrt(ref fe isr, const ref fe x) @nogc nothrow
{
    fe t0 = void, t1 = void, t2 = void;

    // t0 = x^((p-5)/8)
    // Can be achieved with a simple double & add ladder,
    // but it would be slower.
    fe_sq(t0, x);
    fe_sq(t1,t0);                     fe_sq(t1, t1);    fe_mul(t1, x, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);                                      fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  for(size_t i = 1; i < 5;   i++) { fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  for(size_t i = 1; i < 10;  i++) { fe_sq(t1, t1); }  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  for(size_t i = 1; i < 20;  i++) { fe_sq(t2, t2); }  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  for(size_t i = 1; i < 10;  i++) { fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  for(size_t i = 1; i < 50;  i++) { fe_sq(t1, t1); }  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  for(size_t i = 1; i < 100; i++) { fe_sq(t2, t2); }  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  for(size_t i = 1; i < 50;  i++) { fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
    fe_sq(t0, t0);  for(size_t i = 1; i < 2;   i++) { fe_sq(t0, t0); }  fe_mul(t0, t0, x);

    // quartic = x^((p-1)/4)
    fe_sq (t1, t0);
    fe_mul(t1, t1, x);

    fe_0(t2);           int z0 = fe_isequal(x, t2);
    fe_1(t2);           int p1 = fe_isequal(t1, t2);
    fe_neg(t2, t2 );    int m1 = fe_isequal(t1, t2);
    fe_neg(t2, sqrtm1); int ms = fe_isequal(t1, t2);

    // if quartic == -1 or sqrt(-1)
    // then  isr = x^((p-1)/4) * sqrt(-1)
    // else  isr = x^((p-1)/4)
    fe_mul(isr, t0, sqrtm1);
    fe_ccopy(isr, t0, 1 - (m1 | ms));

    //WIPE_BUFFER(t0);
    crypto_wipe(t0.ptr, t0.length * i32.sizeof);
    
    //WIPE_BUFFER(t1);
    crypto_wipe(t1.ptr, t1.length * i32.sizeof);
    
    //WIPE_BUFFER(t2);
    crypto_wipe(t2.ptr, t2.length * i32.sizeof);
    
    return p1 | m1 | z0;
}

// Inverse in terms of inverse square root.
// Requires two additional squarings to get rid of the sign.
//
//   1/x = x * (+invsqrt(x^2))^2
//       = x * (-invsqrt(x^2))^2
//
// A fully optimised exponentiation by p-1 would save 6 field
// multiplications, but it would require more code.
void fe_invert(ref fe out_, const ref fe x) @nogc nothrow
{
    fe tmp = void;
    fe_sq(tmp, x);
    invsqrt(tmp, tmp);
    fe_sq(tmp, tmp);
    fe_mul(out_, tmp, x);
    //WIPE_BUFFER(tmp);
    crypto_wipe(tmp.ptr, tmp.length * i32.sizeof);
}

// trim a scalar for scalar multiplication
void crypto_eddsa_trim_scalar(u8* out_, const(u8)* in_) @nogc nothrow
{
    COPY(out_, in_, 32);
    out_[ 0] &= 248;
    out_[31] &= 127;
    out_[31] |= 64;
}

// get bit from scalar at position i
int scalar_bit(const(u8)* s, int i) @nogc nothrow
{
    if (i < 0)
        return 0; // handle -1 for sliding windows
    return (s[i>>3] >> (i&7)) & 1;
}
