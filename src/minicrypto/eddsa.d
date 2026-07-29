/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * Edwards-curve Digital Signature Algorithm (EdDSA).
 *
 * The module is a D port of Ed25519 implementation from Monocypher.
 */
module minicrypto.eddsa;

import minicrypto.finite_field;
import minicrypto.blake2b;
import minicrypto.utils;

private const(u32)[8] L = [
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
    0x00000000, 0x00000000, 0x00000000, 0x10000000,
];

//  p = a*b + p
void multiply(u32* p, const(u32)* a, const(u32)* b) @nogc nothrow
{
    //FOR(i, 0, 8);
    for (size_t i = 0; i < 8; i++)
    {
        u64 carry = 0;
        //FOR(j, 0, 8);
        for (size_t j = 0; j < 8; j++)
        {
            carry += p[i+j] + cast(u64)a[i] * b[j];
            p[i+j] = cast(u32)carry;
            carry >>= 32;
        }
        p[i+8] = cast(u32)carry;
    }
}

int is_above_l(const(u32)* x) @nogc nothrow
{
    // We work with L directly, in a 2's complement encoding
    // (-L == ~L + 1)
    u64 carry = 1;
    //FOR(i, 0, 8);
    for (size_t i = 0; i < 8; i++)
    {
        carry  += cast(u64)x[i] + (~L[i] & 0xffffffff);
        carry >>= 32;
    }
    return cast(int)carry; // carry is either 0 or 1
}

// Final reduction modulo L, by conditionally removing L.
// if x < l     , then r = x
// if l <= x 2*l, then r = x-l
// otherwise the result will be wrong
void remove_l(u32* r, const(u32)* x) @nogc nothrow
{
    u64 carry = cast(u64)is_above_l(x);
    u32 mask = ~cast(u32)carry + 1; // carry == 0 or 1
    //FOR(i, 0, 8);
    for (size_t i = 0; i < 8; i++)
    {
        carry += cast(u64)x[i] + (~L[i] & mask);
        r[i]   = cast(u32)carry;
        carry >>= 32;
    }
}

// Full reduction modulo L (Barrett reduction)
void mod_l(u8* reduced, const(u32)* x) @nogc nothrow
{
    static const(u32)[9] r = [
        0x0a2c131b,0xed9ce5a3,0x086329a7,0x2106215d,
        0xffffffeb,0xffffffff,0xffffffff,0xffffffff,0xf,
    ];
    
    // xr = x * r
    u32[25] xr = 0;
    //(FOR(i, 0, 9);
    for (size_t i = 0; i < 9; i++)
    {
        u64 carry = 0;
        //FOR(j, 0, 16);
        for (size_t j = 0; j < 16; j++)
        {
            carry  += xr[i+j] + cast(u64)r[i] * x[j];
            xr[i+j] = cast(u32)carry;
            carry >>= 32;
        }
        xr[i+16] = cast(u32)carry;
    }
    // xr = floor(xr / 2^512) * L
    // Since the result is guaranteed to be below 2*L,
    // it is enough to only compute the first 256 bits.
    // The division is performed by saying xr[i+16]. (16 * 32 = 512)
    //ZERO(xr, 8);
    for (size_t i = 0; i < 8; i++)
        xr[i] = 0;
    
    //FOR(i, 0, 8);
    for (size_t i = 0; i < 8; i++)
    {
        u64 carry = 0;
        //FOR(j, 0, 8-i);
        for (size_t j = 0; j < 8-i; j++)
        {
            carry   += xr[i+j] + cast(u64)xr[i+16] * L[j];
            xr[i+j] = cast(u32)carry;
            carry >>= 32;
        }
    }
    // xr = x - xr
    u64 carry = 1;
    //FOR(i, 0, 8);
    for (size_t i = 0; i < 8; i++)
    {
        carry  += cast(u64)x[i] + (~xr[i] & 0xffffffff);
        xr[i]   = cast(u32)carry;
        carry >>= 32;
    }
    // Final reduction modulo L (conditional subtraction)
    remove_l(xr.ptr, xr.ptr);
    store32_le_buf(reduced, xr.ptr, 8);

    //WIPE_BUFFER(xr);
    crypto_wipe(xr.ptr, xr.length * u32.sizeof);
}

void crypto_eddsa_reduce(u8* reduced, const(u8)* expanded) @nogc nothrow
{
    u32[16] x = void;
    load32_le_buf(x.ptr, expanded, 16);
    mod_l(reduced, x.ptr);
    //WIPE_BUFFER(x);
    crypto_wipe(x.ptr, x.length * u32.sizeof);
}

// r = (a * b) + c
void crypto_eddsa_mul_add(u8* r, const(u8)* a, const(u8)* b, const(u8)* c) @nogc nothrow
{
    u32[8] A = void;  load32_le_buf(A.ptr, a, 8);
    u32[8] B = void;  load32_le_buf(B.ptr, b, 8);
    u32[16] p = void; load32_le_buf(p.ptr, c, 8);
    
    //ZERO(p + 8, 8);
    for (size_t i = 8; i < 16; i++)
        p[i] = 0;
    
    multiply(p.ptr, A.ptr, B.ptr);
    mod_l(r, p.ptr);
    
    //WIPE_BUFFER(p);
    crypto_wipe(p.ptr, p.length * u32.sizeof);
    
    //WIPE_BUFFER(A);
    crypto_wipe(A.ptr, A.length * u32.sizeof);
    
    //WIPE_BUFFER(B);
    crypto_wipe(B.ptr, B.length * u32.sizeof);
}

// Point (group element, ge) in a twisted Edwards curve,
// in extended projective coordinates.
// ge        : x  = X/Z, y  = Y/Z, T  = XY/Z
// ge_cached : Yp = X+Y, Ym = X-Y, T2 = T*D2
// ge_precomp: Z  = 1
struct ge { fe X;  fe Y;  fe Z; fe T;  }
struct ge_cached { fe Yp; fe Ym; fe Z; fe T2; }
struct ge_precomp { fe Yp; fe Ym;       fe T2; }

void ge_zero(ge* p) @nogc nothrow
{
    fe_0(p.X);
    fe_1(p.Y);
    fe_1(p.Z);
    fe_0(p.T);
}

void ge_tobytes(u8* s, const(ge)* h) @nogc nothrow
{
    fe recip = void, x = void, y = void;
    fe_invert(recip, h.Z);
    fe_mul(x, h.X, recip);
    fe_mul(y, h.Y, recip);
    fe_tobytes(s, y);
    s[31] ^= cast(u8)fe_isodd(x) << 7;

    //WIPE_BUFFER(recip);
    crypto_wipe(recip.ptr, recip.length * i32.sizeof);
    
    //WIPE_BUFFER(x);
    crypto_wipe(x.ptr, x.length * i32.sizeof);
    
    //WIPE_BUFFER(y);
    crypto_wipe(y.ptr, y.length * i32.sizeof);
}

// h = -s, where s is a point encoded in 32 bytes
//
// Variable time!  Inputs must not be secret!
// => Use only to *check* signatures.
//
// From the specifications:
//   The encoding of s contains y and the sign of x
//   x = sqrt((y^2 - 1) / (d*y^2 + 1))
// In extended coordinates:
//   X = x, Y = y, Z = 1, T = x*y
//
//    Note that num * den is a square iff num / den is a square
//    If num * den is not a square, the point was not on the curve.
// From the above:
//   Let num =   y^2 - 1
//   Let den = d*y^2 + 1
//   x = sqrt((y^2 - 1) / (d*y^2 + 1))
//   x = sqrt(num / den)
//   x = sqrt(num^2 / (num * den))
//   x = num * sqrt(1 / (num * den))
//
// Therefore, we can just compute:
//   num =   y^2 - 1
//   den = d*y^2 + 1
//   isr = invsqrt(num * den)  // abort if not square
//   x   = num * isr
// Finally, negate x if its sign is not as specified.
int ge_frombytes_neg_vartime(ge* h, const(u8)* s) @nogc nothrow
{
    fe_frombytes(h.Y, s);
    fe_1(h.Z);
    fe_sq (h.T, h.Y);        // t =   y^2
    fe_mul(h.X, h.T, d   );  // x = d*y^2
    fe_sub(h.T, h.T, h.Z);  // t =   y^2 - 1
    fe_add(h.X, h.X, h.Z);  // x = d*y^2 + 1
    fe_mul(h.X, h.T, h.X);  // x = (y^2 - 1) * (d*y^2 + 1)
    int is_square = invsqrt(h.X, h.X);
    if (!is_square)
        return -1;             // Not on the curve, abort
    fe_mul(h.X, h.T, h.X);  // x = sqrt((y^2 - 1) / (d*y^2 + 1))
    if (fe_isodd(h.X) == (s[31] >> 7))
        fe_neg(h.X, h.X);
    fe_mul(h.T, h.X, h.Y);
    return 0;
}

void ge_cache(ge_cached* c, const(ge)* p) @nogc nothrow
{
    fe_add (c.Yp, p.Y, p.X);
    fe_sub (c.Ym, p.Y, p.X);
    fe_copy(c.Z , p.Z      );
    fe_mul (c.T2, p.T, D2  );
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
void ge_add(ge* s, const(ge)* p, const(ge_cached)* q) @nogc nothrow
{
    fe a = void, b = void;
    fe_add(a   , p.Y, p.X );
    fe_sub(b   , p.Y, p.X );
    fe_mul(a   , a   , q.Yp);
    fe_mul(b   , b   , q.Ym);
    fe_add(s.Y, a   , b    );
    fe_sub(s.X, a   , b    );

    fe_add(s.Z, p.Z, p.Z );
    fe_mul(s.Z, s.Z, q.Z );
    fe_mul(s.T, p.T, q.T2);
    fe_add(a   , s.Z, s.T );
    fe_sub(b   , s.Z, s.T );

    fe_mul(s.T, s.X, s.Y);
    fe_mul(s.X, s.X, b   );
    fe_mul(s.Y, s.Y, a   );
    fe_mul(s.Z, a   , b   );
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
private void ge_sub(ge* s, const(ge)* p, const(ge_cached)* q) @nogc nothrow
{
    ge_cached neg = void;
    fe_copy(neg.Ym, q.Yp);
    fe_copy(neg.Yp, q.Ym);
    fe_copy(neg.Z , q.Z );
    fe_neg (neg.T2, q.T2);
    ge_add(s, p, &neg);
}

private void ge_madd(ge* s, const(ge)* p, const(ge_precomp)* q, ref fe a, ref fe b) @nogc nothrow
{
    fe_add(a, p.Y, p.X);
    fe_sub(b, p.Y, p.X);
    fe_mul(a, a, q.Yp);
    fe_mul(b, b, q.Ym);
    fe_add(s.Y, a, b);
    fe_sub(s.X, a, b);

    fe_add(s.Z, p.Z, p.Z);
    fe_mul(s.T, p.T, q.T2);
    fe_add(a, s.Z, s.T);
    fe_sub(b, s.Z, s.T);

    fe_mul(s.T, s.X, s.Y);
    fe_mul(s.X, s.X, b);
    fe_mul(s.Y, s.Y, a);
    fe_mul(s.Z, a, b);
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
private void ge_msub(ge* s, const(ge)* p, const(ge_precomp)* q, ref fe a, ref fe b) @nogc nothrow
{
    ge_precomp neg = void;
    fe_copy(neg.Ym, q.Yp);
    fe_copy(neg.Yp, q.Ym);
    fe_neg (neg.T2, q.T2);
    ge_madd(s, p, &neg, a, b);
}

private void ge_double(ge* s, const(ge)* p, ge* q) @nogc nothrow
{
    fe_sq (q.X, p.X);
    fe_sq (q.Y, p.Y);
    fe_sq (q.Z, p.Z);          // qZ = pZ^2
    fe_mul_small(q.Z, q.Z, 2); // qZ = pZ^2 * 2
    fe_add(q.T, p.X, p.Y);
    fe_sq (s.T, q.T);
    fe_add(q.T, q.Y, q.X);
    fe_sub(q.Y, q.Y, q.X);
    fe_sub(q.X, s.T, q.T);
    fe_sub(q.Z, q.Z, q.Y);

    fe_mul(s.X, q.X , q.Z);
    fe_mul(s.Y, q.T , q.Y);
    fe_mul(s.Z, q.Y , q.Z);
    fe_mul(s.T, q.X , q.T);
}

// 5-bit signed window in cached format (Niels coordinates, Z=1)
private const(ge_precomp)[8] b_window = [
    {
        [25967493,-14356035,29566456,3660896,-12694345, 4014787,27544626,-11754271,-6079156,2047605],
        [-12545711,934262,-2722910,3049990,-727428, 9406986,12720692,5043384,19500929,-15469378],
        [-8738181,4489570,9688441,-14785194,10184609, -12363380,29287919,11864899,-24514362,-4438546]
    },
    {
        [15636291,-9688557,24204773,-7912398,616977, -16685262,27787600,-14772189,28944400,-1550024],
        [16568933,4717097,-11556148,-1102322,15682896, -11807043,16354577,-11775962,7689662,11199574],
        [30464156,-5976125,-11779434,-15670865,23220365, 15915852,7512774,10017326,-17749093,-9920357]
    },
    {
        [10861363,11473154,27284546,1981175,-30064349, 12577861,32867885,14515107,-15438304,10819380],
        [4708026,6336745,20377586,9066809,-11272109, 6594696,-25653668,12483688,-12668491,5581306],
        [19563160,16186464,-29386857,4097519,10237984, -4348115,28542350,13850243,-23678021,-15815942]
    },
    {
        [5153746,9909285,1723747,-2777874,30523605, 5516873,19480852,5230134,-23952439,-15175766],
        [-30269007,-3463509,7665486,10083793,28475525, 1649722,20654025,16520125,30598449,7715701],
        [28881845,14381568,9657904,3680757,-20181635, 7843316,-31400660,1370708,29794553,-1409300]
    },
    {
        [-22518993,-6692182,14201702,-8745502,-23510406, 8844726,18474211,-1361450,-13062696,13821877],
        [-6455177,-7839871,3374702,-4740862,-27098617, -10571707,31655028,-7212327,18853322,-14220951],
        [4566830,-12963868,-28974889,-12240689,-7602672, -2830569,-8514358,-10431137,2207753,-3209784]
    },
    {
        [-25154831,-4185821,29681144,7868801,-6854661, -9423865,-12437364,-663000,-31111463,-16132436],
        [25576264,-2703214,7349804,-11814844,16472782, 9300885,3844789,15725684,171356,6466918],
        [23103977,13316479,9739013,-16149481,817875, -15038942,8965339,-14088058,-30714912,16193877]
    },
    {
        [-33521811,3180713,-2394130,14003687,-16903474, -16270840,17238398,4729455,-18074513,9256800],
        [-25182317,-4174131,32336398,5036987,-21236817, 11360617,22616405,9761698,-19827198,630305],
        [-13720693,2639453,-24237460,-7406481,9494427, -5774029,-6554551,-15960994,-2449256,-14291300]
    },
    {
        [-3151181,-5046075,9282714,6866145,-31907062, -863023,-18940575,15033784,25105118,-7894876],
        [-24326370,15950226,-31801215,-14592823,-11662737, -5090925,1573892,-2625887,2198790,-15804619],
        [-3099351,10324967,-2241613,7453183,-5446979, -2735503,-13812022,-16236442,-32461234,-12290683]
    }
];

// Incremental sliding windows (left to right)
// Based on Roberto Maria Avanzi[2005]
struct slide_ctx
{
    i16 next_index; // position of the next signed digit
    i8 next_digit; // next signed digit (odd number below 2^window_width)
    u8 next_check; // point at which we must check for a new window
}

void slide_init(slide_ctx* ctx, const(u8)* scalar) @nogc nothrow
{
    // scalar is guaranteed to be below L, either because we checked (s),
    // or because we reduced it modulo L (h_ram). L is under 2^253, so
    // so bits 253 to 255 are guaranteed to be zero. No need to test them.
    //
    // Note however that L is very close to 2^252, so bit 252 is almost
    // always zero.  If we were to start at bit 251, the tests wouldn't
    // catch the off-by-one error (constructing one that does would be
    // prohibitively expensive).
    //
    // We should still check bit 252, though.
    int i = 252;
    while (i > 0 && scalar_bit(scalar, i) == 0)
        i--;
    
    ctx.next_check = cast(u8)(i + 1);
    ctx.next_index = -1;
    ctx.next_digit = -1;
}

int slide_step(slide_ctx* ctx, int width, int i, const(u8)* scalar) @nogc nothrow
{
    if (i == ctx.next_check)
    {
        if (scalar_bit(scalar, i) == scalar_bit(scalar, i - 1))
        {
            ctx.next_check--;
        }
        else
        {
            // compute digit of next window
            int w = MIN(width, i + 1);
            int v = -(scalar_bit(scalar, i) << (w-1));
            //FOR_T(int, j, 0, w-1);
            for (int j = 0; j < w-1; j++)
            {
                v += scalar_bit(scalar, i-(w-1)+j) << j;
            }
            v += scalar_bit(scalar, i-w);
            int lsb = v & (~v + 1); // smallest bit of v
            int s =
                (((lsb & 0xAA) != 0) << 0) |
                (((lsb & 0xCC) != 0) << 1) |
                (((lsb & 0xF0) != 0) << 2);
            ctx.next_index  = cast(i16)(i-(w-1)+s);
            ctx.next_digit  = cast(i8) (v >> s   );
            ctx.next_check -= cast(u8) w;
        }
    }
    return i == ctx.next_index ? ctx.next_digit: 0;
}

enum P_W_WIDTH = 3; // Affects the size of the stack
enum B_W_WIDTH = 5; // Affects the size of the binary
enum P_W_SIZE =  (1<<(P_W_WIDTH-2));

int crypto_eddsa_check_equation(const(u8)* signature, const(u8)* public_key, const(u8)* h) @nogc nothrow
{
    ge minus_A = void; // -public_key
    ge minus_R = void; // -first_half_of_signature
    const(u8)* s = signature + 32;

    // Check that A and R are on the curve
    // Check that 0 <= S < L (prevents malleability)
    // *Allow* non-cannonical encoding for A and R
    {
        u32[8] s32 = void;
        load32_le_buf(s32.ptr, s, 8);
        if (ge_frombytes_neg_vartime(&minus_A, public_key) ||
            ge_frombytes_neg_vartime(&minus_R, signature)  ||
            is_above_l(s32.ptr)) {
            return -1;
        }
    }

    // look-up table for minus_A
    ge_cached[P_W_SIZE] lutA = void;
    {
        ge minus_A2 = void, tmp = void;
        ge_double(&minus_A2, &minus_A, &tmp);
        ge_cache(&lutA[0], &minus_A);
        //FOR(i, 1, P_W_SIZE);
        for (size_t i = 1; i < P_W_SIZE; i++)
        {
            ge_add(&tmp, &minus_A2, &lutA[i-1]);
            ge_cache(&lutA[i], &tmp);
        }
    }

    // sum = [s]B - [h]A
    // Merged double and add ladder, fused with sliding
    slide_ctx h_slide = void;  slide_init(&h_slide, h);
    slide_ctx s_slide = void;  slide_init(&s_slide, s);
    int i = MAX(h_slide.next_check, s_slide.next_check);
    ge* sum = &minus_A; // reuse minus_A for the sum
    ge_zero(sum);
    while (i >= 0)
    {
        ge tmp = void;
        ge_double(sum, sum, &tmp);
        int h_digit = slide_step(&h_slide, P_W_WIDTH, i, h);
        int s_digit = slide_step(&s_slide, B_W_WIDTH, i, s);
        if (h_digit > 0) { ge_add(sum, sum, &lutA[ h_digit / 2]); }
        if (h_digit < 0) { ge_sub(sum, sum, &lutA[-h_digit / 2]); }
        fe t1 = void, t2 = void;
        if (s_digit > 0) { ge_madd(sum, sum, b_window.ptr +  s_digit/2, t1, t2); }
        if (s_digit < 0) { ge_msub(sum, sum, b_window.ptr + -s_digit/2, t1, t2); }
        i--;
    }

    // Compare [8](sum-R) and the zero point
    // The multiplication by 8 eliminates any low-order component
    // and ensures consistency with batched verification.
    ge_cached cached = void;
    u8[32] check = void;
    static const(u8)[32] zero_point = [1]; // Point of order 1
    ge_cache(&cached, &minus_R);
    ge_add(sum, sum, &cached);
    ge_double(sum, sum, &minus_R); // reuse minus_R as temporary
    ge_double(sum, sum, &minus_R); // reuse minus_R as temporary
    ge_double(sum, sum, &minus_R); // reuse minus_R as temporary
    ge_tobytes(check.ptr, sum);
    return crypto_verify32(check.ptr, zero_point.ptr);
}

// 5-bit signed comb in cached format (Niels coordinates, Z=1)
private const(ge_precomp)[8] b_comb_low = [
    {
        [-6816601,-2324159,-22559413,124364,18015490, 8373481,19993724,1979872,-18549925,9085059],
        [10306321,403248,14839893,9633706,8463310, -8354981,-14305673,14668847,26301366,2818560],
        [-22701500,-3210264,-13831292,-2927732,-16326337, -14016360,12940910,177905,12165515,-2397893],
    },
    {
        [-12282262,-7022066,9920413,-3064358,-32147467, 2927790,22392436,-14852487,2719975,16402117],
        [-7236961,-4729776,2685954,-6525055,-24242706, -15940211,-6238521,14082855,10047669,12228189,],
        [-30495588,-12893761,-11161261,3539405,-11502464, 16491580,-27286798,-15030530,-7272871,-15934455]
    },
    {
        [17650926,582297,-860412,-187745,-12072900, -10683391,-20352381,15557840,-31072141,-5019061],
        [-6283632,-2259834,-4674247,-4598977,-4089240, 12435688,-31278303,1060251,6256175,10480726],
        [-13871026,2026300,-21928428,-2741605,-2406664, -8034988,7355518,15733500,-23379862,7489131]
    },
    {
        [6883359,695140,23196907,9644202,-33430614, 11354760,-20134606,6388313,-8263585,-8491918],
        [-7716174,-13605463,-13646110,14757414,-19430591, -14967316,10359532,-11059670,-21935259,12082603],
        [-11253345,-15943946,10046784,5414629,24840771, 8086951,-6694742,9868723,15842692,-16224787]
    },
    {
        [9639399,11810955,-24007778,-9320054,3912937, -9856959,996125,-8727907,-8919186,-14097242],
        [7248867,14468564,25228636,-8795035,14346339, 8224790,6388427,-7181107,6468218,-8720783],
        [15513115,15439095,7342322,-10157390,18005294, -7265713,2186239,4884640,10826567,7135781]
    },
    {
        [-14204238,5297536,-5862318,-6004934,28095835, 4236101,-14203318,1958636,-16816875,3837147],
        [-5511166,-13176782,-29588215,12339465,15325758, -15945770,-8813185,11075932,-19608050,-3776283],
        [11728032,9603156,-4637821,-5304487,-7827751, 2724948,31236191,-16760175,-7268616,14799772]
    },
    {
        [-28842672,4840636,-12047946,-9101456,-1445464, 381905,-30977094,-16523389,1290540,12798615],
        [27246947,-10320914,14792098,-14518944,5302070, -8746152,-3403974,-4149637,-27061213,10749585],
        [25572375,-6270368,-15353037,16037944,1146292, 32198,23487090,9585613,24714571,-1418265]
    },
    {
        [19844825,282124,-17583147,11004019,-32004269, -2716035,6105106,-1711007,-21010044,14338445],
        [8027505,8191102,-18504907,-12335737,25173494, -5923905,15446145,7483684,-30440441,10009108],
        [-14134701,-4174411,10246585,-14677495,33553567, -14012935,23366126,15080531,-7969992,7663473]
    }
];

private const(ge_precomp)[8] b_comb_high = [
    {
        [33055887,-4431773,-521787,6654165,951411, -6266464,-5158124,6995613,-5397442,-6985227],
        [4014062,6967095,-11977872,3960002,8001989, 5130302,-2154812,-1899602,-31954493,-16173976],
        [16271757,-9212948,23792794,731486,-25808309, -3546396,6964344,-4767590,10976593,10050757]
    },
    {
        [2533007,-4288439,-24467768,-12387405,-13450051, 14542280,12876301,13893535,15067764,8594792],
        [20073501,-11623621,3165391,-13119866,13188608, -11540496,-10751437,-13482671,29588810,2197295],
        [-1084082,11831693,6031797,14062724,14748428, -8159962,-20721760,11742548,31368706,13161200]
    },
    {
        [2050412,-6457589,15321215,5273360,25484180, 124590,-18187548,-7097255,-6691621,-14604792],
        [9938196,2162889,-6158074,-1711248,4278932, -2598531,-22865792,-7168500,-24323168,11746309],
        [-22691768,-14268164,5965485,9383325,20443693, 5854192,28250679,-1381811,-10837134,13717818]
    },
    {
        [-8495530,16382250,9548884,-4971523,-4491811, -3902147,6182256,-12832479,26628081,10395408],
        [27329048,-15853735,7715764,8717446,-9215518, -14633480,28982250,-5668414,4227628,242148],
        [-13279943,-7986904,-7100016,8764468,-27276630, 3096719,29678419,-9141299,3906709,11265498]
    },
    {
        [11918285,15686328,-17757323,-11217300,-27548967, 4853165,-27168827,6807359,6871949,-1075745],
        [-29002610,13984323,-27111812,-2713442,28107359, -13266203,6155126,15104658,3538727,-7513788],
        [14103158,11233913,-33165269,9279850,31014152, 4335090,-1827936,4590951,13960841,12787712]
    },
    {
        [1469134,-16738009,33411928,13942824,8092558, -8778224,-11165065,1437842,22521552,-2792954],
        [31352705,-4807352,-25327300,3962447,12541566, -9399651,-27425693,7964818,-23829869,5541287],
        [-25732021,-6864887,23848984,3039395,-9147354, 6022816,-27421653,10590137,25309915,-1584678]
    },
    {
        [-22951376,5048948,31139401,-190316,-19542447, -626310,-17486305,-16511925,-18851313,-12985140],
        [-9684890,14681754,30487568,7717771,-10829709, 9630497,30290549,-10531496,-27798994,-13812825],
        [5827835,16097107,-24501327,12094619,7413972, 11447087,28057551,-1793987,-14056981,4359312]
    },
    {
        [26323183,2342588,-21887793,-1623758,-6062284, 2107090,-28724907,9036464,-19618351,-13055189],
        [-29697200,14829398,-4596333,14220089,-30022969, 2955645,12094100,-13693652,-5941445,7047569],
        [-3201977,14413268,-12058324,-16417589,-9035655, -7224648,9258160,1399236,30397584,-5684634]
    }
];

void lookup_add(ge* p, ge_precomp* tmp_c, fe tmp_a, fe tmp_b, const(ge_precomp)* comb, const(u8)* scalar, int i) @nogc nothrow
{
    u8 teeth = cast(u8)(
        (scalar_bit(scalar, i)) +
        (scalar_bit(scalar, i + 32) << 1) +
        (scalar_bit(scalar, i + 64) << 2) +
        (scalar_bit(scalar, i + 96) << 3));
    u8 high = teeth >> 3;
    u8 index = (teeth ^ (high - 1)) & 7;
    //FOR(j, 0, 8);
    for (size_t j = 0; j < 8; j++)
    {
        i32 select = 1 & (((j ^ index) - 1) >> 8);
        fe_ccopy(tmp_c.Yp, comb[j].Yp, select);
        fe_ccopy(tmp_c.Ym, comb[j].Ym, select);
        fe_ccopy(tmp_c.T2, comb[j].T2, select);
    }
    fe_neg(tmp_a, tmp_c.T2);
    fe_cswap(tmp_c.T2, tmp_a, high ^ 1);
    fe_cswap(tmp_c.Yp, tmp_c.Ym, high ^ 1);
    ge_madd(p, p, tmp_c, tmp_a, tmp_b);
}

// p = [scalar]B, where B is the base point
void ge_scalarmult_base(ge* p, const(u8)* scalar) @nogc nothrow
{
    // twin 4-bits signed combs, from Mike Hamburg's
    // Fast and compact elliptic-curve cryptography (2012)
    // 1 / 2 modulo L
    static const(u8)[32] half_mod_L = [
        247,233,122,46,141,49,9,44,107,206,123,81,239,124,111,10,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,
    ];
    // (2^256 - 1) / 2 modulo L
    static const(u8)[32] half_ones = [
        142,74,204,70,186,24,118,107,184,231,190,57,250,173,119,99,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,7,
    ];

    // All bits set form: 1 means 1, 0 means -1
    u8[32] s_scalar = void;
    crypto_eddsa_mul_add(s_scalar.ptr, scalar, half_mod_L.ptr, half_ones.ptr);

    // Double and add ladder
    fe tmp_a = void, tmp_b = void;  // temporaries for addition
    ge_precomp tmp_c = void; // temporary for comb lookup
    ge tmp_d = void;         // temporary for doubling
    fe_1(tmp_c.Yp);
    fe_1(tmp_c.Ym);
    fe_0(tmp_c.T2);

    // Save a double on the first iteration
    ge_zero(p);
    lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_low.ptr , s_scalar.ptr, 31);
    lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_high.ptr, s_scalar.ptr, 31+128);
    // Regular double & add for the rest
    for (int i = 30; i >= 0; i--)
    {
        ge_double(p, p, &tmp_d);
        lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_low.ptr , s_scalar.ptr, i);
        lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_high.ptr, s_scalar.ptr, i+128);
    }
    // Note: we could save one addition at the end if we assumed the
    // scalar fit in 252 bits.  Which it does in practice if it is
    // selected at random.  However, non-random, non-hashed scalars
    // *can* overflow 252 bits in practice.  Better account for that
    // than leaving that kind of subtle corner case.

    //WIPE_BUFFER(tmp_a);
    crypto_wipe(tmp_a.ptr, tmp_a.length * i32.sizeof);
    
    //WIPE_CTX(&tmp_d);
    crypto_wipe(&tmp_d, ge.sizeof);
    
    //WIPE_BUFFER(tmp_b`);
    crypto_wipe(tmp_b.ptr, tmp_b.length * i32.sizeof);
    
    //WIPE_CTX(&tmp_c);
    crypto_wipe(&tmp_c, ge_precomp.sizeof);
    
    //WIPE_BUFFER(s_scalar);
    crypto_wipe(s_scalar.ptr, s_scalar.length * u8.sizeof);
}

void crypto_eddsa_scalarbase(u8* point, const(u8)* scalar) @nogc nothrow
{
    ge P = void;
    ge_scalarmult_base(&P, scalar);
    ge_tobytes(point, &P);
    //WIPE_CTX(&P);
    crypto_wipe(&P, ge.sizeof);
}

void crypto_eddsa_key_pair(u8* secret_key, u8* public_key, u8* seed) @nogc nothrow
{
    // To allow overlaps, observable writes happen in this order:
    // 1. seed
    // 2. secret_key
    // 3. public_key
    u8[64] a = void;
    COPY(a.ptr, seed, 32);
    crypto_wipe(seed, 32);
    COPY(secret_key, a.ptr, 32);
    crypto_blake2b(a.ptr, 64, a.ptr, 32);
    crypto_eddsa_trim_scalar(a.ptr, a.ptr);
    crypto_eddsa_scalarbase(secret_key + 32, a.ptr);
    COPY(public_key, secret_key + 32, 32);
    //WIPE_BUFFER(a);
    crypto_wipe(a.ptr, a.length * u8.sizeof);
}

void hash_reduce(u8* h, const(u8)* a, size_t a_size, const(u8)* b, size_t b_size, const(u8)* c, size_t c_size) @nogc nothrow
{
    u8[64] hash = void;
    crypto_blake2b_ctx ctx = void;
    crypto_blake2b_init  (&ctx, 64);
    crypto_blake2b_update(&ctx, a, a_size);
    crypto_blake2b_update(&ctx, b, b_size);
    crypto_blake2b_update(&ctx, c, c_size);
    crypto_blake2b_final (&ctx, hash.ptr);
    crypto_eddsa_reduce(h, hash.ptr);
}

// Digital signature of a message with from a secret key.
//
// The secret key comprises two parts:
// - The seed that generates the key (secret_key[ 0..31])
// - The public key                  (secret_key[32..63])
//
// The seed and the public key are bundled together to make sure users
// don't use mismatched seeds and public keys, which would instantly
// leak the secret scalar and allow forgeries (allowing this to happen
// has resulted in critical vulnerabilities in the wild).
//
// The seed is hashed to derive the secret scalar and a secret prefix.
// The sole purpose of the prefix is to generate a secret random nonce.
// The properties of that nonce must be as follows:
// - Unique: we need a different one for each message.
// - Secret: third parties must not be able to predict it.
// - Random: any detectable bias would break all security.
//
// There are two ways to achieve these properties.  The obvious one is
// to simply generate a random number.  Here that would be a parameter
// (Monocypher doesn't have an RNG).  It works, but then users may reuse
// the nonce by accident, which _also_ leaks the secret scalar and
// allows forgeries.  This has happened in the wild too.
//
// This is no good, so instead we generate that nonce deterministically
// by reducing modulo L a hash of the secret prefix and the message.
// The secret prefix makes the nonce unpredictable, the message makes it
// unique, and the hash/reduce removes all bias.
//
// The cost of that safety is hashing the message twice.  If that cost
// is unacceptable, there are two alternatives:
//
// - Signing a hash of the message instead of the message itself.  This
//   is fine as long as the hash is collision resistant. It is not
//   compatible with existing "pure" signatures, but at least it's safe.
//
// - Using a random nonce.  Please exercise **EXTREME CAUTION** if you
//   ever do that.  It is absolutely **critical** that the nonce is
//   really an unbiased random number between 0 and L-1, never reused,
//   and wiped immediately.
//
//   To lower the likelihood of complete catastrophe if the RNG is
//   either flawed or misused, you can hash the RNG output together with
//   the secret prefix and the beginning of the message, and use the
//   reduction of that hash instead of the RNG output itself.  It's not
//   foolproof (you'd need to hash the whole message) but it helps.
//
// Signing a message involves the following operations:
//
//   scalar, prefix = HASH(secret_key)
//   r              = HASH(prefix || message) % L
//   R              = [r]B
//   h              = HASH(R || public_key || message) % L
//   S              = ((h * a) + r) % L
//   signature      = R || S
void crypto_eddsa_sign(u8* signature, const(u8)* secret_key, const(u8)* message, size_t message_size) @nogc nothrow
{
    u8[64] a = void;  // secret scalar and prefix
    u8[32] r = void;  // secret deterministic "random" nonce
    u8[32] h = void;  // publically verifiable hash of the message (not wiped)
    u8[32] R = void;  // first half of the signature (allows overlapping inputs)

    crypto_blake2b(a.ptr, 64, secret_key, 32);
    crypto_eddsa_trim_scalar(a.ptr, a.ptr);
    hash_reduce(r.ptr, a.ptr + 32, 32, message, message_size, null, 0);
    crypto_eddsa_scalarbase(R.ptr, r.ptr);
    hash_reduce(h.ptr, R.ptr, 32, secret_key + 32, 32, message, message_size);
    COPY(signature, R.ptr, 32);
    crypto_eddsa_mul_add(signature + 32, h.ptr, a.ptr, r.ptr);

    //WIPE_BUFFER(a);
    crypto_wipe(a.ptr, a.length * u8.sizeof);
    
    //WIPE_BUFFER(r);
    crypto_wipe(r.ptr, r.length * u8.sizeof);
}

// To check the signature R, S of the message M with the public key A,
// there are 3 steps:
//
//   compute h = HASH(R || A || message) % L
//   check that A is on the curve.
//   check that R == [s]B - [h]A
//
// The last two steps are done in crypto_eddsa_check_equation()
int crypto_eddsa_check(const(u8)* signature, const(u8)* public_key, const(u8)* message, size_t message_size) @nogc nothrow
{
    u8[32] h = void;
    hash_reduce(h.ptr, signature, 32, public_key, 32, message, message_size);
    return crypto_eddsa_check_equation(signature, public_key, h.ptr);
}

void crypto_eddsa_to_x25519(u8* x25519, const(u8)* eddsa)
{
    // (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
    // Only converting y to u, the sign of x is ignored.
    fe t1 = void, t2 = void;
    fe_frombytes(t2, eddsa);
    fe_add(t1, fe_one, t2);
    fe_sub(t2, fe_one, t2);
    fe_invert(t2, t2);
    fe_mul(t1, t1, t2);
    fe_tobytes(x25519, t1);
    
    //WIPE_BUFFER(t1);
    crypto_wipe(t1.ptr, t1.length * i32.sizeof);
    
    //WIPE_BUFFER(t2);
    crypto_wipe(t2.ptr, t2.length * i32.sizeof);
}

void crypto_x25519_to_eddsa(u8* eddsa, const(u8)* x25519)
{
    // (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
    // Only converting u to y, x is assumed positive.
    fe t1 = void, t2 = void;
    fe_frombytes(t2, x25519);
    fe_sub(t1, t2, fe_one);
    fe_add(t2, t2, fe_one);
    fe_invert(t2, t2);
    fe_mul(t1, t1, t2);
    fe_tobytes(eddsa, t1);
    
    //WIPE_BUFFER(t1);
    crypto_wipe(t1.ptr, t1.length * i32.sizeof);
    
    //WIPE_BUFFER(t2);
    crypto_wipe(t2.ptr, t2.length * i32.sizeof);
}

unittest
{
    import minicrypto.csprng;
    
    ubyte[32] seed = cryptoRandomValue!(ubyte[32])();
    ubyte[64] privateKey; // Secret key
    ubyte[32] publicKey;  // Public key
    ubyte[64] signature;  // Generated signature
    crypto_eddsa_key_pair(privateKey.ptr, publicKey.ptr, seed.ptr);
    
    string message = "Hello, world!";
    
    crypto_eddsa_sign(signature.ptr, privateKey.ptr, cast(const(ubyte)*)message.ptr, message.length);
    
    int verified = crypto_eddsa_check(signature.ptr, publicKey.ptr, cast(const(ubyte)*)message.ptr, message.length);
    assert(verified == 0);
}
