/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
module minicrypto.utils;

import core.stdc.stdint;
import core.volatile;

//#define COPY(dst, src, size) FOR(_i_, 0, size) (dst)[_i_] = (src)[_i_]
pragma(inline, true)
void COPY(T)(T* dst, const(T)* src, size_t size) @nogc nothrow
{
    for(size_t i = 0; i < size; i++)
    {
        dst[i] = src[i];
    }
}

// #define MIN(a, b) ((a) <= (b) ? (a) : (b))
pragma(inline, true)
T MIN(T)(T a, T b) @nogc nothrow
{
    return ((a) <= (b) ? (a) : (b));
}

//#define MAX(a, b) ((a) >= (b) ? (a) : (b))
pragma(inline, true)
T MAX(T)(T a, T b) @nogc nothrow
{
    return ((a) >= (b) ? (a) : (b));
}

alias i8 = byte;
alias u8 = ubyte;
alias i16 = short;
alias u32 = uint;
alias i32 = int;
alias i64 = long;
alias u64 = ulong;

const(u8)[128] zero = 0;

// returns the smallest positive integer y such that
// (x + y) % pow_2  == 0
// Basically, y is the "gap" missing to align x.
// Only works when pow_2 is a power of 2.
// Note: we use ~x+1 instead of -x to avoid compiler warnings
size_t gap(size_t x, size_t pow_2) @nogc nothrow
{
    return (~x + 1) & (pow_2 - 1);
}

u32 load24_le(const(u8)* s) @nogc nothrow
{
    return
        (cast(u32)s[0] <<  0) |
        (cast(u32)s[1] <<  8) |
        (cast(u32)s[2] << 16);
}

u32 load32_le(const(u8)* s) @nogc nothrow
{
    return
        (cast(u32)s[0] <<  0) |
        (cast(u32)s[1] <<  8) |
        (cast(u32)s[2] << 16) |
        (cast(u32)s[3] << 24);
}

u64 load64_le(const(u8)* s) @nogc nothrow
{
    return load32_le(s) | (cast(u64)load32_le(s+4) << 32);
}

void store32_le(u8* out_, u32 in_) @nogc nothrow
{
    out_[0] = cast(u8)(in_      );
    out_[1] = cast(u8)(in_ >>  8);
    out_[2] = cast(u8)(in_ >> 16);
    out_[3] = cast(u8)(in_ >> 24);
}

void store64_le(u8* out_, u64 in_) @nogc nothrow
{
    store32_le(out_    , cast(u32)(in_      ));
    store32_le(out_ + 4, cast(u32)(in_ >> 32));
}

void load32_le_buf(u32* dst, const(u8)* src, size_t size) @nogc nothrow
{
    for (size_t i = 0; i < size; i++) { dst[i] = load32_le(src + i*4); }
}

void load64_le_buf(u64* dst, const(u8)* src, size_t size) @nogc nothrow
{
    for (size_t i = 0; i < size; i++) { dst[i] = load64_le(src + i*8); }
}

void store32_le_buf(u8* dst, const(u32)* src, size_t size) @nogc nothrow
{
    for (size_t i = 0; i < size; i++) { store32_le(dst + i*4, src[i]); }
}

void store64_le_buf(u8* dst, const(u64)* src, size_t size) @nogc nothrow
{
    for (size_t i = 0; i < size; i++) { store64_le(dst + i*8, src[i]); }
}

u64 rotr64(u64 x, u64 n) @nogc nothrow { return (x >> n) ^ (x << (64 - n)); }
u32 rotl32(u32 x, u32 n) @nogc nothrow { return (x << n) ^ (x >> (32 - n)); }

int neq0(u64 diff) @nogc nothrow
{
    // constant time comparison to zero
    // return diff != 0 ? -1 : 0
    u64 half = (diff >> 32) | (cast(u32)diff);  // half < 2^32
    u64 eq0 = 1 & ((half - 1) >> 32); // half == 0 ? 1 : 0
    return cast(int)eq0 - 1; // half == 0 ? 0 : -1
}

u64 x16(const(u8)* a, const(u8)* b) @nogc nothrow
{
    return (load64_le(a + 0) ^ load64_le(b + 0)) |
           (load64_le(a + 8) ^ load64_le(b + 8));
}

u64 x32(const(u8)* a, const(u8)* b) @nogc nothrow {return x16(a,b)| x16(a+16, b+16);}
u64 x64(const(u8)* a, const(u8)* b) @nogc nothrow {return x32(a,b)| x32(a+32, b+32);}
int crypto_verify16(const(u8)* a, const(u8)* b) @nogc nothrow { return neq0(x16(a, b)); }
int crypto_verify32(const(u8)* a, const(u8)* b) @nogc nothrow { return neq0(x32(a, b)); }
int crypto_verify64(const(u8)* a, const(u8)* b) @nogc nothrow { return neq0(x64(a, b)); }

void crypto_wipe(void* secret, size_t size) @nogc nothrow
{
    u8* v_secret = cast(u8*)secret;
    for (size_t i = 0; i < size; i++) 
        volatileStore(v_secret + i, 0);
}
