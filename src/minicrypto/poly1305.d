/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * One-time message authentication code (MAC) designed by Daniel J. Bernstein.
 * The module is a D port of Poly1305 implementation from Monocypher.
 */
module minicrypto.poly1305;

import core.stdc.stdint;
import minicrypto.utils;

// Incremental interface
struct crypto_poly1305_ctx
{
    // Do not rely on the size or contents of this type,
    // for they may change without notice.
    uint8_t[16] c;   // chunk of the message
    size_t c_idx;    // How many bytes are there in the chunk.
    uint32_t[4] r;   // constant multiplier (from the secret key)
    uint32_t[4] pad; // random number added at the end (from the secret key)
    uint32_t[5] h;   // accumulated hash
}

// h = (h + c) * r
// preconditions:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
//   end    <= 1
// Postcondition:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
private void poly_blocks(crypto_poly1305_ctx* ctx, const(u8)* in_, size_t nb_blocks, uint end) @nogc nothrow
{
    // Local all the things!
    const(u32) r0 = ctx.r[0];
    const(u32) r1 = ctx.r[1];
    const(u32) r2 = ctx.r[2];
    const(u32) r3 = ctx.r[3];
    const(u32) rr0 = (r0 >> 2) * 5;  // lose 2 bits...
    const(u32) rr1 = (r1 >> 2) + r1; // rr1 == (r1 >> 2) * 5
    const(u32) rr2 = (r2 >> 2) + r2; // rr1 == (r2 >> 2) * 5
    const(u32) rr3 = (r3 >> 2) + r3; // rr1 == (r3 >> 2) * 5
    const(u32) rr4 = r0 & 3;         // ...recover 2 bits
    u32 h0 = ctx.h[0];
    u32 h1 = ctx.h[1];
    u32 h2 = ctx.h[2];
    u32 h3 = ctx.h[3];
    u32 h4 = ctx.h[4];

    //FOR(i, 0, nb_blocks)
    for (size_t i = 0; i < nb_blocks; i++)
    {
        // h + c, without carry propagation
        const(u64) s0 = cast(u64)h0 + load32_le(in_);  in_ += 4;
        const(u64) s1 = cast(u64)h1 + load32_le(in_);  in_ += 4;
        const(u64) s2 = cast(u64)h2 + load32_le(in_);  in_ += 4;
        const(u64) s3 = cast(u64)h3 + load32_le(in_);  in_ += 4;
        const(u32) s4 = h4 + end;

        pragma(msg, typeof(s0 * r0).stringof);

        // (h + c) * r, without carry propagation
        const(u64) x0 = s0 * r0+ s1 * rr3 + s2 * rr2 + s3 * rr1 + s4 * rr0;
        const(u64) x1 = s0 * r1+ s1 * r0  + s2 * rr3 + s3 * rr2 + s4 * rr1;
        const(u64) x2 = s0 * r2+ s1 * r1  + s2 * r0  + s3 * rr3 + s4 * rr2;
        const(u64) x3 = s0 * r3+ s1 * r2  + s2 * r1  + s3 * r0  + s4 * rr3;
        const(u32) x4 = s4*rr4;

        // partial reduction modulo 2^130 - 5
        const(u32) u5 = cast(u32)(x3 >> 32) + x4; // u5 <= 7ffffff5
        const(u64) u0 = cast(u32)(u5 >>  2) * 5 + (x0 & 0xffffffff);
        const(u64) u1 = cast(u32)(u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
        const(u64) u2 = cast(u32)(u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
        const(u64) u3 = cast(u32)(u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
        const(u32) u4 = cast(u32)(u3 >> 32)     + (u5 & 3); // u4 <= 4

        // Update the hash
        h0 = u0 & 0xffffffff;
        h1 = u1 & 0xffffffff;
        h2 = u2 & 0xffffffff;
        h3 = u3 & 0xffffffff;
        h4 = u4;
    }
    ctx.h[0] = h0;
    ctx.h[1] = h1;
    ctx.h[2] = h2;
    ctx.h[3] = h3;
    ctx.h[4] = h4;
}

void crypto_poly1305_init(crypto_poly1305_ctx* ctx, const(u8)* key) @nogc nothrow
{
    // ZERO(ctx.h, 5)
    for (size_t i = 0; i < ctx.h.length; i++)
        ctx.h[i] = 0; // Initial hash is zero
    
    ctx.c_idx = 0;
    // load r and pad (r has some of its bits cleared)
    load32_le_buf(ctx.r.ptr, key, 4);
    load32_le_buf(ctx.pad.ptr, key + 16, 4);
    
    //FOR (i, 0, 1) { ctx->r[i] &= 0x0fffffff; }
    for (size_t i = 0; i < 1; i++) { ctx.r[i] &= 0x0fffffff; }
    
    //FOR (i, 1, 4) { ctx->r[i] &= 0x0ffffffc; }
    for (size_t i = 1; i < 4; i++) { ctx.r[i] &= 0x0ffffffc; }
}

void crypto_poly1305_update(crypto_poly1305_ctx* ctx, const(u8)* message, size_t message_size) @nogc nothrow
{
    // Avoid undefined null pointer increments with empty messages
    if (message_size == 0)
        return;

    // Align ourselves with block boundaries
    size_t aligned = MIN(gap(ctx.c_idx, 16), message_size);
    
    //FOR(i, 0, aligned)
    for (size_t i = 0; i < aligned; i++)
    {
        ctx.c[ctx.c_idx] = *message;
        ctx.c_idx++;
        message++;
        message_size--;
    }

    // If block is complete, process it
    if (ctx.c_idx == 16)
    {
        poly_blocks(ctx, ctx.c.ptr, 1, 1);
        ctx.c_idx = 0;
    }

    // Process the message block by block
    size_t nb_blocks = message_size >> 4;
    poly_blocks(ctx, message, nb_blocks, 1);
    message += nb_blocks << 4;
    message_size &= 15;

    // remaining bytes (we never complete a block here)
    //FOR(i, 0, message_size)
    for (size_t i = 0; i < message_size; i++)
    {
        ctx.c[ctx.c_idx] = message[i];
        ctx.c_idx++;
    }
}

void crypto_poly1305_final(crypto_poly1305_ctx* ctx, u8* mac) @nogc nothrow
{
    // Process the last block (if any)
    // We move the final 1 according to remaining input length
    // (this will add less than 2^130 to the last input block)
    if (ctx.c_idx != 0)
    {
        //ZERO(ctx.c + ctx.c_idx, 16 - ctx.c_idx);
        auto p = ctx.c.ptr + ctx.c_idx;
        for (size_t i = 0; i < 16 - ctx.c_idx; i++)
        {
            p[i] = 0;
        }
        ctx.c[ctx.c_idx] = 1;
        poly_blocks(ctx, ctx.c.ptr, 1, 0);
    }

    // check if we should subtract 2^130-5 by performing the
    // corresponding carry propagation.
    u64 c = 5;
    //FOR(i, 0, 4);
    for (size_t i = 0; i < 4; i++)
    {
        c  += ctx.h[i];
        c >>= 32;
    }
    c += ctx.h[4];
    c  = (c >> 2) * 5; // shift the carry back to the beginning
    // c now indicates how many times we should subtract 2^130-5 (0 or 1)
    
    //FOR(i, 0, 4);
    for (size_t i = 0; i < 4; i++)
    {
        c += cast(u64)ctx.h[i] + ctx.pad[i];
        store32_le(mac + i*4, cast(u32)c);
        c = c >> 32;
    }
    
    //WIPE_CTX(ctx);
    crypto_wipe(ctx, crypto_poly1305_ctx.sizeof);
}

void crypto_poly1305(u8* mac, const(u8)* message, size_t message_size, const(u8)* key) @nogc nothrow
{
    crypto_poly1305_ctx ctx = void;
    crypto_poly1305_init(&ctx, key);
    crypto_poly1305_update(&ctx, message, message_size);
    crypto_poly1305_final(&ctx, mac);
}

unittest
{
    import core.stdc.string;
    
    uint8_t[32] key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    ];

    string msg = "Cryptographic Forum Research Group";

    uint8_t[16] expected_mac = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    ];

    uint8_t[16] mac;
    
    crypto_poly1305(mac.ptr, cast(const(uint8_t)*)msg.ptr, msg.length, key.ptr);

    assert(memcmp(mac.ptr, expected_mac.ptr, mac.length) == 0);
}
