/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * Authenticated encryption with associated data (AEAD) algorithm that combines
 * the ChaCha20 stream cipher with the Poly1305 message authentication code.
 * The module is a D port of AEAD implementation from Monocypher.
 */
module minicrypto.aead;

import core.stdc.stdint;

import minicrypto.utils;
import minicrypto.chacha20;
import minicrypto.poly1305;

struct crypto_aead_ctx
{
    uint64_t counter;
    uint8_t[32] key;
    uint8_t[8] nonce;
}

private void lock_auth(u8* mac, const(u8)* auth_key, const(u8)* ad, size_t ad_size, const(u8)* cipher_text, size_t text_size)
{
    u8[16] sizes = void; // Not secret, not wiped
    store64_le(sizes.ptr + 0, ad_size);
    store64_le(sizes.ptr + 8, text_size);
    crypto_poly1305_ctx poly_ctx = void; // auto wiped...
    crypto_poly1305_init  (&poly_ctx, auth_key);
    crypto_poly1305_update(&poly_ctx, ad, ad_size);
    crypto_poly1305_update(&poly_ctx, zero.ptr, gap(ad_size, 16));
    crypto_poly1305_update(&poly_ctx, cipher_text, text_size);
    crypto_poly1305_update(&poly_ctx, zero.ptr, gap(text_size, 16));
    crypto_poly1305_update(&poly_ctx, sizes.ptr, 16);
    crypto_poly1305_final (&poly_ctx, mac); // ...here
}

void crypto_aead_init_x(crypto_aead_ctx* ctx, const(u8)* key, const(u8)* nonce)
{
    crypto_chacha20_h(ctx.key.ptr, key, nonce);
    COPY(ctx.nonce.ptr, nonce + 16, 8);
    
    ctx.counter = 0;
}

void crypto_aead_init_djb(crypto_aead_ctx* ctx, const(u8)* key, const(u8)* nonce)
{
    COPY(ctx.key.ptr, key, 32);
    COPY(ctx.nonce.ptr, nonce, 8);
    ctx.counter = 0;
}

void crypto_aead_init_ietf(crypto_aead_ctx* ctx, const(u8)* key, const(u8)* nonce)
{
    COPY(ctx.key.ptr, key, 32);
    COPY(ctx.nonce.ptr, nonce + 4, 8);
    ctx.counter = cast(u64)load32_le(nonce) << 32;
}

void crypto_aead_write(crypto_aead_ctx* ctx, u8* cipher_text, u8* mac, const(u8)* ad, size_t ad_size, const(u8)* plain_text, size_t text_size)
{
    u8[64] auth_key = void; // the last 32 bytes are used for rekeying.
    crypto_chacha20_djb(auth_key.ptr, null, 64, ctx.key.ptr, ctx.nonce.ptr, ctx.counter);
    crypto_chacha20_djb(cipher_text, plain_text, text_size, ctx.key.ptr, ctx.nonce.ptr, ctx.counter + 1);
    lock_auth(mac, auth_key.ptr, ad, ad_size, cipher_text, text_size);
    COPY(ctx.key.ptr, auth_key.ptr + 32, 32);
    //WIPE_BUFFER(auth_key)
    crypto_wipe(auth_key.ptr, auth_key.length * u8.sizeof);
}

int crypto_aead_read(crypto_aead_ctx* ctx, u8* plain_text, const(u8)* mac, const(u8)* ad, size_t ad_size, const(u8)* cipher_text, size_t text_size)
{
    u8[64] auth_key = void; // the last 32 bytes are used for rekeying.
    u8[16] real_mac = void;
    crypto_chacha20_djb(auth_key.ptr, null, 64, ctx.key.ptr, ctx.nonce.ptr, ctx.counter);
    lock_auth(real_mac.ptr, auth_key.ptr, ad, ad_size, cipher_text, text_size);
    int mismatch = crypto_verify16(mac, real_mac.ptr);
    if (!mismatch)
    {
        crypto_chacha20_djb(plain_text, cipher_text, text_size, ctx.key.ptr, ctx.nonce.ptr, ctx.counter + 1);
        COPY(ctx.key.ptr, auth_key.ptr + 32, 32);
    }
    //WIPE_BUFFER(auth_key)
    crypto_wipe(auth_key.ptr, auth_key.length * u8.sizeof);
    //WIPE_BUFFER(real_mac)
    crypto_wipe(real_mac.ptr, real_mac.length * u8.sizeof);
    return mismatch;
}

void crypto_aead_lock(u8* cipher_text, u8* mac, const(u8)* key, const(u8)* nonce, const(u8)* ad, size_t ad_size, const(u8)* plain_text, size_t text_size)
{
    crypto_aead_ctx ctx = void;
    crypto_aead_init_x(&ctx, key, nonce);
    crypto_aead_write(&ctx, cipher_text, mac, ad, ad_size, plain_text, text_size);
    crypto_wipe(&ctx, ctx.sizeof);
}

int crypto_aead_unlock(u8* plain_text, const(u8)* mac, const(u8)* key, const(u8)* nonce, const(u8)* ad, size_t ad_size, const(u8)* cipher_text, size_t text_size)
{
    crypto_aead_ctx ctx = void;
    crypto_aead_init_x(&ctx, key, nonce);
    int mismatch = crypto_aead_read(&ctx, plain_text, mac, ad, ad_size, cipher_text, text_size);
    crypto_wipe(&ctx, ctx.sizeof);
    return mismatch;
}

unittest
{
    import core.stdc.string;
    
    import std.stdio;
    import std.format;
    import std.range: iota;
    import std.array: array;
    import std.algorithm.iteration: map;
    
    ubyte[] key = iota(0x80, 0xa0).map!(x => cast(ubyte) x).array;
    
    ubyte[] nonce = [
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    ];
    
    ubyte[] ad = [
        0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    ];
    
    string plaintext =
    "Ladies and Gentlemen of the class of '99:\n" ~
    "If I could offer you only one tip for the future,\n" ~
    "sunscreen would be it.";

    ubyte[] ciphertext = new ubyte[plaintext.length];
    ubyte[16] mac;

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key.ptr, nonce.ptr);
    crypto_aead_write(
        &ctx,
        ciphertext.ptr,
        mac.ptr,
        ad.ptr,
        ad.length,
        cast(const(ubyte)*)plaintext.ptr,
        plaintext.length);
    
    //writefln("%(%02x%)", ciphertext);
    //writefln("%(%02x%)", mac);
    
    ubyte[] decrypted = new ubyte[plaintext.length];
    
    crypto_aead_ctx ctx2;
    crypto_aead_init_ietf(&ctx2, key.ptr, nonce.ptr);
    int result = crypto_aead_read(
        &ctx2,
        decrypted.ptr,
        mac.ptr,
        ad.ptr,
        ad.length,
        ciphertext.ptr,
        ciphertext.length);
    
    assert(result == 0);
    assert(memcmp(decrypted.ptr, plaintext.ptr, plaintext.length) == 0);
}
