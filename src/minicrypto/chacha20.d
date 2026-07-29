/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * Secure and fast symmetric stream cipher designed by Daniel J. Bernstein.
 *
 * The module is a D port of ChaCha20 implementation from Monocypher.
 */
module minicrypto.chacha20;

import core.stdc.stdint;

import minicrypto.utils;

enum string QUARTERROUND(string a, string b, string c, string d) =
    a ~ " += " ~ b ~ ";  " ~ d ~ " = rotl32(" ~ d ~ " ^ " ~ a ~ ", 16); " ~
    c ~ " += " ~ d ~ ";  " ~ b ~ " = rotl32(" ~ b ~ " ^ " ~ c ~ ", 12); " ~
    a ~ " += " ~ b ~ ";  " ~ d ~ " = rotl32(" ~ d ~ " ^ " ~ a ~ ",  8); " ~
    c ~ " += " ~ d ~ ";  " ~ b ~ " = rotl32(" ~ b ~ " ^ " ~ c ~ ",  7);";

private void chacha20_rounds(u32* out_, const(u32)* in_) @nogc nothrow
{
    // The temporary variables make Chacha20 10% faster.
    u32 t0 = in_[ 0];  u32 t1 = in_[ 1];  u32 t2 = in_[ 2];  u32 t3 = in_[ 3];
    u32 t4 = in_[ 4];  u32 t5 = in_[ 5];  u32 t6 = in_[ 6];  u32 t7 = in_[ 7];
    u32 t8 = in_[ 8];  u32 t9 = in_[ 9];  u32 t10 = in_[10];  u32 t11 = in_[11];
    u32 t12 = in_[12];  u32 t13 = in_[13];  u32 t14 = in_[14];  u32 t15 = in_[15];

    for (size_t i = 0; i < 10; i++)
    {
        // 20 rounds, 2 rounds per loop.
        mixin(QUARTERROUND!(`t0`, `t4`, `t8` , `t12`)); // column 0
        mixin(QUARTERROUND!(`t1`, `t5`, `t9` , `t13`)); // column 1
        mixin(QUARTERROUND!(`t2`, `t6`, `t10`, `t14`)); // column 2
        mixin(QUARTERROUND!(`t3`, `t7`, `t11`, `t15`)); // column 3
        mixin(QUARTERROUND!(`t0`, `t5`, `t10`, `t15`)); // diagonal 0
        mixin(QUARTERROUND!(`t1`, `t6`, `t11`, `t12`)); // diagonal 1
        mixin(QUARTERROUND!(`t2`, `t7`, `t8` , `t13`)); // diagonal 2
        mixin(QUARTERROUND!(`t3`, `t4`, `t9` , `t14`)); // diagonal 3
    }
    
    out_[ 0] = t0;   out_[ 1] = t1;   out_[ 2] = t2;   out_[ 3] = t3;
    out_[ 4] = t4;   out_[ 5] = t5;   out_[ 6] = t6;   out_[ 7] = t7;
    out_[ 8] = t8;   out_[ 9] = t9;   out_[10] = t10;  out_[11] = t11;
    out_[12] = t12;  out_[13] = t13;  out_[14] = t14;  out_[15] = t15;
}

private string chacha20_constant = "expand 32-byte k"; // 16 bytes

void crypto_chacha20_h(u8* out_, const(u8)* key, const(u8)* in_) @nogc nothrow
{
    u32[16] block = void;
    load32_le_buf(block.ptr, cast(const(u8)*)chacha20_constant.ptr, 4);
    load32_le_buf(block.ptr +  4, key, 8);
    load32_le_buf(block.ptr + 12, in_, 4);

    chacha20_rounds(block.ptr, block.ptr);

    // prevent reversal of the rounds by revealing only half of the buffer.
    store32_le_buf(out_,    block.ptr,    4); // constant
    store32_le_buf(out_+16, block.ptr+12, 4); // counter and nonce
    
    crypto_wipe(block.ptr, block.length * u32.sizeof);
}

u64 crypto_chacha20_djb(u8* cipher_text, const(u8)* plain_text, size_t text_size, const(u8)* key, const(u8)* nonce, u64 ctr) @nogc nothrow
{
    u32[16] input = void;
    load32_le_buf(input.ptr     , cast(const(u8)*)chacha20_constant.ptr, 4);
    load32_le_buf(input.ptr +  4, key              , 8);
    load32_le_buf(input.ptr + 14, nonce            , 2);
    input[12] = cast(u32) ctr;
    input[13] = cast(u32)(ctr >> 32);

    // Whole blocks
    u32[16] pool = void;
    size_t nb_blocks = text_size >> 6;
    for (size_t i = 0; i < nb_blocks; i++)
    {
        chacha20_rounds(pool.ptr, input.ptr);
        
        if (plain_text != null)
        {
            //FOR (j, 0, 16)
            for (size_t j = 0; j < 16; j++)
            {
                u32 p = pool[j] + input[j];
                store32_le(cipher_text, p ^ load32_le(plain_text));
                cipher_text += 4;
                plain_text  += 4;
            }
        }
        else
        {
            //FOR (j, 0, 16)
            for (size_t j = 0; j < 16; j++)
            {
                u32 p = pool[j] + input[j];
                store32_le(cipher_text, p);
                cipher_text += 4;
            }
        }
        
        input[12]++;
        
        if (input[12] == 0)
            input[13]++;
    }
    text_size &= 63;

    // Last (incomplete) block
    if (text_size > 0)
    {
        if (plain_text == null)
            plain_text = zero.ptr;
        
        chacha20_rounds(pool.ptr, input.ptr);
        u8[64] tmp = void;

        //FOR (i, 0, 16)
        for (size_t i = 0; i < 16; i++)
            store32_le(tmp.ptr + i*4, pool[i] + input[i]);
        
        //FOR (i, 0, text_size)
        for (size_t i = 0; i < text_size; i++)
            cipher_text[i] = tmp[i] ^ plain_text[i];
        
        crypto_wipe(tmp.ptr, tmp.length * u8.sizeof);
    }
    ctr = input[12] + (cast(u64)input[13] << 32) + (text_size > 0);

    crypto_wipe(pool.ptr, pool.length * u32.sizeof);
    crypto_wipe(input.ptr, input.length * u32.sizeof);
    
    return ctr;
}

u32 crypto_chacha20_ietf(u8* cipher_text, const(u8)* plain_text, size_t text_size, const(u8)* key, const(u8)* nonce, u32 ctr) @nogc nothrow
{
    u64 big_ctr = ctr + (cast(u64)load32_le(nonce) << 32);
    return cast(u32)crypto_chacha20_djb(
        cipher_text, plain_text, text_size,
        key, nonce + 4, big_ctr);
}

u64 crypto_chacha20_x(u8* cipher_text, const(u8)* plain_text, size_t text_size, const(u8)* key, const(u8)* nonce, u64 ctr) @nogc nothrow
{
    u8[32] sub_key = void;
    crypto_chacha20_h(sub_key.ptr, key, nonce);
    ctr = crypto_chacha20_djb(
        cipher_text, plain_text, text_size,
        sub_key.ptr, nonce + 16, ctr);
    crypto_wipe(sub_key.ptr, sub_key.length * u8.sizeof);
    return ctr;
}

unittest
{
    import core.stdc.string;
    import std.stdio;

    string key = "ThisIsA32ByteSecretKeyForChaCha.";
    string nonce = "123456789012"; // 96-bit nonce
    u32 counter = 0;

    string plaintext = "Monocypher is small, fast, and secure!";

    ubyte[64] ciphertext = 0;
    ubyte[64] decrypted = 0;

    assert(key.length == 32);
    assert(nonce.length == 12);

    crypto_chacha20_ietf(
        ciphertext.ptr,
        cast(const(ubyte)*)plaintext.ptr,
        plaintext.length,
        cast(const(ubyte)*)key.ptr,
        cast(const(ubyte)*)nonce.ptr,
        counter
    );

    //writefln("ChaCha20: %(%02x%)", ciphertext[0..plaintext.length]);

    crypto_chacha20_ietf(
        decrypted.ptr,
        ciphertext.ptr,
        plaintext.length,
        cast(const(ubyte)*)key.ptr,
        cast(const(ubyte)*)nonce.ptr,
        counter
    );

    assert(memcmp(plaintext.ptr, decrypted.ptr, plaintext.length) == 0);
}
