/**
 * BLAKE2b cryptographic hash function.
 * Faster than MD5, SHA-1, SHA-2, and SHA-3;
 * provides better security than SHA-2 and similar to that of SHA-3.
 */
module minicrypto.blake2b;

import core.stdc.stdint;

import minicrypto.utils;

struct crypto_blake2b_ctx
{
    // Do not rely on the size or contents of this type,
    // for they may change without notice.
    uint64_t[8] hash;
    uint64_t[2] input_offset;
    uint64_t[16] input;
    size_t input_idx;
    size_t hash_size;
}

private const(u64)[8] iv = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

void blake2b_compress(crypto_blake2b_ctx* ctx, int is_last_block) @nogc nothrow
{
    static const(u8)[16][12] sigma = [
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
        [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
        [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
        [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
        [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
        [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
        [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
        [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
        [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
        [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ],
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
        [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    ];

    // increment input offset
    u64* x = ctx.input_offset.ptr;
    size_t y = ctx.input_idx;
    x[0] += y;
    if (x[0] < y)
        x[1]++;

    // init work vector
    u64 v0 = ctx.hash[0]; u64 v8 = iv[0];
    u64 v1 = ctx.hash[1]; u64 v9 = iv[1];
    u64 v2 = ctx.hash[2]; u64 v10 = iv[2];
    u64 v3 = ctx.hash[3]; u64 v11 = iv[3];
    u64 v4 = ctx.hash[4]; u64 v12 = iv[4] ^ ctx.input_offset[0];
    u64 v5 = ctx.hash[5]; u64 v13 = iv[5] ^ ctx.input_offset[1];
    u64 v6 = ctx.hash[6]; u64 v14 = iv[6] ^ cast(u64)~(is_last_block - 1);
    u64 v7 = ctx.hash[7]; u64 v15 = iv[7];

    // mangle work vector
    u64* input = ctx.input.ptr;
    
    enum string BLAKE2_G(string a, string b, string c, string d, string x, string y) =
        a ~ " += " ~ b ~ " + " ~ x ~ ";  " ~ d ~ " = rotr64(" ~ d ~ " ^ " ~ a ~ ", 32); " ~
        c ~ " += " ~ d ~ ";      " ~ b ~ " = rotr64(" ~ b ~ " ^ " ~ c ~ ", 24); " ~
        a ~ " += " ~ b ~ " + " ~ y ~ ";  " ~ d ~ " = rotr64(" ~ d ~ " ^ " ~ a ~ ", 16); " ~
        c ~ " += " ~ d ~ ";      " ~ b ~ " = rotr64(" ~ b ~ " ^ " ~ c ~ ", 63)";

    enum string BLAKE2_ROUND(string i) =
        BLAKE2_G!("v0", "v4", "v8" , "v12", "input[sigma[" ~ i ~ "][ 0]]", "input[sigma[" ~ i ~ "][ 1]]") ~ "; " ~
        BLAKE2_G!("v1", "v5", "v9" , "v13", "input[sigma[" ~ i ~ "][ 2]]", "input[sigma[" ~ i ~ "][ 3]]") ~ "; " ~
        BLAKE2_G!("v2", "v6", "v10", "v14", "input[sigma[" ~ i ~ "][ 4]]", "input[sigma[" ~ i ~ "][ 5]]") ~ "; " ~
        BLAKE2_G!("v3", "v7", "v11", "v15", "input[sigma[" ~ i ~ "][ 6]]", "input[sigma[" ~ i ~ "][ 7]]") ~ "; " ~
        BLAKE2_G!("v0", "v5", "v10", "v15", "input[sigma[" ~ i ~ "][ 8]]", "input[sigma[" ~ i ~ "][ 9]]") ~ "; " ~
        BLAKE2_G!("v1", "v6", "v11", "v12", "input[sigma[" ~ i ~ "][10]]", "input[sigma[" ~ i ~ "][11]]") ~ "; " ~
        BLAKE2_G!("v2", "v7", "v8" , "v13", "input[sigma[" ~ i ~ "][12]]", "input[sigma[" ~ i ~ "][13]]") ~ "; " ~
        BLAKE2_G!("v3", "v4", "v9" , "v14", "input[sigma[" ~ i ~ "][14]]", "input[sigma[" ~ i ~ "][15]]") ~ ";";

    version (BLAKE2_NO_UNROLLING)
    {
        //FOR(i, 0, 12);
        for (size_t i = 0; i < 12; i++)
        {
            mixin(BLAKE2_ROUND!("i"));
        }
    }
    else
    {
        mixin(BLAKE2_ROUND!("0"));  mixin(BLAKE2_ROUND!("1"));  mixin(BLAKE2_ROUND!("2"));  mixin(BLAKE2_ROUND!("3"));
        mixin(BLAKE2_ROUND!("4"));  mixin(BLAKE2_ROUND!("5"));  mixin(BLAKE2_ROUND!("6"));  mixin(BLAKE2_ROUND!("7"));
        mixin(BLAKE2_ROUND!("8"));  mixin(BLAKE2_ROUND!("9"));  mixin(BLAKE2_ROUND!("10")); mixin(BLAKE2_ROUND!("11"));
    }

    // update hash
    ctx.hash[0] ^= v0 ^ v8;   ctx.hash[1] ^= v1 ^ v9;
    ctx.hash[2] ^= v2 ^ v10;  ctx.hash[3] ^= v3 ^ v11;
    ctx.hash[4] ^= v4 ^ v12;  ctx.hash[5] ^= v5 ^ v13;
    ctx.hash[6] ^= v6 ^ v14;  ctx.hash[7] ^= v7 ^ v15;
}

void crypto_blake2b_keyed_init(crypto_blake2b_ctx* ctx, size_t hash_size, const(u8)* key, size_t key_size) @nogc nothrow
{
    // initial hash
    COPY(ctx.hash.ptr, iv.ptr, 8);
    ctx.hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

    ctx.input_offset[0] = 0;  // beginning of the input, no offset
    ctx.input_offset[1] = 0;  // beginning of the input, no offset
    ctx.hash_size       = hash_size;
    ctx.input_idx       = 0;
    
    //ZERO(ctx.input, 16);
    for (size_t i = 0; i < 16; i++)
        ctx.input[i] = 0;

    // if there is a key, the first block is that key (padded with zeroes)
    if (key_size > 0)
    {
        u8[128] key_block = 0;
        COPY(key_block.ptr, key, key_size);
        // same as calling crypto_blake2b_update(ctx, key_block , 128)
        load64_le_buf(ctx.input.ptr, key_block.ptr, 16);
        ctx.input_idx = 128;
        
        //WIPE_BUFFER(key_block);
        crypto_wipe(key_block.ptr, key_block.length * u8.sizeof);
    }
}

void crypto_blake2b_init(crypto_blake2b_ctx* ctx, size_t hash_size) @nogc nothrow
{
    crypto_blake2b_keyed_init(ctx, hash_size, null, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx* ctx, const(u8)* message, size_t message_size) @nogc nothrow
{
    // Avoid undefined null pointer increments with empty messages
    if (message_size == 0)
        return;

    // Align with word boundaries
    if ((ctx.input_idx & 7) != 0)
    {
        size_t nb_bytes = MIN(gap(ctx.input_idx, 8), message_size);
        size_t word = ctx.input_idx >> 3;
        size_t byte_ = ctx.input_idx & 7;
        
        //FOR(i, 0, nb_bytes);
        for (size_t i = 0; i < nb_bytes; i++)
        {
            ctx.input[word] |= cast(u64)message[i] << ((byte_ + i) << 3);
        }
        
        ctx.input_idx += nb_bytes;
        message += nb_bytes;
        message_size -= nb_bytes;
    }

    // Align with block boundaries (faster than byte by byte)
    if ((ctx.input_idx & 127) != 0)
    {
        size_t nb_words = MIN(gap(ctx.input_idx, 128), message_size) >> 3;
        load64_le_buf(ctx.input.ptr + (ctx.input_idx >> 3), message, nb_words);
        ctx.input_idx += nb_words << 3;
        message += nb_words << 3;
        message_size -= nb_words << 3;
    }

    // Process block by block
    size_t nb_blocks = message_size >> 7;
    //FOR(i, 0, nb_blocks);
    for (size_t i = 0; i < nb_blocks; i++)
    {
        if (ctx.input_idx == 128)
            blake2b_compress(ctx, 0);
        load64_le_buf(ctx.input.ptr, message, 16);
        message += 128;
        ctx.input_idx = 128;
    }
    message_size &= 127;

    if (message_size != 0)
    {
        // Compress block & flush input buffer as needed
        if (ctx.input_idx == 128)
        {
            blake2b_compress(ctx, 0);
            ctx.input_idx = 0;
        }
        if (ctx.input_idx == 0)
        {
            //ZERO(ctx.input, 16);
            for (size_t i = 0; i < 16; i++)
                ctx.input[i] = 0;
        }
        // Fill remaining words (faster than byte by byte)
        size_t nb_words = message_size >> 3;
        load64_le_buf(ctx.input.ptr, message, nb_words);
        ctx.input_idx += nb_words << 3;
        message        += nb_words << 3;
        message_size   -= nb_words << 3;
        
        // Fill remaining bytes
        //FOR(i, 0, message_size);
        for (size_t i = 0; i < message_size; i++)
        {
            size_t word = ctx.input_idx >> 3;
            size_t byte_ = ctx.input_idx & 7;
            ctx.input[word] |= cast(u64)message[i] << (byte_ << 3);
            ctx.input_idx++;
        }
    }
}

void crypto_blake2b_final(crypto_blake2b_ctx* ctx, u8* hash) @nogc nothrow
{
    blake2b_compress(ctx, 1); // compress the last block
    size_t hash_size = MIN(ctx.hash_size, 64);
    size_t nb_words = hash_size >> 3;
    store64_le_buf(hash, ctx.hash.ptr, nb_words);
    //FOR(i, nb_words << 3, hash_size);
    for (size_t i = nb_words << 3; i < hash_size; i++)
    {
        hash[i] = (ctx.hash[i >> 3] >> (8 * (i & 7))) & 0xff;
    }
    //WIPE_CTX(ctx);
    crypto_wipe(ctx, ctx.sizeof);
}

void crypto_blake2b_keyed(u8* hash, size_t hash_size, const(u8)* key, size_t key_size, const(u8)* message, size_t message_size) @nogc nothrow
{
    crypto_blake2b_ctx ctx = void;
    crypto_blake2b_keyed_init(&ctx, hash_size, key, key_size);
    crypto_blake2b_update(&ctx, message, message_size);
    crypto_blake2b_final(&ctx, hash);
}

void crypto_blake2b(u8* hash, size_t hash_size, const(u8)* msg, size_t msg_size) @nogc nothrow
{
    crypto_blake2b_keyed(hash, hash_size, null, 0, msg, msg_size);
}

unittest
{
    import std.stdio;
    import std.digest;
    
    string msg = "Custom digest size example";
    
    ubyte[20] hash;
    crypto_blake2b(hash.ptr, hash.length, cast(const(ubyte)*)msg.ptr, msg.length);
    
    assert(hash == fromHexString("25aa657326afb87bc197f981a63b5a9ce0f51a73"));
}
