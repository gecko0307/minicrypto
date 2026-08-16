/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * Argon2 key derivation function designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich.
 * All three variants are supported: Argon2d, Argon2i, Argon2id.
 *
 * The module is a D port of Argon2 implementation from Monocypher.
 */
module minicrypto.argon2;

import core.stdc.stdint;

import minicrypto.blake2b;
import minicrypto.utils;

enum CRYPTO_ARGON2_D = 0;
enum CRYPTO_ARGON2_I = 1;
enum CRYPTO_ARGON2_ID = 2;

struct crypto_argon2_config
{
    uint32_t algorithm;  // Argon2d, Argon2i, Argon2id
    uint32_t nb_blocks;  // memory hardness, >= 8 * nb_lanes
    uint32_t nb_passes;  // CPU hardness, >= 1 (>= 3 recommended for Argon2i)
    uint32_t nb_lanes;   // parallelism level (single threaded anyway)
}

struct crypto_argon2_inputs
{
    const uint8_t *pass;
    const uint8_t *salt;
    uint32_t pass_size;
    uint32_t salt_size;  // 16 bytes recommended
}

struct crypto_argon2_extras
{
    const uint8_t *key; // may be NULL if no key
    const uint8_t *ad;  // may be NULL if no additional data
    uint32_t key_size;  // 0 if no key (32 bytes recommended otherwise)
    uint32_t ad_size;   // 0 if no additional data
}

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

// Argon2 operates on 1024 byte blocks.
struct blk
{
    u64[128] a;
}

// updates a BLAKE2 hash with a 32 bit word, little endian.
void blake_update_32(crypto_blake2b_ctx* ctx, u32 input) @nogc nothrow
{
    u8[4] buf = void;
    store32_le(buf.ptr, input);
    crypto_blake2b_update(ctx, buf.ptr, 4);
    //WIPE_BUFFER(buf);
    crypto_wipe(buf.ptr, buf.length * u8.sizeof);
}

void blake_update_32_buf(crypto_blake2b_ctx* ctx, const(u8)* buf, u32 size) @nogc nothrow
{
    blake_update_32(ctx, size);
    crypto_blake2b_update(ctx, buf, size);
}

void copy_block(blk* o, const(blk)* in_) @nogc nothrow
{
    //FOR(i, 0, 128);
    for (size_t i = 0; i < 128; i++)
        o.a[i]  = in_.a[i];
}

void xor_block(blk* o, const(blk)* in_) @nogc nothrow
{
    //FOR(i, 0, 128);
    for (size_t i = 0; i < 128; i++)
        o.a[i] ^= in_.a[i];
}

// Hash with a virtually unlimited digest size.
// Doesn't extract more entropy than the base hash function.
// Mainly used for filling a whole kilobyte block with pseudo-random bytes.
// (One could use a stream cipher with a seed hash as the key, but
//  this would introduce another dependency —and point of failure.)
void extended_hash(u8* digest, u32 digest_size, const(u8)* input, u32 input_size) @nogc nothrow
{
    crypto_blake2b_ctx ctx = void;
    crypto_blake2b_init(&ctx, MIN(digest_size, 64));
    blake_update_32(&ctx, digest_size);
    crypto_blake2b_update(&ctx, input, input_size);
    crypto_blake2b_final(&ctx, digest);

    if (digest_size > 64)
    {
        // the conversion to u64 avoids integer overflow on
        // ludicrously big hash sizes.
        u32 r = cast(u32)((cast(u64)digest_size + 31) >> 5) - 2;
        u32 i = 1;
        u32 in_ = 0;
        u32 out_ = 32;
        while (i < r)
        {
            // Input and output overlap. This is intentional
            crypto_blake2b(digest + out_, 64, digest + in_, 64);
            i   +=  1;
            in_  += 32;
            out_ += 32;
        }
        crypto_blake2b(digest + out_, digest_size - (32 * r), digest + in_ , 64);
    }
}

enum string LSB(string x) = "(cast(u64)cast(u32)" ~ x ~ ")";
enum string G(string a, string b, string c, string d) =
    a ~ " += " ~ b ~ " + ((" ~ LSB!(a) ~ " * " ~ LSB!(b) ~ ") << 1);  " ~ d ~ " ^= " ~ a ~ ";  " ~ d ~ " = rotr64(" ~ d ~ ", 32); " ~
    c ~ " += " ~ d ~ " + ((" ~ LSB!(c) ~ " * " ~ LSB!(d) ~ ") << 1);  " ~ b ~ " ^= " ~ c ~ ";  " ~ b ~ " = rotr64(" ~ b ~ ", 24); " ~
    a ~ " += " ~ b ~ " + ((" ~ LSB!(a) ~ " * " ~ LSB!(b) ~ ") << 1);  " ~ d ~ " ^= " ~ a ~ ";  " ~ d ~ " = rotr64(" ~ d ~ ", 16); " ~
    c ~ " += " ~ d ~ " + ((" ~ LSB!(c) ~ " * " ~ LSB!(d) ~ ") << 1);  " ~ b ~ " ^= " ~ c ~ ";  " ~ b ~ " = rotr64(" ~ b ~ ", 63)";

enum string ROUND(string v0, string v1, string v2,  string v3,  string v4,  string v5,  string v6,  string v7,
                  string v8, string v9, string v10, string v11, string v12, string v13, string v14, string v15) =
    G!(v0, v4, v8, v12) ~ "; " ~ G!(v1, v5, v9, v13) ~ "; " ~
    G!(v2, v6, v10, v14) ~ "; " ~ G!(v3, v7, v11, v15) ~ "; " ~
    G!(v0, v5, v10, v15) ~ "; " ~ G!(v1, v6, v11, v12) ~ "; " ~
    G!(v2, v7, v8, v13) ~ "; " ~ G!(v3, v4, v9, v14) ~ ";";

// Core of the compression function G.  Computes Z from R in place.
void g_rounds(blk* b) @nogc nothrow
{
    // column rounds (work_block = Q)
    for (int i = 0; i < 128; i += 16)
    {
        mixin(ROUND!(`b.a[i   ]`, `b.a[i+ 1]`, `b.a[i+ 2]`, `b.a[i+ 3]`,
              `b.a[i+ 4]`, `b.a[i+ 5]`, `b.a[i+ 6]`, `b.a[i+ 7]`,
              `b.a[i+ 8]`, `b.a[i+ 9]`, `b.a[i+10]`, `b.a[i+11]`,
              `b.a[i+12]`, `b.a[i+13]`, `b.a[i+14]`, `b.a[i+15]`));
    }
    // row rounds (b = Z)
    for (int i = 0; i < 16; i += 2)
    {
        mixin(ROUND!(`b.a[i   ]`, `b.a[i+ 1]`, `b.a[i+ 16]`, `b.a[i+ 17]`,
              `b.a[i+32]`, `b.a[i+33]`, `b.a[i+ 48]`, `b.a[i+ 49]`,
              `b.a[i+64]`, `b.a[i+65]`, `b.a[i+ 80]`, `b.a[i+ 81]`,
              `b.a[i+96]`, `b.a[i+97]`, `b.a[i+112]`, `b.a[i+113]`));
    }
}

const(crypto_argon2_extras) crypto_argon2_no_extras = { null, null, 0, 0 };

void crypto_argon2(u8* hash, u32 hash_size, void* work_area, crypto_argon2_config config, crypto_argon2_inputs inputs, crypto_argon2_extras extras) @nogc nothrow
{
    const(u32) segment_size = config.nb_blocks / config.nb_lanes / 4;
    const(u32) lane_size = segment_size * 4;
    const(u32) nb_blocks = lane_size * config.nb_lanes; // rounding down

    // work area seen as blocks (must be suitably aligned)
    blk* blocks = cast(blk*)work_area;
    {
        u8[72] initial_hash = void; // 64 bytes plus 2 words for future hashes
        crypto_blake2b_ctx ctx = void;
        crypto_blake2b_init (&ctx, 64);
        blake_update_32     (&ctx, config.nb_lanes ); // p: number of "threads"
        blake_update_32     (&ctx, hash_size);
        blake_update_32     (&ctx, config.nb_blocks);
        blake_update_32     (&ctx, config.nb_passes);
        blake_update_32     (&ctx, 0x13);             // v: version number
        blake_update_32     (&ctx, config.algorithm); // y: Argon2i, Argon2d...
        blake_update_32_buf (&ctx, inputs.pass, inputs.pass_size);
        blake_update_32_buf (&ctx, inputs.salt, inputs.salt_size);
        blake_update_32_buf (&ctx, extras.key,  extras.key_size);
        blake_update_32_buf (&ctx, extras.ad,   extras.ad_size);
        crypto_blake2b_final(&ctx, initial_hash.ptr); // fill 64 first bytes only

        // fill first 2 blocks of each lane
        u8[1024] hash_area = void;
        //FOR_T(u32, l, 0, config.nb_lanes);
        for (u32 l = 0; l < config.nb_lanes; l++)
        {
            //FOR_T(u32, i, 0, 2);
            for (u32 i = 0; i < 2; i++)
            {
                store32_le(initial_hash.ptr + 64, i); // first  additional word
                store32_le(initial_hash.ptr + 68, l); // second additional word
                extended_hash(hash_area.ptr, 1024, initial_hash.ptr, 72);
                load64_le_buf(blocks[l * lane_size + i].a.ptr, hash_area.ptr, 128);
            }
        }

        //WIPE_BUFFER(initial_hash);
        crypto_wipe(initial_hash.ptr, initial_hash.length * u8.sizeof);
        
        //WIPE_BUFFER(hash_area);
        crypto_wipe(hash_area.ptr, hash_area.length * u8.sizeof);
    }

    // Argon2i and Argon2id start with constant time indexing
    int constant_time = config.algorithm != CRYPTO_ARGON2_D;

    // Fill (and re-fill) the rest of the blocks
    //
    // Note: even though each segment within the same slice can be
    // computed in parallel, (one thread per lane), we are computing
    // them sequentially, because Monocypher doesn't support threads.
    //
    // Yet optimal performance (and therefore security) requires one
    // thread per lane. The only reason Monocypher supports multiple
    // lanes is compatibility.
    blk tmp = void;
    //FOR_T(u32, pass, 0, config.nb_passes);
    for (u32 pass = 0; pass < config.nb_passes; pass++)
    {
        //FOR_T(u32, slice, 0, 4);
        for (u32 slice = 0; slice < 4; slice++)
        {
            // On the first slice of the first pass,
            // blocks 0 and 1 are already filled, hence pass_offset.
            u32 pass_offset = pass == 0 && slice == 0 ? 2 : 0;
            u32 slice_offset = slice * segment_size;

            // Argon2id switches back to non-constant time indexing
            // after the first two slices of the first pass
            if (slice == 2 && config.algorithm == CRYPTO_ARGON2_ID)
                constant_time = 0;

            // Each iteration of the following loop may be performed in
            // a separate thread.  All segments must be fully completed
            // before we start filling the next slice.
            //FOR_T(u32, segment, 0, config.nb_lanes);
            for (u32 segment = 0; segment < config.nb_lanes; segment++)
            {
                blk index_block = void;
                u32 index_ctr = 1;
                //FOR_T(u32, block, pass_offset, segment_size);
                for (u32 block = pass_offset; block < segment_size; block++)
                {
                    // Current and previous blocks
                    u32 lane_offset = segment * lane_size;
                    blk* segment_start = blocks + lane_offset + slice_offset;
                    blk* current = segment_start + block;
                    blk* previous = block == 0 && slice_offset == 0
                        ? segment_start + lane_size - 1
                        : segment_start + block - 1;

                    u64 index_seed = void;
                    if (constant_time)
                    {
                        if (block == pass_offset || (block % 128) == 0)
                        {
                            // Fill or refresh deterministic indices block

                            // seed the beginning of the block...
                            //ZERO(index_block.a, 128);
                            for (size_t i = 0; i < 128; i++)
                                index_block.a[i] = 0;

                            index_block.a[0] = pass;
                            index_block.a[1] = segment;
                            index_block.a[2] = slice;
                            index_block.a[3] = nb_blocks;
                            index_block.a[4] = config.nb_passes;
                            index_block.a[5] = config.algorithm;
                            index_block.a[6] = index_ctr;
                            index_ctr++;

                            // ... then shuffle it
                            copy_block(&tmp, &index_block);
                            g_rounds  (&index_block);
                            xor_block (&index_block, &tmp);
                            copy_block(&tmp, &index_block);
                            g_rounds  (&index_block);
                            xor_block (&index_block, &tmp);
                        }
                        index_seed = index_block.a[block % 128];
                    }
                    else
                    {
                        index_seed = previous.a[0];
                    }

                    // Establish the reference set.  *Approximately* comprises:
                    // - The last 3 slices (if they exist yet)
                    // - The already constructed blocks in the current segment
                    u32 next_slice = ((slice + 1) % 4) * segment_size;
                    u32 window_start = pass == 0 ? 0     : next_slice;
                    u32 nb_segments = pass == 0 ? slice : 3;
                    u32 lane = pass == 0 && slice == 0
                        ? segment
                        : cast(u32)(index_seed >> 32) % config.nb_lanes;
                    u32 window_size = nb_segments * segment_size +
                        (lane  == segment ? block-1 :
                         block == 0       ? cast(u32)-1 : 0);

                    // Find reference block
                    u64 j1 = index_seed & 0xffffffff; // block selector
                    u64 x = (j1 * j1)         >> 32;
                    u64 y = (window_size * x) >> 32;
                    u64 z = (window_size - 1) - y;
                    u32 ref_ = cast(u32)((window_start + z) % lane_size);
                    u32 index = lane * lane_size + ref_;
                    blk* reference = blocks + index;

                    // Shuffle the previous & reference block
                    // into the current block
                    copy_block(&tmp, previous);
                    xor_block (&tmp, reference);
                    if (pass == 0) { copy_block(current, &tmp); }
                    else           { xor_block (current, &tmp); }
                    g_rounds  (&tmp);
                    xor_block (current, &tmp);
                }
            }
        }
    }

    // Wipe temporary block
    //ZERO(p, 128);
    for (size_t i = 0; i < 128; i++)
        tmp.a[i] = 0;

    // XOR last blocks of each lane
    blk* last_block = blocks + lane_size - 1;
    //FOR_T(u32, lane, 1, config.nb_lanes);
    for (u32 lane = 1; lane < config.nb_lanes; lane++)
    {
        blk* next_block = last_block + lane_size;
        xor_block(next_block, last_block);
        last_block = next_block;
    }

    // Serialize last block
    u8[1024] final_block = void;
    store64_le_buf(final_block.ptr, last_block.a.ptr, 128);

    // Wipe work area
    u64* p = cast(u64*)work_area;
    //ZERO(p, 128 * nb_blocks);
    for (size_t i = 0; i < 128 * nb_blocks; i++)
        p[i] = 0;

    // Hash the very last block with H' into the output hash
    extended_hash(hash, hash_size, final_block.ptr, 1024);
    
    //WIPE_BUFFER(final_block);
    crypto_wipe(final_block.ptr, final_block.length * u8.sizeof);
}

unittest
{
    import core.stdc.stdlib;
    import std.stdio;
    import std.digest;
    
    ubyte[32] hash;
    uint numBlocks = 1024;
    void* workArea = malloc(numBlocks * 1024);
    scope(exit) free(workArea);
    
    string password = "secure_password123";
    string salt = "kjM9x8ld";
    
    crypto_argon2_config config = {
        algorithm: CRYPTO_ARGON2_ID,
        nb_blocks: numBlocks,
        nb_passes: 3,
        nb_lanes: 1
    };
    
    crypto_argon2_inputs inputs = {
        pass: cast(const(ubyte)*)password.ptr,
        pass_size: cast(uint)password.length,
        salt: cast(const(ubyte)*)salt.ptr,
        salt_size: cast(uint)salt.length
    };
    
    crypto_argon2(hash.ptr, hash.length, workArea, config, inputs, crypto_argon2_no_extras);
    
    assert(hash == fromHexString("43a21059c9fd9d628c78a8591c7f6b82141e9bfeeb728c7a2c44d1b8f66d96b3"));
}
