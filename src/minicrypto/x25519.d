/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * Elliptic-curve Diffie-Hellman based on Curve25519.
 *
 * The module is a D port of X25519 implementation from Monocypher.
 */
module minicrypto.x25519;

import minicrypto.utils;
import minicrypto.finite_field;

void scalarmult(u8* q, const(u8)* scalar, const(u8)* p, int nb_bits) @nogc nothrow
{
    // computes the scalar product
    fe x1 = void;
    fe_frombytes(x1, p);

    // computes the actual scalar product (the result is in x2 and z2)
    fe x2 = void, z2 = void, x3 = void, z3 = void, t0 = void, t1 = void;
    
    // Montgomery ladder
    // In projective coordinates, to avoid divisions: x = X / Z
    // We don't care about the y coordinate, it's only 1 bit of information
    fe_1(x2);        fe_0(z2); // "zero" point
    fe_copy(x3, x1); fe_1(z3); // "one"  point
    int swap = 0;
    for (int pos = nb_bits - 1; pos >= 0; --pos)
    {
        // constant time conditional swap before ladder step
        int b = scalar_bit(scalar, pos);
        swap ^= b; // xor trick avoids swapping at the end of the loop
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;  // anticipates one last swap after the loop

        // Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3)
        // with differential addition
        fe_sub(t0, x3, z3);
        fe_sub(t1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, t0, x2);
        fe_mul(z2, z2, t1);
        fe_sq (t0, t1    );
        fe_sq (t1, x2    );
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, t1, t0);
        fe_sub(t1, t1, t0);
        fe_sq (z2, z2    );
        fe_mul_small(z3, t1, 121666);
        fe_sq (x3, x3    );
        fe_add(t0, t0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, t1, t0);
    }
    // last swap is necessary to compensate for the xor trick
    // Note: after this swap, P3 == P2 + P1.
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    // normalises the coordinates: x == X / Z
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);

    //WIPE_BUFFER(x1);
    crypto_wipe(x1.ptr, x1.length * i32.sizeof);
    
    //WIPE_BUFFER(x2);
    crypto_wipe(x2.ptr, x2.length * i32.sizeof);
    
    //WIPE_BUFFER(z2);
    crypto_wipe(z2.ptr, z2.length * i32.sizeof);
    
    //WIPE_BUFFER(t0);
    crypto_wipe(t0.ptr, t0.length * i32.sizeof);
    
    //WIPE_BUFFER(x3);
    crypto_wipe(x3.ptr, x3.length * i32.sizeof);
    
    //WIPE_BUFFER(z3);
    crypto_wipe(z3.ptr, z3.length * i32.sizeof);
    
    //WIPE_BUFFER(t1);
    crypto_wipe(t1.ptr, t1.length * i32.sizeof);
}

void crypto_x25519(u8* raw_shared_secret, const(u8)* your_secret_key, const(u8)* their_public_key) @nogc nothrow
{
    // restrict the possible scalar values
    u8[32] e = void;
    crypto_eddsa_trim_scalar(e.ptr, your_secret_key);
    scalarmult(raw_shared_secret, e.ptr, their_public_key, 255);
    //WIPE_BUFFER(e);
    crypto_wipe(e.ptr, e.length * u8.sizeof);
}

void crypto_x25519_public_key(u8* public_key, const(u8)* secret_key) @nogc nothrow
{
    static const(u8)[32] base_point = 9;
    crypto_x25519(public_key, secret_key, base_point.ptr);
}

unittest
{
    import core.stdc.string;
    import std.digest;
    
    ubyte[] alice_secret = fromHexString("3e2ca06a3d39702c00ee794f7a0f82fef9e2c8e23a57b70f1fd1c93f7dc1ed16");
    ubyte[32] alice_public;
    crypto_x25519_public_key(alice_public.ptr, alice_secret.ptr);
    //writefln("Alice's public key: %(%02x%)", alice_public);
    
    ubyte[] bob_secret = fromHexString("57fa48d5c4d94134f13d3d5971f27ca36f832e32560c8f75e95ba07ccd7327ec");
    ubyte[32] bob_public;
    crypto_x25519_public_key(bob_public.ptr, bob_secret.ptr);
    //writefln("Bob's public key: %(%02x%)", bob_public);
    
    ubyte[32] alice_shared_secret;
    crypto_x25519(alice_shared_secret.ptr, alice_secret.ptr, bob_public.ptr);
    //writefln("Alice's shared secret: %(%02x%)", alice_shared_secret);
    
    ubyte[32] bob_shared_secret;
    crypto_x25519(bob_shared_secret.ptr, bob_secret.ptr, alice_public.ptr);
    //writefln("Bob's shared secret: %(%02x%)", bob_shared_secret);
    
    assert(memcmp(alice_shared_secret.ptr, bob_shared_secret.ptr, alice_shared_secret.length) == 0);
}
