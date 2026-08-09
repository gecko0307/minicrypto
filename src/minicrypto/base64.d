/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * @nogc Base64 encoder and decoder.
 *
 * Base64 is a binary-to-text encoding that uses 64 printable characters
 * to represent each 6-bit segment of a sequence of byte values.
 */
module minicrypto.base64;

import core.stdc.stdlib;

private immutable(char)[] base64_map = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
];

size_t base64_encode_buffer_size(const(ubyte)[] input) @nogc nothrow
{
    return ((input.length + 2) / 3) * 4;
}

size_t base64_decode_buffer_size(const(ubyte)[] input) @nogc nothrow
{
    size_t p = 0;
    if (input[$-1] == '=')
    {
        p++;
        if (input[$-2] == '=')
            p++;
    }
    return (input.length / 4) * 3 - p;
}

string base64_encode(const(ubyte)[] input, ref ubyte[] output) @nogc nothrow
{
    char counts = 0;
    char[3] buffer;
    size_t c = 0;

    for (size_t i = 0; i < input.length; i++)
    {
        buffer[counts++] = input[i];
        if (counts == 3)
        {
            output[c++] = base64_map[buffer[0] >> 2];
            output[c++] = base64_map[((buffer[0] & 0x03) << 4) + (buffer[1] >> 4)];
            output[c++] = base64_map[((buffer[1] & 0x0f) << 2) + (buffer[2] >> 6)];
            output[c++] = base64_map[buffer[2] & 0x3f];
            counts = 0;
        }
    }

    if (counts > 0)
    {
        output[c++] = base64_map[buffer[0] >> 2];
        if (counts == 1)
        {
            output[c++] = base64_map[(buffer[0] & 0x03) << 4];
            output[c++] = '=';
        }
        else
        {
            // if counts == 2
            output[c++] = base64_map[((buffer[0] & 0x03) << 4) + (buffer[1] >> 4)];
            output[c++] = base64_map[(buffer[1] & 0x0f) << 2];
        }
        output[c++] = '=';
    }

    return cast(string)output;
}

void base64_decode(const(ubyte)[] input, ref ubyte[] output) @nogc nothrow
{
    char counts = 0;
    char[4] buffer;
    size_t p = 0;

    for (size_t i = 0; i < input.length; i++)
    {
        char k;
        for (k = 0; k < 64 && base64_map[k] != input[i]; k++) {};
        buffer[counts++] = k;
        if (counts == 4)
        {
            output[p++] = cast(ubyte)((buffer[0] << 2) + (buffer[1] >> 4));
            if (buffer[2] != 64)
                output[p++] = cast(ubyte)((buffer[1] << 4) + (buffer[2] >> 2));
            if (buffer[3] != 64)
                output[p++] = cast(ubyte)((buffer[2] << 6) + buffer[3]);
            counts = 0;
        }
    }
}

unittest
{
    import std.stdio;
    import std.base64;
    import minicrypto.csprng;
    
    ubyte[32] data = cryptoRandomValue!(ubyte[32]);
    size_t encodeSize = base64_encode_buffer_size(data);
    assert(encodeSize == Base64.encodeLength(data.length));
    
    //writefln("Input data: %s", data);
    
    ubyte[] encoded = new ubyte[encodeSize];
    string encodedStr = base64_encode(data, encoded);
    //writeln("Encoding:");
    //writefln("Minicrypto: %s", encodedStr);
    //writefln("std.base64: %s", Base64.encode(data));
    assert(encodedStr == Base64.encode(data));
    
    size_t decodeSize = base64_decode_buffer_size(encoded);
    assert(decodeSize == data.length);
    ubyte[] decoded = new ubyte[decodeSize];
    base64_decode(encoded, decoded);
    //writeln("Decoding:");
    //writefln("Minicrypto: %s", decoded);
    //writefln("std.base64  %s", Base64.decode(encoded));
    assert(decoded == data);
}
