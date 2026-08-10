/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * Convert bytes array to a hex string.
 */
module minicrypto.hex;

bool bytes_to_hex(const(ubyte)[] bytes, char[] result) @nogc nothrow
{
    if (result.length != bytes.length * 2)
        return false;
    
    string lookup = "0123456789abcdef";
    for (size_t i = 0; i < bytes.length; i++)
    {
        ubyte b = bytes[i];
        ubyte highNibble = (b >> 4) & 0x0F;
        ubyte lowNibble = b & 0x0F;
        result[i * 2] = lookup[highNibble];
        result[i * 2 + 1] = lookup[lowNibble];
    }
    
    return true;
}

unittest
{
    import std.stdio;
    import std.format;
    import minicrypto.csprng;
    
    ubyte[32] data = cryptoRandomValue!(ubyte[32]);
    
    //writefln("%(%02x%)", data);
    
    char[] hex = new char[data.length * 2];
    bytes_to_hex(data, hex);
    //writeln(hex);
    
    assert(hex == format("%(%02x%)", data));
}
