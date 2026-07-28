/*
 * This code is available under the Creative Commons Zero 1.0 license (CC0).
 * You should have received a copy of CC0 along with this work.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/**
 * Cryptographically secure preudorandom number generator.
 * Works on Windows (Vista and above) and Posix.
 * Doesn't use GC, memory must be allocated on the user side.
 */
module minicrypto.csprng;

import std.traits;

version(Windows)
{
    import core.sys.windows.windows;
    
    alias BCRYPT_ALG_HANDLE = void*;

    alias BCryptGenRandom_f = extern(Windows) int function(
        BCRYPT_ALG_HANDLE hAlgorithm,
        ubyte* pbBuffer,
        uint cbBuffer,
        uint dwFlags) @nogc nothrow;
    
    __gshared BCryptGenRandom_f BCryptGenRandom;
    
    enum uint BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;
    
    static this()
    {
        HMODULE hBcrypt = LoadLibraryA("bcrypt.dll");
        if (hBcrypt !is null)
            BCryptGenRandom = cast(BCryptGenRandom_f)GetProcAddress(hBcrypt, "BCryptGenRandom");
    }
}
else version(Posix)
{
    import core.sys.posix.fcntl;
    import core.sys.posix.unistd;

    __gshared int randomFd = -1;

    static this()
    {
        randomFd = open("/dev/urandom", O_RDONLY);
    }
}
else
    pragma(msg, "csprng is not supported on this system");

pragma(inline, true);
bool cryptoRandomBytes(ubyte* bufferPtr, size_t bufferLength) @nogc nothrow
{
    if (bufferLength == 0)
        return true;

    if (bufferPtr is null || bufferLength > uint.max)
        return false;
    
    version(Windows)
    {
        if (BCryptGenRandom is null)
            return false;
        int res = BCryptGenRandom(null, bufferPtr, cast(uint)bufferLength, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return (res == 0);
    }
    else version(Posix)
    {
        if (randomFd < 0)
            return false;

        size_t remaining = bufferLength;
        ubyte* ptr = bufferPtr;

        while (remaining > 0)
        {
            auto result = read(randomFd, ptr, remaining);

            if (result <= 0)
                return false;

            ptr += result;
            remaining -= result;
        }

        return true;
    }
    else
    {
        return false;
    }
}

pragma(inline, true);
bool cryptoRandomBytes(ubyte[] buffer) @nogc nothrow
{
    return cryptoRandomBytes(buffer.ptr, buffer.length);
}

pragma(inline, true);
T cryptoRandomValue(T)() @nogc nothrow
    if (is(T == struct) ||
        isStaticArray!T ||
        isIntegral!T ||
        isFloatingPoint!T)
{
    T value;
    assert(cryptoRandomBytes(cast(ubyte*)&value, T.sizeof));
    return value;
}

unittest
{
    ubyte[32] data;
    assert(cryptoRandomBytes(data));
}
