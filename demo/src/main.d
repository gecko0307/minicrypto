module main;

import std.stdio;
import minicrypto.csprng;

void main()
{
    ubyte[32] privateKey = cryptoRandomValue!(ubyte[32])();
    writefln("Random key: %(%02x%)", privateKey);
}
