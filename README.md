# Minicrypto

Tiny, zero-dependency cryptographic primitives library for [D language](https://dlang.org).

Most of it is a direct port of [Monocypher](https://github.com/LoupVaillant/monocypher) C code to D.

## Features

* No dependencies
* No garbage collector usage (`@nogc`)
* Designed for systems programming and game development
* Portable across Windows and Posix systems

## Modules

* `minicrypto.chacha20` - [Chacha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) stream cipher
* `minicrypto.poly1305` - [Poly1305](https://en.wikipedia.org/wiki/Poly1305) one-time message authentication code
* `minicrypto.aead` - [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) authenticated encryption with associated data (AEAD) algorithm
* `minicrypto.x25519` - Diffie-Hellman key exchange function based on [Curve25519](https://en.wikipedia.org/wiki/Curve25519) elliptic curve
* `minicrypto.csprng` - cryptographically secure random number generator.

## BetterC

Minicrypto can be optionally used in BetterC mode:

```json
"subConfigurations": {
    "minicrypto": "betterC"
},
```

## License
[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/deed.en)

## Disclaimer

Minicrypto is intended for applications that need lightweight cryptographic primitives. It is not a replacement for a full cryptographic protocol library.
Do not design your own cryptographic systems unless you know what you are doing.
