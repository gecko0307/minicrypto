# Minicrypto

Tiny, zero-dependency cryptographic primitives library for [D language](https://dlang.org). Its main use case is building custom secure transport layers, e.g. for online games, VoIP and IoT.

Most of it is a direct port of [Monocypher](https://github.com/LoupVaillant/monocypher) C code to D, retaining Monocypher API.

[![GitHub Actions CI Status](https://github.com/gecko0307/minicrypto/workflows/CI/badge.svg)](https://github.com/gecko0307/minicrypto/actions?query=workflow%3ACI)
[![DUB Package](https://img.shields.io/dub/v/minicrypto.svg)](https://code.dlang.org/packages/minicrypto)
[![License: CC0-1.0](https://img.shields.io/badge/license-CC0--1.0-blue)](https://creativecommons.org/publicdomain/zero/1.0/deed.en)

## Why another crypto library?

Most existing libraries are bloated with legacy crypto primitives that should not be used for building new stuff. Trying to support every existing standard makes them over-engineered and confuses users. Minicrypto provides only a minimal set of modern algorithms. It is not a binding nor a wrapper around system cryptography, and has no dependencies, which makes usage easy and straightforward. Also Minicrypto is the only known `@nogc` and betterC-compliant crypto library for D. Manual memory management is preferable in real-time applications and a strict requirement for system development.

## Features

* Fast
* No garbage collector usage (`@nogc`)
* Portable across Windows and Posix systems

## Modules

* `minicrypto.argon2` - [Argon2](https://en.wikipedia.org/wiki/Argon2) key derivation function
* `minicrypto.blake2b` - [BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2) cryptographic hash function
* `minicrypto.chacha20` - [ChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) stream cipher
* `minicrypto.poly1305` - [Poly1305](https://en.wikipedia.org/wiki/Poly1305) one-time message authentication code
* `minicrypto.aead` - [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) authenticated encryption with associated data (AEAD) algorithm
* `minicrypto.x25519` - elliptic-curve Diffie-Hellman based on [Curve25519](https://en.wikipedia.org/wiki/Curve25519)
* `minicrypto.eddsa` - [EdDSA](https://en.wikipedia.org/wiki/EdDSA) digital signature algorithm based on Curve25519
* `minicrypto.csprng` - cryptographically secure pseudorandom number generator
* `minicrypto.base64` - [Base64](https://en.wikipedia.org/wiki/Base64) encoder and decoder
* `minicrypto.hex` - data-to-hex encoder.

## BetterC

Minicrypto can be optionally used in BetterC mode. Add the following to your `dub.json`:

```json
"subConfigurations": {
    "minicrypto": "betterC"
}
```

## License
[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/deed.en)
