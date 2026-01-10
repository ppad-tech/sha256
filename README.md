# sha256

[![](https://img.shields.io/hackage/v/ppad-sha256?color=blue)](https://hackage.haskell.org/package/ppad-sha256)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-sha256-lightblue)](https://docs.ppad.tech/sha256)

A Haskell implementation of SHA-256 and HMAC-SHA256 on strict and lazy
ByteStrings, as specified by RFC's [6234][r6234] and [2104][r2104], that
uses ARM SHA2 intrinsics when available.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > -- import qualified
  > import qualified Crypto.Hash.SHA256 as SHA256
  >
  > -- 'hash' and 'hmac' operate on strict bytestrings
  > -- 'hmac' returns a value of type 'MAC' with a constant-time Eq instance
  >
  > let hash_s = SHA256.hash "strict bytestring input"
  > let hmac_s = SHA256.hmac "strict secret" "strict bytestring input"
  >
  > -- 'hash_lazy' and 'hmac_lazy' operate on lazy bytestrings
  > -- but note that the key for HMAC is always strict
  >
  > let hash_l = SHA256.hash_lazy "lazy bytestring input"
  > let MAC hmac_l = SHA256.hmac_lazy "strict secret" "lazy bytestring input"
  >
  > -- digests are always unformatted 256-bit (32-byte) strict bytestrings
  >
  > import qualified Data.ByteString as BS
  >
  > BS.take 10 hash_s
  "1\223\152Ha\USB\171V\a"
  > BS.take 10 hmac_l
  "\DELSOk\180\242\182'v\187"
  >
  > -- you can use third-party libraries for rendering if needed
  > -- e.g., using ppad-base16:
  >
  > import qualified Data.ByteString.Base16 as B16
  >
  > B16.encode hash_s
  "31df9848611f42ab5607ea9e6de84b05d5259085abb30a7917d85efcda42b0e3"
  > B16.encode hmac_l
  "7f534f6bb4f2b62776bba3d6466e384505f2ff89c91f39800d7a0d4623a4711e"
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/sha256][hadoc].

## Performance

The aim is best-in-class performance. Current benchmark figures on an
M4 Silicon MacBook Air, where we avail of hardware acceleration via
ARM cryptography extensions, look like (use `cabal bench` to run the
benchmark suite):

```
  benchmarking ppad-sha256/SHA256 (32B input)/hash
  time                 48.14 ns   (48.12 ns .. 48.18 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 48.17 ns   (48.10 ns .. 48.22 ns)
  std dev              196.5 ps   (107.8 ps .. 358.1 ps)

  benchmarking ppad-sha256/HMAC-SHA256 (32B input)/hmac
  time                 193.1 ns   (192.9 ns .. 193.5 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 193.4 ns   (193.2 ns .. 193.7 ns)
  std dev              767.2 ps   (507.4 ps .. 1.233 ns)
```

You should compile with the 'llvm' flag for maximum performance.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be challenging to achieve.

The HMAC-SHA256 functions within pass all [Wycheproof vectors][wyche],
as well as various other useful unit test vectors found around the
internet.

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-sha256
```

to get a REPL for the main library.

## Attribution

This implementation has benefitted immensely from the [SHA][hacka]
package available on Hackage, which was used as a reference during
development. Many parts wound up being direct translations.

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/sha256
[hacka]: https://hackage.haskell.org/package/SHA
[r6234]: https://datatracker.ietf.org/doc/html/rfc6234
[r2104]: https://datatracker.ietf.org/doc/html/rfc2104
[noble]: https://github.com/paulmillr/noble-hashes
[wyche]: https://github.com/C2SP/wycheproof
