# ppad-sha256

A pure Haskell implementation of SHA-256 and HMAC-SHA256 on strict and
lazy ByteStrings, as specified by RFC's [6234][r6234] and [2104][r2104].

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > -- import qualified
  > import qualified Crypto.Hash.SHA256 as SHA256
  >
  > -- 'hash' and 'hmac' operate on strict bytestrings
  >
  > let hash_s = SHA256.hash "strict bytestring input"
  > let hmac_s = SHA256.hmac "strict secret" "strict bytestring input"
  >
  > -- 'hash_lazy' and 'hmac_lazy' operate on lazy bytestrings
  > -- but note that the key for HMAC is always strict
  >
  > let hash_l = SHA256.hash_lazy "lazy bytestring input"
  > let hmac_l = SHA256.hmac_lazy "strict secret" "lazy bytestring input"
  >
  > -- results are always unformatted 256-bit (32-byte) strict bytestrings
  >
  > import qualified Data.ByteString as BS
  >
  > BS.take 10 hash_s
  "1\223\152Ha\USB\171V\a"
  > BS.take 10 hmac_l
  "\DELSOk\180\242\182'v\187"
  >
  > -- you can use third-party libraries for rendering if necessary
  > -- e.g., using base16-bytestring:
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

The eventual aim is best-in-class performance for pure, highly-auditable
Haskell code. But let's keep it as an eventual goal.

Current benchmark figures look like (use `cabal bench` to run the
benchmark suite):

```
  benchmarking ppad-sha256/SHA256 (32B input)/hash
  time                 2.684 μs   (2.658 μs .. 2.714 μs)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 2.689 μs   (2.674 μs .. 2.706 μs)
  std dev              55.18 ns   (44.66 ns .. 66.35 ns)
  variance introduced by outliers: 22% (moderately inflated)

  benchmarking ppad-sha256/SHA256 (32B input)/hash_lazy
  time                 2.746 μs   (2.712 μs .. 2.786 μs)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 2.747 μs   (2.720 μs .. 2.784 μs)
  std dev              101.1 ns   (73.17 ns .. 144.1 ns)
  variance introduced by outliers: 49% (moderately inflated)

  benchmarking ppad-sha256/HMAC-SHA256 (32B input)/hmac
  time                 10.30 μs   (10.18 μs .. 10.48 μs)
                       0.997 R²   (0.996 R² .. 0.998 R²)
  mean                 10.68 μs   (10.48 μs .. 10.92 μs)
  std dev              720.5 ns   (603.8 ns .. 874.2 ns)
  variance introduced by outliers: 74% (severely inflated)

  benchmarking ppad-sha256/HMAC-SHA256 (32B input)/hmac_lazy
  time                 10.58 μs   (10.36 μs .. 10.85 μs)
                       0.996 R²   (0.991 R² .. 0.998 R²)
  mean                 10.72 μs   (10.56 μs .. 10.93 μs)
  std dev              634.4 ns   (523.1 ns .. 868.8 ns)
  variance introduced by outliers: 68% (severely inflated)
```

When testing `hash_lazy` on a 1GB input, we get a profile like the
following:

```
  COST CENTRE                         %time %alloc

  Crypto.Hash.SHA256.block_hash        72.8    4.9
  Crypto.Hash.SHA256.prepare_schedule  15.9   32.3
  Crypto.Hash.SHA256.blocks_lazy        3.7   37.2
  Crypto.Hash.SHA256.parse              3.6   14.7
  Crypto.Hash.SHA256.hash_alg           2.1    2.9
  hash                                  1.3    8.0
```

The overwhelming majority of time is spent in `block_hash`, i.e. steps
2, 3 and 4 of RFC 6234's section 6.2, which is a good target for
optimisation.

Almost all allocation can be eliminated via the use of 1) better
bytestring management, and 2) unlifted types & unboxed tuples (the
internal `Schedule` type, for example, is a record type of sixty-four
Word32's, which can be replaced by an unboxed 64-tuple, the maximum
tuple size supported by GHC).

More care with bytestrings reduces the majority. The use of
Data.ByteString.Lazy.splitAt is very problematic, as it is neither
O(1) in time nor space as is its strict cousin. The use of a custom
splitAt function that returns a (StrictByteString, LazyByteString) pair
decreases allocation substantially, as do similar strategies (e.g.
careful use of a custom Data.ByteString.splitAt that returns a strict,
unboxed pair).

None of these optimisations actually improve wall-clock performance, so
they are left unimplemented for the time being.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be challenging to achieve.

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
development. Many parts wound up as direct translations.

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/sha256
[hacka]: https://hackage.haskell.org/package/SHA
[r6234]: https://datatracker.ietf.org/doc/html/rfc6234
[r2104]: https://datatracker.ietf.org/doc/html/rfc2104
