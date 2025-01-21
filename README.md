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

The aim is best-in-class performance for pure, highly-auditable Haskell
code.

Current benchmark figures on my mid-2020 MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking ppad-sha256/SHA256 (32B input)/hash
  time                 1.387 μs   (1.365 μs .. 1.409 μs)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 1.386 μs   (1.378 μs .. 1.399 μs)
  std dev              34.07 ns   (24.55 ns .. 52.14 ns)
  variance introduced by outliers: 31% (moderately inflated)

  benchmarking ppad-sha256/HMAC-SHA256 (32B input)/hmac
  time                 5.618 μs   (5.564 μs .. 5.681 μs)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 5.648 μs   (5.603 μs .. 5.697 μs)
  std dev              159.1 ns   (130.7 ns .. 194.1 ns)
  variance introduced by outliers: 34% (moderately inflated)
```

Compare this to Hackage's famous SHA package:

```
  benchmarking ppad-sha256/SHA256 (32B input)/SHA.sha256
  time                 2.585 μs   (2.565 μs .. 2.613 μs)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 2.635 μs   (2.616 μs .. 2.654 μs)
  std dev              68.00 ns   (58.45 ns .. 80.94 ns)
  variance introduced by outliers: 32% (moderately inflated)

  benchmarking ppad-sha256/HMAC-SHA256 (32B input)/SHA.hmacSha256
  time                 9.672 μs   (9.533 μs .. 9.810 μs)
                       0.998 R²   (0.998 R² .. 0.999 R²)
  mean                 9.715 μs   (9.608 μs .. 9.858 μs)
  std dev              394.7 ns   (315.3 ns .. 576.2 ns)
  variance introduced by outliers: 50% (moderately inflated)

```

Or the relevant SHA-256-based functions from a library with similar
aims, [noble-hashes][noble]:

```
SHA256 32B x 420,875 ops/sec @ 2μs/op ± 1.33% (min: 1μs, max: 3ms)
HMAC-SHA256 32B x 97,304 ops/sec @ 10μs/op
```

When reading a 1GB input from disk and testing it with `hash_lazy`, we
get statistics like the following:

```
   2,310,899,616 bytes allocated in the heap
          93,800 bytes copied during GC
          78,912 bytes maximum residency (2 sample(s))
          35,776 bytes maximum slop
              10 MiB total memory in use (0 MiB lost due to fragmentation)

                                     Tot time (elapsed)  Avg pause  Max pause
  Gen  0       295 colls,     0 par    0.007s   0.008s     0.0000s    0.0001s
  Gen  1         2 colls,     0 par    0.000s   0.001s     0.0004s    0.0004s

  INIT    time    0.003s  (  0.003s elapsed)
  MUT     time   22.205s  ( 22.260s elapsed)
  GC      time    0.007s  (  0.009s elapsed)
  EXIT    time    0.000s  (  0.001s elapsed)
  Total   time   22.216s  ( 22.273s elapsed)

  %GC     time       0.0%  (0.0% elapsed)

  Alloc rate    104,073,382 bytes per MUT second

  Productivity 100.0% of total user, 99.9% of total elapsed
```

SHA.sha256 gets more like:

```
  74,403,596,936 bytes allocated in the heap
      12,971,992 bytes copied during GC
          79,176 bytes maximum residency (2 sample(s))
          35,512 bytes maximum slop
               6 MiB total memory in use (0 MiB lost due to fragmentation)

                                     Tot time (elapsed)  Avg pause  Max pause
  Gen  0     17883 colls,     0 par    0.103s   0.148s     0.0000s    0.0001s
  Gen  1         2 colls,     0 par    0.000s   0.000s     0.0002s    0.0003s

  INIT    time    0.006s  (  0.006s elapsed)
  MUT     time   32.367s  ( 32.408s elapsed)
  GC      time    0.104s  (  0.149s elapsed)
  EXIT    time    0.000s  (  0.001s elapsed)
  Total   time   32.477s  ( 32.563s elapsed)

  %GC     time       0.0%  (0.0% elapsed)

  Alloc rate    2,298,740,250 bytes per MUT second

  Productivity  99.7% of total user, 99.5% of total elapsed
```

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
