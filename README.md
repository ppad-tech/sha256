# ppad-sha256

A pure Haskell implementation of SHA-256 and HMAC-SHA256 on strict and
lazy ByteStrings, as specified by RFC's [6234][r6234] and [2104][r2104].

## Usage

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
> import qualified Data.ByteString.Base16
>
> B16.encode hash_s
"31df9848611f42ab5607ea9e6de84b05d5259085abb30a7917d85efcda42b0e3"
> B16.encode hmac_l
"7f534f6bb4f2b62776bba3d6466e384505f2ff89c91f39800d7a0d4623a4711e"
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/sha256][hadoc].

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

This implementation has benefited from the [SHA][hacka] package
available on Hackage, which was used as a reference during development.

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/sha256
[hacka]: https://hackage.haskell.org/package/SHA
[r6234]: https://datatracker.ietf.org/doc/html/rfc6234
[r2104]: https://datatracker.ietf.org/doc/html/rfc2104
