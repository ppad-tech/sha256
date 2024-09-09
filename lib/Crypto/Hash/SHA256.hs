{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE LambdaCase #-}

module Crypto.Hash.SHA256 where

import qualified Data.Bits as B
import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word32, Word64)

-- utilities

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral

-- from Data.Binary
word32be :: BS.ByteString -> Word32
word32be s =
  (fromIntegral (s `BU.unsafeIndex` 0) `B.unsafeShiftL` 24) .|.
  (fromIntegral (s `BU.unsafeIndex` 1) `B.unsafeShiftL` 16) .|.
  (fromIntegral (s `BU.unsafeIndex` 2) `B.unsafeShiftL`  8) .|.
  (fromIntegral (s `BU.unsafeIndex` 3))
{-# INLINE word32be #-}

-- message padding and parsing
-- https://datatracker.ietf.org/doc/html/rfc6234#section-4.1

pad :: BL.ByteString -> BL.ByteString
pad (BL.toChunks -> m) = con 0 mempty m where
  -- consume input, calculating bytelength and accumulating result
  con !l acc = \case
    (c:cs) ->
      let nl = l + fi (BS.length c)
          nacc = acc <> BSB.byteString c
      in  con nl nacc cs

    [] ->
      let k = sol l
          don = fin l k (acc <> BSB.word8 0x80)
      in  BSB.toLazyByteString don

  -- K, where (L + 1 + K) ≅ 56 (mod 64)
  sol :: Word64 -> Word64
  sol l =
    let r :: Integer
        r = 56 - fi l - 1 -- fi prevents potential underflow
    in  fi $ if r < 0 then r + 64 else r

  -- finalize padding, given bytelength
  fin l k acc
    | k == 0 = acc <> BSB.word64BE (l * 8)
    | otherwise =
        let nacc = acc <> BSB.word8 0x00
        in  fin l (pred k) nacc

-- functions and constants used
-- https://datatracker.ietf.org/doc/html/rfc6234#section-5.1

-- choice, a ? b : c
ch :: Word32 -> Word32 -> Word32 -> Word32
ch x y z = (x .&. y) `B.xor` (B.complement x .&. z)

-- majority, (x & y) ^ (x & z) ^ (y & z)
maj :: Word32 -> Word32 -> Word32 -> Word32
maj x y z = (x .&. y) `B.xor` (x .&. z) `B.xor` (y .&. z)

bsig0 :: Word32 -> Word32
bsig0 x = B.rotateR x 2 `B.xor` B.rotateR x 13 `B.xor` B.rotateR x 22

bsig1 :: Word32 -> Word32
bsig1 x = B.rotateR x 6 `B.xor` B.rotateR x 11 `B.xor` B.rotateR x 25

ssig0 :: Word32 -> Word32
ssig0 x = B.rotateR x 7 `B.xor` B.rotateR x 18 `B.xor` B.unsafeShiftR x 3

ssig1 :: Word32 -> Word32
ssig1 x = B.rotateR x 17 `B.xor` B.rotateR x 19 `B.xor` B.unsafeShiftR x 10

data Schedule = Schedule
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
  deriving (Eq, Show)

-- first 32 bits of the fractional parts of the cube roots of the first
-- sixty-four primes
sha256_constants :: Schedule
sha256_constants = Schedule
  0x428a2f98 0x3956c25b 0xd807aa98 0x72be5d74
  0xe49b69c1 0x2de92c6f 0x983e5152 0xc6e00bf3
  0x27b70a85 0x650a7354 0xa2bfe8a1 0xd192e819
  0x19a4c116 0x391c0cb3 0x748f82ee 0x90befffa
  0x71374491 0x59f111f1 0x12835b01 0x80deb1fe
  0xefbe4786 0x4a7484aa 0xa831c66d 0xd5a79147
  0x2e1b2138 0x766a0abb 0xa81a664b 0xd6990624
  0x1e376c08 0x4ed8aa4a 0x78a5636f 0xa4506ceb
  0xb5c0fbcf 0x923f82a4 0x243185be 0x9bdc06a7
  0x0fc19dc6 0x5cb0a9dc 0xb00327c8 0x06ca6351
  0x4d2c6dfc 0x81c2c92e 0xc24b8b70 0xf40e3585
  0x2748774c 0x5b9cca4f 0x84c87814 0xbef9a3f7
  0xe9b5dba5 0xab1c5ed5 0x550c7dc3 0xc19bf174
  0x240ca1cc 0x76f988da 0xbf597fc7 0x14292967
  0x53380d13 0x92722c85 0xc76c51a3 0x106aa070
  0x34b0bcb5 0x682e6ff3 0x8cc70208 0xc67178f2

-- initialization
-- https://datatracker.ietf.org/doc/html/rfc6234#section-6.1

data Registers = Registers
    !Word32 !Word32 !Word32 !Word32
    !Word32 !Word32 !Word32 !Word32
  deriving (Eq, Show)

-- first 32 bits of the fractional parts of the square roots of the
-- first eight primes
sha256_iv :: Registers
sha256_iv = Registers
  0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
  0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19

-- processing
-- https://datatracker.ietf.org/doc/html/rfc6234#section-6.2




