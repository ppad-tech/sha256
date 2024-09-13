{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ExtendedLiterals #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Crypto.Hash.SHA256
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Pure SHA-256 and HMAC-SHA256 implementations for
-- strict and lazy ByteStrings, as specified by RFC's
-- [6234](https://datatracker.ietf.org/doc/html/rfc6234) and
-- [2104](https://datatracker.ietf.org/doc/html/rfc2104).

module Crypto.Hash.SHA256 (
  -- * SHA-256 message digest functions
    hash
  , hash_lazy

  -- * SHA256-based MAC functions
  , hmac
  , hmac_lazy
  ) where

import qualified Data.Bits as B
import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Builder.Extra as BE
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Internal as BLI
import qualified Data.ByteString.Unsafe as BU
import qualified Data.List as L
import Data.Word (Word32, Word64)
import Foreign.ForeignPtr (plusForeignPtr)
import GHC.Exts (Word32#, Int#)
import qualified GHC.Exts as E

-- preliminary utils

-- keystroke savers
fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

p32# :: Word32# -> Word32# -> Word32#
p32# = E.plusWord32#
{-# INLINE p32# #-}

-- break a bytestring into blocks of the specified bytelength
blocks :: Int -> BS.ByteString -> [BS.ByteString]
blocks s = blocks_lazy s . BL.fromStrict

blocks_lazy :: Int -> BL.ByteString -> [BS.ByteString]
blocks_lazy s = loop where
  loop bs
    | BL.null bs = []
    | otherwise = case BL.splitAt (fi s) bs of
        (c, r) -> BL.toStrict c : loop r

-- unsafe parse, strict ByteString to Word32 (verbatim from Data.Binary)
word32be :: BS.ByteString -> Word32
word32be s =
  (fromIntegral (s `BU.unsafeIndex` 0) `B.unsafeShiftL` 24) .|.
  (fromIntegral (s `BU.unsafeIndex` 1) `B.unsafeShiftL` 16) .|.
  (fromIntegral (s `BU.unsafeIndex` 2) `B.unsafeShiftL`  8) .|.
  (fromIntegral (s `BU.unsafeIndex` 3))
{-# INLINE word32be #-}

-- following are utility types for more efficient ByteString management

data SLPair = SLPair {-# UNPACK #-} !BS.ByteString !BL.ByteString

data WSPair = WSPair {-# UNPACK #-} !Word32 {-# UNPACK #-} !BS.ByteString

-- a variant of Data.ByteString.Lazy.splitAt that returns the initial
-- component as a strict, unboxed ByteString
splitAt64 :: BL.ByteString -> SLPair
splitAt64 = splitAt' (64 :: Int) where
  splitAt' _ BLI.Empty        = SLPair mempty BLI.Empty
  splitAt' n (BLI.Chunk c cs) =
    if   n < fi (BS.length c)
    then SLPair (BS.take (fi n) c) (BLI.Chunk (BS.drop (fi n) c) cs)
    else
      let SLPair cs' cs'' = splitAt' (n - fi (BS.length c)) cs
      in  SLPair (c <> cs') cs''

-- this unsafe function turns Data.ByteString.splitAt into an
-- incremental Word32 parser; the initial 32 bits are parsed to an
-- unboxed Word32, and the rest of the ByteString is returned strict and
-- unboxed
parseWord32 :: BS.ByteString -> WSPair
parseWord32 (BI.BS x l) =
  WSPair (word32be (BI.BS x 4)) (BI.BS (plusForeignPtr x 4) (l - 4))
{-# INLINE parseWord32 #-}

-- following are unlifted Word32 bit twiddling functions from
-- GHC.Internal.Word

(.&.#) :: Word32# -> Word32# -> Word32#
x# .&.# y# = E.wordToWord32#
  ((E.word32ToWord# x#) `E.and#` (E.word32ToWord# y#))

(.|.#) :: Word32# -> Word32# -> Word32#
x# .|.# y# = E.wordToWord32#
  ((E.word32ToWord# x#) `E.or#` (E.word32ToWord# y#))

(.^.#) :: Word32# -> Word32# -> Word32#
x# .^.# y# = E.wordToWord32#
  ((E.word32ToWord# x#) `E.xor#` (E.word32ToWord# y#))

complement# :: Word32# -> Word32#
complement# x# = E.wordToWord32# (E.not# (E.word32ToWord# x#))

rotate# :: Word32# -> Int# -> Word32#
rotate# x# i#
    | E.isTrue# (i'# E.==# 0#) = x#
    | otherwise = E.wordToWord32# $
              ((E.word32ToWord# x#) `E.uncheckedShiftL#` i'#)
        `E.or#` ((E.word32ToWord# x#) `E.uncheckedShiftRL#` (32# E.-# i'#))
  where
    !i'# = E.word2Int# (E.int2Word# i# `E.and#` 31##)

rotateR# :: Word32# -> Int# -> Word32#
rotateR# x# i# = x# `rotate#` (E.negateInt# i#)

unsafeShiftR# :: Word32# -> Int# -> Word32#
unsafeShiftR# x# i# = E.wordToWord32#
  ((E.word32ToWord# x#) `E.uncheckedShiftRL#` i#)

-- unbox a Word32
unW32 :: Word32 -> Word32#
unW32 (fi -> i) = case i of
  E.I# i# -> E.wordToWord32# (E.int2Word# i#)
{-# INLINE unW32 #-}

-- box a Word32
lw32 :: Word32# -> Word32
lw32 w = fi (E.I# (E.word2Int# (E.word32ToWord# w)))
{-# INLINE lw32 #-}

-- message padding and parsing
-- https://datatracker.ietf.org/doc/html/rfc6234#section-4.1

-- k such that (l + 1 + k) mod 64 = 56
sol :: Word64 -> Word64
sol l = let r = 56 - fi l `mod` 64 - 1 :: Integer -- fi prevents underflow
        in  fi (if r < 0 then r + 64 else r)

pad :: BS.ByteString -> BS.ByteString
pad m = BL.toStrict . BSB.toLazyByteString $ padded where
  l = fi (BS.length m)

  padded = BSB.byteString m <> fill (sol l) (BSB.word8 0x80)

  fill j !acc
    | j == 0 = acc <> BSB.word64BE (l * 8)
    | otherwise = fill (pred j) (acc <> BSB.word8 0x00)

-- hat tip to hackage SHA authors for traversal strategy
pad_lazy :: BL.ByteString -> BL.ByteString
pad_lazy (BL.toChunks -> m) = BL.fromChunks (walk 0 m) where
  -- walk chunks, calculating length and appending padding
  walk !l = \case
    (c:cs) -> c : walk (l + fi (BS.length c)) cs
    [] -> padding l (sol l) (BSB.word8 0x80)

  -- construct padding
  padding l k bs
    | k == 0 =
          pure
        . BL.toStrict
        . BE.toLazyByteStringWith (BE.safeStrategy 128 BE.smallChunkSize) mempty
        $ bs <> BSB.word64BE (l * 8)
    | otherwise =
        let nacc = bs <> BSB.word8 0x00
        in  padding l (pred k) nacc

-- functions and constants used
-- https://datatracker.ietf.org/doc/html/rfc6234#section-5.1

ch :: Word32 -> Word32 -> Word32 -> Word32
ch x y z = (x .&. y) `B.xor` (B.complement x .&. z)

-- credit to SHA authors for the following optimisation. their text:
--
-- > note:
-- >   the original functions is (x & y) ^ (x & z) ^ (y & z)
-- >   if you fire off truth tables, this is equivalent to
-- >     (x & y) | (x & z) | (y & z)
-- >   which you can the use distribution on:
-- >     (x & (y | z)) | (y & z)
-- >   which saves us one operation.
maj :: Word32 -> Word32 -> Word32 -> Word32
maj x y z = (x .&. (y .|. z)) .|. (y .&. z)

bsig0 :: Word32 -> Word32
bsig0 x = B.rotateR x 2 `B.xor` B.rotateR x 13 `B.xor` B.rotateR x 22

bsig1 :: Word32 -> Word32
bsig1 x = B.rotateR x 6 `B.xor` B.rotateR x 11 `B.xor` B.rotateR x 25

ssig0 :: Word32 -> Word32
ssig0 x = B.rotateR x 7 `B.xor` B.rotateR x 18 `B.xor` B.unsafeShiftR x 3

ssig1 :: Word32 -> Word32
ssig1 x = B.rotateR x 17 `B.xor` B.rotateR x 19 `B.xor` B.unsafeShiftR x 10

ch# :: Word32# -> Word32# -> Word32# -> Word32#
ch# x# y# z# = (x# .&.# y#) .^.# (complement# x# .&.# z#)
{-# INLINE ch# #-}

-- credit to SHA authors for the following optimisation. their text:
--
-- > note:
-- >   the original functions is (x & y) ^ (x & z) ^ (y & z)
-- >   if you fire off truth tables, this is equivalent to
-- >     (x & y) | (x & z) | (y & z)
-- >   which you can the use distribution on:
-- >     (x & (y | z)) | (y & z)
-- >   which saves us one operation.
maj# :: Word32# -> Word32# -> Word32# -> Word32#
maj# x# y# z# = (x# .&.# (y# .|.# z#)) .|.# (y# .&.# z#)
{-# INLINE maj# #-}

bsig0# :: Word32# -> Word32#
bsig0# x# = rotateR# x# 2# .^.# rotateR# x# 13# .^.# rotateR# x# 22#
{-# INLINE bsig0# #-}

bsig1# :: Word32# -> Word32#
bsig1# x# = rotateR# x# 6# .^.# rotateR# x# 11# .^.# rotateR# x# 25#
{-# INLINE bsig1# #-}

ssig0# :: Word32# -> Word32#
ssig0# x# = rotateR# x# 7# .^.# rotateR# x# 18# .^.# unsafeShiftR# x# 3#
{-# INLINE ssig0# #-}

ssig1# :: Word32# -> Word32#
ssig1# x# = rotateR# x# 17# .^.# rotateR# x# 19# .^.# unsafeShiftR# x# 10#
{-# INLINE ssig1# #-}

data Schedule = Schedule {
    w00 :: !Word32, w01 :: !Word32, w02 :: !Word32, w03 :: !Word32
  , w04 :: !Word32, w05 :: !Word32, w06 :: !Word32, w07 :: !Word32
  , w08 :: !Word32, w09 :: !Word32, w10 :: !Word32, w11 :: !Word32
  , w12 :: !Word32, w13 :: !Word32, w14 :: !Word32, w15 :: !Word32
  , w16 :: !Word32, w17 :: !Word32, w18 :: !Word32, w19 :: !Word32
  , w20 :: !Word32, w21 :: !Word32, w22 :: !Word32, w23 :: !Word32
  , w24 :: !Word32, w25 :: !Word32, w26 :: !Word32, w27 :: !Word32
  , w28 :: !Word32, w29 :: !Word32, w30 :: !Word32, w31 :: !Word32
  , w32 :: !Word32, w33 :: !Word32, w34 :: !Word32, w35 :: !Word32
  , w36 :: !Word32, w37 :: !Word32, w38 :: !Word32, w39 :: !Word32
  , w40 :: !Word32, w41 :: !Word32, w42 :: !Word32, w43 :: !Word32
  , w44 :: !Word32, w45 :: !Word32, w46 :: !Word32, w47 :: !Word32
  , w48 :: !Word32, w49 :: !Word32, w50 :: !Word32, w51 :: !Word32
  , w52 :: !Word32, w53 :: !Word32, w54 :: !Word32, w55 :: !Word32
  , w56 :: !Word32, w57 :: !Word32, w58 :: !Word32, w59 :: !Word32
  , w60 :: !Word32, w61 :: !Word32, w62 :: !Word32, w63 :: !Word32
  } deriving (Eq, Show)

-- unboxed 64-tuple (message schedule)
type Sd = (#
    Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  #)

-- unboxed 8-tuple (registers)
type Rs = (#
    Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#
  #)

-- unboxed 16-tuple (block)
type Bl = (#
    Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  #)

choose_w :: Schedule -> Int -> Word32
choose_w s = \case
  0  -> w00 s; 1  -> w01 s; 2  -> w02 s; 3  -> w03 s
  4  -> w04 s; 5  -> w05 s; 6  -> w06 s; 7  -> w07 s
  8  -> w08 s; 9  -> w09 s; 10 -> w10 s; 11 -> w11 s
  12 -> w12 s; 13 -> w13 s; 14 -> w14 s; 15 -> w15 s
  16 -> w16 s; 17 -> w17 s; 18 -> w18 s; 19 -> w19 s
  20 -> w20 s; 21 -> w21 s; 22 -> w22 s; 23 -> w23 s
  24 -> w24 s; 25 -> w25 s; 26 -> w26 s; 27 -> w27 s
  28 -> w28 s; 29 -> w29 s; 30 -> w30 s; 31 -> w31 s
  32 -> w32 s; 33 -> w33 s; 34 -> w34 s; 35 -> w35 s
  36 -> w36 s; 37 -> w37 s; 38 -> w38 s; 39 -> w39 s
  40 -> w40 s; 41 -> w41 s; 42 -> w42 s; 43 -> w43 s
  44 -> w44 s; 45 -> w45 s; 46 -> w46 s; 47 -> w47 s
  48 -> w48 s; 49 -> w49 s; 50 -> w50 s; 51 -> w51 s
  52 -> w52 s; 53 -> w53 s; 54 -> w54 s; 55 -> w55 s
  56 -> w56 s; 57 -> w57 s; 58 -> w58 s; 59 -> w59 s
  60 -> w60 s; 61 -> w61 s; 62 -> w62 s; 63 -> w63 s
  _  -> error "ppad-sha256: internal error (invalid schedule index)"

-- k0-k63 are the first 32 bits of the fractional parts of the cube
-- roots of the first sixty-four prime numbers
choose_k :: Int -> Word32
choose_k = \case
  0  -> 0x428a2f98; 1  -> 0x71374491; 2  -> 0xb5c0fbcf; 3  -> 0xe9b5dba5
  4  -> 0x3956c25b; 5  -> 0x59f111f1; 6  -> 0x923f82a4; 7  -> 0xab1c5ed5
  8  -> 0xd807aa98; 9  -> 0x12835b01; 10 -> 0x243185be; 11 -> 0x550c7dc3
  12 -> 0x72be5d74; 13 -> 0x80deb1fe; 14 -> 0x9bdc06a7; 15 -> 0xc19bf174
  16 -> 0xe49b69c1; 17 -> 0xefbe4786; 18 -> 0x0fc19dc6; 19 -> 0x240ca1cc
  20 -> 0x2de92c6f; 21 -> 0x4a7484aa; 22 -> 0x5cb0a9dc; 23 -> 0x76f988da
  24 -> 0x983e5152; 25 -> 0xa831c66d; 26 -> 0xb00327c8; 27 -> 0xbf597fc7
  28 -> 0xc6e00bf3; 29 -> 0xd5a79147; 30 -> 0x06ca6351; 31 -> 0x14292967
  32 -> 0x27b70a85; 33 -> 0x2e1b2138; 34 -> 0x4d2c6dfc; 35 -> 0x53380d13
  36 -> 0x650a7354; 37 -> 0x766a0abb; 38 -> 0x81c2c92e; 39 -> 0x92722c85
  40 -> 0xa2bfe8a1; 41 -> 0xa81a664b; 42 -> 0xc24b8b70; 43 -> 0xc76c51a3
  44 -> 0xd192e819; 45 -> 0xd6990624; 46 -> 0xf40e3585; 47 -> 0x106aa070
  48 -> 0x19a4c116; 49 -> 0x1e376c08; 50 -> 0x2748774c; 51 -> 0x34b0bcb5
  52 -> 0x391c0cb3; 53 -> 0x4ed8aa4a; 54 -> 0x5b9cca4f; 55 -> 0x682e6ff3
  56 -> 0x748f82ee; 57 -> 0x78a5636f; 58 -> 0x84c87814; 59 -> 0x8cc70208
  60 -> 0x90befffa; 61 -> 0xa4506ceb; 62 -> 0xbef9a3f7; 63 -> 0xc67178f2
  _  -> error "ppad-sha256: internal error (invalid constant index)"

-- initialization
-- https://datatracker.ietf.org/doc/html/rfc6234#section-6.1

data Registers = Registers {
    h0 :: !Word32, h1 :: !Word32, h2 :: !Word32, h3 :: !Word32
  , h4 :: !Word32, h5 :: !Word32, h6 :: !Word32, h7 :: !Word32
  } deriving (Eq, Show)

-- first 32 bits of the fractional parts of the square roots of the
-- first eight primes
iv :: Registers
iv = Registers
  0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
  0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19

-- processing
-- https://datatracker.ietf.org/doc/html/rfc6234#section-6.2

data Block = Block {
    m00 :: !Word32, m01 :: !Word32, m02 :: !Word32, m03 :: !Word32
  , m04 :: !Word32, m05 :: !Word32, m06 :: !Word32, m07 :: !Word32
  , m08 :: !Word32, m09 :: !Word32, m10 :: !Word32, m11 :: !Word32
  , m12 :: !Word32, m13 :: !Word32, m14 :: !Word32, m15 :: !Word32
  } deriving (Eq, Show)

-- parse a 512-bit block into sixteen 32-bit words
parse :: BS.ByteString -> Block
parse bs =
  let (word32be -> m00, t00) = BS.splitAt 4 bs
      (word32be -> m01, t01) = BS.splitAt 4 t00
      (word32be -> m02, t02) = BS.splitAt 4 t01
      (word32be -> m03, t03) = BS.splitAt 4 t02
      (word32be -> m04, t04) = BS.splitAt 4 t03
      (word32be -> m05, t05) = BS.splitAt 4 t04
      (word32be -> m06, t06) = BS.splitAt 4 t05
      (word32be -> m07, t07) = BS.splitAt 4 t06
      (word32be -> m08, t08) = BS.splitAt 4 t07
      (word32be -> m09, t09) = BS.splitAt 4 t08
      (word32be -> m10, t10) = BS.splitAt 4 t09
      (word32be -> m11, t11) = BS.splitAt 4 t10
      (word32be -> m12, t12) = BS.splitAt 4 t11
      (word32be -> m13, t13) = BS.splitAt 4 t12
      (word32be -> m14, t14) = BS.splitAt 4 t13
      (word32be -> m15, t15) = BS.splitAt 4 t14
  in  if   BS.null t15
      then Block {..}
      else error "ppad-sha256: internal error (bytes remaining)"

-- parse a 512-bit block into sixteen 32-bit words
parse# :: BS.ByteString -> Bl
parse# bs =
  let !(WSPair (unW32 -> m00) t00) = parseWord32 bs
      !(WSPair (unW32 -> m01) t01) = parseWord32 t00
      !(WSPair (unW32 -> m02) t02) = parseWord32 t01
      !(WSPair (unW32 -> m03) t03) = parseWord32 t02
      !(WSPair (unW32 -> m04) t04) = parseWord32 t03
      !(WSPair (unW32 -> m05) t05) = parseWord32 t04
      !(WSPair (unW32 -> m06) t06) = parseWord32 t05
      !(WSPair (unW32 -> m07) t07) = parseWord32 t06
      !(WSPair (unW32 -> m08) t08) = parseWord32 t07
      !(WSPair (unW32 -> m09) t09) = parseWord32 t08
      !(WSPair (unW32 -> m10) t10) = parseWord32 t09
      !(WSPair (unW32 -> m11) t11) = parseWord32 t10
      !(WSPair (unW32 -> m12) t12) = parseWord32 t11
      !(WSPair (unW32 -> m13) t13) = parseWord32 t12
      !(WSPair (unW32 -> m14) t14) = parseWord32 t13
      !(WSPair (unW32 -> m15) t15) = parseWord32 t14
  in  if   BS.null t15
      then (# m00, m01, m02, m03, m04, m05, m06, m07
           ,  m08, m09, m10, m11, m12, m13, m14, m15
           #)
      else error "ppad-sha256: internal error (bytes remaining)"

-- RFC 6234 6.2 step 1
prepare_schedule :: Block -> Schedule
prepare_schedule Block {..} = Schedule {..} where
  w00 = m00
  w01 = m01
  w02 = m02
  w03 = m03
  w04 = m04
  w05 = m05
  w06 = m06
  w07 = m07
  w08 = m08
  w09 = m09
  w10 = m10
  w11 = m11
  w12 = m12
  w13 = m13
  w14 = m14
  w15 = m15
  w16 = ssig1 w14 + w09 + ssig0 w01 + w00
  w17 = ssig1 w15 + w10 + ssig0 w02 + w01
  w18 = ssig1 w16 + w11 + ssig0 w03 + w02
  w19 = ssig1 w17 + w12 + ssig0 w04 + w03
  w20 = ssig1 w18 + w13 + ssig0 w05 + w04
  w21 = ssig1 w19 + w14 + ssig0 w06 + w05
  w22 = ssig1 w20 + w15 + ssig0 w07 + w06
  w23 = ssig1 w21 + w16 + ssig0 w08 + w07
  w24 = ssig1 w22 + w17 + ssig0 w09 + w08
  w25 = ssig1 w23 + w18 + ssig0 w10 + w09
  w26 = ssig1 w24 + w19 + ssig0 w11 + w10
  w27 = ssig1 w25 + w20 + ssig0 w12 + w11
  w28 = ssig1 w26 + w21 + ssig0 w13 + w12
  w29 = ssig1 w27 + w22 + ssig0 w14 + w13
  w30 = ssig1 w28 + w23 + ssig0 w15 + w14
  w31 = ssig1 w29 + w24 + ssig0 w16 + w15
  w32 = ssig1 w30 + w25 + ssig0 w17 + w16
  w33 = ssig1 w31 + w26 + ssig0 w18 + w17
  w34 = ssig1 w32 + w27 + ssig0 w19 + w18
  w35 = ssig1 w33 + w28 + ssig0 w20 + w19
  w36 = ssig1 w34 + w29 + ssig0 w21 + w20
  w37 = ssig1 w35 + w30 + ssig0 w22 + w21
  w38 = ssig1 w36 + w31 + ssig0 w23 + w22
  w39 = ssig1 w37 + w32 + ssig0 w24 + w23
  w40 = ssig1 w38 + w33 + ssig0 w25 + w24
  w41 = ssig1 w39 + w34 + ssig0 w26 + w25
  w42 = ssig1 w40 + w35 + ssig0 w27 + w26
  w43 = ssig1 w41 + w36 + ssig0 w28 + w27
  w44 = ssig1 w42 + w37 + ssig0 w29 + w28
  w45 = ssig1 w43 + w38 + ssig0 w30 + w29
  w46 = ssig1 w44 + w39 + ssig0 w31 + w30
  w47 = ssig1 w45 + w40 + ssig0 w32 + w31
  w48 = ssig1 w46 + w41 + ssig0 w33 + w32
  w49 = ssig1 w47 + w42 + ssig0 w34 + w33
  w50 = ssig1 w48 + w43 + ssig0 w35 + w34
  w51 = ssig1 w49 + w44 + ssig0 w36 + w35
  w52 = ssig1 w50 + w45 + ssig0 w37 + w36
  w53 = ssig1 w51 + w46 + ssig0 w38 + w37
  w54 = ssig1 w52 + w47 + ssig0 w39 + w38
  w55 = ssig1 w53 + w48 + ssig0 w40 + w39
  w56 = ssig1 w54 + w49 + ssig0 w41 + w40
  w57 = ssig1 w55 + w50 + ssig0 w42 + w41
  w58 = ssig1 w56 + w51 + ssig0 w43 + w42
  w59 = ssig1 w57 + w52 + ssig0 w44 + w43
  w60 = ssig1 w58 + w53 + ssig0 w45 + w44
  w61 = ssig1 w59 + w54 + ssig0 w46 + w45
  w62 = ssig1 w60 + w55 + ssig0 w47 + w46
  w63 = ssig1 w61 + w56 + ssig0 w48 + w47

-- RFC 6234 6.2 step 1
prepare_schedule# :: Bl -> Sd
prepare_schedule# b = case b of
  (# m00, m01, m02, m03, m04, m05, m06, m07,
     m08, m09, m10, m11, m12, m13, m14, m15 #) ->
    let w00 = m00; w01 = m01; w02 = m02; w03 = m03
        w04 = m04; w05 = m05; w06 = m06; w07 = m07
        w08 = m08; w09 = m09; w10 = m10; w11 = m11
        w12 = m12; w13 = m13; w14 = m14; w15 = m15
        w16 = p32# (ssig1# w14) (p32# w09 (p32# (ssig0# w01) w00))
        w17 = p32# (ssig1# w15) (p32# w10 (p32# (ssig0# w02) w01))
        w18 = p32# (ssig1# w16) (p32# w11 (p32# (ssig0# w03) w02))
        w19 = p32# (ssig1# w17) (p32# w12 (p32# (ssig0# w04) w03))
        w20 = p32# (ssig1# w18) (p32# w13 (p32# (ssig0# w05) w04))
        w21 = p32# (ssig1# w19) (p32# w14 (p32# (ssig0# w06) w05))
        w22 = p32# (ssig1# w20) (p32# w15 (p32# (ssig0# w07) w06))
        w23 = p32# (ssig1# w21) (p32# w16 (p32# (ssig0# w08) w07))
        w24 = p32# (ssig1# w22) (p32# w17 (p32# (ssig0# w09) w08))
        w25 = p32# (ssig1# w23) (p32# w18 (p32# (ssig0# w10) w09))
        w26 = p32# (ssig1# w24) (p32# w19 (p32# (ssig0# w11) w10))
        w27 = p32# (ssig1# w25) (p32# w20 (p32# (ssig0# w12) w11))
        w28 = p32# (ssig1# w26) (p32# w21 (p32# (ssig0# w13) w12))
        w29 = p32# (ssig1# w27) (p32# w22 (p32# (ssig0# w14) w13))
        w30 = p32# (ssig1# w28) (p32# w23 (p32# (ssig0# w15) w14))
        w31 = p32# (ssig1# w29) (p32# w24 (p32# (ssig0# w16) w15))
        w32 = p32# (ssig1# w30) (p32# w25 (p32# (ssig0# w17) w16))
        w33 = p32# (ssig1# w31) (p32# w26 (p32# (ssig0# w18) w17))
        w34 = p32# (ssig1# w32) (p32# w27 (p32# (ssig0# w19) w18))
        w35 = p32# (ssig1# w33) (p32# w28 (p32# (ssig0# w20) w19))
        w36 = p32# (ssig1# w34) (p32# w29 (p32# (ssig0# w21) w20))
        w37 = p32# (ssig1# w35) (p32# w30 (p32# (ssig0# w22) w21))
        w38 = p32# (ssig1# w36) (p32# w31 (p32# (ssig0# w23) w22))
        w39 = p32# (ssig1# w37) (p32# w32 (p32# (ssig0# w24) w23))
        w40 = p32# (ssig1# w38) (p32# w33 (p32# (ssig0# w25) w24))
        w41 = p32# (ssig1# w39) (p32# w34 (p32# (ssig0# w26) w25))
        w42 = p32# (ssig1# w40) (p32# w35 (p32# (ssig0# w27) w26))
        w43 = p32# (ssig1# w41) (p32# w36 (p32# (ssig0# w28) w27))
        w44 = p32# (ssig1# w42) (p32# w37 (p32# (ssig0# w29) w28))
        w45 = p32# (ssig1# w43) (p32# w38 (p32# (ssig0# w30) w29))
        w46 = p32# (ssig1# w44) (p32# w39 (p32# (ssig0# w31) w30))
        w47 = p32# (ssig1# w45) (p32# w40 (p32# (ssig0# w32) w31))
        w48 = p32# (ssig1# w46) (p32# w41 (p32# (ssig0# w33) w32))
        w49 = p32# (ssig1# w47) (p32# w42 (p32# (ssig0# w34) w33))
        w50 = p32# (ssig1# w48) (p32# w43 (p32# (ssig0# w35) w34))
        w51 = p32# (ssig1# w49) (p32# w44 (p32# (ssig0# w36) w35))
        w52 = p32# (ssig1# w50) (p32# w45 (p32# (ssig0# w37) w36))
        w53 = p32# (ssig1# w51) (p32# w46 (p32# (ssig0# w38) w37))
        w54 = p32# (ssig1# w52) (p32# w47 (p32# (ssig0# w39) w38))
        w55 = p32# (ssig1# w53) (p32# w48 (p32# (ssig0# w40) w39))
        w56 = p32# (ssig1# w54) (p32# w49 (p32# (ssig0# w41) w40))
        w57 = p32# (ssig1# w55) (p32# w50 (p32# (ssig0# w42) w41))
        w58 = p32# (ssig1# w56) (p32# w51 (p32# (ssig0# w43) w42))
        w59 = p32# (ssig1# w57) (p32# w52 (p32# (ssig0# w44) w43))
        w60 = p32# (ssig1# w58) (p32# w53 (p32# (ssig0# w45) w44))
        w61 = p32# (ssig1# w59) (p32# w54 (p32# (ssig0# w46) w45))
        w62 = p32# (ssig1# w60) (p32# w55 (p32# (ssig0# w47) w46))
        w63 = p32# (ssig1# w61) (p32# w56 (p32# (ssig0# w48) w47))
    in  (#  w00, w01, w02, w03, w04, w05, w06, w07
        ,   w08, w09, w10, w11, w12, w13, w14, w15
        ,   w16, w17, w18, w19, w20, w21, w22, w23
        ,   w24, w25, w26, w27, w28, w29, w30, w31
        ,   w32, w33, w34, w35, w36, w37, w38, w39
        ,   w40, w41, w42, w43, w44, w45, w46, w47
        ,   w48, w49, w50, w51, w52, w53, w54, w55
        ,   w56, w57, w58, w59, w60, w61, w62, w63
        #)

-- RFC 6234 6.2 steps 2, 3, 4
block_hash :: Registers -> Schedule -> Registers
block_hash r@Registers {..} s = loop 0 r where
  loop t (Registers a b c d e f g h)
    | t == 64 = Registers {
          h0 = a + h0, h1 = b + h1, h2 = c + h2, h3 = d + h3
        , h4 = e + h4, h5 = f + h5, h6 = g + h6, h7 = h + h7
        }
    | otherwise =
        let t1   = h + bsig1 e + ch e f g + choose_k t + choose_w s t
            t2   = bsig0 a + maj a b c
            nacc = Registers (t1 + t2) a b c (d + t1) e f g
        in  loop (succ t) nacc

block_hash# :: Rs -> Sd -> Rs
block_hash# r00@(# h0, h1, h2, h3, h4, h5, h6, h7 #) s# = case s# of
  (# w00, w01, w02, w03, w04, w05, w06, w07,
     w08, w09, w10, w11, w12, w13, w14, w15,
     w16, w17, w18, w19, w20, w21, w22, w23,
     w24, w25, w26, w27, w28, w29, w30, w31,
     w32, w33, w34, w35, w36, w37, w38, w39,
     w40, w41, w42, w43, w44, w45, w46, w47,
     w48, w49, w50, w51, w52, w53, w54, w55,
     w56, w57, w58, w59, w60, w61, w62, w63 #) ->
    let r01 = step# r00 0x428a2f98#Word32 w00
        r02 = step# r01 0x71374491#Word32 w01
        r03 = step# r02 0xb5c0fbcf#Word32 w02
        r04 = step# r03 0xe9b5dba5#Word32 w03
        r05 = step# r04 0x3956c25b#Word32 w04
        r06 = step# r05 0x59f111f1#Word32 w05
        r07 = step# r06 0x923f82a4#Word32 w06
        r08 = step# r07 0xab1c5ed5#Word32 w07
        r09 = step# r08 0xd807aa98#Word32 w08
        r10 = step# r09 0x12835b01#Word32 w09
        r11 = step# r10 0x243185be#Word32 w10
        r12 = step# r11 0x550c7dc3#Word32 w11
        r13 = step# r12 0x72be5d74#Word32 w12
        r14 = step# r13 0x80deb1fe#Word32 w13
        r15 = step# r14 0x9bdc06a7#Word32 w14
        r16 = step# r15 0xc19bf174#Word32 w15
        r17 = step# r16 0xe49b69c1#Word32 w16
        r18 = step# r17 0xefbe4786#Word32 w17
        r19 = step# r18 0x0fc19dc6#Word32 w18
        r20 = step# r19 0x240ca1cc#Word32 w19
        r21 = step# r20 0x2de92c6f#Word32 w20
        r22 = step# r21 0x4a7484aa#Word32 w21
        r23 = step# r22 0x5cb0a9dc#Word32 w22
        r24 = step# r23 0x76f988da#Word32 w23
        r25 = step# r24 0x983e5152#Word32 w24
        r26 = step# r25 0xa831c66d#Word32 w25
        r27 = step# r26 0xb00327c8#Word32 w26
        r28 = step# r27 0xbf597fc7#Word32 w27
        r29 = step# r28 0xc6e00bf3#Word32 w28
        r30 = step# r29 0xd5a79147#Word32 w29
        r31 = step# r30 0x06ca6351#Word32 w30
        r32 = step# r31 0x14292967#Word32 w31
        r33 = step# r32 0x27b70a85#Word32 w32
        r34 = step# r33 0x2e1b2138#Word32 w33
        r35 = step# r34 0x4d2c6dfc#Word32 w34
        r36 = step# r35 0x53380d13#Word32 w35
        r37 = step# r36 0x650a7354#Word32 w36
        r38 = step# r37 0x766a0abb#Word32 w37
        r39 = step# r38 0x81c2c92e#Word32 w38
        r40 = step# r39 0x92722c85#Word32 w39
        r41 = step# r40 0xa2bfe8a1#Word32 w40
        r42 = step# r41 0xa81a664b#Word32 w41
        r43 = step# r42 0xc24b8b70#Word32 w42
        r44 = step# r43 0xc76c51a3#Word32 w43
        r45 = step# r44 0xd192e819#Word32 w44
        r46 = step# r45 0xd6990624#Word32 w45
        r47 = step# r46 0xf40e3585#Word32 w46
        r48 = step# r47 0x106aa070#Word32 w47
        r49 = step# r48 0x19a4c116#Word32 w48
        r50 = step# r49 0x1e376c08#Word32 w49
        r51 = step# r50 0x2748774c#Word32 w50
        r52 = step# r51 0x34b0bcb5#Word32 w51
        r53 = step# r52 0x391c0cb3#Word32 w52
        r54 = step# r53 0x4ed8aa4a#Word32 w53
        r55 = step# r54 0x5b9cca4f#Word32 w54
        r56 = step# r55 0x682e6ff3#Word32 w55
        r57 = step# r56 0x748f82ee#Word32 w56
        r58 = step# r57 0x78a5636f#Word32 w57
        r59 = step# r58 0x84c87814#Word32 w58
        r60 = step# r59 0x8cc70208#Word32 w59
        r61 = step# r60 0x90befffa#Word32 w60
        r62 = step# r61 0xa4506ceb#Word32 w61
        r63 = step# r62 0xbef9a3f7#Word32 w62
        r64 = step# r63 0xc67178f2#Word32 w63
        !(# a, b, c, d, e, f, g, h #) = r64
    in  (# p32# a h0, p32# b h1, p32# c h2, p32# d h3
        ,  p32# e h4, p32# f h5, p32# g h6, p32# h h7
        #)
{-# SCC block_hash# #-}

-- translation of SHA's step256
step# :: Rs -> Word32# -> Word32# -> Rs
step# (# a, b, c, d, e, f, g, h #) k w =
  let t1 = p32# h (p32# (bsig1# e) (p32# (ch# e f g) (p32# k w)))
      t2 = p32# (bsig0# a) (maj# a b c)
      h# = g
      g# = f
      f# = e
      e# = p32# d t1
      d# = c
      c# = b
      b# = a
      a# = p32# t1 t2
  in  (# a#, b#, c#, d#, e#, f#, g#, h# #)

-- RFC 6234 6.2 block pipeline
hash_alg :: Registers -> BS.ByteString -> Registers
hash_alg rs = block_hash rs . prepare_schedule . parse

hash_alg# :: Rs -> BS.ByteString -> Rs
hash_alg# rs bs = block_hash# rs (prepare_schedule# (parse# bs))

-- register concatenation
cat :: Registers -> BS.ByteString
cat Registers {..} =
    BL.toStrict
  . BE.toLazyByteStringWith (BE.safeStrategy 128 BE.smallChunkSize) mempty
  $ mconcat [
        BSB.word32BE h0
      , BSB.word32BE h1
      , BSB.word32BE h2
      , BSB.word32BE h3
      , BSB.word32BE h4
      , BSB.word32BE h5
      , BSB.word32BE h6
      , BSB.word32BE h7
      ]

cat# :: Rs -> BS.ByteString
cat# (# h0, h1, h2, h3, h4, h5, h6, h7 #) =
    BL.toStrict
  . BE.toLazyByteStringWith (BE.safeStrategy 128 BE.smallChunkSize) mempty
  $ mconcat [
        BSB.word32BE (lw32 h0)
      , BSB.word32BE (lw32 h1)
      , BSB.word32BE (lw32 h2)
      , BSB.word32BE (lw32 h3)
      , BSB.word32BE (lw32 h4)
      , BSB.word32BE (lw32 h5)
      , BSB.word32BE (lw32 h6)
      , BSB.word32BE (lw32 h7)
      ]

-- | Compute a condensed representation of a strict bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash "strict bytestring input"
--   "<strict 256-bit message digest>"
hash :: BS.ByteString -> BS.ByteString
hash bs = cat# (go r_iv (pad bs)) where
  r_iv = (#
      0x6a09e667#Word32, 0xbb67ae85#Word32
    , 0x3c6ef372#Word32, 0xa54ff53a#Word32
    , 0x510e527f#Word32, 0x9b05688c#Word32
    , 0x1f83d9ab#Word32, 0x5be0cd19#Word32
    #)

  go :: Rs -> BS.ByteString -> Rs
  go !acc b
    | BS.null b = acc
    | otherwise = case BS.splitAt 64 b of
        (c, r) -> go (hash_alg# acc c) r

-- | Compute a condensed representation of a lazy bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash_lazy "lazy bytestring input"
--   "<strict 256-bit message digest>"
hash_lazy :: BL.ByteString -> BS.ByteString
hash_lazy bl = cat# (go r_iv (pad_lazy bl)) where
  r_iv = (#
      0x6a09e667#Word32, 0xbb67ae85#Word32
    , 0x3c6ef372#Word32, 0xa54ff53a#Word32
    , 0x510e527f#Word32, 0x9b05688c#Word32
    , 0x1f83d9ab#Word32, 0x5be0cd19#Word32
    #)

  go :: Rs -> BL.ByteString -> Rs
  go !acc bs
    | BL.null bs = acc
    | otherwise = case splitAt64 bs of
        SLPair c r -> go (hash_alg# acc c) r

-- HMAC
-- https://datatracker.ietf.org/doc/html/rfc2104#section-2

-- | Produce a message authentication code for a strict bytestring,
--   based on the provided (strict, bytestring) key, via SHA-256.
--
--   The 256-bit MAC is returned as a strict bytestring.
--
--   >>> hmac "strict bytestring key" "strict bytestring input"
--   "<strict 256-bit MAC>"
hmac :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmac k = hmac_lazy k . BL.fromStrict

-- | Produce a message authentication code for a lazy bytestring, based
--   on the provided (strict, bytestring) key, via SHA-256.
--
--   The 256-bit MAC is returned as a strict bytestring.
--
--   >>> hmac_lazy "strict bytestring key" "lazy bytestring input"
--   "<strict 256-bit MAC>"
hmac_lazy :: BS.ByteString -> BL.ByteString -> BS.ByteString
hmac_lazy k text
    | lk > 64 = error "ppad-sha256: hmac key exceeds 64 bytes"
    | otherwise =
        let step1 = k <> BS.replicate (64 - lk) 0x00
            step2 = BS.map (B.xor 0x36) step1
            step3 = BL.fromStrict step2 <> text
            step4 = hash_lazy step3
            step5 = BS.map (B.xor 0x5C) step1
            step6 = step5 <> step4
        in  hash step6
  where
    lk = fi (BS.length k)

