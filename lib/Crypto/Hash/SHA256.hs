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
import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Builder.Extra as BE
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Internal as BLI
import qualified Data.ByteString.Unsafe as BU
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

-- variant of Data.ByteString.Lazy.splitAt that returns the initial
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

-- variant of Data.ByteString.splitAt that behaves like an incremental
-- Word32 parser
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

unW32 :: Word32 -> Word32#
unW32 (fi -> i) = case i of
  E.I# i# -> E.wordToWord32# (E.int2Word# i#)
{-# INLINE unW32 #-}

lw32 :: Word32# -> Word32
lw32 w = fi (E.I# (E.word2Int# (E.word32ToWord# w)))
{-# INLINE lw32 #-}

-- message padding and parsing
-- https://datatracker.ietf.org/doc/html/rfc6234#section-4.1

-- k such that (l + 1 + k) mod 64 = 56
sol :: Word64 -> Word64
sol l =
  let r = 56 - fi l `mod` 64 - 1 :: Integer -- fi prevents underflow
  in  fi (if r < 0 then r + 64 else r)

-- RFC 6234 4.1 (strict)
pad :: BS.ByteString -> BS.ByteString
pad m = BL.toStrict . BSB.toLazyByteString $ padded where
  l = fi (BS.length m)

  padded = BSB.byteString m <> fill (sol l) (BSB.word8 0x80)

  fill j !acc
    | j == 0 = acc <> BSB.word64BE (l * 8)
    | otherwise = fill (pred j) (acc <> BSB.word8 0x00)

-- RFC 6234 4.1 (lazy)
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
          -- more efficient for small builder
        . BE.toLazyByteStringWith
            (BE.safeStrategy 128 BE.smallChunkSize) mempty
        $ bs <> BSB.word64BE (l * 8)
    | otherwise =
        let nacc = bs <> BSB.word8 0x00
        in  padding l (pred k) nacc

-- functions and constants used
-- https://datatracker.ietf.org/doc/html/rfc6234#section-5.1

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

type Schedule = (#
    Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  #)

type Registers = (#
    Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  #)

-- processing
-- https://datatracker.ietf.org/doc/html/rfc6234#section-6.2

type Block = (#
    Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  , Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#, Word32#
  #)

parse# :: BS.ByteString -> Block
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
prepare_schedule# :: Block -> Schedule
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
block_hash# :: Registers -> Schedule -> Registers
block_hash# r00@(# h0, h1, h2, h3, h4, h5, h6, h7 #) s# = case s# of
  (# w00, w01, w02, w03, w04, w05, w06, w07,
     w08, w09, w10, w11, w12, w13, w14, w15,
     w16, w17, w18, w19, w20, w21, w22, w23,
     w24, w25, w26, w27, w28, w29, w30, w31,
     w32, w33, w34, w35, w36, w37, w38, w39,
     w40, w41, w42, w43, w44, w45, w46, w47,
     w48, w49, w50, w51, w52, w53, w54, w55,
     w56, w57, w58, w59, w60, w61, w62, w63 #) ->
    -- constants are the first 32 bits of the fractional parts of the
    -- cube roots of the first sixty-four prime numbers
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

step# :: Registers -> Word32# -> Word32# -> Registers
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
hash_alg# :: Registers -> BS.ByteString -> Registers
hash_alg# rs bs = block_hash# rs (prepare_schedule# (parse# bs))

-- register concatenation
cat# :: Registers -> BS.ByteString
cat# (# h0, h1, h2, h3, h4, h5, h6, h7 #) =
    BL.toStrict
    -- more efficient for small builder
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
  -- https://datatracker.ietf.org/doc/html/rfc6234#section-6.1
  --
  -- first 32 bits of the fractional parts of the square roots of the
  -- first eight primes
  r_iv = (#
      0x6a09e667#Word32, 0xbb67ae85#Word32
    , 0x3c6ef372#Word32, 0xa54ff53a#Word32
    , 0x510e527f#Word32, 0x9b05688c#Word32
    , 0x1f83d9ab#Word32, 0x5be0cd19#Word32
    #)

  go :: Registers -> BS.ByteString -> Registers
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
  -- https://datatracker.ietf.org/doc/html/rfc6234#section-6.1
  --
  -- first 32 bits of the fractional parts of the square roots of the
  -- first eight primes
  r_iv = (#
      0x6a09e667#Word32, 0xbb67ae85#Word32
    , 0x3c6ef372#Word32, 0xa54ff53a#Word32
    , 0x510e527f#Word32, 0x9b05688c#Word32
    , 0x1f83d9ab#Word32, 0x5be0cd19#Word32
    #)

  go :: Registers -> BL.ByteString -> Registers
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

