{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE UnliftedNewtypes #-}

-- |
-- Module: Crypto.Hash.SHA256.Internal
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- SHA-256 internals.

module Crypto.Hash.SHA256.Internal (
    Block(..)
  , pattern B
  , Registers(..)
  , pattern R

  , MAC(..)

  , iv
  , block_hash
  , cat

  , word32be
  , parse_block
  , unsafe_hash_alg
  , unsafe_padding
  ) where

import Control.DeepSeq (NFData(..))
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word8, Word64)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (poke)
import GHC.Exts (Int#)
import qualified GHC.Exts as Exts
import qualified GHC.Word (Word8(..))

-- | A message authentication code.
--
--   Note that you should compare MACs for equality using the 'Eq'
--   instance, which performs the comparison in constant time, instead
--   of unwrapping and comparing the underlying 'ByteStrings'.
--
--   >>> let foo@(MAC bs0) = hmac key "hi"
--   >>> let bar@(MAC bs1) = hmac key "there"
--   >>> foo == bar -- do this
--   False
--   >>> bs0 == bs1 -- don't do this
--   False
newtype MAC = MAC BS.ByteString
  deriving newtype (Show, NFData)

instance Eq MAC where
  -- | A constant-time equality check for message authentication codes.
  --
  --   Runs in variable-time only for invalid inputs.
  (MAC a@(BI.PS _ _ la)) == (MAC b@(BI.PS _ _ lb))
    | la /= lb  = False
    | otherwise = BS.foldl' (B..|.) 0 (BS.packZipWith B.xor a b) == 0

-- https://datatracker.ietf.org/doc/html/rfc6234

newtype Block = Block
  (# Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  ,  Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  ,  Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  ,  Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  #)

pattern B
  :: Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Block
pattern B w00 w01 w02 w03 w04 w05 w06 w07 w08 w09 w10 w11 w12 w13 w14 w15 =
  Block
    (# w00, w01, w02, w03
    ,  w04, w05, w06, w07
    ,  w08, w09, w10, w11
    ,  w12, w13, w14, w15
    #)
{-# COMPLETE B #-}

newtype Registers = Registers
  (# Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  ,  Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  #)

pattern R
  :: Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Registers
pattern R w00 w01 w02 w03 w04 w05 w06 w07 =
  Registers
    (# w00, w01, w02, w03
    ,  w04, w05, w06, w07
    #)
{-# COMPLETE R #-}

-- given a bytestring and offset, parse word32. length not checked.
word32be :: BS.ByteString -> Int -> Exts.Word32#
word32be bs m =
  let !(GHC.Word.W8# ra) = BU.unsafeIndex bs m
      !(GHC.Word.W8# rb) = BU.unsafeIndex bs (m + 1)
      !(GHC.Word.W8# rc) = BU.unsafeIndex bs (m + 2)
      !(GHC.Word.W8# rd) = BU.unsafeIndex bs (m + 3)
      !a = Exts.wordToWord32# (Exts.word8ToWord# ra)
      !b = Exts.wordToWord32# (Exts.word8ToWord# rb)
      !c = Exts.wordToWord32# (Exts.word8ToWord# rc)
      !d = Exts.wordToWord32# (Exts.word8ToWord# rd)
      !sa = Exts.uncheckedShiftLWord32# a 24#
      !sb = Exts.uncheckedShiftLWord32# b 16#
      !sc = Exts.uncheckedShiftLWord32# c 08#
  in  sa `Exts.orWord32#` sb `Exts.orWord32#` sc `Exts.orWord32#` d
{-# INLINE word32be #-}

parse_block :: BS.ByteString -> Int -> Block
parse_block bs m = B
  (word32be bs m)
  (word32be bs (m + 04))
  (word32be bs (m + 08))
  (word32be bs (m + 12))
  (word32be bs (m + 16))
  (word32be bs (m + 20))
  (word32be bs (m + 24))
  (word32be bs (m + 28))
  (word32be bs (m + 32))
  (word32be bs (m + 36))
  (word32be bs (m + 40))
  (word32be bs (m + 44))
  (word32be bs (m + 48))
  (word32be bs (m + 52))
  (word32be bs (m + 56))
  (word32be bs (m + 60))
{-# INLINE parse_block #-}

-- rotate right
rotr# :: Exts.Word32# -> Int# -> Exts.Word32#
rotr# x n =
  Exts.uncheckedShiftRLWord32# x n `Exts.orWord32#`
  Exts.uncheckedShiftLWord32# x (32# Exts.-# n)
{-# INLINE rotr# #-}

-- logical right shift
shr# :: Exts.Word32# -> Int# -> Exts.Word32#
shr# = Exts.uncheckedShiftRLWord32#
{-# INLINE shr# #-}

-- ch(x, y, z) = (x & y) ^ (~x & z)
ch# :: Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
ch# x y z =
  (x `Exts.andWord32#` y) `Exts.xorWord32#`
  (Exts.notWord32# x `Exts.andWord32#` z)
{-# INLINE ch# #-}

-- maj(x, y, z) = (x & (y | z)) | (y & z)
maj# :: Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
maj# x y z =
  (x `Exts.andWord32#` (y `Exts.orWord32#` z)) `Exts.orWord32#`
  (y `Exts.andWord32#` z)
{-# INLINE maj# #-}

-- big sigma 0: rotr2 ^ rotr13 ^ rotr22
bsig0# :: Exts.Word32# -> Exts.Word32#
bsig0# x =
  rotr# x 2# `Exts.xorWord32#` rotr# x 13# `Exts.xorWord32#` rotr# x 22#
{-# INLINE bsig0# #-}

-- big sigma 1: rotr6 ^ rotr11 ^ rotr25
bsig1# :: Exts.Word32# -> Exts.Word32#
bsig1# x =
  rotr# x 6# `Exts.xorWord32#` rotr# x 11# `Exts.xorWord32#` rotr# x 25#
{-# INLINE bsig1# #-}

-- small sigma 0: rotr7 ^ rotr18 ^ shr3
ssig0# :: Exts.Word32# -> Exts.Word32#
ssig0# x =
  rotr# x 7# `Exts.xorWord32#` rotr# x 18# `Exts.xorWord32#` shr# x 3#
{-# INLINE ssig0# #-}

-- small sigma 1: rotr17 ^ rotr19 ^ shr10
ssig1# :: Exts.Word32# -> Exts.Word32#
ssig1# x =
  rotr# x 17# `Exts.xorWord32#` rotr# x 19# `Exts.xorWord32#` shr# x 10#
{-# INLINE ssig1# #-}

-- round step
step#
  :: Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Exts.Word32# -> Exts.Word32#
  -> Registers
step# a b c d e f g h k w =
  let !t1 =                h
        `Exts.plusWord32#` bsig1# e
        `Exts.plusWord32#` ch# e f g
        `Exts.plusWord32#` k
        `Exts.plusWord32#` w
      !t2 = bsig0# a `Exts.plusWord32#` maj# a b c
  in  R (t1 `Exts.plusWord32#` t2) a b c (d `Exts.plusWord32#` t1) e f g
{-# INLINE step# #-}

-- first 32 bits of the fractional parts of the square roots of the
-- first eight primes
iv :: () -> Registers
iv _ = R (Exts.wordToWord32# 0x6a09e667##)
         (Exts.wordToWord32# 0xbb67ae85##)
         (Exts.wordToWord32# 0x3c6ef372##)
         (Exts.wordToWord32# 0xa54ff53a##)
         (Exts.wordToWord32# 0x510e527f##)
         (Exts.wordToWord32# 0x9b05688c##)
         (Exts.wordToWord32# 0x1f83d9ab##)
         (Exts.wordToWord32# 0x5be0cd19##)

block_hash :: Registers -> Block -> Registers
block_hash
    (R h0 h1 h2 h3 h4 h5 h6 h7)
    (B b00 b01 b02 b03 b04 b05 b06 b07 b08 b09 b10 b11 b12 b13 b14 b15)
  =
  let -- message schedule
      !w00 = b00; !w01 = b01; !w02 = b02; !w03 = b03
      !w04 = b04; !w05 = b05; !w06 = b06; !w07 = b07
      !w08 = b08; !w09 = b09; !w10 = b10; !w11 = b11
      !w12 = b12; !w13 = b13; !w14 = b14; !w15 = b15
      !w16 = ssig1# w14 `p` w09 `p` ssig0# w01 `p` w00
      !w17 = ssig1# w15 `p` w10 `p` ssig0# w02 `p` w01
      !w18 = ssig1# w16 `p` w11 `p` ssig0# w03 `p` w02
      !w19 = ssig1# w17 `p` w12 `p` ssig0# w04 `p` w03
      !w20 = ssig1# w18 `p` w13 `p` ssig0# w05 `p` w04
      !w21 = ssig1# w19 `p` w14 `p` ssig0# w06 `p` w05
      !w22 = ssig1# w20 `p` w15 `p` ssig0# w07 `p` w06
      !w23 = ssig1# w21 `p` w16 `p` ssig0# w08 `p` w07
      !w24 = ssig1# w22 `p` w17 `p` ssig0# w09 `p` w08
      !w25 = ssig1# w23 `p` w18 `p` ssig0# w10 `p` w09
      !w26 = ssig1# w24 `p` w19 `p` ssig0# w11 `p` w10
      !w27 = ssig1# w25 `p` w20 `p` ssig0# w12 `p` w11
      !w28 = ssig1# w26 `p` w21 `p` ssig0# w13 `p` w12
      !w29 = ssig1# w27 `p` w22 `p` ssig0# w14 `p` w13
      !w30 = ssig1# w28 `p` w23 `p` ssig0# w15 `p` w14
      !w31 = ssig1# w29 `p` w24 `p` ssig0# w16 `p` w15
      !w32 = ssig1# w30 `p` w25 `p` ssig0# w17 `p` w16
      !w33 = ssig1# w31 `p` w26 `p` ssig0# w18 `p` w17
      !w34 = ssig1# w32 `p` w27 `p` ssig0# w19 `p` w18
      !w35 = ssig1# w33 `p` w28 `p` ssig0# w20 `p` w19
      !w36 = ssig1# w34 `p` w29 `p` ssig0# w21 `p` w20
      !w37 = ssig1# w35 `p` w30 `p` ssig0# w22 `p` w21
      !w38 = ssig1# w36 `p` w31 `p` ssig0# w23 `p` w22
      !w39 = ssig1# w37 `p` w32 `p` ssig0# w24 `p` w23
      !w40 = ssig1# w38 `p` w33 `p` ssig0# w25 `p` w24
      !w41 = ssig1# w39 `p` w34 `p` ssig0# w26 `p` w25
      !w42 = ssig1# w40 `p` w35 `p` ssig0# w27 `p` w26
      !w43 = ssig1# w41 `p` w36 `p` ssig0# w28 `p` w27
      !w44 = ssig1# w42 `p` w37 `p` ssig0# w29 `p` w28
      !w45 = ssig1# w43 `p` w38 `p` ssig0# w30 `p` w29
      !w46 = ssig1# w44 `p` w39 `p` ssig0# w31 `p` w30
      !w47 = ssig1# w45 `p` w40 `p` ssig0# w32 `p` w31
      !w48 = ssig1# w46 `p` w41 `p` ssig0# w33 `p` w32
      !w49 = ssig1# w47 `p` w42 `p` ssig0# w34 `p` w33
      !w50 = ssig1# w48 `p` w43 `p` ssig0# w35 `p` w34
      !w51 = ssig1# w49 `p` w44 `p` ssig0# w36 `p` w35
      !w52 = ssig1# w50 `p` w45 `p` ssig0# w37 `p` w36
      !w53 = ssig1# w51 `p` w46 `p` ssig0# w38 `p` w37
      !w54 = ssig1# w52 `p` w47 `p` ssig0# w39 `p` w38
      !w55 = ssig1# w53 `p` w48 `p` ssig0# w40 `p` w39
      !w56 = ssig1# w54 `p` w49 `p` ssig0# w41 `p` w40
      !w57 = ssig1# w55 `p` w50 `p` ssig0# w42 `p` w41
      !w58 = ssig1# w56 `p` w51 `p` ssig0# w43 `p` w42
      !w59 = ssig1# w57 `p` w52 `p` ssig0# w44 `p` w43
      !w60 = ssig1# w58 `p` w53 `p` ssig0# w45 `p` w44
      !w61 = ssig1# w59 `p` w54 `p` ssig0# w46 `p` w45
      !w62 = ssig1# w60 `p` w55 `p` ssig0# w47 `p` w46
      !w63 = ssig1# w61 `p` w56 `p` ssig0# w48 `p` w47

      -- rounds (cube roots of first 64 primes)
      !(R s00a s00b s00c s00d s00e s00f s00g s00h) =
        step# h0 h1 h2 h3 h4 h5 h6 h7 (k 0x428a2f98##) w00
      !(R s01a s01b s01c s01d s01e s01f s01g s01h) =
        step# s00a s00b s00c s00d s00e s00f s00g s00h (k 0x71374491##) w01
      !(R s02a s02b s02c s02d s02e s02f s02g s02h) =
        step# s01a s01b s01c s01d s01e s01f s01g s01h (k 0xb5c0fbcf##) w02
      !(R s03a s03b s03c s03d s03e s03f s03g s03h) =
        step# s02a s02b s02c s02d s02e s02f s02g s02h (k 0xe9b5dba5##) w03
      !(R s04a s04b s04c s04d s04e s04f s04g s04h) =
        step# s03a s03b s03c s03d s03e s03f s03g s03h (k 0x3956c25b##) w04
      !(R s05a s05b s05c s05d s05e s05f s05g s05h) =
        step# s04a s04b s04c s04d s04e s04f s04g s04h (k 0x59f111f1##) w05
      !(R s06a s06b s06c s06d s06e s06f s06g s06h) =
        step# s05a s05b s05c s05d s05e s05f s05g s05h (k 0x923f82a4##) w06
      !(R s07a s07b s07c s07d s07e s07f s07g s07h) =
        step# s06a s06b s06c s06d s06e s06f s06g s06h (k 0xab1c5ed5##) w07
      !(R s08a s08b s08c s08d s08e s08f s08g s08h) =
        step# s07a s07b s07c s07d s07e s07f s07g s07h (k 0xd807aa98##) w08
      !(R s09a s09b s09c s09d s09e s09f s09g s09h) =
        step# s08a s08b s08c s08d s08e s08f s08g s08h (k 0x12835b01##) w09
      !(R s10a s10b s10c s10d s10e s10f s10g s10h) =
        step# s09a s09b s09c s09d s09e s09f s09g s09h (k 0x243185be##) w10
      !(R s11a s11b s11c s11d s11e s11f s11g s11h) =
        step# s10a s10b s10c s10d s10e s10f s10g s10h (k 0x550c7dc3##) w11
      !(R s12a s12b s12c s12d s12e s12f s12g s12h) =
        step# s11a s11b s11c s11d s11e s11f s11g s11h (k 0x72be5d74##) w12
      !(R s13a s13b s13c s13d s13e s13f s13g s13h) =
        step# s12a s12b s12c s12d s12e s12f s12g s12h (k 0x80deb1fe##) w13
      !(R s14a s14b s14c s14d s14e s14f s14g s14h) =
        step# s13a s13b s13c s13d s13e s13f s13g s13h (k 0x9bdc06a7##) w14
      !(R s15a s15b s15c s15d s15e s15f s15g s15h) =
        step# s14a s14b s14c s14d s14e s14f s14g s14h (k 0xc19bf174##) w15
      !(R s16a s16b s16c s16d s16e s16f s16g s16h) =
        step# s15a s15b s15c s15d s15e s15f s15g s15h (k 0xe49b69c1##) w16
      !(R s17a s17b s17c s17d s17e s17f s17g s17h) =
        step# s16a s16b s16c s16d s16e s16f s16g s16h (k 0xefbe4786##) w17
      !(R s18a s18b s18c s18d s18e s18f s18g s18h) =
        step# s17a s17b s17c s17d s17e s17f s17g s17h (k 0x0fc19dc6##) w18
      !(R s19a s19b s19c s19d s19e s19f s19g s19h) =
        step# s18a s18b s18c s18d s18e s18f s18g s18h (k 0x240ca1cc##) w19
      !(R s20a s20b s20c s20d s20e s20f s20g s20h) =
        step# s19a s19b s19c s19d s19e s19f s19g s19h (k 0x2de92c6f##) w20
      !(R s21a s21b s21c s21d s21e s21f s21g s21h) =
        step# s20a s20b s20c s20d s20e s20f s20g s20h (k 0x4a7484aa##) w21
      !(R s22a s22b s22c s22d s22e s22f s22g s22h) =
        step# s21a s21b s21c s21d s21e s21f s21g s21h (k 0x5cb0a9dc##) w22
      !(R s23a s23b s23c s23d s23e s23f s23g s23h) =
        step# s22a s22b s22c s22d s22e s22f s22g s22h (k 0x76f988da##) w23
      !(R s24a s24b s24c s24d s24e s24f s24g s24h) =
        step# s23a s23b s23c s23d s23e s23f s23g s23h (k 0x983e5152##) w24
      !(R s25a s25b s25c s25d s25e s25f s25g s25h) =
        step# s24a s24b s24c s24d s24e s24f s24g s24h (k 0xa831c66d##) w25
      !(R s26a s26b s26c s26d s26e s26f s26g s26h) =
        step# s25a s25b s25c s25d s25e s25f s25g s25h (k 0xb00327c8##) w26
      !(R s27a s27b s27c s27d s27e s27f s27g s27h) =
        step# s26a s26b s26c s26d s26e s26f s26g s26h (k 0xbf597fc7##) w27
      !(R s28a s28b s28c s28d s28e s28f s28g s28h) =
        step# s27a s27b s27c s27d s27e s27f s27g s27h (k 0xc6e00bf3##) w28
      !(R s29a s29b s29c s29d s29e s29f s29g s29h) =
        step# s28a s28b s28c s28d s28e s28f s28g s28h (k 0xd5a79147##) w29
      !(R s30a s30b s30c s30d s30e s30f s30g s30h) =
        step# s29a s29b s29c s29d s29e s29f s29g s29h (k 0x06ca6351##) w30
      !(R s31a s31b s31c s31d s31e s31f s31g s31h) =
        step# s30a s30b s30c s30d s30e s30f s30g s30h (k 0x14292967##) w31
      !(R s32a s32b s32c s32d s32e s32f s32g s32h) =
        step# s31a s31b s31c s31d s31e s31f s31g s31h (k 0x27b70a85##) w32
      !(R s33a s33b s33c s33d s33e s33f s33g s33h) =
        step# s32a s32b s32c s32d s32e s32f s32g s32h (k 0x2e1b2138##) w33
      !(R s34a s34b s34c s34d s34e s34f s34g s34h) =
        step# s33a s33b s33c s33d s33e s33f s33g s33h (k 0x4d2c6dfc##) w34
      !(R s35a s35b s35c s35d s35e s35f s35g s35h) =
        step# s34a s34b s34c s34d s34e s34f s34g s34h (k 0x53380d13##) w35
      !(R s36a s36b s36c s36d s36e s36f s36g s36h) =
        step# s35a s35b s35c s35d s35e s35f s35g s35h (k 0x650a7354##) w36
      !(R s37a s37b s37c s37d s37e s37f s37g s37h) =
        step# s36a s36b s36c s36d s36e s36f s36g s36h (k 0x766a0abb##) w37
      !(R s38a s38b s38c s38d s38e s38f s38g s38h) =
        step# s37a s37b s37c s37d s37e s37f s37g s37h (k 0x81c2c92e##) w38
      !(R s39a s39b s39c s39d s39e s39f s39g s39h) =
        step# s38a s38b s38c s38d s38e s38f s38g s38h (k 0x92722c85##) w39
      !(R s40a s40b s40c s40d s40e s40f s40g s40h) =
        step# s39a s39b s39c s39d s39e s39f s39g s39h (k 0xa2bfe8a1##) w40
      !(R s41a s41b s41c s41d s41e s41f s41g s41h) =
        step# s40a s40b s40c s40d s40e s40f s40g s40h (k 0xa81a664b##) w41
      !(R s42a s42b s42c s42d s42e s42f s42g s42h) =
        step# s41a s41b s41c s41d s41e s41f s41g s41h (k 0xc24b8b70##) w42
      !(R s43a s43b s43c s43d s43e s43f s43g s43h) =
        step# s42a s42b s42c s42d s42e s42f s42g s42h (k 0xc76c51a3##) w43
      !(R s44a s44b s44c s44d s44e s44f s44g s44h) =
        step# s43a s43b s43c s43d s43e s43f s43g s43h (k 0xd192e819##) w44
      !(R s45a s45b s45c s45d s45e s45f s45g s45h) =
        step# s44a s44b s44c s44d s44e s44f s44g s44h (k 0xd6990624##) w45
      !(R s46a s46b s46c s46d s46e s46f s46g s46h) =
        step# s45a s45b s45c s45d s45e s45f s45g s45h (k 0xf40e3585##) w46
      !(R s47a s47b s47c s47d s47e s47f s47g s47h) =
        step# s46a s46b s46c s46d s46e s46f s46g s46h (k 0x106aa070##) w47
      !(R s48a s48b s48c s48d s48e s48f s48g s48h) =
        step# s47a s47b s47c s47d s47e s47f s47g s47h (k 0x19a4c116##) w48
      !(R s49a s49b s49c s49d s49e s49f s49g s49h) =
        step# s48a s48b s48c s48d s48e s48f s48g s48h (k 0x1e376c08##) w49
      !(R s50a s50b s50c s50d s50e s50f s50g s50h) =
        step# s49a s49b s49c s49d s49e s49f s49g s49h (k 0x2748774c##) w50
      !(R s51a s51b s51c s51d s51e s51f s51g s51h) =
        step# s50a s50b s50c s50d s50e s50f s50g s50h (k 0x34b0bcb5##) w51
      !(R s52a s52b s52c s52d s52e s52f s52g s52h) =
        step# s51a s51b s51c s51d s51e s51f s51g s51h (k 0x391c0cb3##) w52
      !(R s53a s53b s53c s53d s53e s53f s53g s53h) =
        step# s52a s52b s52c s52d s52e s52f s52g s52h (k 0x4ed8aa4a##) w53
      !(R s54a s54b s54c s54d s54e s54f s54g s54h) =
        step# s53a s53b s53c s53d s53e s53f s53g s53h (k 0x5b9cca4f##) w54
      !(R s55a s55b s55c s55d s55e s55f s55g s55h) =
        step# s54a s54b s54c s54d s54e s54f s54g s54h (k 0x682e6ff3##) w55
      !(R s56a s56b s56c s56d s56e s56f s56g s56h) =
        step# s55a s55b s55c s55d s55e s55f s55g s55h (k 0x748f82ee##) w56
      !(R s57a s57b s57c s57d s57e s57f s57g s57h) =
        step# s56a s56b s56c s56d s56e s56f s56g s56h (k 0x78a5636f##) w57
      !(R s58a s58b s58c s58d s58e s58f s58g s58h) =
        step# s57a s57b s57c s57d s57e s57f s57g s57h (k 0x84c87814##) w58
      !(R s59a s59b s59c s59d s59e s59f s59g s59h) =
        step# s58a s58b s58c s58d s58e s58f s58g s58h (k 0x8cc70208##) w59
      !(R s60a s60b s60c s60d s60e s60f s60g s60h) =
        step# s59a s59b s59c s59d s59e s59f s59g s59h (k 0x90befffa##) w60
      !(R s61a s61b s61c s61d s61e s61f s61g s61h) =
        step# s60a s60b s60c s60d s60e s60f s60g s60h (k 0xa4506ceb##) w61
      !(R s62a s62b s62c s62d s62e s62f s62g s62h) =
        step# s61a s61b s61c s61d s61e s61f s61g s61h (k 0xbef9a3f7##) w62
      !(R s63a s63b s63c s63d s63e s63f s63g s63h) =
        step# s62a s62b s62c s62d s62e s62f s62g s62h (k 0xc67178f2##) w63
  in  R (h0 `p` s63a) (h1 `p` s63b) (h2 `p` s63c) (h3 `p` s63d)
        (h4 `p` s63e) (h5 `p` s63f) (h6 `p` s63g) (h7 `p` s63h)
  where
    p = Exts.plusWord32#
    {-# INLINE p #-}
    k :: Exts.Word# -> Exts.Word32#
    k = Exts.wordToWord32#
    {-# INLINE k #-}

-- RFC 6234 6.2 block pipeline
--
-- invariant:
--   the input bytestring is exactly 512 bits in length
unsafe_hash_alg :: Registers -> BS.ByteString -> Registers
unsafe_hash_alg rs bs = block_hash rs (parse_block bs 0)

-- register concatenation
cat :: Registers -> BS.ByteString
cat (R h0 h1 h2 h3 h4 h5 h6 h7) = BI.unsafeCreate 32 $ \ptr -> do
    poke32be ptr 0  h0
    poke32be ptr 4  h1
    poke32be ptr 8  h2
    poke32be ptr 12 h3
    poke32be ptr 16 h4
    poke32be ptr 20 h5
    poke32be ptr 24 h6
    poke32be ptr 28 h7
  where
    poke32be :: Ptr Word8 -> Int -> Exts.Word32# -> IO ()
    poke32be p off w = do
      poke (p `plusPtr` off)       (byte w 24#)
      poke (p `plusPtr` (off + 1)) (byte w 16#)
      poke (p `plusPtr` (off + 2)) (byte w 8#)
      poke (p `plusPtr` (off + 3)) (byte w 0#)

    byte :: Exts.Word32# -> Int# -> Word8
    byte w n = GHC.Word.W8# (Exts.wordToWord8#
      (Exts.word32ToWord# (Exts.uncheckedShiftRLWord32# w n)))

-- keystroke saver
fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- RFC 6234 4.1 message padding
unsafe_padding :: BS.ByteString -> Word64 -> BS.ByteString
unsafe_padding (BI.PS fp off r) len
    | r < 56 = BI.unsafeCreate 64 $ \p -> do
        BI.unsafeWithForeignPtr fp $ \src ->
          copyBytes p (src `plusPtr` off) r
        poke (p `plusPtr` r) (0x80 :: Word8)
        fillBytes (p `plusPtr` (r + 1)) 0 (55 - r)
        poke_word64be (p `plusPtr` 56) (len * 8)
    | otherwise = BI.unsafeCreate 128 $ \p -> do
        BI.unsafeWithForeignPtr fp $ \src ->
          copyBytes p (src `plusPtr` off) r
        poke (p `plusPtr` r) (0x80 :: Word8)
        fillBytes (p `plusPtr` (r + 1)) 0 (63 - r)
        fillBytes (p `plusPtr` 64) 0 56
        poke_word64be (p `plusPtr` 120) (len * 8)
  where
    poke_word64be :: Ptr Word8 -> Word64 -> IO ()
    poke_word64be p w = do
      poke p               (fi (w `B.unsafeShiftR` 56) :: Word8)
      poke (p `plusPtr` 1) (fi (w `B.unsafeShiftR` 48) :: Word8)
      poke (p `plusPtr` 2) (fi (w `B.unsafeShiftR` 40) :: Word8)
      poke (p `plusPtr` 3) (fi (w `B.unsafeShiftR` 32) :: Word8)
      poke (p `plusPtr` 4) (fi (w `B.unsafeShiftR` 24) :: Word8)
      poke (p `plusPtr` 5) (fi (w `B.unsafeShiftR` 16) :: Word8)
      poke (p `plusPtr` 6) (fi (w `B.unsafeShiftR`  8) :: Word8)
      poke (p `plusPtr` 7) (fi w                       :: Word8)
