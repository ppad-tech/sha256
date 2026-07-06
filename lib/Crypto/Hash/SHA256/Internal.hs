{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE UnliftedNewtypes #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Crypto.Hash.SHA256.Internal
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- SHA-256 internals.

module Crypto.Hash.SHA256.Internal (
  -- * Types
    Block(B, ..)
  , Registers(R, ..)
  , MAC(..)

  -- * Parsing
  , parse
  , parse_pad1
  , parse_pad2

  -- * Serializing
  , cat
  , cat_into

  -- * Hash function internals
  , update
  , iv

  -- * HMAC utilities
  , pad_registers
  , pad_registers_with_length
  , xor
  , parse_key

  -- * HMAC-DRBG utilities
  , parse_vsb
  , parse_pad1_vsb
  , parse_pad2_vsb

  -- * Pointer-based IO utilities
  , poke_registers
  ) where

import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word8, Word32, Word64)
import qualified GHC.IO (IO(..))
import GHC.Ptr (Ptr(..))
import GHC.Exts (Int#)
import qualified GHC.Exts as Exts
import qualified GHC.Word (Word32(..), Word8(..))

-- types ----------------------------------------------------------------------

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
  deriving newtype Show

instance Eq MAC where
  -- | A constant-time equality check for message authentication codes.
  --
  --   Runs in variable-time only for invalid inputs.
  (MAC a@(BI.PS _ _ la)) == (MAC b@(BI.PS _ _ lb))
      | la /= lb   = False
      | la == 32   =
          -- fully-unrolled, fixed OR-tree over four 64-bit lanes.
          -- A standard 32-byte MAC folds through no loop-carried
          -- accumulator, so there is no per-byte accumulator whose
          -- nonzero span tracks the position of a differing byte:
          -- the comparison time is independent of where (or whether)
          -- the tags differ.
          let !d0 = Exts.xor64# (word64le a 00) (word64le b 00)
              !d1 = Exts.xor64# (word64le a 08) (word64le b 08)
              !d2 = Exts.xor64# (word64le a 16) (word64le b 16)
              !d3 = Exts.xor64# (word64le a 24) (word64le b 24)
              !d  = (d0 `Exts.or64#` d1) `Exts.or64#`
                    (d2 `Exts.or64#` d3)
          in  Exts.isTrue# (Exts.eqWord64# d (Exts.wordToWord64# 0##))
      | otherwise  = go 0 0
    where
      -- byte-serial fallback for nonstandard MAC lengths. 'hmac'
      -- always yields 32 bytes, so this path is unreachable through
      -- it; it exists only to keep the instance total for MACs built
      -- directly via the exported constructor. The fused fold ORs the
      -- bytewise XORs into an accumulator directly, rather than via
      -- packZipWith, so no intermediate ByteString holding the
      -- (secret-derived) difference bytes is ever materialised.
      go :: Word8 -> Int -> Bool
      go !acc !i
        | i == la   = acc == 0
        | otherwise =
            let !x = BU.unsafeIndex a i
                !y = BU.unsafeIndex b i
            in  go (acc B..|. B.xor x y) (i + 1)

-- | SHA256 block.
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
    (# w00, w01, w02, w03, w04, w05, w06, w07
    ,  w08, w09, w10, w11, w12, w13, w14, w15
    #)
{-# COMPLETE B #-}

-- | SHA256 state.
newtype Registers = Registers
  (# Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  ,  Exts.Word32#, Exts.Word32#, Exts.Word32#, Exts.Word32#
  #)

pattern R
  :: Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Exts.Word32# -> Exts.Word32# -> Exts.Word32# -> Exts.Word32#
  -> Registers
pattern R w00 w01 w02 w03 w04 w05 w06 w07 = Registers
  (# w00, w01, w02, w03
  ,  w04, w05, w06, w07
  #)
{-# COMPLETE R #-}

-- utilities ------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- parsing (nonfinal input) ---------------------------------------------------

-- | Given a bytestring and offset, parse a full block.
--
--   The length of the input is not checked.
parse :: BS.ByteString -> Int -> Block
parse bs m = B
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
{-# INLINE parse #-}

-- | Parse the 32-bit word encoded at the given ofset.
--
--   The length of the input is not checked.
word32be :: BS.ByteString -> Int -> Exts.Word32#
word32be bs m =
  let !(GHC.Word.W8# ra) = BU.unsafeIndex bs m
      !(GHC.Word.W8# rb) = BU.unsafeIndex bs (m + 1)
      !(GHC.Word.W8# rc) = BU.unsafeIndex bs (m + 2)
      !(GHC.Word.W8# rd) = BU.unsafeIndex bs (m + 3)
      !a  = Exts.wordToWord32# (Exts.word8ToWord# ra)
      !b  = Exts.wordToWord32# (Exts.word8ToWord# rb)
      !c  = Exts.wordToWord32# (Exts.word8ToWord# rc)
      !d  = Exts.wordToWord32# (Exts.word8ToWord# rd)
      !sa = Exts.uncheckedShiftLWord32# a 24#
      !sb = Exts.uncheckedShiftLWord32# b 16#
      !sc = Exts.uncheckedShiftLWord32# c 08#
  in  sa `Exts.orWord32#` sb `Exts.orWord32#` sc `Exts.orWord32#` d
{-# INLINE word32be #-}

-- | Assemble the 64-bit word at the given byte offset, little-endian.
--
--   Byte order is immaterial to an equality test as long as both
--   operands are assembled the same way; this is used only by the
--   constant-time 'MAC' comparison. The length is not checked.
word64le :: BS.ByteString -> Int -> Exts.Word64#
word64le bs m =
  let !(GHC.Word.W8# r0) = BU.unsafeIndex bs m
      !(GHC.Word.W8# r1) = BU.unsafeIndex bs (m + 1)
      !(GHC.Word.W8# r2) = BU.unsafeIndex bs (m + 2)
      !(GHC.Word.W8# r3) = BU.unsafeIndex bs (m + 3)
      !(GHC.Word.W8# r4) = BU.unsafeIndex bs (m + 4)
      !(GHC.Word.W8# r5) = BU.unsafeIndex bs (m + 5)
      !(GHC.Word.W8# r6) = BU.unsafeIndex bs (m + 6)
      !(GHC.Word.W8# r7) = BU.unsafeIndex bs (m + 7)
      !w0 = Exts.word8ToWord# r0
      !w1 = Exts.word8ToWord# r1
      !w2 = Exts.word8ToWord# r2
      !w3 = Exts.word8ToWord# r3
      !w4 = Exts.word8ToWord# r4
      !w5 = Exts.word8ToWord# r5
      !w6 = Exts.word8ToWord# r6
      !w7 = Exts.word8ToWord# r7
      !s1 = Exts.uncheckedShiftL# w1 8#
      !s2 = Exts.uncheckedShiftL# w2 16#
      !s3 = Exts.uncheckedShiftL# w3 24#
      !s4 = Exts.uncheckedShiftL# w4 32#
      !s5 = Exts.uncheckedShiftL# w5 40#
      !s6 = Exts.uncheckedShiftL# w6 48#
      !s7 = Exts.uncheckedShiftL# w7 56#
  in  Exts.wordToWord64#
        (w0 `Exts.or#` s1 `Exts.or#` s2 `Exts.or#` s3 `Exts.or#`
         s4 `Exts.or#` s5 `Exts.or#` s6 `Exts.or#` s7)
{-# INLINE word64le #-}

-- parsing (final input) ------------------------------------------------------

-- | Parse the final chunk of an input message, assuming it is less than
--   56 bytes in length (unchecked!).
--
--   Returns one block consisting of the chunk and padding.
parse_pad1
  :: BS.ByteString -- ^ final input chunk (< 56 bytes)
  -> Word64        -- ^ length of all input
  -> Block         -- ^ resulting block
parse_pad1 bs l =
  let !bits = l * 8
      !(GHC.Word.W32# lhi) = fi (bits `B.unsafeShiftR` 32)
      !(GHC.Word.W32# llo) = fi bits
  in  B (w32_at bs 00) (w32_at bs 04) (w32_at bs 08) (w32_at bs 12)
        (w32_at bs 16) (w32_at bs 20) (w32_at bs 24) (w32_at bs 28)
        (w32_at bs 32) (w32_at bs 36) (w32_at bs 40) (w32_at bs 44)
        (w32_at bs 48) (w32_at bs 52) lhi            llo
{-# INLINABLE parse_pad1 #-}

-- | Parse the final chunk of an input message, assuming it is at least 56
--   bytes in length (unchecked!).
--
--   Returns two blocks consisting of the chunk and padding.
parse_pad2
  :: BS.ByteString       -- ^ final input chunk (>= 56 bytes)
  -> Word64              -- ^ length of all input
  -> (# Block, Block #)  -- ^ resulting blocks
parse_pad2 bs l =
  let !bits = l * 8
      !z    = Exts.wordToWord32# 0##
      !(GHC.Word.W32# lhi) = fi (bits `B.unsafeShiftR` 32)
      !(GHC.Word.W32# llo) = fi bits
      !block0 = B
        (w32_at bs 00) (w32_at bs 04) (w32_at bs 08) (w32_at bs 12)
        (w32_at bs 16) (w32_at bs 20) (w32_at bs 24) (w32_at bs 28)
        (w32_at bs 32) (w32_at bs 36) (w32_at bs 40) (w32_at bs 44)
        (w32_at bs 48) (w32_at bs 52) (w32_at bs 56) (w32_at bs 60)
      !block1 = B z z z z z z z z z z z z z z lhi llo
  in  (# block0, block1 #)
{-# INLINABLE parse_pad2 #-}

-- | Return the byte at offset 'i', or a padding separator or zero byte
--   beyond the input bounds, as an unboxed 32-bit word.
w8_as_w32_at
  :: BS.ByteString  -- ^ input chunk
  -> Int            -- ^ offset
  -> Exts.Word32#
w8_as_w32_at bs@(BI.PS _ _ l) i = Exts.wordToWord32# $ case compare i l of
  LT -> let !(GHC.Word.W8# w) = BU.unsafeIndex bs i
        in  Exts.word8ToWord# w
  EQ -> 0x80##
  _  -> 0x00##
{-# INLINE w8_as_w32_at #-}

-- | Return the 32-bit word encoded by four consecutive bytes at the
--   provided offset.
w32_at
  :: BS.ByteString
  -> Int
  -> Exts.Word32#
w32_at bs i =
  let !wa = w8_as_w32_at bs i       `Exts.uncheckedShiftLWord32#` 24#
      !wb = w8_as_w32_at bs (i + 1) `Exts.uncheckedShiftLWord32#` 16#
      !wc = w8_as_w32_at bs (i + 2) `Exts.uncheckedShiftLWord32#` 08#
      !wd = w8_as_w32_at bs (i + 3)
  in  wa `Exts.orWord32#` wb `Exts.orWord32#` wc `Exts.orWord32#` wd
{-# INLINE w32_at #-}

-- update ---------------------------------------------------------------------

-- | Update register state, given new input block.
update :: Registers -> Block -> Registers
update
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

      -- rounds (constants are cube roots of first 64 primes)
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

-- initial register state; first 32 bits of the fractional parts of the
-- square roots of the first eight primes
iv :: () -> Registers
iv _ = R
  (Exts.wordToWord32# 0x6a09e667##)
  (Exts.wordToWord32# 0xbb67ae85##)
  (Exts.wordToWord32# 0x3c6ef372##)
  (Exts.wordToWord32# 0xa54ff53a##)
  (Exts.wordToWord32# 0x510e527f##)
  (Exts.wordToWord32# 0x9b05688c##)
  (Exts.wordToWord32# 0x1f83d9ab##)
  (Exts.wordToWord32# 0x5be0cd19##)

-- serializing ----------------------------------------------------------------

-- | Concat SHA256 state into a ByteString.
cat :: Registers -> BS.ByteString
cat rs = BI.unsafeCreate 32 (cat_into rs)
{-# INLINABLE cat #-}

-- | Serialize SHA256 state to a pointer (big-endian).
cat_into :: Registers -> Ptr Word8 -> IO ()
cat_into (R h0 h1 h2 h3 h4 h5 h6 h7) (Ptr addr) = GHC.IO.IO $ \s0 ->
  case poke32be addr 00# h0 s0 of { s1 ->
  case poke32be addr 04# h1 s1 of { s2 ->
  case poke32be addr 08# h2 s2 of { s3 ->
  case poke32be addr 12# h3 s3 of { s4 ->
  case poke32be addr 16# h4 s4 of { s5 ->
  case poke32be addr 20# h5 s5 of { s6 ->
  case poke32be addr 24# h6 s6 of { s7 ->
  case poke32be addr 28# h7 s7 of { s8 ->
  (# s8, () #)
  }}}}}}}}
{-# INLINE cat_into #-}

poke32be
  :: Exts.Addr#
  -> Int#
  -> Exts.Word32#
  -> Exts.State# Exts.RealWorld
  -> Exts.State# Exts.RealWorld
poke32be a off w s0 =
  case Exts.writeWord8OffAddr# a off (byte# w 24#) s0 of { s1 ->
  case Exts.writeWord8OffAddr# a (off Exts.+# 1#) (byte# w 16#) s1 of { s2 ->
  case Exts.writeWord8OffAddr# a (off Exts.+# 2#) (byte# w 8#) s2 of { s3 ->
  Exts.writeWord8OffAddr# a (off Exts.+# 3#) (byte# w 0#) s3
  }}}
{-# INLINE poke32be #-}

byte# :: Exts.Word32# -> Int# -> Exts.Word8#
byte# w n = Exts.wordToWord8#
  (Exts.word32ToWord# (Exts.uncheckedShiftRLWord32# w n))
{-# INLINE byte# #-}

-- | Write register state to a pointer (native endian Word32s).
poke_registers :: Ptr Word32 -> Registers -> IO ()
poke_registers (Ptr addr) (R w0 w1 w2 w3 w4 w5 w6 w7) = GHC.IO.IO $ \s0 ->
  case Exts.writeWord32OffAddr# addr 0# w0 s0 of { s1 ->
  case Exts.writeWord32OffAddr# addr 1# w1 s1 of { s2 ->
  case Exts.writeWord32OffAddr# addr 2# w2 s2 of { s3 ->
  case Exts.writeWord32OffAddr# addr 3# w3 s3 of { s4 ->
  case Exts.writeWord32OffAddr# addr 4# w4 s4 of { s5 ->
  case Exts.writeWord32OffAddr# addr 5# w5 s5 of { s6 ->
  case Exts.writeWord32OffAddr# addr 6# w6 s6 of { s7 ->
  case Exts.writeWord32OffAddr# addr 7# w7 s7 of { s8 ->
  (# s8, () #) }}}}}}}}
{-# INLINE poke_registers #-}

-- hmac utilities -------------------------------------------------------------

-- pad registers to block
pad_registers :: Registers -> Block
pad_registers (R w0 w1 w2 w3 w4 w5 w6 w7) = B
  w0 w1 w2 w3 w4 w5 w6 w7
  (Exts.wordToWord32# 0##) (Exts.wordToWord32# 0##) (Exts.wordToWord32# 0##)
  (Exts.wordToWord32# 0##) (Exts.wordToWord32# 0##) (Exts.wordToWord32# 0##)
  (Exts.wordToWord32# 0##) (Exts.wordToWord32# 0##)
{-# INLINE pad_registers #-}

-- pad registers to block, using padding separator and augmented length
-- (assumes existence of a leading block)
pad_registers_with_length :: Registers -> Block
pad_registers_with_length (R h0 h1 h2 h3 h4 h5 h6 h7) = B
  h0 h1 h2 h3 h4 h5 h6 h7           -- inner hash
  (Exts.wordToWord32# 0x80000000##) -- padding separator
  (Exts.wordToWord32# 0x00000000##)
  (Exts.wordToWord32# 0x00000000##)
  (Exts.wordToWord32# 0x00000000##)
  (Exts.wordToWord32# 0x00000000##)
  (Exts.wordToWord32# 0x00000000##)
  (Exts.wordToWord32# 0x00000000##) -- high 32 bits of length
  (Exts.wordToWord32# 0x00000300##) -- low 32 bits of length
{-# INLINABLE pad_registers_with_length #-}

xor :: Block -> Exts.Word32# -> Block
xor (B w00 w01 w02 w03 w04 w05 w06 w07 w08 w09 w10 w11 w12 w13 w14 w15) b = B
  (Exts.xorWord32# w00 b)
  (Exts.xorWord32# w01 b)
  (Exts.xorWord32# w02 b)
  (Exts.xorWord32# w03 b)
  (Exts.xorWord32# w04 b)
  (Exts.xorWord32# w05 b)
  (Exts.xorWord32# w06 b)
  (Exts.xorWord32# w07 b)
  (Exts.xorWord32# w08 b)
  (Exts.xorWord32# w09 b)
  (Exts.xorWord32# w10 b)
  (Exts.xorWord32# w11 b)
  (Exts.xorWord32# w12 b)
  (Exts.xorWord32# w13 b)
  (Exts.xorWord32# w14 b)
  (Exts.xorWord32# w15 b)
{-# INLINE xor #-}

parse_key :: BS.ByteString -> Block
parse_key bs = B
  (w32_zero bs 0)  (w32_zero bs 4)  (w32_zero bs 8)  (w32_zero bs 12)
  (w32_zero bs 16) (w32_zero bs 20) (w32_zero bs 24) (w32_zero bs 28)
  (w32_zero bs 32) (w32_zero bs 36) (w32_zero bs 40) (w32_zero bs 44)
  (w32_zero bs 48) (w32_zero bs 52) (w32_zero bs 56) (w32_zero bs 60)
{-# INLINE parse_key #-}

-- read big-endian Word32#, zero-padding beyond input length
w32_zero :: BS.ByteString -> Int -> Exts.Word32#
w32_zero bs i =
  let !wa = w8_zero bs i       `Exts.uncheckedShiftLWord32#` 24#
      !wb = w8_zero bs (i + 1) `Exts.uncheckedShiftLWord32#` 16#
      !wc = w8_zero bs (i + 2) `Exts.uncheckedShiftLWord32#` 08#
      !wd = w8_zero bs (i + 3)
  in  wa `Exts.orWord32#` wb `Exts.orWord32#` wc `Exts.orWord32#` wd
{-# INLINE w32_zero #-}

-- read byte as Word32#, returning zero beyond input length
w8_zero :: BS.ByteString -> Int -> Exts.Word32#
w8_zero bs@(BI.PS _ _ l) i
  | i < l     = let !(GHC.Word.W8# w) = BU.unsafeIndex bs i
                in  Exts.wordToWord32# (Exts.word8ToWord# w)
  | otherwise = Exts.wordToWord32# 0##
{-# INLINE w8_zero #-}

-- hmac-drbg utilities --------------------------------------------------------

-- | Parse first complete block from v || sep || dat[0:31].
--
--   Requires len(dat) >= 31.
parse_vsb :: Registers -> Word8 -> BS.ByteString -> Block
parse_vsb (R v0 v1 v2 v3 v4 v5 v6 v7) (GHC.Word.W8# sep) dat =
  let !(GHC.Word.W8# b0) = BU.unsafeIndex dat 0
      !(GHC.Word.W8# b1) = BU.unsafeIndex dat 1
      !(GHC.Word.W8# b2) = BU.unsafeIndex dat 2
      !w08 =
            Exts.uncheckedShiftLWord32# (w8_w32 sep) 24#
            `Exts.orWord32#`
            Exts.uncheckedShiftLWord32# (w8_w32 b0) 16#
            `Exts.orWord32#`
            Exts.uncheckedShiftLWord32# (w8_w32 b1) 8#
            `Exts.orWord32#`
            w8_w32 b2
  in  B v0 v1 v2 v3 v4 v5 v6 v7
        w08
        (word32be dat 3)  (word32be dat 7)  (word32be dat 11)
        (word32be dat 15) (word32be dat 19) (word32be dat 23) (word32be dat 27)
{-# INLINE parse_vsb #-}

-- | Parse single padding block from v || sep || dat.
--
--   Requires (33 + len(dat)) < 56.
parse_pad1_vsb :: Registers -> Word8 -> BS.ByteString -> Word64 -> Block
parse_pad1_vsb (R v0 v1 v2 v3 v4 v5 v6 v7) sep dat total =
  let !bits = total * 8
      !(GHC.Word.W32# lhi) = fi (bits `B.unsafeShiftR` 32)
      !(GHC.Word.W32# llo) = fi bits
  in  B v0 v1 v2 v3 v4 v5 v6 v7
        (w32_sdp sep dat 32) (w32_sdp sep dat 36)
        (w32_sdp sep dat 40) (w32_sdp sep dat 44)
        (w32_sdp sep dat 48) (w32_sdp sep dat 52)
        lhi llo
{-# INLINABLE parse_pad1_vsb #-}

-- | Parse two padding blocks from v || sep || dat.
--
--   Requires 56 <= (33 + len(dat)) < 64.
parse_pad2_vsb
  :: Registers -> Word8 -> BS.ByteString -> Word64 -> (# Block, Block #)
parse_pad2_vsb (R v0 v1 v2 v3 v4 v5 v6 v7) sep dat total =
  let !bits = total * 8
      !z = Exts.wordToWord32# 0##
      !(GHC.Word.W32# lhi) = fi (bits `B.unsafeShiftR` 32)
      !(GHC.Word.W32# llo) = fi bits
      !b0 = B v0 v1 v2 v3 v4 v5 v6 v7
              (w32_sdp sep dat 32) (w32_sdp sep dat 36)
              (w32_sdp sep dat 40) (w32_sdp sep dat 44)
              (w32_sdp sep dat 48) (w32_sdp sep dat 52)
              (w32_sdp sep dat 56) (w32_sdp sep dat 60)
      !b1 = B z z z z z z z z z z z z z z lhi llo
  in  (# b0, b1 #)
{-# INLINABLE parse_pad2_vsb #-}

-- Read Word32 at offset i (>= 32) from (sep || dat || 0x80 || zeros).
w32_sdp :: Word8 -> BS.ByteString -> Int -> Exts.Word32#
w32_sdp sep dat i =
  let !(GHC.Word.W8# a) = byte_sdp sep dat i
      !(GHC.Word.W8# b) = byte_sdp sep dat (i + 1)
      !(GHC.Word.W8# c) = byte_sdp sep dat (i + 2)
      !(GHC.Word.W8# d) = byte_sdp sep dat (i + 3)
  in  Exts.uncheckedShiftLWord32# (w8_w32 a) 24#
      `Exts.orWord32#`
      Exts.uncheckedShiftLWord32# (w8_w32 b) 16#
      `Exts.orWord32#`
      Exts.uncheckedShiftLWord32# (w8_w32 c) 8#
      `Exts.orWord32#`
      w8_w32 d
{-# INLINE w32_sdp #-}

-- Read byte at offset i (>= 32) from (sep || dat || 0x80 || zeros).
byte_sdp :: Word8 -> BS.ByteString -> Int -> Word8
byte_sdp sep dat@(BI.PS _ _ l) i
  | i == 32     = sep
  | i < 33 + l  = BU.unsafeIndex dat (i - 33)
  | i == 33 + l = 0x80
  | otherwise   = 0x00
{-# INLINE byte_sdp #-}

w8_w32 :: Exts.Word8# -> Exts.Word32#
w8_w32 w = Exts.wordToWord32# (Exts.word8ToWord# w)
{-# INLINE w8_w32 #-}

