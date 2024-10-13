{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}
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
import Data.Bits ((.|.), (.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Builder.Extra as BE
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Internal as BLI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word32, Word64)
import Foreign.ForeignPtr (plusForeignPtr)

-- preliminary utils

-- keystroke saver
fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- parse strict ByteString in BE order to Word32 (verbatim from
-- Data.Binary)
--
-- invariant:
--   the input bytestring is at least 32 bits in length
unsafe_word32be :: BS.ByteString -> Word32
unsafe_word32be s =
  (fi (s `BU.unsafeIndex` 0) `B.unsafeShiftL` 24) .|.
  (fi (s `BU.unsafeIndex` 1) `B.unsafeShiftL` 16) .|.
  (fi (s `BU.unsafeIndex` 2) `B.unsafeShiftL`  8) .|.
  (fi (s `BU.unsafeIndex` 3))
{-# INLINE unsafe_word32be #-}

-- utility types for more efficient ByteString management

data SSPair = SSPair
  {-# UNPACK #-} !BS.ByteString
  {-# UNPACK #-} !BS.ByteString

data SLPair = SLPair {-# UNPACK #-} !BS.ByteString !BL.ByteString

data WSPair = WSPair {-# UNPACK #-} !Word32 {-# UNPACK #-} !BS.ByteString

-- unsafe version of splitAt that does no bounds checking
--
-- invariant:
--   0 <= n <= l
unsafe_splitAt :: Int -> BS.ByteString -> SSPair
unsafe_splitAt n (BI.BS x l) =
  SSPair (BI.BS x n) (BI.BS (plusForeignPtr x n) (l - n))

-- variant of Data.ByteString.Lazy.splitAt that returns the initial
-- component as a strict, unboxed ByteString
splitAt64 :: BL.ByteString -> SLPair
splitAt64 = splitAt' (64 :: Int) where
  splitAt' _ BLI.Empty        = SLPair mempty BLI.Empty
  splitAt' n (BLI.Chunk c cs) =
    if    n < BS.length c
    then
      -- n < BS.length c, so unsafe_splitAt is safe
      let !(SSPair c0 c1) = unsafe_splitAt n c
      in  SLPair c0 (BLI.Chunk c1 cs)
    else
      let SLPair cs' cs'' = splitAt' (n - BS.length c) cs
      in  SLPair (c <> cs') cs''

-- variant of Data.ByteString.splitAt that behaves like an incremental
-- Word32 parser
--
-- invariant:
--   the input bytestring is at least 32 bits in length
unsafe_parseWsPair :: BS.ByteString -> WSPair
unsafe_parseWsPair (BI.BS x l) =
  WSPair (unsafe_word32be (BI.BS x 4)) (BI.BS (plusForeignPtr x 4) (l - 4))
{-# INLINE unsafe_parseWsPair #-}

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
  walk !l bs = case bs of
    (c:cs) -> c : walk (l + fi (BS.length c)) cs
    [] -> padding l (sol l) (BSB.word8 0x80)

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

ch :: Word32 -> Word32 -> Word32 -> Word32
ch x y z = (x .&. y) `B.xor` (B.complement x .&. z)
{-# INLINE ch #-}

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
{-# INLINE maj #-}

bsig0 :: Word32 -> Word32
bsig0 x = B.rotateR x 2 `B.xor` B.rotateR x 13 `B.xor` B.rotateR x 22
{-# INLINE bsig0 #-}

bsig1 :: Word32 -> Word32
bsig1 x = B.rotateR x 6 `B.xor` B.rotateR x 11 `B.xor` B.rotateR x 25
{-# INLINE bsig1 #-}

ssig0 :: Word32 -> Word32
ssig0 x = B.rotateR x 7 `B.xor` B.rotateR x 18 `B.xor` B.unsafeShiftR x 3
{-# INLINE ssig0 #-}

ssig1 :: Word32 -> Word32
ssig1 x = B.rotateR x 17 `B.xor` B.rotateR x 19 `B.xor` B.unsafeShiftR x 10
{-# INLINE ssig1 #-}

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
  }

-- initialization
-- https://datatracker.ietf.org/doc/html/rfc6234#section-6.1

data Registers = Registers {
    h0 :: !Word32, h1 :: !Word32, h2 :: !Word32, h3 :: !Word32
  , h4 :: !Word32, h5 :: !Word32, h6 :: !Word32, h7 :: !Word32
  }

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
  }

-- parse strict bytestring to block
--
-- invariant:
--   the input bytestring is exactly 512 bits long
unsafe_parse :: BS.ByteString -> Block
unsafe_parse bs =
  let !(WSPair m00 t00) = unsafe_parseWsPair bs
      !(WSPair m01 t01) = unsafe_parseWsPair t00
      !(WSPair m02 t02) = unsafe_parseWsPair t01
      !(WSPair m03 t03) = unsafe_parseWsPair t02
      !(WSPair m04 t04) = unsafe_parseWsPair t03
      !(WSPair m05 t05) = unsafe_parseWsPair t04
      !(WSPair m06 t06) = unsafe_parseWsPair t05
      !(WSPair m07 t07) = unsafe_parseWsPair t06
      !(WSPair m08 t08) = unsafe_parseWsPair t07
      !(WSPair m09 t09) = unsafe_parseWsPair t08
      !(WSPair m10 t10) = unsafe_parseWsPair t09
      !(WSPair m11 t11) = unsafe_parseWsPair t10
      !(WSPair m12 t12) = unsafe_parseWsPair t11
      !(WSPair m13 t13) = unsafe_parseWsPair t12
      !(WSPair m14 t14) = unsafe_parseWsPair t13
      !(WSPair m15 t15) = unsafe_parseWsPair t14
  in  if   BS.null t15
      then Block {..}
      else error "ppad-sha256: internal error (bytes remaining)"

-- RFC 6234 6.2 step 1
prepare_schedule :: Block -> Schedule
prepare_schedule Block {..} = Schedule {..} where
  w00 = m00; w01 = m01; w02 = m02; w03 = m03
  w04 = m04; w05 = m05; w06 = m06; w07 = m07
  w08 = m08; w09 = m09; w10 = m10; w11 = m11
  w12 = m12; w13 = m13; w14 = m14; w15 = m15
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

-- RFC 6234 6.2 steps 2, 3, 4
block_hash :: Registers -> Schedule -> Registers
block_hash r00@Registers {..} Schedule {..} =
  -- constants are the first 32 bits of the fractional parts of the
  -- cube roots of the first sixty-four prime numbers
  let r01 = step r00 0x428a2f98 w00; r02 = step r01 0x71374491 w01
      r03 = step r02 0xb5c0fbcf w02; r04 = step r03 0xe9b5dba5 w03
      r05 = step r04 0x3956c25b w04; r06 = step r05 0x59f111f1 w05
      r07 = step r06 0x923f82a4 w06; r08 = step r07 0xab1c5ed5 w07
      r09 = step r08 0xd807aa98 w08; r10 = step r09 0x12835b01 w09
      r11 = step r10 0x243185be w10; r12 = step r11 0x550c7dc3 w11
      r13 = step r12 0x72be5d74 w12; r14 = step r13 0x80deb1fe w13
      r15 = step r14 0x9bdc06a7 w14; r16 = step r15 0xc19bf174 w15
      r17 = step r16 0xe49b69c1 w16; r18 = step r17 0xefbe4786 w17
      r19 = step r18 0x0fc19dc6 w18; r20 = step r19 0x240ca1cc w19
      r21 = step r20 0x2de92c6f w20; r22 = step r21 0x4a7484aa w21
      r23 = step r22 0x5cb0a9dc w22; r24 = step r23 0x76f988da w23
      r25 = step r24 0x983e5152 w24; r26 = step r25 0xa831c66d w25
      r27 = step r26 0xb00327c8 w26; r28 = step r27 0xbf597fc7 w27
      r29 = step r28 0xc6e00bf3 w28; r30 = step r29 0xd5a79147 w29
      r31 = step r30 0x06ca6351 w30; r32 = step r31 0x14292967 w31
      r33 = step r32 0x27b70a85 w32; r34 = step r33 0x2e1b2138 w33
      r35 = step r34 0x4d2c6dfc w34; r36 = step r35 0x53380d13 w35
      r37 = step r36 0x650a7354 w36; r38 = step r37 0x766a0abb w37
      r39 = step r38 0x81c2c92e w38; r40 = step r39 0x92722c85 w39
      r41 = step r40 0xa2bfe8a1 w40; r42 = step r41 0xa81a664b w41
      r43 = step r42 0xc24b8b70 w42; r44 = step r43 0xc76c51a3 w43
      r45 = step r44 0xd192e819 w44; r46 = step r45 0xd6990624 w45
      r47 = step r46 0xf40e3585 w46; r48 = step r47 0x106aa070 w47
      r49 = step r48 0x19a4c116 w48; r50 = step r49 0x1e376c08 w49
      r51 = step r50 0x2748774c w50; r52 = step r51 0x34b0bcb5 w51
      r53 = step r52 0x391c0cb3 w52; r54 = step r53 0x4ed8aa4a w53
      r55 = step r54 0x5b9cca4f w54; r56 = step r55 0x682e6ff3 w55
      r57 = step r56 0x748f82ee w56; r58 = step r57 0x78a5636f w57
      r59 = step r58 0x84c87814 w58; r60 = step r59 0x8cc70208 w59
      r61 = step r60 0x90befffa w60; r62 = step r61 0xa4506ceb w61
      r63 = step r62 0xbef9a3f7 w62; r64 = step r63 0xc67178f2 w63
      !(Registers a b c d e f g h) = r64
  in  Registers
        (a + h0) (b + h1) (c + h2) (d + h3)
        (e + h4) (f + h5) (g + h6) (h + h7)

step :: Registers -> Word32 -> Word32 -> Registers
step (Registers a b c d e f g h) k w =
  let t1 = h + bsig1 e + ch e f g + k + w
      t2 = bsig0 a + maj a b c
  in  Registers (t1 + t2) a b c (d + t1) e f g

-- RFC 6234 6.2 block pipeline
--
-- invariant:
--   the input bytestring is exactly 512 bits in length
unsafe_hash_alg :: Registers -> BS.ByteString -> Registers
unsafe_hash_alg rs bs = block_hash rs (prepare_schedule (unsafe_parse bs))

-- register concatenation
cat :: Registers -> BS.ByteString
cat Registers {..} =
    BL.toStrict
    -- more efficient for small builder
  . BE.toLazyByteStringWith (BE.safeStrategy 128 BE.smallChunkSize) mempty
  $ mconcat [
        BSB.word32BE h0, BSB.word32BE h1, BSB.word32BE h2, BSB.word32BE h3
      , BSB.word32BE h4, BSB.word32BE h5, BSB.word32BE h6, BSB.word32BE h7
      ]

-- | Compute a condensed representation of a strict bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash "strict bytestring input"
--   "<strict 256-bit message digest>"
hash :: BS.ByteString -> BS.ByteString
hash bs = cat (go iv (pad bs)) where
  -- proof that 'go' always terminates safely:
  --
  -- let b = pad bs
  -- then length(b) = n * 512 bits for some n >= 0                  (1)
  go :: Registers -> BS.ByteString -> Registers
  go !acc b
    -- if n == 0, then 'go' terminates safely                       (2)
    | BS.null b = acc
    -- if n > 0, then
    --
    -- let (c, r) = unsafe_splitAt 64 b
    -- then length(c) == 512 bits                                   by (1)
    --      length(r) == m * 512 bits for some m >= 0               by (1)
    --
    -- note 'unsafe_hash_alg' terminates safely for bytestring      (3)
    -- input of exactly 512 bits in length
    --
    -- length(c) == 512
    --   => 'unsafe_hash_alg' terminates safely                     by (3)
    --   => 'go' terminates safely                                  (4)
    -- length(r) == m * 512 bits for m >= 0
    --   => next invocation of 'go' terminates safely               by (2), (4)
    --
    -- then by induction, 'go' always terminates safely (QED)
    | otherwise = case unsafe_splitAt 64 b of
        SSPair c r -> go (unsafe_hash_alg acc c) r

-- | Compute a condensed representation of a lazy bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash_lazy "lazy bytestring input"
--   "<strict 256-bit message digest>"
hash_lazy :: BL.ByteString -> BS.ByteString
hash_lazy bl = cat (go iv (pad_lazy bl)) where
  -- proof of safety proceeds analogously
  go :: Registers -> BL.ByteString -> Registers
  go !acc bs
    | BL.null bs = acc
    | otherwise = case splitAt64 bs of
        SLPair c r -> go (unsafe_hash_alg acc c) r

-- HMAC -----------------------------------------------------------------------
-- https://datatracker.ietf.org/doc/html/rfc2104#section-2

data KeyAndLen = KeyAndLen
  {-# UNPACK #-} !BS.ByteString
  {-# UNPACK #-} !Int

-- | Produce a message authentication code for a strict bytestring,
--   based on the provided (strict, bytestring) key, via SHA-256.
--
--   The 256-bit MAC is returned as a strict bytestring.
--
--   Per RFC 2104, the key /should/ be a minimum of 32 bytes long. Keys
--   exceeding 64 bytes in length will first be hashed (via SHA-256).
--
--   >>> hmac "strict bytestring key" "strict bytestring input"
--   "<strict 256-bit MAC>"
hmac
  :: BS.ByteString -- ^ key
  -> BS.ByteString -- ^ text
  -> BS.ByteString
hmac mk text =
    let step1 = k <> BS.replicate (64 - lk) 0x00
        step2 = BS.map (B.xor 0x36) step1
        step3 = step2 <> text
        step4 = hash step3
        step5 = BS.map (B.xor 0x5C) step1
        step6 = step5 <> step4
    in  hash step6
  where
    !(KeyAndLen k lk) =
      let l = BS.length mk
      in  if   l > 64
          then KeyAndLen (hash mk) 32
          else KeyAndLen mk l

-- | Produce a message authentication code for a lazy bytestring, based
--   on the provided (strict, bytestring) key, via SHA-256.
--
--   The 256-bit MAC is returned as a strict bytestring.
--
--   Per RFC 2104, the key /should/ be a minimum of 32 bytes long. Keys
--   exceeding 64 bytes in length will first be hashed (via SHA-256).
--
--   >>> hmac_lazy "strict bytestring key" "lazy bytestring input"
--   "<strict 256-bit MAC>"
hmac_lazy
  :: BS.ByteString -- ^ key
  -> BL.ByteString -- ^ text
  -> BS.ByteString
hmac_lazy mk text =
    let step1 = k <> BS.replicate (64 - lk) 0x00
        step2 = BS.map (B.xor 0x36) step1
        step3 = BL.fromStrict step2 <> text
        step4 = hash_lazy step3
        step5 = BS.map (B.xor 0x5C) step1
        step6 = step5 <> step4
    in  hash step6
  where
    !(KeyAndLen k lk) =
      let l = BS.length mk
      in  if   l > 64
          then KeyAndLen (hash mk) 32
          else KeyAndLen mk l

