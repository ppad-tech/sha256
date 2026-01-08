{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE UnliftedNewtypes #-}

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
  , Lazy.hash_lazy

  -- * SHA256-based MAC functions
  , hmac
  , Lazy.hmac_lazy
  ) where

import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word8, Word32, Word64)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (poke, peek)
import Crypto.Hash.SHA256.Internal
import qualified Crypto.Hash.SHA256.Lazy as Lazy
import System.IO.Unsafe (unsafePerformIO)

-- ffi ------------------------------------------------------------------------

foreign import ccall unsafe "sha256_block_arm"
  c_sha256_block :: Ptr Word32 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sha256_arm_available"
  c_sha256_arm_available :: IO Int

-- preliminary utils ----------------------------------------------------------

-- keystroke saver
fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- hash -----------------------------------------------------------------------

hash :: BS.ByteString -> BS.ByteString
hash m
  | sha256_arm_available = hash_arm m
  | otherwise            = cat (process m)

sha256_arm_available :: Bool
sha256_arm_available = unsafePerformIO c_sha256_arm_available /= 0
{-# NOINLINE sha256_arm_available #-}

hash_arm :: BS.ByteString -> BS.ByteString
hash_arm m@(BI.PS _ _ l) = unsafePerformIO $
    allocaBytes 32 $ \state -> do
      poke state               (0x6a09e667 :: Word32)
      poke (state `plusPtr` 4) (0xbb67ae85 :: Word32)
      poke (state `plusPtr` 8) (0x3c6ef372 :: Word32)
      poke (state `plusPtr` 12) (0xa54ff53a :: Word32)
      poke (state `plusPtr` 16) (0x510e527f :: Word32)
      poke (state `plusPtr` 20) (0x9b05688c :: Word32)
      poke (state `plusPtr` 24) (0x1f83d9ab :: Word32)
      poke (state `plusPtr` 28) (0x5be0cd19 :: Word32)
      go state 0
      finalize state
      BI.create 32 $ \out -> do
        h0 <- peek state               :: IO Word32
        h1 <- peek (state `plusPtr` 4) :: IO Word32
        h2 <- peek (state `plusPtr` 8) :: IO Word32
        h3 <- peek (state `plusPtr` 12) :: IO Word32
        h4 <- peek (state `plusPtr` 16) :: IO Word32
        h5 <- peek (state `plusPtr` 20) :: IO Word32
        h6 <- peek (state `plusPtr` 24) :: IO Word32
        h7 <- peek (state `plusPtr` 28) :: IO Word32
        poke_word32be out 0 h0
        poke_word32be out 4 h1
        poke_word32be out 8 h2
        poke_word32be out 12 h3
        poke_word32be out 16 h4
        poke_word32be out 20 h5
        poke_word32be out 24 h6
        poke_word32be out 28 h7
  where
    go !state !j
      | j + 64 <= l = do
          BI.unsafeWithForeignPtr fp $ \src ->
            c_sha256_block state (src `plusPtr` (off + j))
          go state (j + 64)
      | otherwise = pure ()
      where
        BI.PS fp off _ = m

    finalize !state = do
      let !remaining@(BI.PS _ _ len) = BU.unsafeDrop (l - l `rem` 64) m
          BI.PS pfp poff _ = unsafe_padding remaining (fi l)
      BI.unsafeWithForeignPtr pfp $ \src -> do
        c_sha256_block state (src `plusPtr` poff)
        if len >= 56
          then c_sha256_block state (src `plusPtr` (poff + 64))
          else pure ()

    poke_word32be :: Ptr Word8 -> Int -> Word32 -> IO ()
    poke_word32be !p !off !w = do
      poke (p `plusPtr` off)       (fi (w `B.unsafeShiftR` 24) :: Word8)
      poke (p `plusPtr` (off + 1)) (fi (w `B.unsafeShiftR` 16) :: Word8)
      poke (p `plusPtr` (off + 2)) (fi (w `B.unsafeShiftR` 8) :: Word8)
      poke (p `plusPtr` (off + 3)) (fi w :: Word8)

unsafe_padding :: BS.ByteString -> Word64 -> BS.ByteString
unsafe_padding (BI.PS fp off r) l
    | r < 56 = BI.unsafeCreate 64 $ \p -> do
        BI.unsafeWithForeignPtr fp $ \src ->
          copyBytes p (src `plusPtr` off) r
        poke (p `plusPtr` r) (0x80 :: Word8)
        fillBytes (p `plusPtr` (r + 1)) 0 (55 - r)
        poke_word64be (p `plusPtr` 56) (l * 8)
    | otherwise = BI.unsafeCreate 128 $ \p -> do
        BI.unsafeWithForeignPtr fp $ \src ->
          copyBytes p (src `plusPtr` off) r
        poke (p `plusPtr` r) (0x80 :: Word8)
        fillBytes (p `plusPtr` (r + 1)) 0 (63 - r)
        fillBytes (p `plusPtr` 64) 0 56
        poke_word64be (p `plusPtr` 120) (l * 8)
  where
    poke_word64be :: Ptr Word8 -> Word64 -> IO ()
    poke_word64be !p !w = do
      poke p               (fi (w `B.unsafeShiftR` 56) :: Word8)
      poke (p `plusPtr` 1) (fi (w `B.unsafeShiftR` 48) :: Word8)
      poke (p `plusPtr` 2) (fi (w `B.unsafeShiftR` 40) :: Word8)
      poke (p `plusPtr` 3) (fi (w `B.unsafeShiftR` 32) :: Word8)
      poke (p `plusPtr` 4) (fi (w `B.unsafeShiftR` 24) :: Word8)
      poke (p `plusPtr` 5) (fi (w `B.unsafeShiftR` 16) :: Word8)
      poke (p `plusPtr` 6) (fi (w `B.unsafeShiftR`  8) :: Word8)
      poke (p `plusPtr` 7) (fi w                       :: Word8)

process :: BS.ByteString -> Registers
process m@(BI.PS _ _ l) = finalize (go (iv ()) 0) where
  go !acc !j
    | j + 64 <= l = go (block_hash acc (parse_block m j)) (j + 64)
    | otherwise   = acc

  finalize !acc
      | len < 56  = block_hash acc (parse_block padded 0)
      | otherwise = block_hash
          (block_hash acc (parse_block padded 0))
          (parse_block padded 64)
    where
      !remaining@(BI.PS _ _ len) = BU.unsafeDrop (l - l `rem` 64) m
      !padded = unsafe_padding remaining (fi l)

-- hmac -----------------------------------------------------------------------

data KeyAndLen = KeyAndLen
  {-# UNPACK #-} !BS.ByteString
  {-# UNPACK #-} !Int

hmac
  :: BS.ByteString -- ^ key
  -> BS.ByteString -- ^ text
  -> BS.ByteString
hmac mk@(BI.PS _ _ l) text =
    let step1 = k <> BS.replicate (64 - lk) 0x00
        step2 = BS.map (B.xor 0x36) step1
        step3 = step2 <> text
        step4 = hash step3
        step5 = BS.map (B.xor 0x5C) step1
        step6 = step5 <> step4
    in  hash step6
  where
    !(KeyAndLen k lk)
      | l > 64    = KeyAndLen (hash mk) 32
      | otherwise = KeyAndLen mk l





-- -- utility types for more efficient ByteString management
--
-- data SSPair = SSPair
--   {-# UNPACK #-} !BS.ByteString
--   {-# UNPACK #-} !BS.ByteString
--
-- data SLPair = SLPair {-# UNPACK #-} !BS.ByteString !BL.ByteString
--
-- -- unsafe version of splitAt that does no bounds checking
-- --
-- -- invariant:
-- --   0 <= n <= l
-- unsafe_splitAt :: Int -> BS.ByteString -> SSPair
-- unsafe_splitAt n (BI.BS x l) =
--   SSPair (BI.BS x n) (BI.BS (plusForeignPtr x n) (l - n))
--
-- -- variant of Data.ByteString.Lazy.splitAt that returns the initial
-- -- component as a strict, unboxed ByteString
-- splitAt64 :: BL.ByteString -> SLPair
-- splitAt64 = splitAt' (64 :: Int) where
--   splitAt' _ BLI.Empty        = SLPair mempty BLI.Empty
--   splitAt' n (BLI.Chunk c@(BI.PS _ _ l) cs) =
--     if    n < l
--     then
--       -- n < BS.length c, so unsafe_splitAt is safe
--       let !(SSPair c0 c1) = unsafe_splitAt n c
--       in  SLPair c0 (BLI.Chunk c1 cs)
--     else
--       let SLPair cs' cs'' = splitAt' (n - l) cs
--       in  SLPair (c <> cs') cs''
--
-- -- builder realization strategies
--
-- to_strict :: BSB.Builder -> BS.ByteString
-- to_strict = BL.toStrict . BSB.toLazyByteString
--
-- to_strict_small :: BSB.Builder -> BS.ByteString
-- to_strict_small = BL.toStrict . BE.toLazyByteStringWith
--   (BE.safeStrategy 128 BE.smallChunkSize) mempty
--
-- -- message padding and parsing
-- -- https://datatracker.ietf.org/doc/html/rfc6234#section-4.1
--
-- -- k such that (l + 1 + k) mod 64 = 56
-- sol :: Word64 -> Word64
-- sol l =
--   let r = 56 - fi l `rem` 64 - 1 :: Integer -- fi prevents underflow
--   in  fi (if r < 0 then r + 64 else r)
--
-- -- RFC 6234 4.1 (strict)
-- pad :: BS.ByteString -> BS.ByteString
-- pad m@(BI.PS _ _ (fi -> l))
--     | l < 128 = to_strict_small padded
--     | otherwise = to_strict padded
--   where
--     padded = BSB.byteString m
--           <> fill (sol l) (BSB.word8 0x80)
--           <> BSB.word64BE (l * 8)
--
--     fill j !acc
--       | j `rem` 8 == 0 =
--              loop64 j acc
--       | (j - 7) `rem` 8 == 0 =
--              loop64 (j - 7) acc
--           <> BSB.word32BE 0x00
--           <> BSB.word16BE 0x00
--           <> BSB.word8 0x00
--       | (j - 6) `rem` 8 == 0 =
--              loop64 (j - 6) acc
--           <> BSB.word32BE 0x00
--           <> BSB.word16BE 0x00
--       | (j - 5) `rem` 8 == 0 =
--              loop64 (j - 5) acc
--           <> BSB.word32BE 0x00
--           <> BSB.word8 0x00
--       | (j - 4) `rem` 8 == 0 =
--              loop64 (j - 4) acc
--           <> BSB.word32BE 0x00
--       | (j - 3) `rem` 8 == 0 =
--              loop64 (j - 3) acc
--           <> BSB.word16BE 0x00
--           <> BSB.word8 0x00
--       | (j - 2) `rem` 8 == 0 =
--              loop64 (j - 2) acc
--           <> BSB.word16BE 0x00
--       | (j - 1) `rem` 8 == 0 =
--              loop64 (j - 1) acc
--           <> BSB.word8 0x00
--
--       | j `rem` 4 == 0 =
--              loop32 j acc
--       | (j - 3) `rem` 4 == 0 =
--              loop32 (j - 3) acc
--           <> BSB.word16BE 0x00
--           <> BSB.word8 0x00
--       | (j - 2) `rem` 4 == 0 =
--              loop32 (j - 2) acc
--           <> BSB.word16BE 0x00
--       | (j - 1) `rem` 4 == 0 =
--              loop32 (j - 1) acc
--           <> BSB.word8 0x00
--
--       | j `rem` 2 == 0 =
--              loop16 j acc
--       | (j - 1) `rem` 2 == 0 =
--              loop16 (j - 1) acc
--           <> BSB.word8 0x00
--
--       | otherwise =
--             loop8 j acc
--
--     loop64 j !acc
--       | j == 0 = acc
--       | otherwise = loop64 (j - 8) (acc <> BSB.word64BE 0x00)
--
--     loop32 j !acc
--       | j == 0 = acc
--       | otherwise = loop32 (j - 4) (acc <> BSB.word32BE 0x00)
--
--     loop16 j !acc
--       | j == 0 = acc
--       | otherwise = loop16 (j - 2) (acc <> BSB.word16BE 0x00)
--
--     loop8 j !acc
--       | j == 0 = acc
--       | otherwise = loop8 (pred j) (acc <> BSB.word8 0x00)
--
-- -- RFC 6234 4.1 (lazy)
-- pad_lazy :: BL.ByteString -> BL.ByteString
-- pad_lazy (BL.toChunks -> m) = BL.fromChunks (walk 0 m) where
--   walk !l bs = case bs of
--     (c:cs) -> c : walk (l + fi (BS.length c)) cs
--     [] -> padding l (sol l) (BSB.word8 0x80)
--
--   padding l k bs
--     | k == 0 =
--           pure
--         . to_strict
--           -- more efficient for small builder
--         $ bs <> BSB.word64BE (l * 8)
--     | otherwise =
--         let nacc = bs <> BSB.word8 0x00
--         in  padding l (pred k) nacc
--
-- -- | Compute a condensed representation of a strict bytestring via
-- --   SHA-256.
-- --
-- --   The 256-bit output digest is returned as a strict bytestring.
-- --
-- --   >>> hash "strict bytestring input"
-- --   "<strict 256-bit message digest>"
-- hash :: BS.ByteString -> BS.ByteString
-- hash bs = cat (go (iv ()) (pad bs)) where
--   go :: Registers -> BS.ByteString -> Registers
--   go !acc b
--     | BS.null b = acc
--     | otherwise = case unsafe_splitAt 64 b of
--         SSPair c r -> go (unsafe_hash_alg acc c) r
--
-- -- | Compute a condensed representation of a lazy bytestring via
-- --   SHA-256.
-- --
-- --   The 256-bit output digest is returned as a strict bytestring.
-- --
-- --   >>> hash_lazy "lazy bytestring input"
-- --   "<strict 256-bit message digest>"
-- hash_lazy :: BL.ByteString -> BS.ByteString
-- hash_lazy bl = cat (go (iv ()) (pad_lazy bl)) where
--   go :: Registers -> BL.ByteString -> Registers
--   go !acc bs
--     | BL.null bs = acc
--     | otherwise = case splitAt64 bs of
--         SLPair c r -> go (unsafe_hash_alg acc c) r
--
-- -- HMAC -----------------------------------------------------------------------
-- -- https://datatracker.ietf.org/doc/html/rfc2104#section-2
--
-- data KeyAndLen = KeyAndLen
--   {-# UNPACK #-} !BS.ByteString
--   {-# UNPACK #-} !Int
--
-- -- | Produce a message authentication code for a strict bytestring,
-- --   based on the provided (strict, bytestring) key, via SHA-256.
-- --
-- --   The 256-bit MAC is returned as a strict bytestring.
-- --
-- --   Per RFC 2104, the key /should/ be a minimum of 32 bytes long. Keys
-- --   exceeding 64 bytes in length will first be hashed (via SHA-256).
-- --
-- --   >>> hmac "strict bytestring key" "strict bytestring input"
-- --   "<strict 256-bit MAC>"
-- hmac
--   :: BS.ByteString -- ^ key
--   -> BS.ByteString -- ^ text
--   -> BS.ByteString
-- hmac mk@(BI.PS _ _ l) text =
--     let step1 = k <> BS.replicate (64 - lk) 0x00
--         step2 = BS.map (B.xor 0x36) step1
--         step3 = step2 <> text
--         step4 = hash step3
--         step5 = BS.map (B.xor 0x5C) step1
--         step6 = step5 <> step4
--     in  hash step6
--   where
--     !(KeyAndLen k lk)
--       | l > 64    = KeyAndLen (hash mk) 32
--       | otherwise = KeyAndLen mk l
--
-- -- | Produce a message authentication code for a lazy bytestring, based
-- --   on the provided (strict, bytestring) key, via SHA-256.
-- --
-- --   The 256-bit MAC is returned as a strict bytestring.
-- --
-- --   Per RFC 2104, the key /should/ be a minimum of 32 bytes long. Keys
-- --   exceeding 64 bytes in length will first be hashed (via SHA-256).
-- --
-- --   >>> hmac_lazy "strict bytestring key" "lazy bytestring input"
-- --   "<strict 256-bit MAC>"
-- hmac_lazy
--   :: BS.ByteString -- ^ key
--   -> BL.ByteString -- ^ text
--   -> BS.ByteString
-- hmac_lazy mk@(BI.PS _ _ l) text =
--     let step1 = k <> BS.replicate (64 - lk) 0x00
--         step2 = BS.map (B.xor 0x36) step1
--         step3 = BL.fromStrict step2 <> text
--         step4 = hash_lazy step3
--         step5 = BS.map (B.xor 0x5C) step1
--         step6 = step5 <> step4
--     in  hash step6
--   where
--     !(KeyAndLen k lk)
--       | l > 64    = KeyAndLen (hash mk) 32
--       | otherwise = KeyAndLen mk l
