{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Crypto.Hash.SHA256.Lazy
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Pure SHA-256 and HMAC-SHA256 implementations for lazy ByteStrings,
-- as specified by RFC's
-- [6234](https://datatracker.ietf.org/doc/html/rfc6234) and
-- [2104](https://datatracker.ietf.org/doc/html/rfc2104).

module Crypto.Hash.SHA256.Lazy (
  -- * SHA-256 message digest functions
    hash_lazy

  -- * SHA256-based MAC functions
  , hmac_lazy
  ) where

import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Internal as BLI
import Data.Word (Word64)
import Foreign.ForeignPtr (plusForeignPtr)
import Crypto.Hash.SHA256.Internal
import qualified Crypto.Hash.SHA256.Pure as Pure

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- utility types for more efficient ByteString management

data SSPair = SSPair
  {-# UNPACK #-} !BS.ByteString
  {-# UNPACK #-} !BS.ByteString

data SLPair = SLPair {-# UNPACK #-} !BS.ByteString !BL.ByteString

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
  splitAt' n (BLI.Chunk c@(BI.PS _ _ l) cs) =
    if    n < l
    then
      -- n < BS.length c, so unsafe_splitAt is safe
      let !(SSPair c0 c1) = unsafe_splitAt n c
      in  SLPair c0 (BLI.Chunk c1 cs)
    else
      let SLPair cs' cs'' = splitAt' (n - l) cs
      in  SLPair (c <> cs') cs''

-- builder realization strategies

to_strict :: BSB.Builder -> BS.ByteString
to_strict = BL.toStrict . BSB.toLazyByteString

-- message padding and parsing
-- https://datatracker.ietf.org/doc/html/rfc6234#section-4.1

-- k such that (l + 1 + k) mod 64 = 56
sol :: Word64 -> Word64
sol l = (55 - l) B..&. 63 -- wraps mod 2^64, a multiple of 64

-- RFC 6234 4.1 (lazy)
pad_lazy :: BL.ByteString -> BL.ByteString
pad_lazy (BL.toChunks -> m) = BL.fromChunks (walk 0 m) where
  walk !l bs = case bs of
    (c:cs) -> c : walk (l + fi (BS.length c)) cs
    [] -> [padding l]

  padding l = to_strict $
       BSB.word8 0x80
    <> BSB.byteString (BS.replicate (fi (sol l)) 0x00)
    <> BSB.word64BE (l * 8)

-- | Compute a condensed representation of a lazy bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash_lazy "lazy bytestring input"
--   "<strict 256-bit message digest>"
hash_lazy :: BL.ByteString -> BS.ByteString
hash_lazy bl = cat (go (iv ()) (pad_lazy bl)) where
  go :: Registers -> BL.ByteString -> Registers
  go !acc bs
    | BL.null bs = acc
    | otherwise = case splitAt64 bs of
        SLPair c r -> go (update acc (parse c 0)) r

-- HMAC -----------------------------------------------------------------------
-- https://datatracker.ietf.org/doc/html/rfc2104#section-2

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
  -> MAC
hmac_lazy mk@(BI.PS _ _ l) text =
    let step1 = k <> BS.replicate (64 - lk) 0x00
        step2 = BS.map (B.xor 0x36) step1
        step3 = BL.fromStrict step2 <> text
        step4 = hash_lazy step3
        step5 = BS.map (B.xor 0x5C) step1
        step6 = step5 <> step4
    in  MAC (Pure.hash step6)
  where
    !(k, lk) = if l > 64 then (Pure.hash mk, 32) else (mk, l)
