{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
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
-- SHA-256 and HMAC-SHA256 implementations for
-- strict and lazy ByteStrings, as specified by RFC's
-- [6234](https://datatracker.ietf.org/doc/html/rfc6234) and
-- [2104](https://datatracker.ietf.org/doc/html/rfc2104).
--
-- The 'hash' and 'hmac' functions will use primitive instructions from
-- the ARM cryptographic extensions via FFI if they're available, and
-- will otherwise use a pure Haskell implementation.

module Crypto.Hash.SHA256 (
  -- * SHA-256 message digest functions
    hash
  , Lazy.hash_lazy

  -- * SHA256-based MAC functions
  , MAC(..)
  , hmac
  , Lazy.hmac_lazy

  -- low-level specialized HMAC primitives
  , _hmac_rr
  , _hmac_rsb
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word8, Word32, Word64)
import Foreign.Ptr (Ptr)
import qualified GHC.Exts as Exts
import qualified Crypto.Hash.SHA256.Arm as Arm
import Crypto.Hash.SHA256.Internal
import qualified Crypto.Hash.SHA256.Lazy as Lazy

-- utilities ------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- hash -----------------------------------------------------------------------

-- | Compute a condensed representation of a strict bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash "strict bytestring input"
--   "<strict 256-bit message digest>"
hash :: BS.ByteString -> BS.ByteString
hash m
  | Arm.sha256_arm_available = Arm.hash m
  | otherwise = cat (_hash 0 (iv ()) m)
{-# INLINABLE hash #-}

_hash
  :: Word64        -- ^ extra prefix length for padding calculations
  -> Registers     -- ^ register state
  -> BS.ByteString -- ^ input
  -> Registers
_hash el rs m@(BI.PS _ _ l) = do
  let !state = _hash_blocks rs m
      !fin@(BI.PS _ _ ll) = BU.unsafeDrop (l - l `rem` 64) m
      !total = el + fi l
  if   ll < 56
  then
    let !ult = parse_pad1 fin total
    in  update state ult
  else
    let !(# pen, ult #) = parse_pad2 fin total
    in  update (update state pen) ult
{-# INLINABLE _hash #-}

_hash_blocks
  :: Registers     -- ^ state
  -> BS.ByteString -- ^ input
  -> Registers
_hash_blocks rs m@(BI.PS _ _ l) = loop rs 0 where
  loop !acc !j
    | j + 64 > l = acc
    | otherwise  =
        let !nacc = update acc (parse m j)
        in  loop nacc (j + 64)
{-# INLINABLE _hash_blocks #-}

-- hmac ----------------------------------------------------------------------

-- | Compute a condensed representation of a strict bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash "strict bytestring input"
--   "<strict 256-bit message digest>"
hmac :: BS.ByteString -> BS.ByteString -> MAC
hmac k m
  | Arm.sha256_arm_available = MAC (Arm.hmac k m)
  | otherwise = MAC (cat (_hmac (prep_key k) m))
{-# INLINABLE hmac #-}

prep_key :: BS.ByteString -> Block
prep_key k@(BI.PS _ _ l)
    | l > 64    = parse_key (hash k)
    | otherwise = parse_key k
{-# INLINABLE prep_key #-}

_hmac
  :: Block          -- ^ padded key
  -> BS.ByteString  -- ^ message
  -> Registers
_hmac k m =
  let !rs0   = update (iv ()) (xor k (Exts.wordToWord32# 0x36363636##))
      !block = pad_registers_with_length (_hash 64 rs0 m)
      !rs1   = update (iv ()) (xor k (Exts.wordToWord32# 0x5C5C5C5C##))
  in  update rs1 block
{-# INLINABLE _hmac #-}

-- the following functions are useful when we want to avoid allocating certain
-- components of the HMAC key and message on the heap.

-- Computes hmac(k, v) when k and v are Registers.
--
-- The 32-byte result is written to the destination pointer.
_hmac_rr
  :: Ptr Word32    -- ^ destination (8 Word32s)
  -> Ptr Word32    -- ^ scratch block buffer (16 Word32s)
  -> Registers     -- ^ key
  -> Registers     -- ^ message
  -> IO ()
_hmac_rr rp bp k m
  | Arm.sha256_arm_available = Arm._hmac_rr rp bp k m
  | otherwise = do
      let !key   = pad_registers k
          !block = pad_registers_with_length m
          !rs    = _hmac_bb key block
      poke_registers rp rs
{-# INLINABLE _hmac_rr #-}

_hmac_bb
  :: Block     -- ^ key
  -> Block     -- ^ message
  -> Registers
_hmac_bb k m =
  let !rs0   = update (iv ()) (xor k (Exts.wordToWord32# 0x36363636##))
      !rs1   = update rs0 m
      !inner = pad_registers_with_length rs1
      !rs2   = update (iv ()) (xor k (Exts.wordToWord32# 0x5C5C5C5C##))
  in  update rs2 inner
{-# INLINABLE _hmac_bb #-}

-- Calculate hmac(k, m) where m is the concatenation of v (registers), a
-- separator byte, and a ByteString. This avoids allocating 'v' on the
-- heap.
--
-- The 32-byte result is written to the destination pointer.
_hmac_rsb
  :: Ptr Word32    -- ^ destination pointer (8 x Word32)
  -> Ptr Word32    -- ^ scratch block pointer (16 x Word32)
  -> Registers     -- ^ k
  -> Registers     -- ^ v
  -> Word8         -- ^ separator byte
  -> BS.ByteString -- ^ data
  -> IO ()
_hmac_rsb rp bp k v sep dat
  | Arm.sha256_arm_available = Arm._hmac_rsb rp bp k v sep dat
  | otherwise = do
      let !key   = pad_registers k
          !rs0   = update (iv ()) (xor key (Exts.wordToWord32# 0x36363636##))
          !inner = _hash_vsb 64 rs0 v sep dat
          !block = pad_registers_with_length inner
          !rs1   = update (iv ()) (xor key (Exts.wordToWord32# 0x5C5C5C5C##))
          !rs    = update rs1 block
      poke_registers rp rs
{-# INLINABLE _hmac_rsb #-}

-- hash(v || sep || dat) with a custom initial state and extra
-- prefix length. used for producing a more specialized hmac.
_hash_vsb
  :: Word64        -- ^ extra prefix length
  -> Registers     -- ^ initial state
  -> Registers     -- ^ v
  -> Word8         -- ^ sep
  -> BS.ByteString -- ^ dat
  -> Registers
_hash_vsb el rs0 v sep dat@(BI.PS _ _ l)
  | l >= 31 =
      -- first block is complete
      let !b0    = parse_vsb v sep dat
          !rs1   = update rs0 b0
          !rest  = BU.unsafeDrop 31 dat
          !rlen  = l - 31
          !rs2   = _hash_blocks rs1 rest
          !flen  = rlen `rem` 64
          !fin   = BU.unsafeDrop (rlen - flen) rest
          !total = el + 33 + fi l
      in  if   flen < 56
          then update rs2 (parse_pad1 fin total)
          else let !(# pen, ult #) = parse_pad2 fin total
               in  update (update rs2 pen) ult
  | otherwise =
      -- message < 64 bytes, goes straight to padding
      let !total = el + 33 + fi l
      in  if   33 + l < 56
          then update rs0 (parse_pad1_vsb v sep dat total)
          else let !(# pen, ult #) = parse_pad2_vsb v sep dat total
               in  update (update rs0 pen) ult
{-# INLINABLE _hash_vsb #-}

