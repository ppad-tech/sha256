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

  -- low-level specialized primitives
  , _hmac_rr
  , _hmac_rm
  , _hmac_rsb

  -- pointer-based IO functions (for HMAC-DRBG)
  , hmac_rr_unsafe
  , hmac_rsb_unsafe
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

-- XX these need testing

_hmac_rm
  :: Registers     -- ^ key
  -> BS.ByteString -- ^ message
  -> Registers
_hmac_rm k m
  | Arm.sha256_arm_available = Arm.hmac_rm k m
  | otherwise =
      let !key = pad_registers k
      in  _hmac key m
{-# INLINABLE _hmac_rm #-}

_hmac_rr
  :: Registers -- ^ key
  -> Registers -- ^ message
  -> Registers
_hmac_rr k m
  | Arm.sha256_arm_available = Arm.hmac_rr k m
  | otherwise =
      let !key   = pad_registers k
          !block = pad_registers_with_length m
      in  _hmac_bb key block
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

-- | HMAC for message (v || sep || dat), avoiding concatenation allocation.
_hmac_rsb
  :: Registers     -- ^ key
  -> Registers     -- ^ v (32 bytes)
  -> Word8         -- ^ separator byte
  -> BS.ByteString -- ^ data
  -> Registers
_hmac_rsb k v sep dat
  -- XX add Arm.hmac_rsb when available
  -- | Arm.sha256_arm_available = Arm.hmac_rsb k v sep dat
  | otherwise =
      let !key   = pad_registers k
          !rs0   = update (iv ()) (xor key (Exts.wordToWord32# 0x36363636##))
          !inner = hash_vsb 64 rs0 v sep dat
          !block = pad_registers_with_length inner
          !rs1   = update (iv ()) (xor key (Exts.wordToWord32# 0x5C5C5C5C##))
      in  update rs1 block
{-# INLINABLE _hmac_rsb #-}

-- Hash (v || sep || dat) with initial state and extra prefix length.
hash_vsb
  :: Word64        -- ^ extra prefix length
  -> Registers     -- ^ initial state
  -> Registers     -- ^ v
  -> Word8         -- ^ sep
  -> BS.ByteString -- ^ dat
  -> Registers
hash_vsb el rs0 v sep dat@(BI.PS _ _ l)
  | l >= 31 =
      -- first block is complete
      let !b0      = parse_vsb v sep dat
          !rs1     = update rs0 b0
          !rest    = BU.unsafeDrop 31 dat
          !restLen = l - 31
          !rs2     = _hash_blocks rs1 rest
          !finLen  = restLen `rem` 64
          !fin     = BU.unsafeDrop (restLen - finLen) rest
          !total   = el + 33 + fi l
      in  if   finLen < 56
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
{-# INLINABLE hash_vsb #-}

-- pointer-based IO functions ------------------------------------------------

-- | HMAC(key, message) where both are register-sized.
-- Writes 32-byte result to destination pointer.
-- Uses ARM crypto extensions if available, otherwise software fallback.
hmac_rr_unsafe
  :: Ptr Word32    -- ^ destination (8 Word32s)
  -> Ptr Word32    -- ^ scratch block buffer (16 Word32s)
  -> Registers     -- ^ key
  -> Registers     -- ^ message
  -> IO ()
hmac_rr_unsafe rp bp k m
  | Arm.sha256_arm_available = Arm._hmac_rr rp bp k m
  | otherwise = do
      let !key   = pad_registers k
          !block = pad_registers_with_length m
          !rs    = _hmac_bb key block
      poke_registers rp rs
{-# INLINABLE hmac_rr_unsafe #-}

-- | HMAC(key, v || sep || data).
-- Writes 32-byte result to destination pointer.
-- Uses ARM crypto extensions if available, otherwise software fallback.
hmac_rsb_unsafe
  :: Ptr Word32    -- ^ destination (8 Word32s)
  -> Ptr Word32    -- ^ scratch block buffer (16 Word32s)
  -> Registers     -- ^ key
  -> Registers     -- ^ v
  -> Word8         -- ^ separator byte
  -> BS.ByteString -- ^ data
  -> IO ()
hmac_rsb_unsafe rp bp k v sep dat
  | Arm.sha256_arm_available = Arm._hmac_rsb rp bp k v sep dat
  | otherwise = do
      let !rs = _hmac_rsb k v sep dat
      poke_registers rp rs
{-# INLINABLE hmac_rsb_unsafe #-}
