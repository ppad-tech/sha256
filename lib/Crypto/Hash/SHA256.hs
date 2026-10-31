{-# OPTIONS_HADDOCK prune #-}

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
-- the ARM SHA2 or x86 SHA extensions via FFI if they're available, and
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
import Data.Word (Word8, Word32)
import Foreign.Ptr (Ptr)
import qualified Crypto.Hash.SHA256.Native as Native
import Crypto.Hash.SHA256.Internal (MAC(..), Registers)
import qualified Crypto.Hash.SHA256.Lazy as Lazy
import qualified Crypto.Hash.SHA256.Pure as Pure

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
  | Native.sha256_native_available = Native.hash m
  | otherwise = Pure.hash m
{-# INLINABLE hash #-}

-- hmac ----------------------------------------------------------------------

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
hmac :: BS.ByteString -> BS.ByteString -> MAC
hmac k m
  | Native.sha256_native_available = MAC (Native.hmac k m)
  | otherwise = MAC (Pure.hmac k m)
{-# INLINABLE hmac #-}

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
  | Native.sha256_native_available = Native._hmac_rr rp bp k m
  | otherwise = Pure._hmac_rr rp bp k m
{-# INLINABLE _hmac_rr #-}

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
  | Native.sha256_native_available = Native._hmac_rsb rp bp k v sep dat
  | otherwise = Pure._hmac_rsb rp bp k v sep dat
{-# INLINABLE _hmac_rsb #-}
