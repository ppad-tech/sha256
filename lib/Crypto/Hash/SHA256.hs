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
  ) where

import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word64)
import Crypto.Hash.SHA256.Arm
import Crypto.Hash.SHA256.Internal
import qualified Crypto.Hash.SHA256.Lazy as Lazy

-- utils ---------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- hash ----------------------------------------------------------------------

-- | Compute a condensed representation of a strict bytestring via
--   SHA-256.
--
--   The 256-bit output digest is returned as a strict bytestring.
--
--   >>> hash "strict bytestring input"
--   "<strict 256-bit message digest>"
hash :: BS.ByteString -> BS.ByteString
hash m
  | sha256_arm_available = hash_arm m
  | otherwise            = cat (process m)

-- process a message, given the specified iv
process_with :: Registers -> Word64 -> BS.ByteString -> Registers
process_with acc0 el m@(BI.PS _ _ l) = finalize (go acc0 0) where
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
      !padded = unsafe_padding remaining (el + fi l)

process :: BS.ByteString -> Registers
process = process_with (iv ()) 0

-- hmac ----------------------------------------------------------------------

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
  -> MAC
hmac mk@(BI.PS _ _ l) text
    | sha256_arm_available =
        let !inner = hash_arm_with ipad 64 text
        in  MAC (hash_arm (opad <> inner))
    | otherwise =
        let !ipad_state = block_hash (iv ()) (parse_block ipad 0)
            !inner = cat (process_with ipad_state 64 text)
        in  MAC (hash (opad <> inner))
  where
    !step1 = k <> BS.replicate (64 - lk) 0x00
    !ipad  = BS.map (B.xor 0x36) step1
    !opad  = BS.map (B.xor 0x5C) step1
    !(KeyAndLen k lk)
      | l > 64    = KeyAndLen (hash mk) 32
      | otherwise = KeyAndLen mk l
