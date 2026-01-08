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

import Control.Monad (unless, when)
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

hash_arm :: BS.ByteString -> BS.ByteString
hash_arm = hash_arm_with mempty 0

sha256_arm_available :: Bool
sha256_arm_available = unsafePerformIO c_sha256_arm_available /= 0
{-# NOINLINE sha256_arm_available #-}

-- hash_arm, parameterized by optional 64-byte prefix and extra length
-- for padding
hash_arm_with
  :: BS.ByteString  -- ^ optional 64-byte prefix (or empty)
  -> Word64         -- ^ extra length to add for padding
  -> BS.ByteString  -- ^ message
  -> BS.ByteString
hash_arm_with prefix el m@(BI.PS fp off l) = unsafePerformIO $
    allocaBytes 32 $ \state -> do
      poke_iv state
      -- process prefix block if provided
      unless (BS.null prefix) $ do
        let BI.PS pfp poff _ = prefix
        BI.unsafeWithForeignPtr pfp $ \src ->
          c_sha256_block state (src `plusPtr` poff)

      go state 0

      let !remaining@(BI.PS _ _ rlen) = BU.unsafeDrop (l - l `rem` 64) m
          BI.PS padfp padoff _ = unsafe_padding remaining (el + fi l)
      BI.unsafeWithForeignPtr padfp $ \src -> do
        c_sha256_block state (src `plusPtr` padoff)
        when (rlen >= 56) $
          c_sha256_block state (src `plusPtr` (padoff + 64))

      read_state state
  where
    go !state !j
      | j + 64 <= l = do
          BI.unsafeWithForeignPtr fp $ \src ->
            c_sha256_block state (src `plusPtr` (off + j))
          go state (j + 64)
      | otherwise = pure ()

poke_iv :: Ptr Word32 -> IO ()
poke_iv !state = do
  poke state                (0x6a09e667 :: Word32)
  poke (state `plusPtr` 4)  (0xbb67ae85 :: Word32)
  poke (state `plusPtr` 8)  (0x3c6ef372 :: Word32)
  poke (state `plusPtr` 12) (0xa54ff53a :: Word32)
  poke (state `plusPtr` 16) (0x510e527f :: Word32)
  poke (state `plusPtr` 20) (0x9b05688c :: Word32)
  poke (state `plusPtr` 24) (0x1f83d9ab :: Word32)
  poke (state `plusPtr` 28) (0x5be0cd19 :: Word32)

read_state :: Ptr Word32 -> IO BS.ByteString
read_state !state = BI.create 32 $ \out -> do
  h0 <- peek state                :: IO Word32
  h1 <- peek (state `plusPtr` 4)  :: IO Word32
  h2 <- peek (state `plusPtr` 8)  :: IO Word32
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

-- process message, parameterized by initial state and extra length for
-- padding
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

-- hmac -----------------------------------------------------------------------

data KeyAndLen = KeyAndLen
  {-# UNPACK #-} !BS.ByteString
  {-# UNPACK #-} !Int

hmac
  :: BS.ByteString -- ^ key
  -> BS.ByteString -- ^ text
  -> BS.ByteString
hmac mk@(BI.PS _ _ l) text
    | sha256_arm_available =
        let !inner = hash_arm_with ipad 64 text
        in  hash_arm (opad <> inner)
    | otherwise =
        let !ipad_state = block_hash (iv ()) (parse_block ipad 0)
            !inner = cat (process_with ipad_state 64 text)
        in  hash (opad <> inner)
  where
    !step1 = k <> BS.replicate (64 - lk) 0x00
    !ipad  = BS.map (B.xor 0x36) step1
    !opad  = BS.map (B.xor 0x5C) step1
    !(KeyAndLen k lk)
      | l > 64    = KeyAndLen (hash mk) 32
      | otherwise = KeyAndLen mk l

