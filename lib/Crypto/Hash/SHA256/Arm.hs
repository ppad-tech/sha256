{-# LANGUAGE BangPatterns #-}

-- |
-- Module: Crypto.Hash.SHA256.Arm
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- ARM crypto extension support for SHA-256.

module Crypto.Hash.SHA256.Arm (
    sha256_arm_available
  , hash_arm
  , hash_arm_with
  ) where

import Control.Monad (unless, when)
import qualified Data.Bits as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word8, Word32, Word64)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (poke, peek)
import Crypto.Hash.SHA256.Internal (unsafe_padding)
import System.IO.Unsafe (unsafePerformIO)

-- ffi -----------------------------------------------------------------------

foreign import ccall unsafe "sha256_block_arm"
  c_sha256_block :: Ptr Word32 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sha256_arm_available"
  c_sha256_arm_available :: IO Int

-- utilities -----------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- api -----------------------------------------------------------------------

sha256_arm_available :: Bool
sha256_arm_available = unsafePerformIO c_sha256_arm_available /= 0
{-# NOINLINE sha256_arm_available #-}

hash_arm :: BS.ByteString -> BS.ByteString
hash_arm = hash_arm_with mempty 0

-- | Hash with optional 64-byte prefix and extra length for padding.
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

-- arm helpers ---------------------------------------------------------------

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
