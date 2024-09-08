{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}

module Crypto.Hash.SHA256 where

-- import qualified Data.Binary as I
-- import qualified Data.Binary.Get as I
-- import qualified Data.Binary.Put as I
-- import qualified Data.Bits as B
-- import Data.Bits ((.|.), (.&.))
-- import Data.Word (Word32)
--
-- data SHA256S =  SHA256S
--   !Word32 !Word32 !Word32 !Word32
--   !Word32 !Word32 !Word32 !Word32
--
-- sha256_iv :: SHA256S
-- sha256_iv = SHA256S
--   0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
--   0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19
--
-- data SHA256 = SHA256
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 00-04
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 05-09
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 10-04
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 15-09
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 20-04
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 25-09
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 30-04
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 35-09
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 40-04
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 45-09
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 50-04
--   !Word32 !Word32 !Word32 !Word32 !Word32 -- 55-09
--   !Word32 !Word32 !Word32 !Word32         -- 60-63
--   deriving Show
--
-- putsha256 :: SHA256S -> I.Put
-- putsha256 (SHA256S a b c d e f g h) = do
--   I.putWord32be a
--   I.putWord32be b
--   I.putWord32be c
--   I.putWord32be d
--   I.putWord32be e
--   I.putWord32be f
--   I.putWord32be g
--   I.putWord32be h
--
-- getSHA256 :: I.Get SHA256S
-- getSHA256 = do
--   a <- I.getWord32be
--   b <- I.getWord32be
--   c <- I.getWord32be
--   d <- I.getWord32be
--   e <- I.getWord32be
--   f <- I.getWord32be
--   g <- I.getWord32be
--   h <- I.getWord32be
--   return $! SHA256S a b c d e f g h
--
-- step :: SHA256S -> Word32 -> Word32 -> SHA256S
-- step !(SHA256S a b c d e f g h) k w = SHA256S a' b' c' d' e' f' g' h'
--  where
--   t1 = h + bsig1 e + ch e f g + k + w
--   t2 = bsig0 a + maj a b c
--   h' = g
--   g' = f
--   f' = e
--   e' = d + t1
--   d' = c
--   c' = b
--   b' = a
--   a' = t1 + t2
-- {-# INLINE step #-}
--
-- bsig0 :: Word32 -> Word32
-- bsig0 x = B.rotateR x 2 `B.xor` B.rotateR x 13 `B.xor` B.rotateR x 22
--
-- bsig1 :: Word32 -> Word32
-- bsig1 x = B.rotateR x 6 `B.xor` B.rotateR x 11 `B.xor` B.rotateR x 25
--
-- lsig0 :: Word32 -> Word32
-- lsig0 x = B.rotateR x 7 `B.xor` B.rotateR x 18 `B.xor` B.shiftR x 3
--
-- lsig1 :: Word32 -> Word32
-- lsig1 x = B.rotateR x 17 `B.xor` B.rotateR x 19 `B.xor` B.shiftR x 10
--
-- -- choice, a ? b : c
-- ch :: Word32 -> Word32 -> Word32 -> Word32
-- ch x y z = (x .&. y) `B.xor` (B.complement x .&. z)
--
-- -- majority, (x & y) ^ (x & z) ^ (y & z)
-- --
-- -- XX from original
-- --
-- --  > note:
-- --  >   the original functions is (x & y) ^ (x & z) ^ (y & z)
-- --  >   if you fire off truth tables, this is equivalent to
-- --  >     (x & y) | (x & z) | (y & z)
-- --  >   which you can the use distribution on:
-- maj :: Word32 -> Word32 -> Word32 -> Word32
-- maj x y z = (x .&. (y .|. z)) .|. (y .&. z)
