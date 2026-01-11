{-# OPTIONS_GHC -fno-warn-orphans #-}

module Property (
    properties
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Crypto.Hash.SHA256
import Test.Tasty
import qualified Test.Tasty.QuickCheck as Q
import Test.QuickCheck.Instances.ByteString ()

-- strict/lazy hash equivalence
hash_equiv :: BS.ByteString -> Bool
hash_equiv bs = hash bs == hash_lazy (BL.fromStrict bs)

-- strict/lazy hmac equivalence
hmac_equiv :: BS.ByteString -> BS.ByteString -> Bool
hmac_equiv k m = hmac k m == hmac_lazy k (BL.fromStrict m)

-- hash output is always 32 bytes
hash_length :: BS.ByteString -> Bool
hash_length bs = BS.length (hash bs) == 32

-- hmac output is always 32 bytes
hmac_length :: BS.ByteString -> BS.ByteString -> Bool
hmac_length k m = let MAC h = hmac k m in BS.length h == 32

-- hash_lazy produces same result regardless of chunking
hash_chunking :: BS.ByteString -> [Q.Positive Int] -> Bool
hash_chunking bs chunks =
  let lazy_single = BL.fromStrict bs
      lazy_chunked = BL.fromChunks (chunk_by (map Q.getPositive chunks) bs)
  in  hash_lazy lazy_single == hash_lazy lazy_chunked

-- hmac_lazy produces same result regardless of chunking
hmac_chunking :: BS.ByteString -> BS.ByteString -> [Q.Positive Int] -> Bool
hmac_chunking k m chunks =
  let lazy_single = BL.fromStrict m
      lazy_chunked = BL.fromChunks (chunk_by (map Q.getPositive chunks) m)
  in  hmac_lazy k lazy_single == hmac_lazy k lazy_chunked

chunk_by :: [Int] -> BS.ByteString -> [BS.ByteString]
chunk_by _ bs | BS.null bs = []
chunk_by [] bs = [bs]
chunk_by (n:ns) bs =
  let (h, t) = BS.splitAt n bs
  in  h : chunk_by ns t

properties :: TestTree
properties = testGroup "properties" [
    Q.testProperty "hash == hash_lazy" $
      Q.withMaxSuccess 1000 hash_equiv
  , Q.testProperty "hmac == hmac_lazy" $
      Q.withMaxSuccess 1000 hmac_equiv
  , Q.testProperty "hash output is 32 bytes" $
      Q.withMaxSuccess 1000 hash_length
  , Q.testProperty "hmac output is 32 bytes" $
      Q.withMaxSuccess 1000 hmac_length
  , Q.testProperty "hash_lazy chunking-invariant" $
      Q.withMaxSuccess 1000 hash_chunking
  , Q.testProperty "hmac_lazy chunking-invariant" $
      Q.withMaxSuccess 1000 hmac_chunking
  ]
