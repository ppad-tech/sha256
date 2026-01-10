{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Digest.Pure.SHA as SHA

main :: IO ()
main = defaultMain [
    suite
  ]

suite :: Benchmark
suite =
  let !bs    = BS.replicate 32 0
      !bl    = BL.fromStrict bs
      !mac0  = SHA256.hmac "key" "foo"
      !mac1  = SHA256.hmac "key" "bar"
      !mac2  = SHA256.hmac "key" "foo"
      !macl0 = SHA256.hmac_lazy "key" "foo"
      !macl1 = SHA256.hmac_lazy "key" "bar"
      !macl2 = SHA256.hmac_lazy "key" "foo"
  in  bgroup "ppad-sha256" [
        bgroup "SHA256 (32B input)" [
          bench "hash" $ whnf SHA256.hash bs
        , bench "hash_lazy" $ whnf SHA256.hash_lazy bl
        , bench "SHA.sha256" $ whnf SHA.sha256 bl
        ]
      , bgroup "HMAC-SHA256 (32B input)" [
          bench "hmac" $ whnf (SHA256.hmac "key") bs
        , bench "hmac_lazy" $ whnf (SHA256.hmac_lazy "key") bl
        , bench "SHA.hmacSha256" $ whnf (SHA.hmacSha256 "key") bl
        ]
      , bgroup "MAC comparison" [
          bench "hmac, unequal" $ whnf (mac0 ==) mac1
        , bench "hmac, equal" $ whnf (mac0 ==) mac2
        , bench "hmac_lazy, unequal" $ whnf (macl0 ==) macl1
        , bench "hmac_lazy, equal" $ whnf (macl0 ==) macl2
        ]
      ]
