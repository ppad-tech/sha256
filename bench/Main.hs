{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA256D as D
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Digest.Pure.SHA as SHA

main :: IO ()
main = defaultMain [
    suite
  ]

suite :: Benchmark
suite = env setup $ \ ~(bs, bl) ->
    bgroup "ppad-sha256" [
      bgroup "SHA256 (32B input)" [
        bench "hash" $ whnf SHA256.hash bs
      , bench "hashd" $ whnf D.hash bs
      , bench "hash_lazy" $ whnf SHA256.hash_lazy bl
      , bench "SHA.sha256" $ whnf SHA.sha256 bl
      ]
    , bgroup "HMAC-SHA256 (32B input)" [
        bench "hmac" $ whnf (SHA256.hmac "key") bs
      , bench "hmacd" $ whnf (D.hmac "key") bs
      , bench "hmac_lazy" $ whnf (SHA256.hmac_lazy "key") bl
      , bench "SHA.hmacSha256" $ whnf (SHA.hmacSha256 "key") bl
      ]
    ]
  where
    setup = do
      let bs_32B = BS.replicate 32 0
          bl_32B = BL.fromStrict bs_32B
      pure (bs_32B, bl_32B)

