{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns -fno-warn-type-defaults #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import Weigh

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = mainWith $ do
  hash
  hmac

hash :: Weigh ()
hash =
  let !bs0 = BS.replicate 32 0
      !bs1 = BS.replicate 64 0
      !bs2 = BS.replicate 128 0
      !bs3 = BS.replicate 12288 0
  in  wgroup "hash" $ do
        func' "hash (32B  input)" SHA256.hash bs0
        func' "hash (64B  input)" SHA256.hash bs1
        func' "hash (128B input)" SHA256.hash bs2
        func' "hash (12288B input)" SHA256.hash bs3

hmac :: Weigh ()
hmac =
  let !key = BS.replicate 32 9
      !bs0 = BS.replicate 32 0
      !bs1 = BS.replicate 64 0
      !bs2 = BS.replicate 128 0
      !bs3 = BS.replicate 12288 0
  in  wgroup "hmac" $ do
        func' "hmac (32B  input)" (SHA256.hmac key) bs0
        func' "hmac (64B  input)" (SHA256.hmac key) bs1
        func' "hmac (128B input)" (SHA256.hmac key) bs2
        func' "hmac (12288B input)" (SHA256.hmac key) bs3

