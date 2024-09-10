{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Builder as BSB
import qualified Crypto.Hash.SHA256 as SHA256
import System.Exit

-- XX add hmac tests, use tasty

-- vectors from
-- https://www.di-mgt.com.au/sha_testvectors.html

v0 :: (BS.ByteString, BS.ByteString)
v0 = (
    "abc"
  , "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  )

v1 :: (BS.ByteString, BS.ByteString)
v1 = (
    mempty
  , "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  )

v2 :: (BS.ByteString, BS.ByteString)
v2 = (
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  , "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  )

v3 :: (BS.ByteString, BS.ByteString)
v3 = (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
  , "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
  )

v4 :: (BS.ByteString, BS.ByteString)
v4 = (
    BS.replicate 1000000 0x61
  , "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
  )

construct_long :: BL.ByteString
construct_long = go (16777216 :: Int) mempty where
  go j acc
    | j == 0 = BSB.toLazyByteString acc
    | otherwise =
        let nacc = acc <> BSB.lazyByteString
              "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        in  go (pred j) nacc

v5 :: (BL.ByteString, BS.ByteString)
v5 = (
    construct_long
  , "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
  )

main :: IO ()
main = do
  let (v0_in, v0_out) = v0
      v0_res = B16.encode (SHA256.hash v0_in) == v0_out

      (v1_in, v1_out) = v1
      v1_res = B16.encode (SHA256.hash v1_in) == v1_out

      (v2_in, v2_out) = v2
      v2_res = B16.encode (SHA256.hash v2_in) == v2_out

      (v3_in, v3_out) = v3
      v3_res = B16.encode (SHA256.hash v3_in) == v3_out

      (v4_in, v4_out) = v4
      v4_res = B16.encode (SHA256.hash v4_in) == v4_out

      -- warning, slow
      (v5_in, v5_out) = v5
      v5_res = B16.encode (SHA256.hash_lazy v5_in) == v5_out

  unless (and [v0_res, v1_res, v2_res, v3_res, v4_res, v5_res]) $
    exitFailure

  exitSuccess
