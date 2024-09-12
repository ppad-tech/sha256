{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Base16 as B16
import System.Environment

main :: IO ()
main = do
  args <- getArgs
  case args of
    mode:[] ->
      if   mode == "make"
      then make
      else hash
    _ -> error "incorrect args"

hash :: IO ()
hash = do
  input <- BL.readFile "ppad-sha256-hash-large.dat"
  let digest = B16.encode $ SHA256.u_hash_lazy input
  print digest

make :: IO ()
make = BL.writeFile "ppad-sha256-hash-large.dat" big_input where
  big_input :: BL.ByteString
  big_input = go (16777216 :: Int) mempty where
    go j acc
      | j == 0 = BSB.toLazyByteString acc
      | otherwise =
          let nacc = acc <> BSB.lazyByteString
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          in  go (pred j) nacc

