{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module Main where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base16 as B16
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain unit_tests

-- vectors from
-- https://www.di-mgt.com.au/sha_testvectors.html

hv0_put, hv0_pec :: BS.ByteString
hv0_put = "abc"
hv0_pec = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

hv1_put, hv1_pec :: BS.ByteString
hv1_put = mempty
hv1_pec = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

hv2_put, hv2_pec :: BS.ByteString
hv2_put = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
hv2_pec = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

hv3_put, hv3_pec :: BS.ByteString
hv3_put = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
hv3_pec = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"

hv4_put, hv4_pec :: BS.ByteString
hv4_put = BS.replicate 1000000 0x61
hv4_pec = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"

big_input :: BL.ByteString
big_input = go (16777216 :: Int) mempty where
  go j acc
    | j == 0 = BSB.toLazyByteString acc
    | otherwise =
        let nacc = acc <> BSB.lazyByteString
              "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        in  go (pred j) nacc

hv5_put :: BL.ByteString
hv5_put = big_input

hv5_pec :: BS.ByteString
hv5_pec = "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"

-- vectors from
-- https://datatracker.ietf.org/doc/html/rfc4231#section-4.1

hmv1_key :: BS.ByteString
hmv1_key = B16.decodeLenient "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"

hmv1_put :: BS.ByteString
hmv1_put = "Hi There"

hmv1_pec :: BS.ByteString
hmv1_pec = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

hmv2_key :: BS.ByteString
hmv2_key = "Jefe"

hmv2_put :: BS.ByteString
hmv2_put = "what do ya want for nothing?"

hmv2_pec :: BS.ByteString
hmv2_pec = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

hmv3_key :: BS.ByteString
hmv3_key = B16.decodeLenient "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

hmv3_put :: BS.ByteString
hmv3_put = B16.decodeLenient "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

hmv3_pec :: BS.ByteString
hmv3_pec = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"

hmv4_key :: BS.ByteString
hmv4_key = B16.decodeLenient "0102030405060708090a0b0c0d0e0f10111213141516171819"

hmv4_put :: BS.ByteString
hmv4_put = B16.decodeLenient "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

hmv4_pec :: BS.ByteString
hmv4_pec = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"

hmv5_key :: BS.ByteString
hmv5_key = B16.decodeLenient "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

hmv5_put :: BS.ByteString
hmv5_put = "Test With Truncation"

hmv5_pec :: BS.ByteString
hmv5_pec = "a3b6167473100ee06e0c796c2955552b"

hmv6_key :: BS.ByteString
hmv6_key = B16.decodeLenient "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

hmv6_put :: BS.ByteString
hmv6_put = "Test Using Larger Than Block-Size Key - Hash Key First"

hmv6_pec :: BS.ByteString
hmv6_pec = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"

hmv7_key :: BS.ByteString
hmv7_key = hmv6_key

hmv7_put :: BS.ByteString
hmv7_put = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."

hmv7_pec :: BS.ByteString
hmv7_pec = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"

unit_tests :: TestTree
unit_tests = testGroup "ppad-sha256" [
    testGroup "hash" [
      cmp_hash "hv0" hv0_put hv0_pec
    , cmp_hash "hv1" hv1_put hv1_pec
    , cmp_hash "hv2" hv2_put hv2_pec
    , cmp_hash "hv3" hv3_put hv3_pec
    , cmp_hash "hv4" hv4_put hv4_pec
    ]
  , testGroup "hash_lazy" [
      cmp_hash_lazy "hv0" hv0_put hv0_pec
    , cmp_hash_lazy "hv1" hv1_put hv1_pec
    , cmp_hash_lazy "hv2" hv2_put hv2_pec
    , cmp_hash_lazy "hv3" hv3_put hv3_pec
    , cmp_hash_lazy "hv4" hv4_put hv4_pec
    ]
  , testGroup "u_hash_lazy" [
      cmp_u_hash_lazy "hv0" hv0_put hv0_pec
    , cmp_u_hash_lazy "hv1" hv1_put hv1_pec
    , cmp_u_hash_lazy "hv2" hv2_put hv2_pec
    , cmp_u_hash_lazy "hv3" hv3_put hv3_pec
    , cmp_u_hash_lazy "hv4" hv4_put hv4_pec
    ]
  -- uncomment me to run (slow, ~40s)
  --
  -- , testGroup "hash_lazy (1GB input)" [
  --     testCase "hv5" $ do
  --       let out = B16.encode (SHA256.hash_lazy hv5_put)
  --       assertEqual mempty hv5_pec out
  --   ]
  , testGroup "hmac" [
      cmp_hmac "hmv1" hmv1_key hmv1_put hmv1_pec
    , cmp_hmac "hmv2" hmv2_key hmv2_put hmv2_pec
    , cmp_hmac "hmv3" hmv3_key hmv3_put hmv3_pec
    , cmp_hmac "hmv4" hmv4_key hmv4_put hmv4_pec
    , testCase "hmv5" $ do
        let out = BS.take 32 $ B16.encode (SHA256.hmac hmv5_key hmv5_put)
        assertEqual mempty hmv5_pec out
    , testCase "hmv6" $ do
        let keh = SHA256.hash hmv6_key
            out = B16.encode (SHA256.hmac keh hmv6_put)
        assertEqual mempty hmv6_pec out
    , testCase "hmv7" $ do
        let keh = SHA256.hash hmv7_key
            out = B16.encode (SHA256.hmac keh hmv7_put)
        assertEqual mempty hmv7_pec out
    ]
  , testGroup "hmac_lazy" [
      cmp_hmac_lazy "hmv1" hmv1_key hmv1_put hmv1_pec
    , cmp_hmac_lazy "hmv2" hmv2_key hmv2_put hmv2_pec
    , cmp_hmac_lazy "hmv3" hmv3_key hmv3_put hmv3_pec
    , cmp_hmac_lazy "hmv4" hmv4_key hmv4_put hmv4_pec
    , testCase "hmv5" $ do
        let lut = BL.fromStrict hmv5_put
            out = BS.take 32 $ B16.encode (SHA256.hmac_lazy hmv5_key lut)
        assertEqual mempty hmv5_pec out
    , testCase "hmv6" $ do
        let keh = SHA256.hash hmv6_key
            lut = BL.fromStrict hmv6_put
            out = B16.encode (SHA256.hmac_lazy keh lut)
        assertEqual mempty hmv6_pec out
    , testCase "hmv7" $ do
        let keh = SHA256.hash hmv7_key
            lut = BL.fromStrict hmv7_put
            out = B16.encode (SHA256.hmac_lazy keh lut)
        assertEqual mempty hmv7_pec out
    ]
  ]

cmp_hash :: String -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hash msg put pec = testCase msg $ do
  let out = B16.encode (SHA256.hash put)
  assertEqual mempty pec out

cmp_hash_lazy :: String -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hash_lazy msg (BL.fromStrict -> put) pec = testCase msg $ do
  let out = B16.encode (SHA256.hash_lazy put)
  assertEqual mempty pec out

cmp_u_hash_lazy :: String -> BS.ByteString -> BS.ByteString -> TestTree
cmp_u_hash_lazy msg (BL.fromStrict -> put) pec = testCase msg $ do
  let out = B16.encode (SHA256.u_hash_lazy put)
  assertEqual mempty pec out

cmp_hmac
  :: String -> BS.ByteString -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hmac msg key put pec = testCase msg $ do
  let out = B16.encode (SHA256.hmac key put)
  assertEqual mempty pec out

cmp_hmac_lazy
  :: String -> BS.ByteString -> BS.ByteString -> BS.ByteString -> TestTree
cmp_hmac_lazy msg key (BL.fromStrict -> put) pec = testCase msg $ do
  let out = B16.encode (SHA256.hmac_lazy key put)
  assertEqual mempty pec out

