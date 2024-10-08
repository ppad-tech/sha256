{-# LANGUAGE OverloadedStrings #-}

module Wycheproof (
    Wycheproof(..)
  , MacTestGroup(..)
  , MacTest(..)
  ) where

import Data.Aeson ((.:))
import qualified Data.Aeson as A
import qualified Data.Text as T

data Wycheproof = Wycheproof {
    wp_numberOfTests :: !Int
  , wp_testGroups :: ![MacTestGroup]
  } deriving Show

instance A.FromJSON Wycheproof where
  parseJSON = A.withObject "Wycheproof" $ \m -> Wycheproof
    <$> m .: "numberOfTests"
    <*> m .: "testGroups"

data MacTestGroup = MacTestGroup {
    mtg_keySize :: !Int
  , mtg_tagSize :: !Int
  , mtg_type    :: !T.Text
  , mtg_tests   :: ![MacTest]
  } deriving Show

instance A.FromJSON MacTestGroup where
  parseJSON = A.withObject "MacTestGroup" $ \m -> MacTestGroup
    <$> m .: "keySize"
    <*> m .: "tagSize"
    <*> m .: "type"
    <*> m .: "tests"

data MacTest = MacTest {
    mt_tcId    :: !Int
  , mt_comment :: !T.Text
  , mt_key     :: !T.Text
  , mt_msg     :: !T.Text
  , mt_tag     :: !T.Text
  , mt_result  :: !T.Text
  , mt_flags   :: ![T.Text]
  } deriving Show

instance A.FromJSON MacTest where
  parseJSON = A.withObject "MacTest" $ \m -> MacTest
    <$> m .: "tcId"
    <*> m .: "comment"
    <*> m .: "key"
    <*> m .: "msg"
    <*> m .: "tag"
    <*> m .: "result"
    <*> m .: "flags"

