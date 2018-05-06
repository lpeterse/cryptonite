{-# LANGUAGE OverloadedStrings #-}
module BCryptPBKDF (tests) where

import qualified Data.ByteArray         as B
import           Data.ByteString        (ByteString)
import           Data.ByteString.Char8  ()

import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit

import qualified Crypto.Hash            as Hash
import qualified Crypto.Hash.Algorithms as Hash
import           Crypto.KDF.BCryptPBKDF (Parameters (..), bcryptHash, generate)

vectors :: [ ((Parameters, ByteString, ByteString), ByteString) ]
vectors =
    [
        ( (Parameters 32 32, "", "")
        , "\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97\xf1\x6b\x48\x44\xe3\x07\x4a\xe8\xdf\xdf\xfa\x3f\xed\xe2\x14\x42\xfc\xd0\x06\x9d\xed\x09\x48\xf8\x32\x6a\x75\x3a\x0f\xc8\x1f\x17\xe8\xd3\xe0\xfb\x2e\x0d\x36\x28\xcf\x35\xe2\x0c\x38\xd1\x89\x06"
        )
    ,   ( (Parameters 32 32, "password", "NaCl")
        , "\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7\x19\x0d\x01\xe9\xfe\x7c\x6a\xd7\xcb\xc8\x23\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62\x2e\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27\x9d\x98\x30\xda\xc7\x27\xaf\xb9\x4a\x83\xee\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40"
        )
    ,   ( (Parameters 32 32, "pleaseletmein", "SodiumChloride")
        , "\x70\x23\xbd\xcb\x3a\xfd\x73\x48\x46\x1c\x06\xcd\x81\xfd\x38\xeb\xfd\xa8\xfb\xba\x90\x4f\x8e\x3e\xa9\xb5\x43\xf6\x54\x5d\xa1\xf2\xd5\x43\x29\x55\x61\x3f\x0f\xcf\x62\xd4\x97\x05\x24\x2a\x9a\xf9\xe6\x1e\x85\xdc\x0d\x65\x1e\x40\xdf\xcf\x01\x7b\x45\x57\x58\x87"
        )
    ,   ( (Parameters 32 32, "pleaseletmein", "SodiumChloride")
        , "\x21\x01\xcb\x9b\x6a\x51\x1a\xae\xad\xdb\xbe\x09\xcf\x70\xf8\x81\xec\x56\x8d\x57\x4a\x2f\xfd\x4d\xab\xe5\xee\x98\x20\xad\xaa\x47\x8e\x56\xfd\x8f\x4b\xa5\xd0\x9f\xfa\x1c\x6d\x92\x7c\x40\xf4\xc3\x37\x30\x40\x49\xe8\xa9\x52\xfb\xcb\xf4\x5c\x6f\xa7\x7a\x41\xa4"
        )
    ]

tests = testGroup "BCryptPBKDF"
    $ zipWith (curry toCase) [(1 :: Int) ..] vectors
    where toCase (i, ((params, pass, salt), output)) =
              testCase (show i) ("" @=?  show (B.unpack (bcryptHash (Hash.hash salt) (Hash.hash pass) :: ByteString)))-- generate params pass salt)
