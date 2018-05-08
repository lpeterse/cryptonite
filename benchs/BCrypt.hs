{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Crypto.KDF.BCrypt as BCrypt
import           Data.ByteString   as B
import           Gauge.Main

salt :: ByteString
salt = "saltsaltsaltsalt"

password :: ByteString
password = "password"

main :: IO ()
main = defaultMain
    [ bgroup "KDF.BCrypt"
        [ bench "bcrypt" $ whnf (\x-> BCrypt.bcrypt 10 salt x :: ByteString) password
        ]
    ]
