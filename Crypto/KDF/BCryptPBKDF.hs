module Crypto.KDF.BCryptPBKDF
    ( bcryptHash
    , bcryptPBKDF
    )
where

import qualified Crypto.Cipher.Blowfish.Primitive as Blowfish
import qualified Crypto.Hash                      as Hash
import qualified Crypto.Hash.Algorithms           as Hash
import           Data.Bits
import qualified Data.ByteArray                   as B
import           Data.Foldable
import           Data.Word
import           Foreign.Ptr                      (Ptr)
import           Foreign.Storable

-- | Create a bcrypt_pbkdf hash for a password with a provided cost value and salt.
bcryptPBKDF :: (B.ByteArray salt, B.ByteArray pass, B.ByteArray key)
       => Int
       -> salt
       -> pass
       -> Int
       -> key
bcryptPBKDF rounds salt pass keylen =
  B.allocAndFreeze keylen $ outerLoop 1 amt0 keylen
  where
    sha2pass :: Hash.Digest Hash.SHA512
    sha2pass  = Hash.hash pass

    stride :: Int
    stride  = (keylen + 32 - 1) `div` 32 -- the magic string is 32 bytes long

    amt0   :: Int
    amt0    = (keylen + stride - 1) `div` stride

    outerLoop :: Int -> Int -> Int -> Ptr Word8 -> IO ()
    outerLoop count amt kl keyPtr
      | kl > 0    = innerLoop 0 -- tail recursion
      | otherwise = pure ()
      where
        countsalt = salt `mappend` B.pack
          [ fromIntegral $ (count `unsafeShiftR` 24) .&. 0xff
          , fromIntegral $ (count `unsafeShiftR` 24) .&. 0xff
          , fromIntegral $ (count `unsafeShiftR` 24) .&. 0xff
          , fromIntegral $  count                    .&. 0xff
          ]
        sha2salt   :: Hash.Digest Hash.SHA512
        sha2salt    = Hash.hash countsalt
        r0          = bcryptHash sha2salt sha2pass `asTypeOf` pass
        f r         = let r' = bcryptHash (Hash.hash r) sha2pass in r' : f r'
        out         = foldl' B.xor r0 $ take (rounds - 1) (f r0)
        amt'        = min amt kl
        innerLoop i = x
          where
            dest = i * stride + (count - 1)
            x | i < amt' && dest < keylen = do
                  pokeElemOff keyPtr dest (B.index out i)
                  innerLoop (i + 1) -- tail recursion
              | otherwise =
                  outerLoop (count + 1) amt' (kl - i) keyPtr -- tail recursion

-- The output of this function is always 256 bits.
bcryptHash :: (B.ByteArray output) => Hash.Digest Hash.SHA512 -> Hash.Digest Hash.SHA512 -> output
bcryptHash salt password = loop (0 :: Int) magic
  where
    ctx :: Blowfish.Context
    ctx  = Blowfish.eksBlowfish 6 salt password -- 2^6 is 64 (see `makeKeySchedule`)

    loop i input
      | i < 64    = loop (i + 1) (Blowfish.encrypt ctx input)
      | otherwise = input

    magic = B.pack -- "OxychromaticBlowfishSwatDynamite"
      [ 0x4f, 0x78, 0x79, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x61, 0x74, 0x69, 0x63, 0x42, 0x6c, 0x6f, 0x77
      , 0x66, 0x69, 0x73, 0x68, 0x53, 0x77, 0x61, 0x74, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x74, 0x65 ]


