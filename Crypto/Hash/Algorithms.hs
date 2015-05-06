-- |
-- Module      : Crypto.Hash.Algorithms
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Definitions of known hash algorithms
--
module Crypto.Hash.Algorithms
    ( HashAlgorithm
    -- * hash algorithms
    , MD2(..)
    , MD4(..)
    , MD5(..)
    , SHA1(..)
    , SHA224(..)
    , SHA256(..)
    , SHA384(..)
    , SHA512(..)
    , SHA512t_224(..)
    , SHA512t_256(..)
    , RIPEMD160(..)
    , Tiger(..)
    , Kekkak_224(..)
    , Kekkak_256(..)
    , Kekkak_384(..)
    , Kekkak_512(..)
    , SHA3_224(..)
    , SHA3_256(..)
    , SHA3_384(..)
    , SHA3_512(..)
    , Skein256_224(..)
    , Skein256_256(..)
    , Skein512_224(..)
    , Skein512_256(..)
    , Skein512_384(..)
    , Skein512_512(..)
    , Whirlpool(..)
    ) where

import           Crypto.Hash.Types (HashAlgorithm)
import           Crypto.Hash.MD2
import           Crypto.Hash.MD4
import           Crypto.Hash.MD5
import           Crypto.Hash.SHA1
import           Crypto.Hash.SHA224
import           Crypto.Hash.SHA256
import           Crypto.Hash.SHA384
import           Crypto.Hash.SHA512
import           Crypto.Hash.SHA512t
import           Crypto.Hash.SHA3
import           Crypto.Hash.Kekkak
import           Crypto.Hash.RIPEMD160
import           Crypto.Hash.Tiger
import           Crypto.Hash.Skein256
import           Crypto.Hash.Skein512
import           Crypto.Hash.Whirlpool
