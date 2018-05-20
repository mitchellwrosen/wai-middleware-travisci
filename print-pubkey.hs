#!/usr/bin/env stack
-- stack script --resolver lts-11.9 --ghc-options=-Wall

{-# language OverloadedStrings #-}
{-# options_ghc -fno-warn-incomplete-patterns #-}

import Control.Lens
import Data.Aeson.Lens
import Data.ASN1.BinaryEncoding (DER(DER))
import Data.ASN1.Encoding (decodeASN1)
import Data.ASN1.Types (fromASN1)
import Data.PEM (pemContent, pemParseBS)
import Data.X509 (PubKey(PubKeyRSA))
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Network.HTTP.Client
import Network.HTTP.Client.TLS

import qualified Data.ByteString.Lazy as LazyByteString

main :: IO ()
main = do
  manager <- newTlsManager
  request <- parseRequest "https://api.travis-ci.com/config"
  response <- httpLbs request manager

  let rawPem :: Text
      rawPem =
        response
          ^?! to responseBody
            . key "config"
            . key "notifications"
            . key "webhook"
            . key "public_key"
            . _String

  -- * Parse the stringy PEM fetched from https://api.travis-ci-com/config
  -- * Decode the PEM as an ASN.1 stream
  -- * Decode the ASN.1 stream as a public RSA key

  case pemParseBS (encodeUtf8 rawPem) of
    Right [pem] ->
      case decodeASN1 DER (LazyByteString.fromStrict (pemContent pem)) of
        Right asn1 ->
          case fromASN1 asn1 of
            Right (PubKeyRSA rsa, []) ->
              print rsa
