package com.twitter.joauth.keyvalue

class NotOAuthKeyValueHandler(underlying: KeyValueHandler)
  extends FilteredKeyValueHandler(
    new UrlEncodingNormalizingKeyValueHandler(underlying), NotOAuthFieldFilter)

class OAuthKeyValueHandler(underlying: KeyValueHandler)
  extends TrimmingKeyValueHandler(
    new FilteredKeyValueHandler(
      new UrlEncodingNormalizingKeyValueHandler(underlying),
      OAuthFieldFilter))

class OAuth2HeaderKeyValueHandler(underlying: KeyValueHandler)
  extends TrimmingKeyValueHandler(
    new FilteredKeyValueHandler(
      new KeyTransformingKeyValueHandler(underlying, OAuth2KeyTransformer),
      OAuth2FieldFilter))