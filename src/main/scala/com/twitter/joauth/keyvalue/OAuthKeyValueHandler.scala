package com.twitter.joauth.keyvalue

/**
 * A collection of KeyValueHandlers useful for OAuth parameter parsing
 */


/**
 * NotOAuthKeyValueHandler only calls the underlying KeyValueHandler 
 * if the field is a non-OAuth field
 */
class NotOAuthKeyValueHandler(underlying: KeyValueHandler) 
  extends FilteredKeyValueHandler(
    new UrlEncodingNormalizingKeyValueHandler(underlying), NotOAuthFieldFilter)

/**
 * OAuthKeyValueHandler only calls the underlying KeyValueHandler 
 * if the key is an OAuth 1.0a field and the value is non-empty
 */
class OAuthKeyValueHandler(underlying: KeyValueHandler)
  extends TrimmingKeyValueHandler(
    new FilteredKeyValueHandler(
      new UrlEncodingNormalizingKeyValueHandler(underlying),
      OAuthFieldFilter))

/**
  * OAuth2HeaderKeyValueHandler only calls the underlying KeyValueHandler 
  * if the key is "token", transforming the key to "oauth_token" in the process.
  * This servers as an adaptor from the OAuth2 Authorization header to the
  * standard OAuth token field name. Wrapping this around the OAuthKeyValueHandler 
  * used to parse the query string and you can parse the OAuth2 header into the 
  * same underlying KeyValueHandler. 
  */
class OAuth2HeaderKeyValueHandler(underlying: KeyValueHandler)
  extends TrimmingKeyValueHandler(
    new FilteredKeyValueHandler(
      new KeyTransformingKeyValueHandler(underlying, OAuth2KeyTransformer),
      OAuth2FieldFilter))