package com.twitter.joauth.keyvalue

/**
 * The KeyValueFilter trait tests validity of a key/value pair
 */
trait KeyValueFilter extends ((String, String) => Boolean)

/**
 * OAuthFieldFilter returns true if the key is an OAuth 1.0a field, and the value is non-empty
 */
object OAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = OAuthParams.isOAuthParam(k) && v != ""
}

/**
 * OAuthFieldFilter returns true if the key is not an OAuth 1.0a or 2.0 field
 */
object NotOAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = !OAuthParams.isOAuthParam(k)
}

/**
 * OAuth2FieldFilter returns true if the key is not an OAuth 2.0 field, and the value is non-empty
 */
object OAuth2FieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = k == OAuthParams.OAUTH2_HEADER_TOKEN && v != ""
}