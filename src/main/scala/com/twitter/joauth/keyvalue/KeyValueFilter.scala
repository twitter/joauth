package com.twitter.joauth.keyvalue

trait KeyValueFilter extends ((String, String) => Boolean)

object OAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = OAuthParams.isOAuthParam(k) && v != ""
}

object NotOAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = !OAuthParams.isOAuthParam(k)
}

object OAuth2FieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = k == OAuthParams.OAUTH2_HEADER_TOKEN && v != ""
}