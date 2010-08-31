package com.twitter.joauth.keyvalue

trait KeyValueFilter extends ((String, String) => Boolean)

object OAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = OAuthUtils.isOAuthField(k) && v != ""
}

object NotOAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = !OAuthUtils.isOAuthField(k)
}

object OAuth2FieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = k == OAuthUtils.OAUTH2_HEADER_TOKEN && v != ""
}