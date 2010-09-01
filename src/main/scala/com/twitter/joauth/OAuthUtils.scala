package com.twitter.joauth

object OAuthUtils {
  val OAUTH_TOKEN = "oauth_token"
  val OAUTH_CONSUMER_KEY = "oauth_consumer_key"
  val OAUTH_SIGNATURE = "oauth_signature"
  val OAUTH_NONCE = "oauth_nonce"
  val OAUTH_TIMESTAMP = "oauth_timestamp"
  val OAUTH_SIGNATURE_METHOD = "oauth_signature_method"
  val OAUTH_VERSION = "oauth_version"

  val HMAC_SHA1 = "HMAC-SHA1"
  val ONE_DOT_OH = "1.0"

  val OAUTH2_HEADER_TOKEN = "token"

  val OAUTH1_HEADER_AUTHTYPE = "oauth"
  val OAUTH2_HEADER_AUTHTYPE = OAUTH2_HEADER_TOKEN
  
  def isOAuthField(field: String): Boolean = {
    field == OAUTH_TOKEN ||
        field == OAUTH_CONSUMER_KEY ||
        field == OAUTH_SIGNATURE ||
        field == OAUTH_NONCE ||
        field == OAUTH_TIMESTAMP ||
        field == OAUTH_SIGNATURE_METHOD ||
        field == OAUTH_VERSION
  }
}