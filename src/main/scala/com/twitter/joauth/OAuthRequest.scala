package com.twitter.joauth

trait OAuthRequest {
  def token: String
}

case class OAuth1Request(
  override val token: String,
  consumerKey: String,
  nonce: String,
  timestamp: Long,
  signature: String,
  signatureMethod: String,
  version: String,
  normalizedRequest: String) extends OAuthRequest

case class OAuth2Request(override val token: String) extends OAuthRequest