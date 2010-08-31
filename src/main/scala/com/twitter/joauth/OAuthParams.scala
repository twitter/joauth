package com.twitter.joauth

import java.net.URLDecoder

class OAuthParams extends KeyValueHandler {
  var token: String = null
  var consumerKey: String = null
  var nonce: String = null
  var timestamp: Int = -1
  var signature: String = null
  var signatureMethod: String = null
  var version: String = null

  def apply(k: String, v: String): Unit = {
    k match {
      case OAuthUtils.OAUTH_TOKEN => token = v
      case OAuthUtils.OAUTH_CONSUMER_KEY => consumerKey = v
      case OAuthUtils.OAUTH_NONCE => nonce = v
      case OAuthUtils.OAUTH_TIMESTAMP => try {
        timestamp = v.toInt
      } catch {
        case _ =>
      }
      case OAuthUtils.OAUTH_SIGNATURE => signature = URLDecoder.decode(v)
      case OAuthUtils.OAUTH_SIGNATURE_METHOD => signatureMethod = v
      case OAuthUtils.OAUTH_VERSION => version = v
      case _ => // ignore
    }
  }

  override def toString(): String =
    "%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s".format(
    OAuthUtils.OAUTH_TOKEN, token,
    OAuthUtils.OAUTH_CONSUMER_KEY, consumerKey,
    OAuthUtils.OAUTH_NONCE, nonce,
    OAuthUtils.OAUTH_TIMESTAMP, timestamp,
    OAuthUtils.OAUTH_SIGNATURE, signature,
    OAuthUtils.OAUTH_SIGNATURE_METHOD, signatureMethod,
    OAuthUtils.OAUTH_VERSION, version)

  def toListNoSignature(): List[(String, String)] =  
    List(
      (OAuthUtils.OAUTH_TOKEN, token),
      (OAuthUtils.OAUTH_CONSUMER_KEY, consumerKey),
      (OAuthUtils.OAUTH_NONCE, nonce),
      (OAuthUtils.OAUTH_TIMESTAMP, timestamp.toString),
      (OAuthUtils.OAUTH_SIGNATURE_METHOD, signatureMethod),
      (OAuthUtils.OAUTH_VERSION, version))
      
  def isOnlyOAuthTokenSet(): Boolean =
    token != null &&
        consumerKey == null &&
        nonce == null &&
        timestamp < 0 &&
        signature == null &&
        signatureMethod == null &&
        version == null

  def areAllOAuth1FieldsSet(): Boolean =
    token != null &&
        consumerKey != null &&
        nonce != null &&
        timestamp >= 0 &&
        signature != null &&
        signatureMethod != null &&
        version != null
}