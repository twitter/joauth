package com.twitter.joauth

import com.twitter.joauth.keyvalue.KeyValueHandler
import java.net.URLDecoder

object OAuthParams {
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

  def isOAuthParam(field: String): Boolean = {
    field == OAUTH_TOKEN ||
        field == OAUTH_CONSUMER_KEY ||
        field == OAUTH_SIGNATURE ||
        field == OAUTH_NONCE ||
        field == OAUTH_TIMESTAMP ||
        field == OAUTH_SIGNATURE_METHOD ||
        field == OAUTH_VERSION
  }
}

class OAuthParams extends KeyValueHandler {
  import OAuthParams._

  var token: String = null
  var consumerKey: String = null
  var nonce: String = null
  var timestamp: Int = -1
  var signature: String = null
  var signatureMethod: String = null
  var version: String = null

  def apply(k: String, v: String): Unit = {
    k match {
      case OAUTH_TOKEN => token = v
      case OAUTH_CONSUMER_KEY => consumerKey = v
      case OAUTH_NONCE => nonce = v
      case OAUTH_TIMESTAMP => try {
        timestamp = v.toInt
      } catch {
        case _ =>
      }
      case OAUTH_SIGNATURE => signature = URLDecoder.decode(v)
      case OAUTH_SIGNATURE_METHOD => signatureMethod = v
      case OAUTH_VERSION => version = v
      case _ => // ignore
    }
  }

  override def toString: String =
    "%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s".format(
    OAUTH_TOKEN, token,
    OAUTH_CONSUMER_KEY, consumerKey,
    OAUTH_NONCE, nonce,
    OAUTH_TIMESTAMP, timestamp,
    OAUTH_SIGNATURE, signature,
    OAUTH_SIGNATURE_METHOD, signatureMethod,
    OAUTH_VERSION, version)

  def toListNoSignature: List[(String, String)] =  
    List(
      (OAUTH_TOKEN, token),
      (OAUTH_CONSUMER_KEY, consumerKey),
      (OAUTH_NONCE, nonce),
      (OAUTH_TIMESTAMP, timestamp.toString),
      (OAUTH_SIGNATURE_METHOD, signatureMethod),
      (OAUTH_VERSION, version))
    
  def isOnlyOAuthTokenSet: Boolean =
    token != null &&
        consumerKey == null &&
        nonce == null &&
        timestamp < 0 &&
        signature == null &&
        signatureMethod == null &&
        version == null

  def areAllOAuth1FieldsSet: Boolean =
    token != null &&
        consumerKey != null &&
        nonce != null &&
        timestamp >= 0 &&
        signature != null &&
        signatureMethod != null &&
        version != null
}