// Copyright 2011 Twitter, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package com.twitter.joauth

import com.twitter.joauth.keyvalue.{KeyValueHandler, DuplicateKeyValueHandler, SingleKeyValueHandler}
import scala.collection.mutable.ListBuffer

trait OAuthParamsHelper {
  /**
   * allows one to override the default behavior when parsing timestamps,
   * which is to parse them as integers, and ignore timestamps that are
   * malformed
   */
  def parseTimestamp(str: String): Option[Long]

  /**
   * allows custom processing of the OAuth 1.0 signature obtained from the request.
   */
  def processSignature(str: String): String

  /**
   * allows custom processing of keys obtained from the request
   */
  def processKey(str: String): String
}

/**
 * Provides the default implementation of the OAuthParamsHelper trait
 * Though stateless and threadsafe, this is a class rather than an object to allow easy
 * access from Java. Scala codebases should use the corresponding StandardOAuthParamsHelper
 * object instead.
 */
class StandardOAuthParamsHelper extends OAuthParamsHelper {
  override def parseTimestamp(str: String): Option[Long] = try {
    Some(str.toLong)
  } catch {
    case _ => None
  }
  override def processKey(str: String) = str
  override def processSignature(str: String): String = str
}

/**
 * the singleton object of StandardOAuthParamsHelper
 */
object StandardOAuthParamsHelper extends StandardOAuthParamsHelper

/**
 * pull all the OAuth parameter string constants into one place,
 * add a convenience method for determining if a string is an
 * OAuth 1.0 fieldname.
 */
object OAuthParams {
  val ACCESS_TOKEN = "access_token"
  val BEARER_TOKEN = "Bearer"
  val CLIENT_ID = "client_id"
  val OAUTH_TOKEN = "oauth_token"
  val OAUTH_CONSUMER_KEY = "oauth_consumer_key"
  val OAUTH_SIGNATURE = "oauth_signature"
  val OAUTH_NONCE = "oauth_nonce"
  val OAUTH_TIMESTAMP = "oauth_timestamp"
  val OAUTH_SIGNATURE_METHOD = "oauth_signature_method"
  val OAUTH_VERSION = "oauth_version"
  val NORMALIZED_REQUEST = "normalized_request"
  val UNSET = "(unset)"
  val OAUTH_2D11 = "oauth2d11"

  val OAUTH_PREFIX_REGEX = "^oauth_[a-z_]+$".r

  val HMAC_SHA1 = "HMAC-SHA1"
  val ONE_DOT_OH = "1.0"
  val ONE_DOT_OH_A = "1.0a"

  val OAUTH1_HEADER_AUTHTYPE = "oauth"
  val OAUTH2D11_HEADER_AUTHTYPE = "oauth2"
  val OAUTH2_HEADER_AUTHTYPE = "bearer"

  def isOAuthParam(field: String): Boolean = {
    field == ACCESS_TOKEN ||
      field == OAUTH_TOKEN ||
      field == OAUTH_CONSUMER_KEY ||
      field == OAUTH_SIGNATURE ||
      field == OAUTH_NONCE ||
      field == OAUTH_TIMESTAMP ||
      field == OAUTH_SIGNATURE_METHOD ||
      field == OAUTH_VERSION
  }

  def valueOrUnset(value: String) = if (value == null) UNSET else value
}

/**
 * OAuth1Params is mostly just a container for OAuth 1.0a parameters.
 */
case class OAuth1Params(
  token: String,
  consumerKey: String,
  nonce: String,
  timestampSecs: Long,
  timestampStr: String,
  signature: String,
  signatureMethod: String,
  version: String) {

  import OAuthParams._

  def toList(includeSig: Boolean): List[(String, String)] = {
    val buf = new ListBuffer[(String, String)]
    buf += OAUTH_CONSUMER_KEY -> consumerKey
    buf += OAUTH_NONCE -> nonce
    buf += OAUTH_TOKEN -> token
    if (includeSig) buf += OAUTH_SIGNATURE -> signature
    buf += OAUTH_SIGNATURE_METHOD -> signatureMethod
    buf += OAUTH_TIMESTAMP -> timestampStr
    if (version != null) buf += OAUTH_VERSION -> version
    buf.toList
  }

  // we use String.format here, because we're probably not that worried about
  // effeciency when printing the class for debugging
  override def toString: String =
    "%s=%s,%s=%s,%s=%s,%s=%s(->%s),%s=%s,%s=%s,%s=%s".format(
    OAUTH_TOKEN, valueOrUnset(token),
    OAUTH_CONSUMER_KEY, valueOrUnset(consumerKey),
    OAUTH_NONCE, valueOrUnset(nonce),
    OAUTH_TIMESTAMP, timestampStr, timestampSecs,
    OAUTH_SIGNATURE, valueOrUnset(signature),
    OAUTH_SIGNATURE_METHOD, valueOrUnset(signatureMethod),
    OAUTH_VERSION, valueOrUnset(version))
}

/**
 * A collector for OAuth and other params. There are convenience methods for determining
 * if it has all OAuth parameters set, just the token set, and for obtaining
 * a list of all params for use in producing the normalized request.
 */

class OAuthParamsBuilder(helper: OAuthParamsHelper) {
  import OAuthParams._

  private[joauth] var v2Token: String = null
  private[joauth] var oauth2d11: Boolean = true
  private[joauth] var token: String = null
  private[joauth] var consumerKey: String = null
  private[joauth] var nonce: String = null
  private[joauth] var timestampSecs: Long = -1
  private[joauth] var timestampStr: String = null
  private[joauth] var signature: String = null
  private[joauth] var signatureMethod: String = null
  private[joauth] var version: String = null

  private[joauth] var paramsHandler = new DuplicateKeyValueHandler
  private[joauth] var otherOAuthParamsHandler = new SingleKeyValueHandler

  val headerHandler: KeyValueHandler = new KeyValueHandler {
    override def apply(k: String, v: String) = handleKeyValue(k, v, true)
  }

  val queryHandler: KeyValueHandler = new KeyValueHandler {
    override def apply(k: String, v: String) = handleKeyValue(k, v, false)
  }

  private[this] def handleKeyValue(k: String, v: String, fromHeader: Boolean): Unit = {
    def ifNonEmpty(value: String)(f: => Unit) {
      if (value != null && value != "") {
        f
      }
    }

    k match {
      // empty values for these keys are swallowed
      case ACCESS_TOKEN => ifNonEmpty(v) { v2Token = v }
      case BEARER_TOKEN => ifNonEmpty(v) {
        if (fromHeader) {
          v2Token = v
          oauth2d11 = false
        }
      }
      case CLIENT_ID => ifNonEmpty(v) { if(fromHeader) consumerKey = v }
      case OAUTH_TOKEN => ifNonEmpty(v) { token = v.trim }
      case OAUTH_CONSUMER_KEY => ifNonEmpty(v) { consumerKey = v }
      case OAUTH_NONCE => ifNonEmpty(v) { nonce = v }
      case OAUTH_TIMESTAMP => ifNonEmpty(v) {
        helper.parseTimestamp(v) match {
          case Some(t: Long) => {
            timestampSecs = t
            timestampStr = v
          }
          case None => // ignore
        }
      }
      case OAUTH_SIGNATURE => ifNonEmpty(v) { signature = helper.processSignature(v) }
      case OAUTH_SIGNATURE_METHOD => ifNonEmpty(v) { signatureMethod = v }
      case OAUTH_VERSION => ifNonEmpty(v) { version = v }
      // send oauth_prefixed to a uniquekey handler
      case OAUTH_PREFIX_REGEX() => otherOAuthParamsHandler(k, v)
      // send other params to the handler, but only if they didn't come from the header
      case _ => if (!fromHeader) paramsHandler(k, v)
    }
  }

  // we use String.format here, because we're probably not that worried about
  // effeciency when printing the class for debugging
  override def toString: String =
    "%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s(->%s),%s=%s,%s=%s,%s=%s".format(
      OAUTH_2D11, oauth2d11,
      ACCESS_TOKEN, valueOrUnset(v2Token),
      OAUTH_TOKEN, valueOrUnset(token),
      OAUTH_CONSUMER_KEY, valueOrUnset(consumerKey),
      OAUTH_NONCE, valueOrUnset(nonce),
      OAUTH_TIMESTAMP, timestampStr, timestampSecs,
      OAUTH_SIGNATURE, valueOrUnset(signature),
      OAUTH_SIGNATURE_METHOD, valueOrUnset(signatureMethod),
      OAUTH_VERSION, valueOrUnset(version))

  def valueOrUnset(value: String) = if (value == null) UNSET else value

  def isOAuth2: Boolean = v2Token != null && !oauth2d11
  def isOAuth2d11: Boolean = v2Token != null && !isOAuth1 && oauth2d11

  def isOAuth1: Boolean =
    token != null &&
    consumerKey != null &&
    nonce != null &&
    timestampStr != null &&
    signature != null &&
    signatureMethod != null
    // version is optional, so not included here

  def oAuth2Token = v2Token

  def otherParams = paramsHandler.toList ++ otherOAuthParamsHandler.toList

  // make an immutable params instance
  def oAuth1Params = OAuth1Params(
    token,
    consumerKey,
    nonce,
    timestampSecs,
    timestampStr,
    signature,
    signatureMethod,
    version)
}