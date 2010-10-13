// Copyright 2010 Twitter, Inc.
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

import com.twitter.joauth.keyvalue.KeyValueHandler

/**
 * pull all the OAuth parameter string constants into one place,
 * add a convenience method for determining if a string is an
 * OAuth 1.0 fieldname.
 */
object OAuthParams {
  val OAUTH_TOKEN = "oauth_token"
  val OAUTH_CONSUMER_KEY = "oauth_consumer_key"
  val OAUTH_SIGNATURE = "oauth_signature"
  val OAUTH_NONCE = "oauth_nonce"
  val OAUTH_TIMESTAMP = "oauth_timestamp"
  val OAUTH_SIGNATURE_METHOD = "oauth_signature_method"
  val OAUTH_VERSION = "oauth_version"
  val UNSET = "(unset)"

  val HMAC_SHA1 = "HMAC-SHA1"
  val ONE_DOT_OH = "1.0"
  val ONE_DOT_OH_A = "1.0a"

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

/**
 * OAuthParams is mostly just a container for OAuth 1.0a parameters.
 * It's a KeyValueHandler so that it can be easily populated by a
 * KeyValueParser. There are convenience methods for determining
 * if it has all parameters set, just the token set, and for obtaining
 * a list of the params for use in producing the normalized request.
 */
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
      case OAUTH_SIGNATURE => signature = UrlDecoder(v)
      case OAUTH_SIGNATURE_METHOD => signatureMethod = v
      case OAUTH_VERSION => version = v
      case _ => // ignore
    }
  }

  // we use String.format here, because we're probably not that worried about
  // effeciency when printing the class for debugging
  override def toString: String =
    "%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s".format(
    OAUTH_TOKEN, valueOrUnset(token),
    OAUTH_CONSUMER_KEY, valueOrUnset(consumerKey),
    OAUTH_NONCE, valueOrUnset(nonce),
    OAUTH_TIMESTAMP, timestamp,
    OAUTH_SIGNATURE, valueOrUnset(signature),
    OAUTH_SIGNATURE_METHOD, valueOrUnset(signatureMethod),
    OAUTH_VERSION, valueOrUnset(version))

  def valueOrUnset(value: String) = if (value == null) UNSET else value

  def toListNoSignature: List[(String, String)] =
    List(
      (OAUTH_TOKEN, token),
      (OAUTH_CONSUMER_KEY, consumerKey),
      (OAUTH_NONCE, nonce),
      (OAUTH_TIMESTAMP, timestamp.toString),
      (OAUTH_SIGNATURE_METHOD, signatureMethod)) ::: 
      (if (version == null) Nil else List((OAUTH_VERSION, version)))
    
  def isOnlyOAuthTokenSet: Boolean =
    token != null &&
        consumerKey == null &&
        nonce == null &&
        timestamp < 0 &&
        signature == null &&
        signatureMethod == null &&
        // version is optional, but its inclusion indicates an oAuth1 request
        version == null

  def areAllOAuth1FieldsSet: Boolean =
    token != null &&
        consumerKey != null &&
        nonce != null &&
        timestamp >= 0 &&
        signature != null &&
        signatureMethod != null
        // version is optional, so not included here
}