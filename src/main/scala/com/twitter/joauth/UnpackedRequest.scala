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

sealed trait UnpackedRequest {
  def parsedRequest: ParsedRequest
}

case class UnknownRequest(parsedRequest: ParsedRequest) extends UnpackedRequest

/**
 * Both OAuth 1.0a and 2.0 requests have access tokens,
 * so it's convenient to combine them into a single trait
 */
sealed trait OAuthRequest extends UnpackedRequest {
  def oAuthVersionString: String
  def token: String
  def oAuthParamMap: Map[String, String]
}

/**
 * models an OAuth 1.0a request. Rather than passing the
 * scheme, host, port, etc around, we pre-calculate the normalized request,
 * since that's all we need for signature validation anyway.
 */
case class OAuth1Request(
  token: String,
  consumerKey: String,
  nonce: String,
  timestampSecs: Long,
  signature: String,
  signatureMethod: String,
  version: String,
  parsedRequest: ParsedRequest,
  normalizedRequest: String) extends OAuthRequest {

  import OAuthParams._

  override val oAuthVersionString = "oauth1"

  override lazy val oAuthParamMap = Map(
    OAUTH_TOKEN -> token,
    OAUTH_CONSUMER_KEY -> consumerKey,
    OAUTH_NONCE -> nonce,
    OAUTH_TIMESTAMP -> timestampSecs.toString,
    OAUTH_SIGNATURE_METHOD -> signatureMethod,
    OAUTH_SIGNATURE -> signature,
    OAUTH_VERSION -> (if (version == null) ONE_DOT_OH else version),
    NORMALIZED_REQUEST -> normalizedRequest)
}

/**
 * models an OAuth 2.0 request. Just a wrapper for the token, really.
 */
@deprecated("Use OAuth2Request instead")
case class OAuth2d11Request(token: String, parsedRequest: ParsedRequest) extends OAuthRequest {
  override val oAuthVersionString = "oauth2d11"

  override lazy val oAuthParamMap = Map(OAuthParams.ACCESS_TOKEN -> token)
}

/**
 * models an OAuth 2.0 rev 25 request. Just a wrapper for the token, really.
 */
case class OAuth2Request(token: String, parsedRequest: ParsedRequest, clientId: String = "") extends OAuthRequest {
  override val oAuthVersionString = "oauth2"

  override lazy val oAuthParamMap = Map(OAuthParams.ACCESS_TOKEN -> token,
                                        OAuthParams.CLIENT_ID -> clientId)
}

/**
 * The companion object's apply method produces an OAuth1Request instance by
 * passing the request details into a Normalizer to produce the normalized
 * request. Will throw a MalformedRequest if any required parameter is unset.
 */
object OAuth1Request {
  val NO_VALUE_FOR = "no value for "
  val SCHEME = "scheme"
  val HOST = "host"
  val PORT = "port"
  val VERB = "verb"
  val PATH = "path"
  val UNSUPPORTED_METHOD = "unsupported signature method: "
  val UNSUPPORTED_VERSION = "unsupported oauth version: "
  val MALFORMED_TOKEN = "malformed oauth token: "
  val MaxTokenLength = 50   // This is limited by DB schema

  def nullException(name: String) = new MalformedRequest(NO_VALUE_FOR+name)

  @throws(classOf[MalformedRequest])
  def verify(
    parsedRequest: ParsedRequest,
    oAuth1Params: OAuth1Params) {
      if (parsedRequest.scheme == null) throw nullException(SCHEME)
      else if (parsedRequest.host == null) throw nullException(HOST)
      else if (parsedRequest.port < 0) throw nullException(PORT)
      else if (parsedRequest.verb == null) throw nullException(VERB)
      else if (parsedRequest.path == null) throw nullException(PATH)
      else if (oAuth1Params.signatureMethod != OAuthParams.HMAC_SHA1) {
        throw new MalformedRequest(UNSUPPORTED_METHOD+oAuth1Params.signatureMethod)
      }
      else if (oAuth1Params.version != null &&
          oAuth1Params.version != OAuthParams.ONE_DOT_OH &&
          oAuth1Params.version.toLowerCase != OAuthParams.ONE_DOT_OH_A) {
        throw new MalformedRequest(UNSUPPORTED_VERSION+oAuth1Params.version)
      }
      else if (oAuth1Params.token != null &&
          (oAuth1Params.token.indexOf(' ') > 0 || oAuth1Params.token.length > MaxTokenLength)) {
        throw new MalformedRequest(MALFORMED_TOKEN+oAuth1Params.token)
      }
      // we don't check the validity of the OAuthParams object, because it must be
      // fully populated in order for the factory to even be called, and we'd like
      // to save the expense of iterating over all the fields again
    }

  @throws(classOf[MalformedRequest])
  def apply(
    parsedRequest: ParsedRequest,
    oAuth1Params: OAuth1Params,
    normalize: Normalizer): OAuth1Request = {

    verify(parsedRequest, oAuth1Params)

    new OAuth1Request(
      UrlDecoder(oAuth1Params.token),
      UrlDecoder(oAuth1Params.consumerKey),
      UrlDecoder(oAuth1Params.nonce),
      oAuth1Params.timestampSecs,
      oAuth1Params.signature,
      oAuth1Params.signatureMethod,
      oAuth1Params.version,
      parsedRequest,
      normalize(parsedRequest, oAuth1Params))
  }
}
