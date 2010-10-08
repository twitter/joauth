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

/**
 * Both OAuth 1.0a and 2.0 requests have access tokens,
 * so it's convenient to combine them into a single trait
 */
trait OAuthRequest {
  def token: String
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
  timestamp: Long,
  signature: String,
  signatureMethod: String,
  version: String,
  normalizedRequest: String) extends OAuthRequest

/**
 * models an OAuth 2.0 request. Just a wrapper for the token, really.
 */
case class OAuth2Request(token: String) extends OAuthRequest

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

  def nullException(name: String) = new MalformedRequest(NO_VALUE_FOR+name)

  @throws(classOf[MalformedRequest])
  def verify(
    scheme: String,
    host: String,
    port: Int,
    verb: String,
    path: String,
    oAuthParams: OAuthParams) {
      if (scheme == null) throw nullException(SCHEME)
      else if (host == null) throw nullException(HOST)
      else if (port < 0) throw nullException(PORT)
      else if (verb == null) throw nullException(VERB)
      else if (path == null) throw nullException(PATH)
      else if (oAuthParams.signatureMethod != OAuthParams.HMAC_SHA1) {
        throw new MalformedRequest(UNSUPPORTED_METHOD+oAuthParams.signatureMethod)
      }
      else if (oAuthParams.version != null &&
          oAuthParams.version != OAuthParams.ONE_DOT_OH &&
          oAuthParams.version != OAuthParams.ONE_DOT_OH_A) {
        throw new MalformedRequest(UNSUPPORTED_VERSION+oAuthParams.version)
      }
      // we don't check the validity of the OAuthParams object, because it must be
      // fully populated in order for the factory to even be called, and we'd like
      // to save the expense of iterating over all the fields again
    }

  @throws(classOf[MalformedRequest])
  def apply(
    scheme: String, 
    host: String, 
    port: Int,
    verb: String,
    path: String,
    params: List[(String, String)], 
    oAuthParams: OAuthParams,
    normalize: Normalizer): OAuth1Request = {

    verify(scheme, host, port, verb, path, oAuthParams)

    new OAuth1Request(
      oAuthParams.token,
      oAuthParams.consumerKey,
      oAuthParams.nonce,
      oAuthParams.timestamp.toInt,
      oAuthParams.signature,
      oAuthParams.signatureMethod,
      oAuthParams.version,
      normalize(scheme, host, port, verb, path, params, oAuthParams))
  }
}