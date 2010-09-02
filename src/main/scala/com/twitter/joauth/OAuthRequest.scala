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

trait OAuthRequest {
  def token: String
}

case class OAuth1Request(
  token: String,
  consumerKey: String,
  nonce: String,
  timestamp: Long,
  signature: String,
  signatureMethod: String,
  version: String,
  normalizedRequest: String) extends OAuthRequest

case class OAuth2Request(token: String) extends OAuthRequest

object OAuth1Request {
  def nullException(name: String) = new MalformedRequest("no value for %s".format(name))

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
    if (scheme == null) throw nullException("scheme")
    else if (host == null) throw nullException("host")
    else if (port < 0) throw nullException("port")
    else if (verb == null) throw nullException("verb")
    else if (path == null) throw nullException("path")
    else if (oAuthParams.signatureMethod != OAuthParams.HMAC_SHA1)
    throw new MalformedRequest(
      "unsupported signature method: %s".format(oAuthParams.signatureMethod))
    else if (oAuthParams.version != OAuthParams.ONE_DOT_OH)
    throw new MalformedRequest(
      "unsupported oauth version: %s".format(oAuthParams.version))
    else new OAuth1Request(
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