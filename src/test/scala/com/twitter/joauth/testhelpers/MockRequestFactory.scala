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

package com.twitter.joauth.testhelpers

import com.twitter.joauth.UrlEncoder
import scala.util.Random

object MockRequestFactory {
  val random = new Random()

  def oAuth1Header(token: String, clientKey: String, signature: String, nonce: String, timestamp: String, urlEncodeSig: Boolean): String = {
    val encodedSignature = if (signature == null || !urlEncodeSig) signature else UrlEncoder(signature)
    "OAuth " + (oAuth1ParameterMap(token, clientKey, encodedSignature, nonce, timestamp).flatMap { (e) =>
      if (e._2 == null) None
      else Some(getRandomWhitespace + e._1 + getRandomWhitespace + "=" + getRandomWhitespace + quote(e._2) + getRandomWhitespace)
    }).mkString(",")
  }

  def oAuth2Header(token: String) = "OAuth2 %s".format(token)
  def oAuth2HeaderWithKey(token: String) = "OAuth2 access_token=\"%s\"".format(token)

  def quote(str: String) ="\"%s\"".format(str)

  def oAuth1QueryString(token: String, clientKey: String, signature: String, nonce: String, timestamp: String, urlEncode: Boolean) =
    ParamHelper.toQueryString(oAuth1ParameterMap(token, clientKey, signature, nonce, timestamp), urlEncode)

  def oAuth1ParameterMap(
    token: String,
    clientKey: String,
    signature: String,
    nonce: String,
    timestamp: String): Map[String, String] = {
    Map(
      "oauth_token" -> token,
      "oauth_consumer_key" -> clientKey,
      "oauth_signature" -> signature,
      "oauth_nonce" -> nonce,
      "oauth_timestamp" -> timestamp,
      "oauth_version" -> "1.0",
      "oauth_signature_method" -> "HMAC-SHA1"
      )
  }

  def getRandomWhitespace() =  " " * random.nextInt(2)

  def requestWithAuthHeader(header: String): MockRequest = {
    val request = new MockRequest()
    request.authHeader = Some(header)
    request
  }

  def oAuth1RequestInHeader(token: String, clientKey: String, signature: String, nonce: String, timestamp: String) =
    requestWithAuthHeader(oAuth1Header(token, clientKey, signature, nonce, timestamp, true))

  def oAuth1RequestInParams(token: String, clientKey: String, signature: String, nonce: String, timestamp: String) = {
    val request = new MockRequest()
    request.queryString = oAuth1QueryString(token, clientKey, signature, nonce, timestamp, true)
    request
  }

  def oAuth2RequestInParams(token: String)  : MockRequest = {
    val request = new MockRequest()
    request.queryString = "access_token=%s".format(token)
    request
  }

  def postRequest(request: MockRequest) = {
    if (request.queryString ne null) {
      request.body = request.queryString
      request.queryString = null
    }
    request.contentType = Some("application/x-www-form-urlencoded")
    request.method = "POST"
    request
  }
}
