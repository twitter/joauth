// Copyright 2011 Twitter, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package com.twitter.joauth.testhelpers

import com.twitter.joauth.UrlCodec
import scala.util.Random

object MockRequestFactory {
  val random = new Random()

  def oAuth1Header(
    token: String,
    clientKey: String,
    signature: String,
    nonce: String,
    timestamp: String,
    urlEncodeSig: Boolean,
    extraHeaderParams: Seq[(String, String)] = Nil,
    quotedHeaderValues: Boolean = true): String = {

    def maybeQuote(str: String) = if (quotedHeaderValues) "\"%s\"".format(str) else str

    val encodedSignature = if (signature == null || !urlEncodeSig) signature else UrlCodec.encode(signature)
    val params = oAuth1ParameterMap(token, clientKey, encodedSignature, nonce, timestamp) ++ extraHeaderParams
    val paramString = params.filter(_._2 != null).map { case (k, v) =>
      getRandomWhitespace + k + getRandomWhitespace + "=" + getRandomWhitespace + maybeQuote(v) + getRandomWhitespace
    }
    "OAuth " + paramString.mkString(",")
  }

  def oAuth2Header(token: String) = "Bearer %s".format(token)

  def oAuth1QueryString(token: String, clientKey: String, signature: String, nonce: String, timestamp: String, urlEncode: Boolean) =
    ParamHelper.toQueryString(oAuth1ParameterMap(token, clientKey, signature, nonce, timestamp), urlEncode)

  def oAuth1ParameterMap(
    token: String,
    clientKey: String,
    signature: String,
    nonce: String,
    timestamp: String): Seq[(String, String)] = {
    Seq(
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
    request.authHeader = header
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

  def addParamsToRequestBody(request: MockRequest) = {
    if (request.queryString ne null) {
      request.body = request.queryString
      request.queryString = null
    }
    request.contentType = "application/x-www-form-urlencoded"
    request
  }

  def postRequest(request: MockRequest) = {
    if (request.queryString ne null) {
      request.body = request.queryString
      request.queryString = null
    }
    request.contentType = "application/x-www-form-urlencoded"
    request.method = "POST"
    request
  }

  def putRequest(request: MockRequest) = {
    postRequest(request)
    request.method = "PUT"
    request
  }

  def oAuth2nRequestInHeader(token: String) = requestWithAuthHeader(oAuth2Header(token))
}
