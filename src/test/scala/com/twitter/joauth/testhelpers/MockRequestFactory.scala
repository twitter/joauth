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

import java.io.StringBufferInputStream
import java.net.URLEncoder
import scala.util.Random

object MockRequestFactory {
  val random = new Random()
  
  def oAuth1Header(token: String, clientKey: String, signature: String, nonce: String, timestamp: String, urlEncodeSig: Boolean): String = {
    val encodedSignature = if (signature == null || !urlEncodeSig) signature else URLEncoder.encode(signature)
    "OAuth " + (oAuth1ParameterMap(token, clientKey, encodedSignature, nonce, timestamp).flatMap { (e) =>
      if (e._2 == null) None
      else Some(getRandomWhitespace + e._1 + getRandomWhitespace + "=" + getRandomWhitespace + quote(e._2) + getRandomWhitespace)
    }).mkString(",")
  }

  def oAuth2Header(token: String) = "Token token=\"%s\"".format(token)

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

  def request(method: String, protocol: String, ipaddr: String): MockServletRequest = {
    new MockServletRequest(method, protocol, ipaddr)
  }

  def request(): MockServletRequest = new MockServletRequest("GET", "http", "123.123.123.123")

  def requestWithAuthHeader(header: String): MockServletRequest = {
    val req = new MockServletRequest
    req.getHeaders.put("Authorization", header)
    req
  }

  def oAuth1RequestInHeader(token: String, clientKey: String, signature: String, nonce: String, timestamp: String) =
    requestWithAuthHeader(oAuth1Header(token, clientKey, signature, nonce, timestamp, true))

  def oAuth1RequestInParams(token: String, clientKey: String, signature: String, nonce: String, timestamp: String) = {
    val req = new MockServletRequest
    req.queryString = oAuth1QueryString(token, clientKey, signature, nonce, timestamp, true)
    req
  }

  def oAuth2RequestInHeader(token: String): MockServletRequest =
    requestWithAuthHeader(oAuth2Header(token))

  def oAuth2RequestInParams(token: String)  : MockServletRequest = {
    val req = new MockServletRequest
    req.queryString = "oauth_token=%s".format(token)
    req
  }
  
  def postRequest(request: MockServletRequest) = {
    val sbis = new StringBufferInputStream(request.queryString)
    request.inputStream = new MockServletInputStream(sbis)
    request.queryString = null
    request.contentType = "application/x-www-form-urlencoded";
    request.method = "POST"
    request
  }
}
