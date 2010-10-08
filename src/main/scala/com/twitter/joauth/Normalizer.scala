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

import java.net.URLEncoder
import java.util.Date

/**
 * a Normalizer takes the fields that describe an OAuth 1.0a request, and produces
 * the normalized string that is used for the signature.
 */
trait Normalizer {
  def apply(
    scheme: String, 
    host: String, 
    port: Int, 
    verb: String,
    path: String, 
    params: List[(String, String)], 
    oAuthParams: OAuthParams): String
}

/**
 * ConstNormalizer can be used for testing. It will always return the same String.
 */
class ConstNormalizer(const: String) extends Normalizer {
  def apply(
    scheme: String, 
    host: String, 
    port: Int,
    verb: String,
    path: String, 
    params: List[(String, String)], 
    oAuthParams: OAuthParams): String = const
}

/**
 * A convenience factory for a StandardNormalizer
 */
object Normalizer {
  def apply(): Normalizer = StandardNormalizer
}

/**
 * a singleton of the StandardNormalizer class
 */
object StandardNormalizer extends StandardNormalizer

/**
 * the standard implmenentation of the Normalizer trait. Though stateless and threadsafe,
 * this is a class rather than an object to allow easy access from Java. Scala codebases
 * should use the corresponding StandardNormalizer object instead.
 */
class StandardNormalizer extends Normalizer {
  val HTTP = "HTTP"
  val HTTPS = "HTTPS"
  val AND = "&"
  val COLON = ":"
  val EQ = "="
  val COLON_SLASH_SLASH = "://"

  def apply(
    scheme: String, 
    host: String, 
    port: Int,
    verb: String,
    path: String,
    params: List[(String, String)], 
    oAuthParams: OAuthParams): String = {

    // first, concatenate the params and the oAuthParams together.
    // the parameters are already URLEncoded, so we leave them alone
    val sigParams = params ::: oAuthParams.toListNoSignature

    // now turn these back into a standard query string, with keys delimited
    // from values with "=" and pairs delimited from one another by "&"
    val normalizedParams = sigParams.map(p => p._1+EQ+p._2).sort(_ < _).mkString(AND)

    // the normalized URL is scheme://host[:port]/path, lowercased
    val requestUrl = (scheme+COLON_SLASH_SLASH+host).toLowerCase+getPortString(port,scheme)+path

    // the normalized string is VERB&normalizedParams&requestUrl,
    // where URL and PARAMS are UrlEncoded
    verb.toUpperCase+AND+URLEncoder.encode(requestUrl)+AND+URLEncoder.encode(normalizedParams)
  }

  /**
   * The OAuth 1.0a spec says that the port should not be included in the normalized string
   * when (1) it is port 80 and the scheme is HTTP or (2) it is port 443 and the scheme is HTTPS
   */
  def getPortString(port: Int, scheme: String): String = {
    (port, scheme.toUpperCase) match {
      case (80, HTTP) => ""
      case (443, HTTPS) => ""
      case _ => COLON + port
    }
  }
}