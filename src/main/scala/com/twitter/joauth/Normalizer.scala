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

object Normalizer {
  def apply(): Normalizer = StandardNormalizer
}

object StandardNormalizer extends StandardNormalizer

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
    // parameters are already URLEncoded, so we leave them alone
    val sigParams = params ::: oAuthParams.toListNoSignature
    val normalizedParams =
      sigParams.map(p => p._1+EQ+p._2).sort(_ < _).mkString(AND)
    val requestUrl = (scheme+COLON_SLASH_SLASH+host+getPortString(port,scheme)+path).toLowerCase
    verb.toUpperCase+AND+URLEncoder.encode(requestUrl)+AND+URLEncoder.encode(normalizedParams)
  }

  def getPortString(port: Int, scheme: String): String = {
    (port, scheme.toUpperCase) match {
      case (80, HTTP) => ""
      case (443, HTTPS) => ""
      case _ => COLON + port
    }
  }
}