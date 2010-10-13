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

package com.twitter.joauth.keyvalue

import com.twitter.joauth.OAuthParams

/**
 * The Transformer trait describes the transformation function
 * from a string to a derived string
 */
trait Transformer extends ((String) => String)

/**
 * The TrimTransformer trims the string
 */
object TrimTransformer extends Transformer {
  def apply(str: String) = str.trim
}

/**
 * The OAuth2KeyTransformer trims the "token" to "oauth_token",
 * which is handy when passing an OAuth2 Authorization header
 * into the same KeyValueHandler into which you're parsing the
 * query string
 */
object OAuth2KeyTransformer extends Transformer {
  def apply(str: String): String = 
    if (str == OAuthParams.OAUTH2_HEADER_TOKEN) OAuthParams.OAUTH_TOKEN 
    else str
}

/**
 * The UrlEncodingNormalizingTransformer capitializes all of the
 * URLEncoded entities in a string. It will do strange things to
 * a string that is not actually URLEncoded.
 */
object UrlEncodingNormalizingTransformer extends Transformer {
  def apply(s: String) = {
    val normalized = new StringBuilder()
    var percented = 0
    s.foreach {char =>
      if (percented > 0) {
        normalized.append(Character.toUpperCase(char))
        percented -= 1
      } else if (char == '%') {
        percented = 2
        normalized.append(char)
      } else {
        normalized.append(char)
      }
    }
    normalized.toString
  }
}