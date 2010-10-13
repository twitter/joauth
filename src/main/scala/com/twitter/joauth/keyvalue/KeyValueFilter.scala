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
 * The KeyValueFilter trait tests validity of a key/value pair
 */
trait KeyValueFilter extends ((String, String) => Boolean)

/**
 * OAuthFieldFilter returns true if the key is an OAuth 1.0a field, and the value is non-empty
 */
object OAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = OAuthParams.isOAuthParam(k) && v != ""
}

/**
 * OAuthFieldFilter returns true if the key is not an OAuth 1.0a or 2.0 field
 */
object NotOAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = !OAuthParams.isOAuthParam(k)
}

/**
 * OAuth2FieldFilter returns true if the key is not an OAuth 2.0 field, and the value is non-empty
 */
object OAuth2FieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = k == OAuthParams.OAUTH2_HEADER_TOKEN && v != ""
}