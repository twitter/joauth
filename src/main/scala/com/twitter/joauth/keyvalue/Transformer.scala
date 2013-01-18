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

package com.twitter.joauth.keyvalue

import com.twitter.joauth.UrlEncoder

/**
 * The Transformer trait describes the transformation function
 * from a string to a derived string
 */
trait Transformer extends (String => String)

/**
 * The TrimTransformer trims the string
 */
object TrimTransformer extends Transformer {
  def apply(str: String) = str.trim
}

/**
 * The UrlEncodingNormalizingTransformer capitializes all of the
 * URLEncoded entities in a string, replaces +'s with %20s, and
 * un-encodes dashes and underscores. It will do strange things to
 * a string that is not actually URLEncoded.
 */
object UrlEncodingNormalizingTransformer extends Transformer {
  def apply(s: String) = UrlEncoder.normalize(s)
}