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

import java.net.URLDecoder
import java.net.URLEncoder

object UrlEncoder {
  val UTF_8 = "UTF-8"
  val PLUS = "\\+"
  val PERCENT_20 = "%20"
  def apply(s: String) = if (s == null) null else URLEncoder.encode(s, UTF_8).replaceAll(PLUS, PERCENT_20)
}

trait UrlDecoder {
  def apply(s: String) = if (s == null) null else URLDecoder.decode(s, UrlEncoder.UTF_8)
}
object UrlDecoder extends UrlDecoder