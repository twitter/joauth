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

package com.twitter.joauth

import java.net.URLDecoder
import java.nio.charset.Charset

object UrlEncoder {
  val UTF_8 = "UTF-8"
  val UTF_8_CHARSET = Charset.forName(UTF_8)

  val PLUS = "+"
  val ENCODED_PLUS = "%20"
  val UNDERSCORE = "_"
  val ENCODED_UNDERSCORE = "%5F"
  val DASH = "-"
  val ENCODED_DASH = "%2D"
  val PERIOD = "."
  val ENCODED_PERIOD = "%2E"
  val TILDE = "~"
  val ENCODED_TILDE = "%7E"
  val COMMA = ","
  val ENCODED_COMMA = "%2C"
  val ENCODED_OPEN_BRACKET = "%5B"
  val ENCODED_CLOSE_BRACKET = "%5D"

  def apply(s: String): String = {
    if (s == null) {
      return null
    }
    var sb: StringBuilder = null
    for (i <- 0 until s.length) {
      val c = s.charAt(i)

      val shouldAppend =
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~'

      if (shouldAppend) {
        if (sb != null) {
          sb.append(c)
        }
      } else {
        if (sb == null) {
          sb = new StringBuilder(s.length + 40)
          sb.append(s.substring(0, i))
        }

        for (b <- c.toString.getBytes(UTF_8_CHARSET)) {
          sb.append("%").append(b.toInt.toHexString.toUpperCase)
        }
      }
    }

    if (sb == null) s else sb.toString()
  }

  def normalize(s: String): String = {
    if (s == null) {
      return null
    }

    var sb: StringBuilder = null
    val length = s.length
    var i = 0

    while (i < length) {
      val c = s.charAt(i)
      if (c == '%' || c == '+' || c == ',' || c == '[' || c == ']') {
        if (sb == null) {
          sb = new StringBuilder(s.length + 40)
          sb.append(s.substring(0, i))
        }
        if (c == '%') {
          val toAppend = s.substring(i, i + 3).toUpperCase match {
            case ENCODED_UNDERSCORE => UNDERSCORE
            case ENCODED_DASH => DASH
            case ENCODED_TILDE => TILDE
            case ENCODED_PERIOD => PERIOD
            case o => o
          }

          sb.append(toAppend)
          i += 2
        } else if (c == ',') {
          sb.append(ENCODED_COMMA)
        } else if (c == '+') {
          sb.append(ENCODED_PLUS)
        } else if (c == '[') {
          sb.append(ENCODED_OPEN_BRACKET)
        } else if (c == ']') {
          sb.append(ENCODED_CLOSE_BRACKET)
        }
      } else if (sb != null) {
        sb.append(c)
      }
      i += 1
    }

    if (sb == null) s else sb.toString()
  }
}

trait UrlDecoder {
  def apply(s: String) = {
    if (s == null) {
      null
    } else {
      URLDecoder.decode(s, UrlEncoder.UTF_8)
    }
  }
}
object UrlDecoder extends UrlDecoder