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


  private[this] def isUnreserved(b: Byte): Boolean = {
    (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
      (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_' || b == '~'
  }

  private[this] def isUnreserved(c: Char): Boolean = {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~'
  }

  def apply(s: String): String = {
    if (s == null) {
      return null
    }
    var sb: StringBuilder = null

    var startingIndex = 0
    var hasReservedChars = false
    // scan through to see where we have to start % encoding, if at all
    while (startingIndex < s.length && !hasReservedChars) {
      if (!isUnreserved(s.charAt(startingIndex))) {
        hasReservedChars = true
      } else {
        startingIndex += 1
      }
    }

    if (hasReservedChars && startingIndex < s.length) {
      sb = new StringBuilder(s.length + 40)
      sb.append(s.substring(0, startingIndex))

      val byteArray = s.substring(startingIndex).getBytes(UTF_8_CHARSET)
      for (i <- 0 until byteArray.length) {
        val bite = byteArray(i)
        if (isUnreserved(bite)) {
          sb.append(bite.toChar)
        } else {
          // turn the Byte into an int into the hex string, but be sure to mask out the unneeded bits
          // to avoid nastiness with converting to a negative int
          sb.append("%")
            .append(((bite >> 4) & 0xF).toHexString.toUpperCase)
            .append(((bite & 0xF).toHexString.toUpperCase))
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
          if (i + 3 <= length) {
            // TODO: look into reducing garbage here
            val toAppend = s.substring(i, i + 3).toUpperCase match {
              case ENCODED_UNDERSCORE => UNDERSCORE
              case ENCODED_DASH => DASH
              case ENCODED_TILDE => TILDE
              case ENCODED_PERIOD => PERIOD
              case o => o
            }

            sb.append(toAppend)
            i += 2
          } else {
            sb.append(c)
          }
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
