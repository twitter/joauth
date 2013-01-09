/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Adapted from org.apache.commons.codec.binary.Base64
 *
 */
package com.twitter.joauth

import java.nio.charset.Charset

object Base64Util {
  /**
   * 6 bits per byte, 4 bytes per block
   */
  private val BITS_PER_ENCODED_BYTE: Int = 6
  private val BYTES_PER_ENCODED_BLOCK: Int = 4

  /**
   * This array is a lookup table that translates Unicode characters drawn from the "Base64 Alphabet" (as specified in
   * Table 1 of RFC 2045) into their 6-bit positive integer equivalents. Characters that are not in the Base64
   * alphabet but fall within the bounds of the array are translated to -1.
   *
   * Note: '+' and '-' both decode to 62. '/' and '_' both decode to 63. This means decoder seamlessly handles both
   * URL_SAFE and STANDARD base64. (The encoder, on the other hand, needs to know ahead of time what to emit).
   *
   * Thanks to "commons" project in ws.apache.org for this code.
   * http://svn.apache.org/repos/asf/webservices/commons/trunk/modules/util/
   */
  private val DECODE_TABLE: Array[Byte] = Array(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1,
    -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51)

  private val UTF_8 = Charset.forName("UTF-8")
  /**
   * Compare each decoded byte with the passed in byte array. This code could theoretically
   * suffer from timing attacks. We should consider not returning early and just ultimately
   * returning a false result if any comparison fails. This is also true of Arrays.equals
   * and String.equals.
   */
  def equals(base64: String, bytes: Array[Byte]): Boolean = {
    val in = base64.getBytes(UTF_8)
    val length = in.length
    var eof = false
    var bitWorkArea = 0
    var modulus = 0
    var pos = 0
    var i: Int = 0
    while (i < length && !eof) {
      val b: Byte = in(i);
      if (b == '=') {
        eof = true
      } else {
        if (b >= 0 && b < DECODE_TABLE.length) {
          val result: Int = DECODE_TABLE(b)
          if (result >= 0) {
            modulus = (modulus + 1) % BYTES_PER_ENCODED_BLOCK
            bitWorkArea = (bitWorkArea << BITS_PER_ENCODED_BYTE) + result
            if (modulus == 0) {
              if (bytes(pos) != ((bitWorkArea >> 16) & 0xff).asInstanceOf[Byte]) {
                return false
              }
              pos += 1
              if (bytes(pos) != ((bitWorkArea >> 8) & 0xff).asInstanceOf[Byte]) {
                return false
              }
              pos += 1
              if (bytes(pos) != (bitWorkArea & 0xff).asInstanceOf[Byte]) {
                return false
              }
              pos += 1
            }
          }
        }
      }
      i += 1
    }

    // Some may be left over at the end, we need to compare that as well
    if (eof && modulus != 0) {
      modulus match {
        case 2 =>
          bitWorkArea = bitWorkArea >> 4
          if (bytes(pos) != ((bitWorkArea) & 0xff).asInstanceOf[Byte]) {
            return false
          }
          pos += 1
        case 3 =>
          bitWorkArea = bitWorkArea >> 2
          if (bytes(pos) != ((bitWorkArea >> 8) & 0xff).asInstanceOf[Byte]) {
            return false
          }
          pos += 1
          if (bytes(pos) != ((bitWorkArea) & 0xff).asInstanceOf[Byte]) {
            return false
          }
          pos += 1
      }
    }

    pos == bytes.length
  }

}