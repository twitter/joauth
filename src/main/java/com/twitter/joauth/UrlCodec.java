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

package com.twitter.joauth;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;

public class UrlCodec {
  private static final String UTF_8 = "UTF-8";
  private static final Charset UTF_8_CHARSET = Charset.forName(UTF_8);

  //TODO: is this necessary? can we just call isUnreserved((char)b) ?
  private static final String PLUS = "+";
  private static final String ENCODED_PLUS = "%20";
  private static final String UNDERSCORE = "_";
  private static final String ENCODED_UNDERSCORE = "%5F";
  private static final String DASH = "-";
  private static final String ENCODED_DASH = "%2D";
  private static final String PERIOD = ".";
  private static final String ENCODED_PERIOD = "%2E";
  private static final String TILDE = "~";
  private static final String ENCODED_TILDE = "%7E";
  private static final String COMMA = ",";
  private static final String ENCODED_COMMA = "%2C";
  private static final String ENCODED_OPEN_BRACKET = "%5B";
  private static final String ENCODED_CLOSE_BRACKET = "%5D";

  private final static char[] HEX_DIGITS = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  };

  private static boolean isUnreserved(byte b) {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
      (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_' || b == '~';
  }

  private static boolean isUnreserved(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~';
  }

  public static String encode(String s) {
    if (s == null) {
      return null;
    }

    StringBuilder sb = null;

    int startingIndex = 0;
    boolean hasReservedChars = false;

    // scan through to see where we have to start % encoding, if at all
    while (startingIndex < s.length() && !hasReservedChars) {
      if (!isUnreserved(s.charAt(startingIndex))) {
        hasReservedChars = true;
      } else {
        startingIndex += 1;
      }
    }

    if (hasReservedChars && startingIndex < s.length()) {
      sb = new StringBuilder(s.length() + 40);
      sb.append(s.substring(0, startingIndex));

      byte[] byteArray = s.substring(startingIndex).getBytes(UTF_8_CHARSET);
      for (int i = 0; i < byteArray.length; i++) {
        byte bite = byteArray[i];
        if (isUnreserved(bite)) {
          sb.append((char)bite);
        } else {
          // turn the Byte into an int into the hex string, but be sure to mask out the unneeded bits
          // to avoid nastiness with converting to a negative int
          sb.append('%');
          sb.append(HEX_DIGITS[(bite >> 4) & 0x0F]);
          sb.append(HEX_DIGITS[bite & 0x0F]);
        }
      }
    }

    return (sb == null) ? s : sb.toString();
  }

  public static String normalize(String s) {
    if (s == null) {
      return null;
    }

    StringBuilder sb = null;
    int length = s.length();
    int i = 0;

    while (i < length) {
      char c = s.charAt(i);
      if (c == '%' || c == '+' || c == ',' || c == '[' || c == ']') {
        if (sb == null) {
          sb = new StringBuilder(s.length() + 40); //use length
          sb.append(s.substring(0, i));
        }
        if (c == '%') {
          if (i + 3 <= length) {
            if (ENCODED_UNDERSCORE.regionMatches(true, 1, s, i + 1, 2)) {
              sb.append(UNDERSCORE);
            } else if (ENCODED_DASH.regionMatches(true, 1, s, i + 1, 2)) {
              sb.append(DASH);
            } else if (ENCODED_TILDE.regionMatches(true, 1, s, i + 1, 2)) {
              sb.append(TILDE);
            } else if (ENCODED_PERIOD.regionMatches(true, 1, s, i + 1, 2)) {
              sb.append(PERIOD);
            } else {
              for (int j = i; j < i + 3; j++) {
                sb.append(Character.toUpperCase(s.charAt(j)));
              }
            }

            i += 2;
          } else {
            sb.append(c);
          }
        } else if (c == ',') {
          sb.append(ENCODED_COMMA);
        } else if (c == '+') {
          sb.append(ENCODED_PLUS);
        } else if (c == '[') {
          sb.append(ENCODED_OPEN_BRACKET);
        } else if (c == ']') {
          sb.append(ENCODED_CLOSE_BRACKET);
        }
      } else if (sb != null) {
        sb.append(c);
      }
      i += 1;
    }

    return (sb == null) ? s : sb.toString();
  }

  public static String decode(String s) throws UnsupportedEncodingException {
    return (s == null) ? null : URLDecoder.decode(s, UrlCodec.UTF_8);
  }
}
