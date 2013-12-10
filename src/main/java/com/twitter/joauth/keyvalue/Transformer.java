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

package com.twitter.joauth.keyvalue;

import com.twitter.joauth.UrlCodec;

/**
 * The Transformer trait describes the transformation function
 * from a string to a derived string
 */
public interface Transformer {
  public String transform(String input);

  public final Transformer TRIM_TRANSFORMER = new TrimTransformer();
  public final Transformer URL_ENCODING_NORMALIZING_TRANSFORMER = new UrlEncodingNormalizingTransformer();


  /**
   * The TrimTransformer trims the string
   */
  static class TrimTransformer implements Transformer {
    @Override
    public String transform(String input) {
      return input.trim();
    }
  }

  /**
   * The UrlEncodingNormalizingTransformer capitializes all of the
   * URLEncoded entities in a string, replaces +'s with %20s, and
   * un-encodes dashes and underscores. It will do strange things to
   * a string that is not actually URLEncoded.
   */
  static class UrlEncodingNormalizingTransformer implements Transformer {
    @Override
    public String transform(String input) {
      return UrlCodec.normalize(input);
    }
  }
}
