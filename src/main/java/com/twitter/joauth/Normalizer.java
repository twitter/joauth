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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * a Normalizer takes the fields that describe an OAuth 1.0a request, and produces
 * the normalized string that is used for the signature.
 */
public abstract class Normalizer {

  static final String HTTP = "HTTP";
  static final String HTTPS = "HTTPS";

  private static final StandardNormalizer STANDARD_NORMALIZER = new StandardNormalizer();

  public static Normalizer getStandardNormalizer() {
    return STANDARD_NORMALIZER;
  }

  public abstract String normalize(
    String scheme,
    String host,
    int port,
    String verb,
    String path,
    List<Request.Pair> params,
    OAuthParams.OAuth1Params oAuth1Params
  );

  public String normalize(Request.ParsedRequest req, OAuthParams.OAuth1Params oAuth1Params) {
    return normalize(
      req.scheme(),
      req.host(),
      req.port(),
      req.verb(),
      req.path(),
      req.params(),
      oAuth1Params
    );
  }

  /**
   * the standard implementation of the Normalizer trait. Though stateless and threadsafe,
   * this is a class rather than an object to allow easy access from Java. Scala codebases
   * should use the corresponding STANDARD_NORMALIZER object instead.
   */
  public static class StandardNormalizer extends Normalizer {

    /* TODO: there is no way to clear string builder in java. see what can be done here.
     Not using thread local.

    private static final ThreadLocal<StringBuilder> builders = new ThreadLocal<StringBuilder>() {
      @Override
      protected StringBuilder initialValue() {
        return new StringBuilder(512);
      }
    };
    */

    @Override
    public String normalize(
        String scheme,
        String host,
        int port,
        String verb,
        String path,
        List<Request.Pair> params,
        OAuthParams.OAuth1Params oAuth1Params
    ) {

      // We only need the stringbuilder for the duration of this method
      StringBuilder paramsBuilder = new StringBuilder(512);

      // first, concatenate the params and the oAuth1Params together.
      // the parameters are already URLEncoded, so we leave them alone
      ArrayList<Request.Pair> sigParams = new ArrayList<Request.Pair>();
      sigParams.addAll(params);
      sigParams.addAll(oAuth1Params.toList(false));

      Collections.sort(sigParams, new Comparator<Request.Pair>() {
        @Override
        public int compare(Request.Pair thisPair, Request.Pair thatPair) {
          // sort params first by key, then by value
          int keyCompare = thisPair.key.compareTo(thatPair.key);
          if (keyCompare == 0) {
            return thisPair.value.compareTo(thatPair.value);
          } else {
            return keyCompare;
          }
        }
      });

      if (!sigParams.isEmpty()) {
        Request.Pair head = sigParams.get(0);
        paramsBuilder.append(head.key).append('=').append(head.value);
        for (int i=1; i<sigParams.size(); i++) {
          Request.Pair pair = sigParams.get(i);
          paramsBuilder.append('&').append(pair.key).append('=').append(pair.value);
        }
      }

      StringBuilder requestUrlBuilder = new StringBuilder(512);
      requestUrlBuilder.append(scheme.toLowerCase());
      requestUrlBuilder.append("://");
      requestUrlBuilder.append(host.toLowerCase());
      if (includePortString(port, scheme)) {
        requestUrlBuilder.append(":").append(port);
      }
      requestUrlBuilder.append(path);

      StringBuilder normalizedBuilder = new StringBuilder(512);

      normalizedBuilder.append(verb.toUpperCase());
      normalizedBuilder.append('&').append(UrlCodec.encode(requestUrlBuilder.toString()));
      normalizedBuilder.append('&').append(UrlCodec.encode(paramsBuilder.toString()));

      return normalizedBuilder.toString();
    }

    /**
     * The OAuth 1.0a spec says that the port should not be included in the normalized string
     * when (1) it is port 80 and the scheme is HTTP or (2) it is port 443 and the scheme is HTTPS
     */
    boolean includePortString(int port, String scheme) {
      return !((port == 80 && HTTP.equalsIgnoreCase(scheme)) || (port == 443 && HTTPS.equalsIgnoreCase(scheme)));
    }
  }
}
