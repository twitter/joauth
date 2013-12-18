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

import com.twitter.joauth.keyvalue.KeyValueHandler;

import java.util.ArrayList;
import java.util.List;

public class OAuthParams {

  /**
   * the singleton object of StandardOAuthParamsHelper
   */
  public static final OAuthParamsHelper STANDARD_OAUTH_PARAMS_HELPER = new StandardOAuthParamsHelperImpl();

  /**
   * pull all the OAuth parameter string constants into one place,
   * add a convenience method for determining if a string is an
   * OAuth 1.0 fieldname.
   */
  public static final String BEARER_TOKEN = "Bearer";
  public static final String CLIENT_ID = "client_id";
  public static final String OAUTH_TOKEN = "oauth_token";
  public static final String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
  public static final String OAUTH_SIGNATURE = "oauth_signature";
  public static final String OAUTH_NONCE = "oauth_nonce";
  public static final String OAUTH_TIMESTAMP = "oauth_timestamp";
  public static final String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
  public static final String OAUTH_VERSION = "oauth_version";
  public static final String NORMALIZED_REQUEST = "normalized_request";
  public static final String UNSET = "(unset)";

  public static final String HMAC_SHA1 = "HMAC-SHA1";
  public static final String ONE_DOT_OH = "1.0";
  public static final String ONE_DOT_OH_A = "1.0a";

  public static final String OAUTH1_HEADER_AUTHTYPE = "oauth";
  public static final String OAUTH2_HEADER_AUTHTYPE = "bearer";


  private static String valueOrUnset(String value) {
    return (value == null) ? UNSET : value;
  }

  /**
   * OAuth1Params is mostly just a container for OAuth 1.0a parameters.
   * The token is optional to allow for OAuth 1.0 two-legged requests.
   */
  public static class OAuth1Params {
    private final String token;
    private final String consumerKey;
    private final String nonce;
    private final Long timestampSecs;
    private final String timestampStr;
    private final String signature;
    private final String signatureMethod;
    private final String version;


    public OAuth1Params(
      String token,
      String consumerKey,
      String nonce,
      Long timestampSecs,
      String timestampStr,
      String signature,
      String signatureMethod,
      String version
    ) {
      this.token = token;
      this.consumerKey = consumerKey;
      this.nonce = nonce;
      this.timestampSecs = timestampSecs;
      this.timestampStr = timestampStr;
      this.signature = signature;
      this.signatureMethod = signatureMethod;
      this.version = version;
    }

    public String token() { return token; }
    public String consumerKey() { return consumerKey; }
    public String nonce() { return  nonce; }
    public Long timestampSecs() { return timestampSecs; }
    public String timestampStr() { return timestampStr; }
    public String signature() { return signature; }
    public String signatureMethod() { return signatureMethod; }
    public String version() { return version; }


    public List<Request.Pair> toList(boolean includeSig) {
      ArrayList<Request.Pair> buf = new ArrayList<Request.Pair>();

      buf.add(new Request.Pair(OAUTH_CONSUMER_KEY, consumerKey));
      buf.add(new Request.Pair(OAUTH_NONCE, nonce));
      if (token != null) buf.add(new Request.Pair(OAUTH_TOKEN, token));
      if (includeSig) buf.add(new Request.Pair(OAUTH_SIGNATURE, signature));
      buf.add(new Request.Pair(OAUTH_SIGNATURE_METHOD, signatureMethod));
      buf.add(new Request.Pair(OAUTH_TIMESTAMP, timestampStr));
      if (version != null) buf.add(new Request.Pair(OAUTH_VERSION, version));

      return buf;
    }

    // we use String.format here, because we're probably not that worried about
    // effeciency when printing the class for debugging
    @Override
    public String toString() {
      return String.format("%s=%s,%s=%s,%s=%s,%s=%s(->%s),%s=%s,%s=%s,%s=%s",
        OAUTH_TOKEN, valueOrUnset(token),
        OAUTH_CONSUMER_KEY, valueOrUnset(consumerKey),
        OAUTH_NONCE, valueOrUnset(nonce),
        OAUTH_TIMESTAMP, timestampStr, timestampSecs,
        OAUTH_SIGNATURE, valueOrUnset(signature),
        OAUTH_SIGNATURE_METHOD, valueOrUnset(signatureMethod),
        OAUTH_VERSION, valueOrUnset(version));
    }
  }

  /**
   * A collector for OAuth and other params. There are convenience methods for determining
   * if it has all OAuth parameters set, just the token set, and for obtaining
   * a list of all params for use in producing the normalized request.
   */
  public static class OAuthParamsBuilder {

    private OAuthParamsHelper helper;

    public OAuthParamsBuilder(OAuthParamsHelper helper) {
      this.helper = helper;
    }

    //todo: make this final
    public String v2Token;
    public String token;
    public String consumerKey;
    public String nonce;
    public Long timestampSecs = -1L;
    public String timestampStr;
    public String signature;
    public String signatureMethod;
    public String version;

    private KeyValueHandler.DuplicateKeyValueHandler paramsHandler = new KeyValueHandler.DuplicateKeyValueHandler();
    private KeyValueHandler.SingleKeyValueHandler otherOAuthParamsHandler = new KeyValueHandler.SingleKeyValueHandler();

    public KeyValueHandler headerHandler = new KeyValueHandler() {
      @Override
      public void handle(String key, String value) {
        handleKeyValue(key, value, true);
      }
    };

    public KeyValueHandler queryHandler = new KeyValueHandler() {
      @Override
      public void handle(String key, String value) {
        handleKeyValue(key, value, false);
      }
    };

    private boolean notEmpty(String value) {
      return (value != null && !value.equals(""));
    }

    private void handleKeyValue(String key, String value, boolean fromHeader) {

      // TODO: This needs clean up. replace the if/else with enum/map-lookup
      // Known keys can be in an enum, and parser can be updated to point to these keys, instead of creating a new key string.

      // empty values for these keys are swallowed
      if(BEARER_TOKEN.equals(key)) {
        if (fromHeader && notEmpty(value)) {
          v2Token = value;
        }
      } else if (CLIENT_ID.equals(key)) {
        if(fromHeader && notEmpty(value)) {
          consumerKey = value;
        }
      } else if (OAUTH_TOKEN.equals(key)) {
        if (value != null) {
          token = value.trim();
        }
      } else if (OAUTH_CONSUMER_KEY.equals(key)) {
        if (notEmpty(value)) {
          consumerKey = value;
        }
      } else if (OAUTH_NONCE.equals(key)) {
        if (notEmpty(value)) {
          nonce = value;
        }
      } else if (OAUTH_TIMESTAMP.equals(key)) {
        Long timestamp = helper.parseTimestamp(value);
        if (timestamp != null) {
          timestampSecs = timestamp;
          timestampStr = value;
        }
      } else if (OAUTH_SIGNATURE.equals(key)) {
        if (notEmpty(value)) {
          signature = helper.processSignature(value);
        }
      } else if (OAUTH_SIGNATURE_METHOD.equals(key)) {
        if (notEmpty(value)) {
          signatureMethod = value;
        }
      } else if (OAUTH_VERSION.equals(key)) {
        if (notEmpty(value)) {
          version = value;
        }
      } else if (key.startsWith("oauth_")) {
           // send oauth_prefixed to a uniquekey handler
           otherOAuthParamsHandler.handle(key, value);
      } else {
        // send other params to the handler, but only if they didn't come from the header
        if (!fromHeader) paramsHandler.handle(key, value);
      }
    }

    // we use String.format here, because we're probably not that worried about
    // effeciency when printing the class for debugging
    public String toString() {
      return String.format("%s=%s,%s=%s,%s=%s,%s=%s,%s=%s(->%s),%s=%s,%s=%s,%s=%s",
        BEARER_TOKEN, valueOrUnset(v2Token),
        OAUTH_TOKEN, valueOrUnset(token),
        OAUTH_CONSUMER_KEY, valueOrUnset(consumerKey),
        OAUTH_NONCE, valueOrUnset(nonce),
        OAUTH_TIMESTAMP, timestampStr, timestampSecs,
        OAUTH_SIGNATURE, valueOrUnset(signature),
        OAUTH_SIGNATURE_METHOD, valueOrUnset(signatureMethod),
        OAUTH_VERSION, valueOrUnset(version));
    }


    public boolean isOAuth2() {
     return v2Token != null && !isOAuth1() && !isOAuth1TwoLegged();
    }

    public boolean isOAuth1TwoLegged() {
      return (token == null || "".equals(token)) &&
        consumerKey != null &&
        nonce != null &&
        timestampStr != null &&
        signature != null &&
        signatureMethod != null;
    }

    public boolean isOAuth1() {
      return token != null &&
        !"".equals(token) &&
        consumerKey != null &&
        nonce != null &&
        timestampStr != null &&
        signature != null &&
        signatureMethod != null;
      // version is optional, so not included here
    }

    public String oAuth2Token() {
      return v2Token;
    }

    public List<Request.Pair> otherParams() {
      List<Request.Pair> list = paramsHandler.toList();
      list.addAll(otherOAuthParamsHandler.toList());
      return list;
    }

    // make an immutable params instance
    public OAuth1Params oAuth1Params() {
      return new OAuth1Params(
        token,
        consumerKey,
        nonce,
        timestampSecs,
        timestampStr,
        signature,
        signatureMethod,
        version
      );
    }
  }

  public interface OAuthParamsHelper {
    /**
     * allows one to override the default behavior when parsing timestamps,
     * which is to parse them as integers, and ignore timestamps that are
     * malformed
     */
    Long parseTimestamp(String str);

    /**
     * allows custom processing of the OAuth 1.0 signature obtained from the request.
     */
    String processSignature(String str);

    /**
     * allows custom processing of keys obtained from the request
     */
    String processKey(String str);
  }

  /**
   * Provides the default implementation of the OAuthParamsHelper trait
   * Though stateless and threadsafe, this is a class rather than an object to allow easy
   * access from Java. Scala codebases should use the corresponding STANDARD_OAUTH_PARAMS_HELPER
   * object instead.
   */
  public static class StandardOAuthParamsHelperImpl implements OAuthParamsHelper {

    @Override
    public Long parseTimestamp(String str) {
      try {
        return Long.parseLong(str);
      } catch (Exception e) {
        return null;
      }
    }

    @Override
    public String processKey(String str) {
      return str;
    }

    @Override
    public String processSignature(String str) {
      return str;
    }
  }
}
