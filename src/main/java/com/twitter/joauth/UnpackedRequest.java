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
import java.util.HashMap;
import java.util.Map;

public interface UnpackedRequest {

  public static final OAuth1RequestHelper O_AUTH_1_REQUEST_HELPER = new OAuth1RequestHelper();

  public Request.ParsedRequest parsedRequest();

  public static class UnknownRequest implements UnpackedRequest {
    private final Request.ParsedRequest parsedRequest;

    public UnknownRequest(Request.ParsedRequest parsedRequest) {
      this.parsedRequest = parsedRequest;
    }

    @Override
    public Request.ParsedRequest parsedRequest() {
      return parsedRequest;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      UnknownRequest that = (UnknownRequest) o;

      if (parsedRequest != null ? !parsedRequest.equals(that.parsedRequest) : that.parsedRequest != null) return false;

      return true;
    }

    @Override
    public int hashCode() {
      return parsedRequest != null ? parsedRequest.hashCode() : 0;
    }
  }

  /**
   * Both OAuth 1.0a and 2.0 requests have access tokens,
   * so it's convenient to combine them into a single trait
   */
  public interface OAuthRequest extends UnpackedRequest {
    public String oAuthVersionString();
    public Map<String, String> oAuthParamMap();
  }

  /**
   * models an OAuth 1.0a request. Rather than passing the
   * scheme, host, port, etc around, we pre-calculate the normalized request,
   * since that's all we need for signature validation anyway.
   */
  public static class OAuth1TwoLeggedRequest extends OAuth1RequestBase {

    public OAuth1TwoLeggedRequest(
      String consumerKey,
      String nonce,
      Long timestampSecs,
      String signature,
      String signatureMethod,
      String version,
      Request.ParsedRequest parsedRequest,
      String normalizedRequest
    ) {
      super(consumerKey, nonce, timestampSecs, signature, signatureMethod, version, parsedRequest, normalizedRequest);
    }
  }

  public static class OAuth1RequestBase implements OAuthRequest {
    private final String consumerKey;
    private final String nonce;
    private final Long timestampSecs;
    private final String signature;
    private final String signatureMethod;
    private final String version;
    private final Request.ParsedRequest parsedRequest;
    private final String normalizedRequest;

    public String consumerKey() {
      return consumerKey;
    }

    public String nonce() {
      return nonce;
    }

    public Long timestampSecs() {
      return timestampSecs;
    }

    public String signature() {
      return signature;
    }

    public String signatureMethod() {
      return signatureMethod;
    }

    public String version() {
      return version;
    }

    public String normalizedRequest() {
      return normalizedRequest;
    }

    public OAuth1RequestBase(
      String consumerKey,
      String nonce,
      Long timestampSecs,
      String signature,
      String signatureMethod,
      String version,
      Request.ParsedRequest parsedRequest,
      String normalizedRequest
    ) {
      this.consumerKey = consumerKey;
      this.nonce = nonce;
      this.timestampSecs = timestampSecs;
      this.signature = signature;
      this.signatureMethod = signatureMethod;
      this.version = version;
      this.parsedRequest = parsedRequest;
      this.normalizedRequest = normalizedRequest;
    }

    @Override
    public Request.ParsedRequest parsedRequest() {
      return parsedRequest;
    }

    @Override
    public String oAuthVersionString() {
      return "oauth1";
    }

    @Override
    public Map<String, String> oAuthParamMap() {
      HashMap<String, String> map = new HashMap<String, String>();

      map.put(OAuthParams.OAUTH_CONSUMER_KEY, consumerKey);
      map.put(OAuthParams.OAUTH_NONCE, nonce);
      map.put(OAuthParams.OAUTH_TIMESTAMP, timestampSecs.toString());
      map.put(OAuthParams.OAUTH_SIGNATURE_METHOD, signatureMethod);
      map.put(OAuthParams.OAUTH_SIGNATURE, signature);
      map.put(OAuthParams.OAUTH_VERSION, (version == null) ? OAuthParams.ONE_DOT_OH : version);
      map.put(OAuthParams.NORMALIZED_REQUEST, normalizedRequest);

      return map;
    }

    public String toString() {
      return String.format("{consumerKey -> %s, nonce -> %s, timestamp -> %s, signature -> %s, method -> %s}",
        consumerKey, nonce, timestampSecs, signature, signatureMethod
      );
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      OAuth1RequestBase that = (OAuth1RequestBase) o;

      if (consumerKey != null ? !consumerKey.equals(that.consumerKey) : that.consumerKey != null) return false;
      if (nonce != null ? !nonce.equals(that.nonce) : that.nonce != null) return false;
      if (normalizedRequest != null ? !normalizedRequest.equals(that.normalizedRequest) : that.normalizedRequest != null)
        return false;
      if (parsedRequest != null ? !parsedRequest.equals(that.parsedRequest) : that.parsedRequest != null) return false;
      if (signature != null ? !signature.equals(that.signature) : that.signature != null) return false;
      if (signatureMethod != null ? !signatureMethod.equals(that.signatureMethod) : that.signatureMethod != null)
        return false;
      if (timestampSecs != null ? !timestampSecs.equals(that.timestampSecs) : that.timestampSecs != null) return false;
      if (version != null ? !version.equals(that.version) : that.version != null) return false;

      return true;
    }

    @Override
    public int hashCode() {
      int result = consumerKey != null ? consumerKey.hashCode() : 0;
      result = 31 * result + (nonce != null ? nonce.hashCode() : 0);
      result = 31 * result + (timestampSecs != null ? timestampSecs.hashCode() : 0);
      result = 31 * result + (signature != null ? signature.hashCode() : 0);
      result = 31 * result + (signatureMethod != null ? signatureMethod.hashCode() : 0);
      result = 31 * result + (version != null ? version.hashCode() : 0);
      result = 31 * result + (parsedRequest != null ? parsedRequest.hashCode() : 0);
      result = 31 * result + (normalizedRequest != null ? normalizedRequest.hashCode() : 0);
      return result;
    }
  }

  public static class OAuth1Request extends OAuth1RequestBase {
    private final String token;

    public OAuth1Request(
      String token,
      String consumerKey,
      String nonce,
      Long timestampSecs,
      String signature,
      String signatureMethod,
      String version,
      Request.ParsedRequest parsedRequest,
      String normalizedRequest
    ) {
      super(consumerKey, nonce, timestampSecs, signature, signatureMethod, version, parsedRequest, normalizedRequest);
      this.token = token;
    }

    public String token() {
      return token;
    }

    @Override
    public Map<String, String> oAuthParamMap() {
      Map<String, String> map = super.oAuthParamMap();
      map.put(OAuthParams.OAUTH_TOKEN, token);
      return map;
    }

    public String toString() {
      return String.format("{token -> %s, consumerKey -> %s, nonce -> %s, timestamp -> %s, signature -> %s, method -> %s}",
        token, consumerKey(), nonce(), timestampSecs(), signature(), signatureMethod()
      );
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      if (!super.equals(o)) return false;

      OAuth1Request that = (OAuth1Request) o;

      if (token != null ? !token.equals(that.token) : that.token != null) return false;

      return true;
    }

    @Override
    public int hashCode() {
      int result = super.hashCode();
      result = 31 * result + (token != null ? token.hashCode() : 0);
      return result;
    }
  }

  /**
   * models an OAuth 2.0 rev 25 request. Just a wrapper for the token, really.
   */
  public static class OAuth2Request implements OAuthRequest {
    public final String token;
    private final Request.ParsedRequest parsedRequest;
    private final String clientId;

    public OAuth2Request(String token, Request.ParsedRequest parsedRequest, String clientId) {
      this.token = token;
      this.parsedRequest = parsedRequest;
      this.clientId = clientId;
    }

    public String clientId() {
      return clientId;
    }

    public String token() {
      return token;
    }

    @Override
    public Request.ParsedRequest parsedRequest() {
      return parsedRequest;
    }

    @Override
    public String oAuthVersionString() {
      return "oauth2";
    }

    @Override
    public HashMap<String, String> oAuthParamMap() {
      HashMap<String, String> map = new HashMap<String, String>(4);
      map.put(OAuthParams.BEARER_TOKEN, token);
      map.put(OAuthParams.CLIENT_ID, clientId);
      return map;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      OAuth2Request that = (OAuth2Request) o;

      if (clientId != null ? !clientId.equals(that.clientId) : that.clientId != null) return false;
      if (parsedRequest != null ? !parsedRequest.equals(that.parsedRequest) : that.parsedRequest != null) return false;
      if (token != null ? !token.equals(that.token) : that.token != null) return false;

      return true;
    }

    @Override
    public int hashCode() {
      int result = token != null ? token.hashCode() : 0;
      result = 31 * result + (parsedRequest != null ? parsedRequest.hashCode() : 0);
      result = 31 * result + (clientId != null ? clientId.hashCode() : 0);
      return result;
    }
  }

  /**
   * The companion object's apply method produces an OAuth1Request instance by
   * passing the request details into a Normalizer to produce the normalized
   * request. Will throw a MalformedRequest if any required parameter is unset.
   */
  static class OAuth1RequestHelper {
    private static final String NO_VALUE_FOR = "no value for ";
    private static final String SCHEME = "scheme";
    private static final String HOST = "host";
    private static final String PORT = "port";
    private static final String VERB = "verb";
    private static final String PATH = "path";
    private static final String UNSUPPORTED_METHOD = "unsupported signature method: ";
    private static final String UNSUPPORTED_VERSION = "unsupported oauth version: ";
    private static final String MALFORMED_TOKEN = "malformed oauth token: ";

    //TODO: remove MaxTokenLength, this limit is specific to twitter
    private static final int MaxTokenLength = 50;   // This is limited by DB schema

    private void throwMalformedException(String name) throws MalformedRequest {
      throw new MalformedRequest(NO_VALUE_FOR+name);
    }

    public void verify(Request.ParsedRequest parsedRequest, OAuthParams.OAuth1Params oAuth1Params) throws MalformedRequest {
      if (parsedRequest.scheme() == null) throwMalformedException(SCHEME);
      else if (parsedRequest.host() == null) throwMalformedException(HOST);
      else if (parsedRequest.port() < 0) throwMalformedException(PORT);
      else if (parsedRequest.verb() == null) throwMalformedException(VERB);
      else if (parsedRequest.path() == null) throwMalformedException(PATH);
      else if (oAuth1Params.signatureMethod() == null || !oAuth1Params.signatureMethod().equals(OAuthParams.HMAC_SHA1)) {
        throw new MalformedRequest(UNSUPPORTED_METHOD + oAuth1Params.signatureMethod());
      }
      else if (oAuth1Params.version() != null &&
          !oAuth1Params.version().equals(OAuthParams.ONE_DOT_OH) &&
          !oAuth1Params.version().toLowerCase().equals(OAuthParams.ONE_DOT_OH_A)) {
        throw new MalformedRequest(UNSUPPORTED_VERSION + oAuth1Params.version());
      }
      else if (oAuth1Params.token() != null &&
          (oAuth1Params.token().indexOf(' ') > 0 || oAuth1Params.token().length() > MaxTokenLength)) {
        throw new MalformedRequest(MALFORMED_TOKEN + oAuth1Params.token());
      }
      // we don't check the validity of the OAuthParams object, because it must be
      // fully populated in order for the factory to even be called, and we'd like
      // to save the expense of iterating over all the fields again
    }

    public OAuth1Request buildOAuth1Request(
      Request.ParsedRequest parsedRequest,
      OAuthParams.OAuth1Params oAuth1Params,
      Normalizer normalize
    ) throws MalformedRequest, UnsupportedEncodingException {

      verify(parsedRequest, oAuth1Params);

      return new OAuth1Request(
        UrlCodec.decode(oAuth1Params.token()), // should never be called when token is None
        UrlCodec.decode(oAuth1Params.consumerKey()),
        UrlCodec.decode(oAuth1Params.nonce()),
        oAuth1Params.timestampSecs(),
        oAuth1Params.signature(),
        oAuth1Params.signatureMethod(),
        oAuth1Params.version(),
        parsedRequest,
        normalize.normalize(parsedRequest, oAuth1Params)
      );
    }


    public OAuth1TwoLeggedRequest buildOAuth1TwoLeggedRequest(
      Request.ParsedRequest parsedRequest,
      OAuthParams.OAuth1Params oAuth1Params,
      Normalizer normalize
    ) throws MalformedRequest, UnsupportedEncodingException {

      verify(parsedRequest, oAuth1Params);

      return new OAuth1TwoLeggedRequest(
        UrlCodec.decode(oAuth1Params.consumerKey()),
        UrlCodec.decode(oAuth1Params.nonce()),
        oAuth1Params.timestampSecs(),
        oAuth1Params.signature(),
        oAuth1Params.signatureMethod(),
        oAuth1Params.version(),
        parsedRequest,
        normalize.normalize(parsedRequest, oAuth1Params)
      );
    }
  }
}
