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
import com.twitter.joauth.keyvalue.KeyValueParser;
import com.twitter.joauth.keyvalue.Transformer;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An Unpacker takes an Request and optionally a Seq[KeyValueHandler],
 * and parses the request into an OAuthRequest instance, invoking each KeyValueHandler
 * for every key/value pair obtained from either the queryString or the request body.
 * If no valid request can be obtained, an UnpackerException is thrown.
 */
public interface Unpacker {
  public UnpackedRequest unpack(Request request) throws UnpackerException;

  public UnpackedRequest unpack(Request request, KeyValueHandler kvHandler) throws UnpackerException;

  public UnpackedRequest unpack(Request request, List<KeyValueHandler> kvHandlers) throws UnpackerException;


  //TODO: callback and checker can be removed. unnecessary indirection, carried over from scala.
  public static interface KeyValueCallback {
    public KeyValueHandler invoke(KeyValueHandler input);
  }

  public static interface OAuth2Checker {
    public boolean shouldAllowOAuth2(Request request, Request.ParsedRequest parsedRequest);
  }


  public static class CustomizableUnpacker implements Unpacker {

    public static final String WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String HTTPS = "HTTPS";

    private static final Logger log = Logger.getLogger("CustomizableUnpacker");

    private final OAuthParams.OAuthParamsHelper helper;
    private final Normalizer normalizer;
    private final KeyValueParser queryParser;
    private final KeyValueParser headerParser;
    private final KeyValueCallback queryParamTransformer;
    private final KeyValueCallback bodyParamTransformer;
    private final KeyValueCallback headerTransformer;
    private final OAuth2Checker shouldAllowOAuth2;

    public CustomizableUnpacker(
      OAuthParams.OAuthParamsHelper helper,
      Normalizer normalizer,
      KeyValueParser queryParser,
      KeyValueParser headerParser,
      KeyValueCallback queryParamTransformer,
      KeyValueCallback bodyParamTransformer,
      KeyValueCallback headerTransformer,
      OAuth2Checker shouldAllowOAuth2
    ) {
      this.helper = helper;
      this.normalizer = normalizer;
      this.queryParser = queryParser;
      this.headerParser = headerParser;
      this.queryParamTransformer = queryParamTransformer;
      this.bodyParamTransformer = bodyParamTransformer;
      this.headerTransformer = headerTransformer;
      this.shouldAllowOAuth2 = shouldAllowOAuth2;
    }

    private KeyValueHandler createKeyValueHandler(
      KeyValueHandler kvHandler,
      KeyValueCallback transformer
    ) {

      Transformer processKey = new Transformer() {
        @Override
        public String transform(String input) {
          return helper.processKey(input);
        }
      };

      return new KeyValueHandler.KeyTransformingKeyValueHandler(
        new KeyValueHandler.TrimmingKeyValueHandler(transformer.invoke(kvHandler)),
        processKey);
    }

    public KeyValueHandler queryParamKeyValueHandler(KeyValueHandler kvHandler) {
      return createKeyValueHandler(kvHandler, queryParamTransformer);
    }

    public KeyValueHandler bodyParamKeyValueHandler(KeyValueHandler kvHandler) {
      return createKeyValueHandler(kvHandler, bodyParamTransformer);
    }

    public KeyValueHandler headerParamKeyValueHandler(KeyValueHandler kvHandler) {
      return createKeyValueHandler(kvHandler, headerTransformer);
    }

    public void parseHeader(String header, KeyValueHandler nonTransformingHandler){
      // trim, normalize encodings
      KeyValueHandler handler = headerParamKeyValueHandler(nonTransformingHandler);

      // check for OAuth credentials in the header. OAuth 1.0a and 2.0 have
      // different header schemes, so match first on the auth scheme.
      if (header != null) {
        //TODO: make sure oauth1 and oauth2 check is correct.

        int spaceIndex = header.indexOf(' ');

        if (spaceIndex != -1 && spaceIndex != 0 && spaceIndex + 1 < header.length()) {
          String authType = header.substring(0, spaceIndex);
          String authString = header.substring(spaceIndex+1, header.length());

          boolean shouldParse = false;
          boolean oauth2 = false;

          if (authType.equalsIgnoreCase(OAuthParams.OAUTH2_HEADER_AUTHTYPE)) {
            shouldParse = false;
            oauth2 = true;
          } else if (authType.equalsIgnoreCase(OAuthParams.OAUTH1_HEADER_AUTHTYPE)) {
            shouldParse = true;
            oauth2 = false;
          }

          if (shouldParse) {
            // if we were able match an appropriate auth header,
            // we'll wrap that handler with a MaybeQuotedValueKeyValueHandler,
            // which will strip quotes from quoted values before passing
            // to the underlying handler
            KeyValueHandler quotedHandler = new KeyValueHandler.MaybeQuotedValueKeyValueHandler(handler);

            // now we'll pass the handler to the headerParser,
            // which splits on commas rather than ampersands,
            // and is more forgiving with whitespace
            List<KeyValueHandler> handlers = Collections.singletonList(quotedHandler);
            headerParser.parse(authString, handlers);
          } else if (oauth2) {
            nonTransformingHandler.handle(OAuthParams.BEARER_TOKEN, authString);
          }
        }
      }
    }

    public OAuthParams.OAuthParamsBuilder parseRequest(Request request, List<KeyValueHandler> kvHandlers) {
      // use an oAuthParamsBuilder instance to accumulate key/values from
      // the query string, the request body (if the appropriate Content-Type),
      // and the Authorization header, if any.
      OAuthParams.OAuthParamsBuilder oAuthParamsBuilder = new OAuthParams.OAuthParamsBuilder(helper);

      // parse the header, if present
      parseHeader(request.authHeader(), oAuthParamsBuilder.headerHandler);

      // If it is an oAuth2 we do not need to process any further
      if (!oAuthParamsBuilder.isOAuth2()) {

        // add our handlers to the passed-in handlers, to which
        // we'll only send non-oauth key/values.
        ArrayList<KeyValueHandler> queryHandlers = new ArrayList<KeyValueHandler>(kvHandlers.size() + 1);
        queryHandlers.add(queryParamKeyValueHandler(oAuthParamsBuilder.queryHandler));
        queryHandlers.addAll(kvHandlers);

        ArrayList<KeyValueHandler> bodyParamHandlers = new ArrayList<KeyValueHandler>(kvHandlers.size() + 1);
        bodyParamHandlers.add(bodyParamKeyValueHandler(oAuthParamsBuilder.queryHandler));
        bodyParamHandlers.addAll(kvHandlers);

        // parse the GET query string
        queryParser.parse(request.queryString(), queryHandlers);

        // parse the request body if the Content-Type is appropriate. Use the
        // same set of KeyValueHandlers that we used to parse the query string.
        if (request.contentType() != null &&
            request.contentType().startsWith(WWW_FORM_URLENCODED)) {
          queryParser.parse(request.body(), bodyParamHandlers);
        }
      }

      // now we just return the accumulated parameters and OAuthParams
      return oAuthParamsBuilder;
    }



    @Override
    public UnpackedRequest unpack(Request request, List<KeyValueHandler> kvHandlers) throws UnpackerException {
      try {
        OAuthParams.OAuthParamsBuilder oAuthParamsBuilder = parseRequest(request, kvHandlers);
        Request.ParsedRequest parsedRequest = Request.factory.parsedRequest(request, oAuthParamsBuilder.otherParams());

        if (oAuthParamsBuilder.isOAuth2()) {
          return getOAuth2Request(request, parsedRequest, oAuthParamsBuilder.oAuth2Token());
        } else if (oAuthParamsBuilder.isOAuth1()) {
          return getOAuth1Request(parsedRequest, oAuthParamsBuilder.oAuth1Params());
        } else if (oAuthParamsBuilder.isOAuth1TwoLegged()) {
          return getOAuth1TwoLeggedRequest(parsedRequest, oAuthParamsBuilder.oAuth1Params());
        } else {
          return new UnpackedRequest.UnknownRequest(parsedRequest);
        }

      } catch (UnpackerException u) {
        throw u;
      } catch (Throwable t) {
        log.log(Level.WARNING, "could not unpack request", t);
        throw new UnpackerException("could not unpack request: " + t, t);
      }
    }

    @Override
    public UnpackedRequest unpack(Request request) throws UnpackerException {
      List<KeyValueHandler> emptyList = Collections.emptyList();
      return unpack(request, emptyList);
    }

    @Override
    public UnpackedRequest unpack(Request request, KeyValueHandler kvHandler) throws UnpackerException {
      List<KeyValueHandler> handlers = Collections.singletonList(kvHandler);
      return unpack(request, handlers);
    }

    public UnpackedRequest.OAuth1Request getOAuth1Request(
      Request.ParsedRequest parsedRequest,
      OAuthParams.OAuth1Params oAuth1Params
    ) throws MalformedRequest, UnsupportedEncodingException {

    if (log.isLoggable(Level.FINE)) {
      log.log(Level.FINE, String.format(
        "building oauth1 request -> path = %s, host = %s, token = %s, consumer key = %s, signature = %s, method = %s",
        parsedRequest.path(), parsedRequest.host(), oAuth1Params.token(),
        oAuth1Params.consumerKey(), oAuth1Params.signature(), oAuth1Params.signatureMethod()));
    }

    return UnpackedRequest.O_AUTH_1_REQUEST_HELPER.buildOAuth1Request(parsedRequest, oAuth1Params, normalizer);
  }

  public UnpackedRequest.OAuth1TwoLeggedRequest getOAuth1TwoLeggedRequest(
    Request.ParsedRequest parsedRequest,
    OAuthParams.OAuth1Params oAuth1Params
  ) throws MalformedRequest, UnsupportedEncodingException {

    if (log.isLoggable(Level.FINE)) {
      log.log(Level.FINE, String.format(
        "building oauth1 two-legged request -> path = %s, host = %s, consumer key = %s, signature = %s, method = %s",
        parsedRequest.path(), parsedRequest.host(), oAuth1Params.consumerKey(),
        oAuth1Params.signature(), oAuth1Params.signatureMethod()));
    }

    return UnpackedRequest.O_AUTH_1_REQUEST_HELPER.buildOAuth1TwoLeggedRequest(parsedRequest, oAuth1Params, normalizer);
  }

  public UnpackedRequest.OAuth2Request getOAuth2Request(
    Request request,
    Request.ParsedRequest parsedRequest,
    String token
  ) throws UnsupportedEncodingException, MalformedRequest {

    // OAuth 2.0 requests are totally insecure without SSL, so depend on HTTPS to provide
    // protection against replay and man-in-the-middle attacks.
    if (log.isLoggable(Level.FINE)) {
      log.log(Level.FINE, String.format("building oauth2 request -> path = %s, host = %s, token = %s",
        parsedRequest.path(), parsedRequest.host(), token));
    }

    if (shouldAllowOAuth2.shouldAllowOAuth2(request, parsedRequest)) {
      return new UnpackedRequest.OAuth2Request(UrlCodec.decode(token), parsedRequest, "");
    } else {
      throw new MalformedRequest("OAuth 2.0 requests not allowed");
    }
  }
}

  /**
   * StandardUnpacker constants, and a few more convenience factory methods, for tests
   * that need to call methods of the StandardUnpacker directly.
   */
  static class StandardUnpackerFactory {

    public static StandardUnpacker newUnpacker() {
      return new StandardUnpacker(
        OAuthParams.STANDARD_OAUTH_PARAMS_HELPER,
        Normalizer.getStandardNormalizer(),
        KeyValueParser.QueryKeyValueParser,
        KeyValueParser.HeaderKeyValueParser
      );
    }

    public static StandardUnpacker newUnpacker(OAuthParams.OAuthParamsHelper helper) {
      return new StandardUnpacker(
        helper,
        Normalizer.getStandardNormalizer(),
        KeyValueParser.QueryKeyValueParser,
        KeyValueParser.HeaderKeyValueParser
      );
    }
  }

  class StandardUnpacker extends CustomizableUnpacker {

    final static KeyValueCallback callback = new KeyValueCallback() {
      @Override
      public KeyValueHandler invoke(KeyValueHandler kvHandler) {
        return new KeyValueHandler.UrlEncodingNormalizingKeyValueHandler(kvHandler);
      }
    };

    final static OAuth2Checker checker = new OAuth2Checker() {
      @Override
      public boolean shouldAllowOAuth2(Request request, Request.ParsedRequest parsedRequest) {
        return CustomizableUnpacker.HTTPS.equalsIgnoreCase(request.scheme());
      }
    };

    public StandardUnpacker(
      OAuthParams.OAuthParamsHelper helper,
      Normalizer normalizer,
      KeyValueParser queryParser,
      KeyValueParser headerParser
    ) {
      super(helper, normalizer, queryParser, headerParser, callback, callback, callback, checker);
    }
  }
}
