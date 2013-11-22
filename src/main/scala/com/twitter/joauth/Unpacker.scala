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

import org.slf4j.LoggerFactory
import com.twitter.joauth.keyvalue._

/**
 * An Unpacker takes an Request and optionally a Seq[KeyValueHandler],
 * and parses the request into an OAuthRequest instance, invoking each KeyValueHandler
 * for every key/value pair obtained from either the queryString or the request body.
 * If no valid request can be obtained, an UnpackerException is thrown.
 */
trait Unpacker[RequestImpl <: Request] {
  @throws(classOf[UnpackerException])
  def apply(request: RequestImpl): UnpackedRequest = apply(request, Seq())

  @throws(classOf[UnpackerException])
  def apply(request: RequestImpl, kvHandler: KeyValueHandler): UnpackedRequest =
    apply(request, Seq(kvHandler))

  @throws(classOf[UnpackerException])
  def apply(request: RequestImpl, kvHandlers: Seq[KeyValueHandler]): UnpackedRequest
}

/**
 * for testing. Always returns the same result.
 */
class ConstUnpacker[RequestImpl <: Request](result: OAuthRequest) extends Unpacker[RequestImpl] {
  override def apply(request: RequestImpl, kvHandlers: Seq[KeyValueHandler]): OAuthRequest = result
}

/**
 * A convenience factory for a StandardUnpacker
 */
object Unpacker {
  def apply(): Unpacker[Request] = StandardUnpacker()

  def apply(
    helper: OAuthParamsHelper,
    normalizer: Normalizer,
    queryParser: KeyValueParser,
    headerParser: KeyValueParser): Unpacker[Request] =
  new StandardUnpacker[Request](helper, normalizer, queryParser, headerParser)
}

object CustomizableUnpacker {
  val AUTH_HEADER_REGEX = """^(\S+)\s+(.*)$""".r
  val WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"
  val HTTPS = "HTTPS"
  val UTF_8 = "UTF-8"

  private val log = LoggerFactory.getLogger(getClass.getName)

}

class CustomizableUnpacker[RequestImpl <: Request](
  helper: OAuthParamsHelper,
  normalizer: Normalizer,
  queryParser: KeyValueParser,
  headerParser: KeyValueParser,
  queryParamTransformer: KeyValueHandler => TransformingKeyValueHandler,
  bodyParamTransformer: KeyValueHandler => TransformingKeyValueHandler,
  headerTransformer: KeyValueHandler => TransformingKeyValueHandler,
  shouldAllowOAuth2: (RequestImpl, Request.ParsedRequest) => Boolean =
    (_: RequestImpl, p: Request.ParsedRequest) => p.scheme == CustomizableUnpacker.HTTPS
) extends Unpacker[RequestImpl] {

  import CustomizableUnpacker._

  @throws(classOf[UnpackerException])
  override def apply(request: RequestImpl, kvHandlers: Seq[KeyValueHandler]): UnpackedRequest = {
    try {
      val oAuthParamsBuilder = parseRequest(request, kvHandlers)
      val parsedRequest = request.parsedRequest(oAuthParamsBuilder.otherParams)

      if (oAuthParamsBuilder.isOAuth2) {
        getOAuth2Request(request, parsedRequest, oAuthParamsBuilder.oAuth2Token)
      } else if (oAuthParamsBuilder.isOAuth1) {
        getOAuth1Request(parsedRequest, oAuthParamsBuilder.oAuth1Params)
      } else if (oAuthParamsBuilder.isOAuth1TwoLegged) {
        getOAuth1TwoLeggedRequest(parsedRequest, oAuthParamsBuilder.oAuth1Params)
      } else UnknownRequest(parsedRequest)

    } catch {
      // just rethrow UnpackerExceptions
      case u: UnpackerException => throw u
      // wrap other Throwables in an UnpackerException
      case t: Throwable => t.printStackTrace;
        throw new UnpackerException("could not unpack request: " + t, t)
    }
  }

  @throws(classOf[MalformedRequest])
  def getOAuth1Request(
    parsedRequest: Request.ParsedRequest, oAuth1Params: OAuth1Params): OAuth1Request = {
    log.debug("building oauth1 request -> path = {}, host = {}, token = {}, consumer key = {}, signature = {}, method = {}",
      parsedRequest.path, parsedRequest.host, oAuth1Params.token,
      oAuth1Params.consumerKey, oAuth1Params.signature, oAuth1Params.signatureMethod)
    OAuth1Request.buildOAuth1Request(parsedRequest, oAuth1Params, normalizer)
  }

  @throws(classOf[MalformedRequest])
  def getOAuth1TwoLeggedRequest(
    parsedRequest: Request.ParsedRequest, oAuth1Params: OAuth1Params): OAuth1TwoLeggedRequest = {
    log.debug("building oauth1 two-legged request -> path = {}, host = {}, consumer key = {}, signature = {}, method = {}",
      parsedRequest.path, parsedRequest.host, oAuth1Params.consumerKey,
      oAuth1Params.signature, oAuth1Params.signatureMethod)
    OAuth1Request.buildOAuth1TwoLeggedRequest(parsedRequest, oAuth1Params, normalizer)
  }

  @throws(classOf[MalformedRequest])
  def getOAuth2Request(request: RequestImpl, parsedRequest: Request.ParsedRequest, token: String): OAuth2Request = {
    // OAuth 2.0 requests are totally insecure without SSL, so depend on HTTPS to provide
    // protection against replay and man-in-the-middle attacks.
    log.debug("building oauth2 request -> path = {}, host = {}, token = {}",
      parsedRequest.path, parsedRequest.host, token)
    if (shouldAllowOAuth2(request, parsedRequest)) OAuth2Request(UrlCodec.decode(token), parsedRequest)
    else throw new MalformedRequest("OAuth 2.0 requests not allowed")
  }

  private[this] def createKeyValueHandler(
    kvHandler: KeyValueHandler,
    transformer: KeyValueHandler => TransformingKeyValueHandler
  ) = {
    new KeyTransformingKeyValueHandler(
      new TrimmingKeyValueHandler(transformer(kvHandler)),
      helper.processKey _)
  }

  protected[this] def queryParamKeyValueHandler(kvHandler: KeyValueHandler) = {
    createKeyValueHandler(kvHandler, queryParamTransformer)
  }

  protected[this] def bodyParamKeyValueHandler(kvHandler: KeyValueHandler) = {
    createKeyValueHandler(kvHandler, bodyParamTransformer)
  }

  protected[this] def headerParamKeyValueHandler(kvHandler: KeyValueHandler) = {
    createKeyValueHandler(kvHandler, headerTransformer)
  }

  def parseRequest(request: RequestImpl, kvHandlers: Seq[KeyValueHandler]): OAuthParamsBuilder = {
    // use an oAuthParamsBuilder instance to accumulate key/values from
    // the query string, the request body (if the appropriate Content-Type),
    // and the Authorization header, if any.
    val oAuthParamsBuilder = new OAuthParamsBuilder(helper)

    // parse the header, if present
    parseHeader(Some(request.authHeader), oAuthParamsBuilder.headerHandler)

    // If it is an oAuth2 we do not need to process any further
    if (!oAuthParamsBuilder.isOAuth2) {

      // add our handlers to the passed-in handlers, to which
      // we'll only send non-oauth key/values.
      val queryHandlers: Seq[KeyValueHandler] = queryParamKeyValueHandler(oAuthParamsBuilder.queryHandler) +: kvHandlers
      val bodyParamHandlers = bodyParamKeyValueHandler(oAuthParamsBuilder.queryHandler) +: kvHandlers

      // parse the GET query string
      queryParser(request.queryString, queryHandlers)

      // parse the request body if the Content-Type is appropriate. Use the
      // same set of KeyValueHandlers that we used to parse the query string.
      if (request.contentType != null &&
          request.contentType.startsWith(WWW_FORM_URLENCODED)) {
        queryParser(request.body, bodyParamHandlers)
      }
    }

    // now we just return the accumulated parameters and OAuthParams
    oAuthParamsBuilder
  }

  def parseHeader(header: Option[String], nonTransformingHandler: KeyValueHandler): Unit = {
    // trim, normalize encodings
    val handler = headerParamKeyValueHandler(nonTransformingHandler)

    // check for OAuth credentials in the header. OAuth 1.0a and 2.0 have
    // different header schemes, so match first on the auth scheme.
    header match {
      case Some(AUTH_HEADER_REGEX(authType, authString)) => {
        val (shouldParse, oauth2) = authType.toLowerCase match {
          case OAuthParams.OAUTH2_HEADER_AUTHTYPE => (false, true)
          case OAuthParams.OAUTH1_HEADER_AUTHTYPE => (true, false)
          case _ => (false, false)
        }
        if (shouldParse) {
          // if we were able match an appropriate auth header,
          // we'll wrap that handler with a MaybeQuotedValueKeyValueHandler,
          // which will strip quotes from quoted values before passing
          // to the underlying handler
          val quotedHandler = new MaybeQuotedValueKeyValueHandler(handler)

          // now we'll pass the handler to the headerParser,
          // which splits on commas rather than ampersands,
          // and is more forgiving with whitespace
          headerParser(authString, Seq(quotedHandler))

        } else if (oauth2) {
          nonTransformingHandler(OAuthParams.BEARER_TOKEN, authString)
        }
      }
      case _ =>
    }
  }
}

/**
 * StandardUnpacker constants, and a few more convenience factory methods, for tests
 * that need to call methods of the StandardUnpacker directly.
 */
object StandardUnpacker {
  val AUTH_HEADER_REGEX = CustomizableUnpacker.AUTH_HEADER_REGEX
  val WWW_FORM_URLENCODED = CustomizableUnpacker.WWW_FORM_URLENCODED
  val HTTPS = CustomizableUnpacker.HTTPS
  val UTF_8 = CustomizableUnpacker.UTF_8

  def apply(): StandardUnpacker[Request] = new StandardUnpacker[Request](
    StandardOAuthParamsHelper, Normalizer(), QueryKeyValueParser, HeaderKeyValueParser)

  def apply(helper: OAuthParamsHelper): StandardUnpacker[Request] =
    new StandardUnpacker[Request](helper, Normalizer(), QueryKeyValueParser, HeaderKeyValueParser)
}

class StandardUnpacker[RequestImpl <: Request](
  helper: OAuthParamsHelper,
  normalizer: Normalizer,
  queryParser: KeyValueParser,
  headerParser: KeyValueParser)
extends CustomizableUnpacker[RequestImpl](
  helper,
  normalizer,
  queryParser,
  headerParser,
  (kvHandler: KeyValueHandler) => new UrlEncodingNormalizingKeyValueHandler(kvHandler),
  (kvHandler: KeyValueHandler) => new UrlEncodingNormalizingKeyValueHandler(kvHandler),
  (kvHandler: KeyValueHandler) => new UrlEncodingNormalizingKeyValueHandler(kvHandler),
  (_: RequestImpl, p: Request.ParsedRequest) => p.scheme == StandardUnpacker.HTTPS
)
