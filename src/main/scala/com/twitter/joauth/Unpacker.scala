// Copyright 2010 Twitter, Inc.
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

import com.twitter.joauth.keyvalue._
import com.twitter.thrust.protocol.Post
import com.twitter.thrust.server.Request
import java.io.ByteArrayOutputStream

trait UnpackerHelper extends OAuthParamsHelper {
  /**
   * it's sometimes useful to override the scheme of the request in one way or another.
   */
  def getScheme(request: Request): String

  /**
   * it's sometimes useful to override the path of the request in one way or another.
   */
  def getPath(request: Request): String

  /**
   * allows custom logic for obtaining the port from the request
   */
  def getPort(request: Request): Int
}

/**
 * Provides the default implementation of the UnpackerHelper trait
 * Though stateless and threadsafe, this is a class rather than an object to allow easy
 * access from Java. Scala codebases should use the corresponding StandardUnpackerHelper
 * object instead.
 */
class StandardUnpackerHelper extends StandardOAuthParamsHelper with UnpackerHelper {
  override def getScheme(request: Request): String = request.scheme
  override def getPath(request: Request): String = request.path.toString
  override def getPort(request: Request): Int = request.serverPort
}

/**
 * the singleton object of StandardUnpackerHelper
 */
object StandardUnpackerHelper extends StandardUnpackerHelper

/**
 * An Unpacker takes an Request and optionally a Seq[KeyValueHandler],
 * and parses the request into an OAuthRequest instance, invoking each KeyValueHandler
 * for every key/value pair obtained from either the queryString or the POST data.
 * If no valid request can be obtained, an UnpackerException is thrown.
 */
trait Unpacker {
  @throws(classOf[UnpackerException])
  def apply(request: Request): OAuthRequest = apply(request, Seq())

  @throws(classOf[UnpackerException])
  def apply(request: Request, kvHandler: KeyValueHandler): OAuthRequest =
    apply(request, Seq(kvHandler))

  @throws(classOf[UnpackerException])
  def apply(equest: Request, kvHandlers: Seq[KeyValueHandler]): OAuthRequest
}

/**
 * for testing. Always returns the same result.
 */
class ConstUnpacker(result: OAuthRequest) extends Unpacker {
  override def apply(request: Request, kvHandlers: Seq[KeyValueHandler]): OAuthRequest = result
}

/**
 * A convenience factory for a StandardUnpacker
 */
object Unpacker {
  def apply(): Unpacker = StandardUnpacker()

  def apply(
      helper: UnpackerHelper,
      normalizer: Normalizer,
      queryParser: KeyValueParser,
      headerParser: KeyValueParser): Unpacker =
    new StandardUnpacker(helper, normalizer, queryParser, headerParser)
}

/**
 * StandardUnpacker constants, and a few more convenience factory methods, for tests
 * that need to call methods of the StandardUnpacker directly.
 */
object StandardUnpacker {
  val AUTH_HEADER_REGEX = """^(\S+)\s+(.*)$""".r
  val POST = "POST"
  val WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"
  val AUTHORIZATION = "Authorization"
  val HTTPS = "HTTPS"
  val UTF_8 = "UTF-8"

  def apply(): StandardUnpacker = new StandardUnpacker(
      StandardUnpackerHelper, Normalizer(), QueryKeyValueParser, HeaderKeyValueParser)

  def apply(helper: UnpackerHelper): StandardUnpacker =
    new StandardUnpacker(helper, Normalizer(), QueryKeyValueParser, HeaderKeyValueParser)
}

/**
 * the standard implmenentation of the Unpacker trait.
 *
 * WARNING: The StandardUnpacker will call the HttpRequest.getInputStream method if the method
 * of the request is POST and the Content-Type is "application/x-www-form-urlencoded." If you
 * need to read the POST yourself, this will cause you problems, since getInputStream/getReader
 * can only be called once. There are two solutions: (1) Write an HttpServletWrapper to buffer
 * the POST data and allow multiple calls to getInputStream, and pass the HttpServletWrapper
 * into the Unpacker. (2) Pass a KeyValueHandler into the unpacker call, which will let you
 * get the parameters in the POST as a side effect of unpacking.
 */
class StandardUnpacker(
    helper: UnpackerHelper,
    normalizer: Normalizer,
    queryParser: KeyValueParser,
    headerParser: KeyValueParser) extends Unpacker {

  import StandardUnpacker._

  @throws(classOf[UnpackerException])
  override def apply(request: Request, kvHandlers: Seq[KeyValueHandler]): OAuthRequest = {
    try {
      val (params, oAuthParams) = parseRequest(request, kvHandlers)

      if (oAuthParams.isOAuth2) {
        getOAuth2Request(request, params, oAuthParams.v2Token)
      } else if (oAuthParams.isOAuth1) {
        getOAuth1Request(request, params, oAuthParams)
      } else throw new UnknownAuthType("could not determine the authentication type")

    } catch {
      // just rethrow UnpackerExceptions
      case u: UnpackerException => throw u
      // wrap other Throwables in an UnpackerException
      case t: Throwable =>
        throw new UnpackerException("could not unpack request: " + t, t)
    }
  }

  @throws(classOf[MalformedRequest])
  def getOAuth1Request(
    request: Request,
    params: List[(String, String)],
    oAuthParams: OAuthParams): OAuth1Request = {
      OAuth1Request(
        ProcessedRequest(request, params, helper),
        oAuthParams,
        normalizer)
  }

  @throws(classOf[MalformedRequest])
  def getOAuth2Request(
      request: Request,
      params: List[(String, String)],
      token: String): OAuthRequest = {
    // OAuth 2.0 requests are totally insecure with SSL, so depend on HTTPS to provide
    // protection against replay and man-in-the-middle attacks. If you need to run
    // an authorization service that can't do HTTPS for some reason, you can define
    // a custom UriSchemeGetter to make the scheme pretend to be HTTPS for the purposes
    // of request validation
    if (helper.getScheme(request).toUpperCase == HTTPS)
      OAuth2Request(UrlDecoder(token), ProcessedRequest(request, params, helper))
    else throw new MalformedRequest("OAuth 2.0 requests must use HTTPS")
  }

  def parseRequest(request: Request, kvHandlers: Seq[KeyValueHandler]) = {
    // get all key/value pairs, allow duplicate values for keys
    val kvHandler = new DuplicateKeyValueHandler

    // filter out all the OAuth fields, which we'll collect separately
    val filteredKvHandler = new NotOAuthKeyValueHandler(kvHandler)

    // use an OAuthParams instance to accumulate OAuth key/values from
    // the query string, the POST (if the appropriate Content-Type), and
    // the Authorization header, if any.
    val oAuthParams = OAuthParams(helper)

    // filter out non-OAuth keys, and empty values
    val filteredOAuthKvHandler = new OAuthKeyValueHandler(oAuthParams)

    // add our handlers to the passed-in handlers, to which
    // we'll only send non-oauth key/values.
    val handlerSeq = Seq(filteredKvHandler, filteredOAuthKvHandler) ++
      kvHandlers.map(h => new NotOAuthKeyValueHandler(h))

    // parse the GET query string
    queryParser(request.queryString, handlerSeq)

    // parse the POST if the Content-Type is appropriate. Use the same
    // set of KeyValueHandlers that we used to parse the query string.
    if (request.method == Post &&
        request.contentType.isDefined &&
        request.contentType.get.startsWith(WWW_FORM_URLENCODED)) {
      queryParser(request.body, handlerSeq)
    }

    parseHeader(request.headers.get(AUTHORIZATION), filteredOAuthKvHandler)

    // now we just return the accumulated parameters and OAuthParams
    (kvHandler.toList, oAuthParams)
  }

  def parseHeader(header: Option[String], handler: KeyValueHandler): Unit = {
    // check for OAuth credentials in the header. OAuth 1.0a and 2.0 have
    // different header schemes, so match first on the auth scheme.
    header match {
      case Some(AUTH_HEADER_REGEX(authType, authString)) => {
        val shouldParse = authType.toLowerCase match {
          case OAuthParams.OAUTH2_HEADER_AUTHTYPE => true
          case OAuthParams.OAUTH1_HEADER_AUTHTYPE => true
          case _ => false
        }
        if (shouldParse) {
          // if we were able match an appropriate auth header,
          // we'll wrap that handler with a QuotedValueKeyValueHandler,
          // which will only pass quoted values to the underlying handler,
          // stripping the quotes on the way.
          val quotedHandler = new QuotedValueKeyValueHandler(handler)

          // oauth2 allows specification of the access token alone,
          // without a key, so we pass in a kvHandler that can detect this case
          val oneKeyOnlyHandler = new OneKeyOnlyKeyValueHandler

          // now we'll pass the handler to the headerParser,
          // which splits on commas rather than ampersands,
          // and is more forgiving with whitespace
          headerParser(authString, Seq(quotedHandler, oneKeyOnlyHandler))

          // if we did encounter exactly one key with an empty value, invoke
          // the underlying handler as if it were the token
          oneKeyOnlyHandler.key match {
            case Some(token) => handler(OAuthParams.ACCESS_TOKEN, token)
            case None =>
          }
        }
      }
      case None =>
    }
  }
}