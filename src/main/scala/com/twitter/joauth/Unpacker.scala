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
import java.io.ByteArrayOutputStream
import javax.servlet.http.HttpServletRequest

/**
 * it's sometimes useful to override the scheme of the request in one way or another.
 * Passing a custom class that extends UriSchemeGetter will allow this.
 */
trait UriSchemeGetter extends ((HttpServletRequest) => String)

/**
 * The StandardUriSchemeGetter class obtains the scheme by calling request.getScheme.
 * Though stateless and threadsafe, this is a class rather than an object to allow easy
 * access from Java. Scala codebases should use the corresponding StandardPathGetter
 * object instead.
 */
class StandardUriSchemeGetter extends UriSchemeGetter {
  def apply(request: HttpServletRequest): String = request.getScheme
}

/**
 * a singleton of the StandardPathGetter class
 */
object StandardUriSchemeGetter extends StandardUriSchemeGetter

/**
 * it's sometimes useful to override the path of the request in one way or another.
 * Passing a custom class that extends PathGetter will allow this.
 */
trait PathGetter extends ((HttpServletRequest) => String)

/**
 * The StandardPathGetter class obtains the path by calling request.getPathInfo.
 * Though stateless and threadsafe, this is a class rather than an object to allow easy
 * access from Java. Scala codebases should use the corresponding StandardPathGetter
 * object instead.
 */
class StandardPathGetter extends PathGetter {
  def apply(request: HttpServletRequest): String = request.getPathInfo
}

/**
 * a singleton of the StandardPathGetter class
 */
object StandardPathGetter extends StandardPathGetter

/**
 * An Unpacker takes an HttpServletRequest and optionally a Seq[KeyValueHandler],
 * and parses the request into an OAuthRequest instance, invoking each KeyValueHandler
 * for every key/value pair obtained from either the queryString or the POST data.
 * If no valid request can be obtained, an UnpackerException is thrown.
 */
trait Unpacker {
  @throws(classOf[UnpackerException])
  def apply(request: HttpServletRequest): OAuthRequest = apply(request, Seq())
  @throws(classOf[UnpackerException])
  def apply(
      request: HttpServletRequest,
      kvHandler: KeyValueHandler): OAuthRequest = apply(request, Seq(kvHandler))
  @throws(classOf[UnpackerException])
  def apply(
      request: HttpServletRequest,
      kvHandlers: Seq[KeyValueHandler]): OAuthRequest
}

/**
 * for testing. Always returns the same result.
 */
class ConstUnpacker(result: OAuthRequest) extends Unpacker {
  def apply(
      request: HttpServletRequest,
      kvHandlers: Seq[KeyValueHandler]): OAuthRequest = result
}

/**
 * A convenience factory for a StandardUnpacker
 */
object Unpacker {
  def apply(): Unpacker = StandardUnpacker()

  def apply(getScheme: UriSchemeGetter, getPath: PathGetter): Unpacker =
    StandardUnpacker(getScheme, getPath)

  def apply(
      getScheme: UriSchemeGetter,
      getPath: PathGetter,
      normalizer: Normalizer,
      queryParser: KeyValueParser,
      headerParser: KeyValueParser): Unpacker =
    new StandardUnpacker(getScheme, getPath, normalizer, queryParser, headerParser)
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
    StandardUriSchemeGetter,
    StandardPathGetter,
    Normalizer(),
    QueryKeyValueParser,
    HeaderKeyValueParser)

  def apply(
    getScheme: UriSchemeGetter,
    getPath: PathGetter): StandardUnpacker = new StandardUnpacker(
      getScheme,
      getPath,
      Normalizer(),
      QueryKeyValueParser,
      HeaderKeyValueParser)
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
    getScheme: UriSchemeGetter,
    getPath: PathGetter,
    normalizer: Normalizer,
    queryParser: KeyValueParser,
    headerParser: KeyValueParser) extends Unpacker {
  import StandardUnpacker._

  @throws(classOf[UnpackerException])
  def apply(
    request: HttpServletRequest, 
    kvHandlers: Seq[KeyValueHandler]): OAuthRequest = {

    try {
      val (params, oAuthParams) = parseRequest(request, kvHandlers)

      if (oAuthParams.areAllOAuth1FieldsSet) {
        getOAuth1Request(request, params, oAuthParams)
      } else if (oAuthParams.isOnlyOAuthTokenSet) {
        getOAuth2Request(request, oAuthParams.token)
      } else throw new UnknownAuthType("could not determine the authentication type")

    } catch {
      // just rethrow UnpackerExceptions
      case u:UnpackerException => throw u
      // wrap other Throwables in an UnpackerException
      case t:Throwable => throw new UnpackerException("could not unpack request: " + t, t)
    }
  }

  @throws(classOf[MalformedRequest])
  def getOAuth1Request(
    request: HttpServletRequest,
    params: List[(String, String)],
    oAuthParams: OAuthParams): OAuth1Request = {
      OAuth1Request(
        getScheme(request).toUpperCase,
        request.getServerName,
        request.getServerPort,
        request.getMethod.toUpperCase,
        getPath(request),
        params, 
        oAuthParams,
        normalizer)
  }

  @throws(classOf[MalformedRequest])
  def getOAuth2Request(
      request: HttpServletRequest, token: String): OAuthRequest = {
    // OAuth 2.0 requests are totally insecure with SSL, so depend on HTTPS to provide
    // protection against replay and man-in-the-middle attacks. If you need to run
    // an authorization service that can't do HTTPS for some reason, you can define
    // a custom UriSchemeGetter to make the scheme pretend to be HTTPS for the purposes
    // of request validation
    if (getScheme(request).toUpperCase == HTTPS) new OAuth2Request(token)
    else throw new MalformedRequest("OAuth 2.0 requests must use HTTPS")
  }

  def parseRequest(request: HttpServletRequest, kvHandlers: Seq[KeyValueHandler]) = {
    // get all key/value pairs, allow duplicate values for keys
    val kvHandler = new DuplicateKeyValueHandler

    // filter out all the OAuth fields, which we'll collect separately
    val filteredKvHandler = new NotOAuthKeyValueHandler(kvHandler)

    // use an OAuthParams instance to accumulate OAuth key/values from
    // the query string, the POST (if the appropriate Content-Type), and
    // the Authorization header, if any.
    val oAuthParams = new OAuthParams

    // filter out non-OAuth keys, and empty values
    val filteredOAuthKvHandler = new OAuthKeyValueHandler(oAuthParams)

    // add our handlers to the passed-in handlers, to which
    // we'll only send non-oauth key/values.
    val handlerSeq = Seq(filteredKvHandler, filteredOAuthKvHandler) ++ 
      kvHandlers.map(h => new NotOAuthKeyValueHandler(h))

    // parse the GET query string
    queryParser(request.getQueryString, handlerSeq)

    // parse the POST if the Content-Type is appropriate. Use the same
    // set of KeyValueHandlers that we used to parse the query string.
    if (request.getMethod.toUpperCase == POST &&
        request.getContentType != null &&
        request.getContentType.startsWith(WWW_FORM_URLENCODED)) {
      queryParser(getPostData(request), handlerSeq)
    }

    parseHeader(request.getHeader(AUTHORIZATION), filteredOAuthKvHandler)

    // now we just return the accumulated parameters and OAuthParams
    (kvHandler.toList, oAuthParams)
  }

  def parseHeader(header: String, filteredOAuthKvHandler: KeyValueHandler): Unit = {
    // check for OAuth credentials in the header. OAuth 1.0a and 2.0 have
    // different header schemes, so match first on the auth scheme.
    header match {
      case AUTH_HEADER_REGEX(authType, authString) => {
        val headerHandler = authType.toLowerCase match {

          // if the auth scheme is OAuth 2.0, we want to parse the header,
          // pull out only the token="<TOKEN>" pair, and map it to oauth_token,
          // and pass it to our existing OAuth KeyValueHandler.
          case OAuthParams.OAUTH2_HEADER_AUTHTYPE => 
            Some(new OAuth2HeaderKeyValueHandler(filteredOAuthKvHandler))

          // otherwise, we'll send all the key/value paris directly
          // to the OAuth KeyValueHandler
          case OAuthParams.OAUTH1_HEADER_AUTHTYPE => Some(filteredOAuthKvHandler)
          case _ => None
        }
        headerHandler match {
          case Some(handler) => {

            // finally, if we were able to determine the auth type and produce
            // a handler, we'll wrap that handler with a QuotedValueKeyValueHandler,
            // which will only pass quoted values to the underlying handler,
            // stripping the quotes on the way.
            val quotedHandler = new QuotedValueKeyValueHandler(handler)

            // now we'll pass the handler to the headerParser,
            // which splits on commas rather than ampersands,
            // and is more forgiving with whitespace
            headerParser(authString, Seq(quotedHandler))
          }
          case None =>
        }
      }
      case _ =>
    }
  }

  def getPostData(request: HttpServletRequest) = {
    val is = request.getInputStream
    val stream = new ByteArrayOutputStream()
    val buf = new Array[Byte](4 * 1024)
    var letti = is.read(buf)
    var totalBytesRead = 0
    
    val characterEncoding = request.getCharacterEncoding() match {
      case null => UTF_8
      case encoding => encoding
    }

    // make sure the Content-Length isn't a lie
    while (letti > 0) {
      stream.write(buf, 0, letti)
      letti = is.read(buf)
      totalBytesRead += letti
      if (totalBytesRead > request.getContentLength) {
        throw new IllegalStateException("more bytes in input stream than content-length specified")
      }
    }
    val result = new String(stream.toByteArray(), characterEncoding)
    result
  }
}