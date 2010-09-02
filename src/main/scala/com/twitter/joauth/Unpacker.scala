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
import javax.servlet.http.HttpServletRequest
import java.io.ByteArrayOutputStream

trait UriSchemeGetter extends ((HttpServletRequest) => String)

class StandardUriSchemeGetter extends UriSchemeGetter {
  def apply(request: HttpServletRequest): String = request.getScheme
}
object StandardUriSchemeGetter extends StandardUriSchemeGetter

trait PathGetter extends ((HttpServletRequest) => String)

class StandardPathGetter extends PathGetter {
  def apply(request: HttpServletRequest): String = request.getPathInfo
}
object StandardPathGetter extends StandardPathGetter

trait Unpacker {
  @throws(classOf[UnpackerException])
  def apply(request: HttpServletRequest): OAuthRequest = apply(request, Seq())
  def apply(
      request: HttpServletRequest,
      kvHandlers: Seq[KeyValueHandler]): OAuthRequest
}

class ConstUnpacker(result: OAuthRequest) extends Unpacker {
  def apply(
      request: HttpServletRequest,
      kvHandlers: Seq[KeyValueHandler]): OAuthRequest = result
}

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
      case u:UnpackerException => throw u
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
    if (getScheme(request).toUpperCase == HTTPS) new OAuth2Request(token)
    else throw new MalformedRequest("OAuth 2.0 requests must use HTTPS")
  }

  def parseRequest(request: HttpServletRequest, kvHandlers: Seq[KeyValueHandler]) = {
    val kvHandler = new DuplicateKeyValueHandler
    val filteredKvHandler = new NotOAuthKeyValueHandler(kvHandler)

    val oAuthParams = new OAuthParams
    val filteredOAuthKvHandler = new OAuthKeyValueHandler(oAuthParams)
    val handlerSeq = Seq(filteredKvHandler, filteredOAuthKvHandler) ++ 
      kvHandlers.map(h => new NotOAuthKeyValueHandler(h))

    queryParser(request.getQueryString, handlerSeq)

    if (request.getMethod.toUpperCase == POST &&
        request.getContentType != null &&
        request.getContentType.startsWith(WWW_FORM_URLENCODED)) {
      queryParser(getPostData(request), handlerSeq)
    }

    request.getHeader(AUTHORIZATION) match {
      case AUTH_HEADER_REGEX(authType, authString) => {
        val headerHandler = authType.toLowerCase match {
          case OAuthParams.OAUTH2_HEADER_AUTHTYPE => 
            Some(new OAuth2HeaderKeyValueHandler(filteredOAuthKvHandler))
          case OAuthParams.OAUTH1_HEADER_AUTHTYPE => Some(filteredOAuthKvHandler)
          case _ => None
        }
        headerHandler match {
          case Some(handler) => {
            val quotedHandler = new QuotedValueKeyValueHandler(handler)
            headerParser(authString, Seq(quotedHandler))
          }
          case None =>
        }
      }
      case _ =>
    }

    (kvHandler.toList, oAuthParams)
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