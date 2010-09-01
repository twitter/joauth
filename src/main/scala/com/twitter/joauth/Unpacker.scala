package com.twitter.joauth

import com.twitter.joauth.keyvalue._
import javax.servlet.http.HttpServletRequest
import java.io.ByteArrayOutputStream

trait UriSchemeGetter extends ((HttpServletRequest) => String)

object StandardUriSchemeGetter extends UriSchemeGetter {
  def apply(request: HttpServletRequest): String = request.getScheme
}

trait PathGetter extends ((HttpServletRequest) => String)

object StandardPathGetter extends PathGetter {
  def apply(request: HttpServletRequest): String = request.getPathInfo
}

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
  def apply(): StandardUnpacker = 
    new StandardUnpacker(
      StandardUriSchemeGetter,
      StandardPathGetter,
      Normalizer(),
      new StandardKeyValueParser("&", "="),
      new StandardKeyValueParser("\\s*,\\s*", "\\s*=\\s*"))

  def apply(
    getScheme: UriSchemeGetter,
    getPath: PathGetter): StandardUnpacker = 
    new StandardUnpacker(
      getScheme,
      getPath,
      Normalizer(),
      new StandardKeyValueParser("&", "="),
      new StandardKeyValueParser("\\s*,\\s*", "\\s*=\\s*"))

  def apply(
      getScheme: UriSchemeGetter,
      getPath: PathGetter,
      normalizer: Normalizer,
      queryParser: KeyValueParser,
      headerParser: KeyValueParser): StandardUnpacker =
    new StandardUnpacker(getScheme, getPath, normalizer, queryParser, headerParser)
}

object StandardUnpacker {
  val AUTH_HEADER_REGEX = """^(\S+)\s+(.*)$""".r
  val POST = "POST"
  val WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"
  val AUTHORIZATION = "Authorization"
  val HTTPS = "HTTPS"
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
    val queryParser = new StandardKeyValueParser("&", "=")

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

    request.getHeader("Authorization") match {
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

    while (letti > 0) {
      stream.write(buf, 0, letti)
      letti = is.read(buf)
      totalBytesRead += letti
      if (totalBytesRead > request.getContentLength) {
        throw new IllegalStateException("more bytes in input stream than content-length specified")
      }
    }
    val result = new String(stream.toByteArray())
    result
  }
}