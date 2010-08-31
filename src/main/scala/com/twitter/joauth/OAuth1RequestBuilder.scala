package com.twitter.joauth

import java.net.URLEncoder

object OAuth1RequestBuilder {
  def nullException(name: String) = new MalformedRequest("no value for %s".format(name))
}
class OAuth1RequestBuilder(params: List[(String, String)], oAuthParams: OAuthParams) {
  import OAuth1RequestBuilder._

  var scheme: String = null
  var host: String = null
  var port: Int = -1
  var verb: String = null
  var path: String = null

  @throws(classOf[MalformedRequest])
  def build(): OAuth1Request = {
    if (scheme == null) throw nullException("scheme")
    else if (host == null) throw nullException("host")
    else if (port < 0) throw nullException("port")
    else if (verb == null) throw nullException("verb")
    else if (path == null) throw nullException("path")
    else if (oAuthParams.signatureMethod != OAuthUtils.HMAC_SHA1)
      throw new MalformedRequest("unsupported signature method: %s".format(oAuthParams.signatureMethod))
    else if (oAuthParams.version != OAuthUtils.ONE_DOT_OH)
      throw new MalformedRequest("unsupported oauth version: %s".format(oAuthParams.version))
    else new OAuth1Request(
      oAuthParams.token,
      oAuthParams.consumerKey,
      oAuthParams.nonce,
      oAuthParams.timestamp.toInt,
      oAuthParams.signature,
      oAuthParams.signatureMethod,
      oAuthParams.version,
      getNormalizedRequest)
  }

  def getPortString(port: Int, scheme: String): String = {
    val schemeLower: String = scheme.toLowerCase
    val stripPort = (port == 80 && schemeLower == "http") || (port == 443 && schemeLower == "https")
    if (stripPort) "" else ":" + port
  }

  def getNormalizedRequest: String = {
    // parameters are already URLEncoded, so we leave them alone
    val sigParams = params ::: oAuthParams.toListNoSignature
    val normalizedParams = sigParams.map(t => t._1 + "=" + t._2).sort(_ < _).mkString("&")
    val requestURL = "%s://%s%s%s".format(scheme, host, getPortString(port, scheme), path).toLowerCase
    "%s&%s&%s".format(verb.toUpperCase, URLEncoder.encode(requestURL), URLEncoder.encode(normalizedParams))
  }
}

