package com.twitter.joauth

trait OAuthRequest {
  def token: String
}

case class OAuth1Request(
  override val token: String,
  consumerKey: String,
  nonce: String,
  timestamp: Long,
  signature: String,
  signatureMethod: String,
  version: String,
  normalizedRequest: String) extends OAuthRequest

case class OAuth2Request(override val token: String) extends OAuthRequest

object OAuth1Request {
  def nullException(name: String) = new MalformedRequest("no value for %s".format(name))

  @throws(classOf[MalformedRequest])
  def apply(
    scheme: String, 
    host: String, 
    port: Int,
    verb: String,
    path: String,
    params: List[(String, String)], 
    oAuthParams: OAuthParams,
    normalize: Normalizer): OAuth1Request = {
    if (scheme == null) throw nullException("scheme")
    else if (host == null) throw nullException("host")
    else if (port < 0) throw nullException("port")
    else if (verb == null) throw nullException("verb")
    else if (path == null) throw nullException("path")
    else if (oAuthParams.signatureMethod != OAuthParams.HMAC_SHA1)
    throw new MalformedRequest(
      "unsupported signature method: %s".format(oAuthParams.signatureMethod))
    else if (oAuthParams.version != OAuthParams.ONE_DOT_OH)
    throw new MalformedRequest(
      "unsupported oauth version: %s".format(oAuthParams.version))
    else new OAuth1Request(
      oAuthParams.token,
      oAuthParams.consumerKey,
      oAuthParams.nonce,
      oAuthParams.timestamp.toInt,
      oAuthParams.signature,
      oAuthParams.signatureMethod,
      oAuthParams.version,
      normalize(scheme, host, port, verb, path, params, oAuthParams))
  }
}