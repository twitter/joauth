package com.twitter.joauth

import java.net.URLEncoder

trait Normalizer {
  def apply(
    scheme: String, 
    host: String, 
    port: Int, 
    verb: String,
    path: String, 
    params: List[(String, String)], 
    oAuthParams: OAuthParams): String
}

class ConstNormalizer(const: String) extends Normalizer {
  def apply(
    scheme: String, 
    host: String, 
    port: Int,
    verb: String,
    path: String, 
    params: List[(String, String)], 
    oAuthParams: OAuthParams): String = const
}

object Normalizer {
  def apply(): Normalizer = new StandardNormalizer
}

class StandardNormalizer extends Normalizer {
  val URL_BASE = "%s://%s%s%s"
  val NORMALIZED_BASE = "%s&%s&%s"
  val HTTP = "HTTP"
  val HTTPS = "HTTPS"
  val AND = "&"
  val COLON = ":"
  val EQ_BASE = "%s=%s"

  def apply(
    scheme: String, 
    host: String, 
    port: Int,
    verb: String,
    path: String,
    params: List[(String, String)], 
    oAuthParams: OAuthParams): String = {
    // parameters are already URLEncoded, so we leave them alone
    val sigParams = params ::: oAuthParams.toListNoSignature
    val normalizedParams = sigParams.map(t => EQ_BASE.format(t._1, t._2)).sort(_ < _).mkString(AND)
    val requestURL = URL_BASE.format(scheme, host, getPortString(port, scheme), path).toLowerCase
    NORMALIZED_BASE.format(verb.toUpperCase, URLEncoder.encode(requestURL), URLEncoder.encode(normalizedParams))
  }
  
  def getPortString(port: Int, scheme: String): String = {
    val schemeUpper: String = scheme.toUpperCase
    val stripPort = (port == 80 && schemeUpper == HTTP) || (port == 443 && schemeUpper == HTTPS)
    if (stripPort) "" else COLON + port
  }
}