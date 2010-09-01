package com.twitter.joauth

import java.net.URLEncoder
import java.util.Date

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
  def apply(): Normalizer = StandardNormalizer
}

object StandardNormalizer extends StandardNormalizer

class StandardNormalizer extends Normalizer {
  val HTTP = "HTTP"
  val HTTPS = "HTTPS"
  val AND = "&"
  val COLON = ":"
  val EQ = "="
  val COLON_SLASH_SLASH = "://"

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
    val normalizedParams =
      sigParams.map(p => p._1+EQ+p._2).sort(_ < _).mkString(AND)
    val requestUrl = (scheme+COLON_SLASH_SLASH+host+getPortString(port,scheme)+path).toLowerCase
    verb.toUpperCase+AND+URLEncoder.encode(requestUrl)+AND+URLEncoder.encode(normalizedParams)
  }

  def getPortString(port: Int, scheme: String): String = {
    (port, scheme.toUpperCase) match {
      case (80, HTTP) => ""
      case (443, HTTPS) => ""
      case _ => COLON + port
    }
  }
}