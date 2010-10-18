package com.twitter.joauth

import java.net.URLDecoder
import java.net.URLEncoder

object UrlEncoder {
  val UTF_8 = "UTF-8"
  def apply(s: String) = if (s == null) null else URLEncoder.encode(s, UTF_8) 
}

trait UrlDecoder {
  def apply(s: String) = if (s == null) null else URLDecoder.decode(s, UrlEncoder.UTF_8) 
}
object UrlDecoder extends UrlDecoder