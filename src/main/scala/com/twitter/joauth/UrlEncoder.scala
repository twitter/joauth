package com.twitter.joauth

import java.net.URLDecoder
import java.net.URLEncoder

object UrlEncoder {
  val UTF_8 = "UTF-8"
  def apply(s: String) = URLEncoder.encode(s, UTF_8) 
}

object UrlDecoder {
  def apply(s: String) = URLDecoder.decode(s, UrlEncoder.UTF_8) 
}