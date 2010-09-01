package com.twitter.joauth.keyvalue

trait Transformer extends ((String) => String)

object TrimTransformer extends Transformer {
  def apply(str: String) = str.trim
}

object OAuth2KeyTransformer extends Transformer {
  def apply(str: String): String = 
    if (str == OAuthParams.OAUTH2_HEADER_TOKEN) OAuthParams.OAUTH_TOKEN 
    else str
}

object UrlEncodingNormalizingTransformer extends Transformer {
  def apply(s: String) = {
    val normalized = new StringBuffer()
    var percented = 0
    s.foreach {char =>
      if (percented > 0) {
        normalized.append(Character.toUpperCase(char))
        percented -= 1
      } else if (char == '%') {
        percented = 2
        normalized.append(char)
      } else {
        normalized.append(char)
      }
    }
    normalized.toString
  }
}