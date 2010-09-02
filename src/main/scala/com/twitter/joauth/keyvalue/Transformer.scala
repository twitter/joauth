package com.twitter.joauth.keyvalue

/**
 * The Transformer trait describes the transformation function from a string to a derived string
 */
trait Transformer extends ((String) => String)

/**
 * The TrimTransformer trims the string
 */
object TrimTransformer extends Transformer {
  def apply(str: String) = str.trim
}

/**
 * The OAuth2KeyTransformer trims the "token" to "oauth_token", which is handy 
 * when passing an OAuth2 Authorization header into the same KeyValueHandler you're 
 * parsing the query string into
 */
object OAuth2KeyTransformer extends Transformer {
  def apply(str: String): String = 
    if (str == OAuthParams.OAUTH2_HEADER_TOKEN) OAuthParams.OAUTH_TOKEN 
    else str
}

/**
 * The UrlEncodingNormalizingTransformer capitializes all of the URLEncoded entities in a string. 
 * It will do strange things to a string that is not actually URLEncoded.
 */
object UrlEncodingNormalizingTransformer extends Transformer {
  def apply(s: String) = {
    val normalized = new StringBuilder()
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