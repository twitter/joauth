package com.twitter.joauth

import collection.mutable.{HashMap, ArrayBuffer}

trait KeyValueHandler extends ((String, String) => Unit)
trait KeyValueFilter extends ((String, String) => Boolean)
trait Transformer extends ((String) => String)

object TrimTransformer extends Transformer {
  def apply(str: String) = str.trim
}

class DuplicateKeyValueHandler extends KeyValueHandler {
  private val buffer = new ArrayBuffer[(String, String)]
  override def apply(k: String, v: String): Unit = buffer += (k, v)
  def toList = buffer.toList
}

class SingleKeyValueHandler extends KeyValueHandler {
  private val kv = new HashMap[String, String]
  override def apply(k: String, v: String): Unit = kv += k -> v
  def toMap = Map(kv.toList:_*)
}

object QuotedSingleKeyValueHandler {
  val QUOTED_REGEX = """^\s*\"(.*)\"\s*$""".r
}
class QuotedValueKeyValueHandler(underlying: KeyValueHandler) extends KeyValueHandler {
  import QuotedSingleKeyValueHandler._
  override def apply(k: String, v: String): Unit = {
    v match {
      case QUOTED_REGEX(quotedV) => underlying(k, quotedV)
      case _ =>
    }
  }
}

class PrintlnKeyValueHandler(prefix: String) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = println("%s%s=%s".format(prefix, k, v))
}

class FilteredKeyValueHandler(
    underlying: KeyValueHandler, isValid: KeyValueFilter) extends KeyValueHandler{
  override def apply(k: String, v: String): Unit = if (isValid(k, v)) underlying(k, v)
}

class TransformingKeyValueHandler(
    underlying: KeyValueHandler, keyTransform: Transformer, valueTransform: Transformer) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = underlying(keyTransform(k), valueTransform(v))
}

class TrimmingKeyValueHandler(underlying: KeyValueHandler)
    extends TransformingKeyValueHandler(underlying, TrimTransformer, TrimTransformer)

class KeyTransformingKeyValueHandler(
    underlying: KeyValueHandler, keyTransform: Transformer) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = underlying(keyTransform(k), v)
}

class ValueTransformingKeyValueHandler(
    underlying: KeyValueHandler, valueTransform: Transformer) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = underlying(k, valueTransform(v))
}

class UrlEncodingNormalizingKeyValueHandler(underlying: KeyValueHandler)
    extends ValueTransformingKeyValueHandler(underlying, UrlEncodingNormalizingTransformer)

/* filter, then normalize, call underlying */
class NotOAuthKeyValueHandler(underlying: KeyValueHandler)
  extends FilteredKeyValueHandler(new UrlEncodingNormalizingKeyValueHandler(underlying), NotOAuthFieldFilter)

/* trim, filter, normalize, call underlying */
class OAuthKeyValueHandler(underlying: KeyValueHandler)
  extends TrimmingKeyValueHandler(new FilteredKeyValueHandler(new UrlEncodingNormalizingKeyValueHandler(underlying), OAuthFieldFilter))

/* trim, filter, transform key, call underlying */
class OAuth2HeaderKeyValueHandler(underlying: KeyValueHandler)
  extends TrimmingKeyValueHandler(
    new FilteredKeyValueHandler(
      new KeyTransformingKeyValueHandler(underlying, OAuth2KeyTransformer),
      OAuth2FieldFilter))

object OAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = OAuthUtils.isOAuthField(k) && v != ""
}

object NotOAuthFieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = !OAuthUtils.isOAuthField(k)
}

object OAuth2FieldFilter extends KeyValueFilter {
  def apply(k: String, v: String): Boolean = k == OAuthUtils.OAUTH2_HEADER_TOKEN && v != ""
}

object OAuth2KeyTransformer extends Transformer {
  def apply(str: String): String = if (str == OAuthUtils.OAUTH2_HEADER_TOKEN) OAuthUtils.OAUTH_TOKEN else str
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