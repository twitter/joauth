package com.twitter.joauth.keyvalue

import collection.mutable.{HashMap, ArrayBuffer}

trait KeyValueHandler extends ((String, String) => Unit)

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