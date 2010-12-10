// Copyright 2010 Twitter, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package com.twitter.joauth.keyvalue

import collection.mutable.{HashMap, ListBuffer}

/**
 * KeyValueHandler is a trait for a callback with a key and a value.
 * What you do with the key and value are up to you.
 */
trait KeyValueHandler extends ((String, String) => Unit)

/**
 * DuplicateKeyValueHandler produces a List[(String, String)] of key
 * value pairs, allowing duplicate values for keys.
 */
class DuplicateKeyValueHandler extends KeyValueHandler {
  private val buffer = new ListBuffer[(String, String)]
  override def apply(k: String, v: String): Unit = buffer += ((k, v))
  def toList = buffer.toList
}

/**
 * SingleKeyValueHandler produces either a List[(String, String)]
 * or a Map[String, String] of key/value pairs, and will override
 * duplicate values for keys, using the last value encountered
 */
class SingleKeyValueHandler extends KeyValueHandler {
  private val kv = new HashMap[String, String]
  override def apply(k: String, v: String): Unit = kv += k -> v
  def toMap = Map(kv.toList: _*)
  def toList = kv.toList
}

/**
 * key is set iff the handler was invoked exactly once with an empty value
 */
class OneKeyOnlyKeyValueHandler extends KeyValueHandler {
  private var invoked = false
  private var _key: Option[String] = None

  override def apply(k: String, v: String): Unit = {
    if (invoked) {
      if (_key.isDefined) _key = None
    } else {
      invoked = true
      if (v == null || v == "") _key = Some(k)
    }
  }

  def key = _key
}

/**
 * The QuotedValueKeyValueHandler passes only quoted strings to its
 * underlying KeyValueHandler, removing the quotes along the way.
 * Unquoted strings are blackholed. Note that this could have been
 * implemented as a composition of a FilteringKeyValueHandler and a
 * TransformingKeyValueHandler, but it was easier to do the filter
 * and transform in a single pass
 */
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

/**
 * PrintlnKeyValueHandler is very nice for debugging!
 * Pass it in to the Unpacker to see what's going on.
 */
class PrintlnKeyValueHandler(prefix: String) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = println("%s%s=%s".format(prefix, k, v))
}

/**
 * FilteredKeyValueHandler applies the KeyValueFilter to each
 * key value pair, and only calls the underlying KeyValueHandler
 * if the filter returns true
 */
class FilteredKeyValueHandler(
    underlying: KeyValueHandler, isValid: KeyValueFilter) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = if (isValid(k, v)) underlying(k, v)
}

/**
 * TransformingKeyValueHandler applies the Transformers to
 * their respective key and value before passing along to the
 * underlying KeyValueHandler
 */
class TransformingKeyValueHandler(
    underlying: KeyValueHandler,
    keyTransform: Transformer,
    valueTransform: Transformer) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = underlying(keyTransform(k), valueTransform(v))
}

/**
 * TrimmingKeyValueHandler trims the key and value before
 * passing them to the underlying KeyValueHandler
 */
class TrimmingKeyValueHandler(underlying: KeyValueHandler)
    extends TransformingKeyValueHandler(underlying, TrimTransformer, TrimTransformer)

/**
 * KeyTransformingKeyValueHandler applies a Transformer to the key
 * before passing the key value pair to the underlying KeyValueHandler
 */
class KeyTransformingKeyValueHandler(
    underlying: KeyValueHandler, keyTransform: Transformer) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = underlying(keyTransform(k), v)
}

/**
 * ValueTransformingKeyValueHandler applies a Transformer to the value
 * before passing the key value pair to the underlying KeyValueHandler
 */
class ValueTransformingKeyValueHandler(
    underlying: KeyValueHandler, valueTransform: Transformer) extends KeyValueHandler {
  override def apply(k: String, v: String): Unit = underlying(k, valueTransform(v))
}

/**
 * UrlEncodingNormalizingKeyValueHandler normalizes URLEncoded
 * keys and values, to properly capitalize them
 */
class UrlEncodingNormalizingKeyValueHandler(underlying: KeyValueHandler)
    extends ValueTransformingKeyValueHandler(underlying, UrlEncodingNormalizingTransformer)