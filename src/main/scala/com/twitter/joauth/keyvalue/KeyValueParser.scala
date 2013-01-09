// Copyright 2011 Twitter, Inc.
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

/**
 * The KeyValueParser trait describes a parser that takes a String and a Seq[KeyValueHandler],
 * and calls each handler for each key/value pair encountered in the parsed String
 */
trait KeyValueParser extends ((String, Seq[KeyValueHandler]) => Unit)

/**
 * For testing. Calls the KeyValueParsers with the same List of key/value pairs every time
 */
class ConstKeyValueParser(pairs: List[(String, String)]) extends KeyValueParser {
  override def apply(str: String, handlers: Seq[KeyValueHandler]): Unit = {
    pairs.foreach { case (k, v) =>
      handlers.foreach(_(k, v))
    }
  }
}

/**
 * HeaderKeyValueParser is a KeyValueParser for Authorization headers
 */
object HeaderKeyValueParser extends StandardKeyValueParser("\\s*,\\s*", "\\s*=\\s*")

/**
 * QueryKeyValueParser is a KeyValueParser for a query string
 */
object QueryKeyValueParser extends StandardKeyValueParser("&", "=")

/**
 * StandardKeyValueParser is a KeyValueParser that splits a string on a delimiter,
 * and then splits each pair with the kvDelimiter. both delimiters can be java-style
 * regular expressions.
 */
class StandardKeyValueParser(delimiter: String, kvDelimiter: String) extends KeyValueParser {
  private[this] val delimiterRegex = delimiter.r
  private[this] val kvDelimiterRegex = kvDelimiter.r

  override def apply(str: String, handlers: Seq[KeyValueHandler]): Unit = {
    if (!empty(str)) {
      delimiterRegex.split(str).foreach { kvStr =>
        val kv = kvDelimiterRegex.split(kvStr)
        kv.length match {
          // don't call handler for empty keys
          case 2 if (!empty(kv(0))) => handlers.foreach(_(kv(0), kv(1)))
          case 1 if (!empty(kv(0))) => handlers.foreach(_(kv(0), ""))
          case _ =>
        }
      }
    }
  }

  protected[this] def empty(str: String) = str == null || str.length == 0
}