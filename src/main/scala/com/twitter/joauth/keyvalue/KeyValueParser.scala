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
  def apply(str: String, handlers: Seq[KeyValueHandler]): Unit = {
    pairs.foreach(e => handlers.foreach(_(e._1, e._2)))
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
  def apply(str: String, handlers: Seq[KeyValueHandler]): Unit = {
    if (str == null || str.length == 0) return
    str.split(delimiter).foreach { kvStr =>
      val kv = kvStr.split(kvDelimiter)
      kv.length match {
        case 2 => handlers.foreach(_(kv(0), kv(1)))
        case 1 => handlers.foreach(_(kv(0), ""))
        case _ =>
      }
    }
  }
}