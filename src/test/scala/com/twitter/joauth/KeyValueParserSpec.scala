package com.twitter.joauth

import org.specs.mock.Mockito
import org.specs.Specification

class KeyValueParserSpec extends Specification with Mockito {
  val handler = mock[KeyValueHandler]

  "ConstKeyValueParser" should {
    "call handler with key values" in {
      val parser = new ConstKeyValueParser(List(("a", "b"), ("c", "d")))
      parser("foo", Seq(handler))
      handler.apply("a", "b") was called.once
      handler.apply("c", "d") was called.once
    }
  }

  "StandardKeyValueParser" should {
    val parser = new StandardKeyValueParser("&", "=")
    "not blow up on null string" in {
      parser(null, Seq(handler))
      handler.apply(any[String], any[String]) was notCalled
    }
    "not blow up on empty string" in {
      parser("", Seq(handler))
      handler.apply(any[String], any[String]) was notCalled
    }
    "parse simple string" in {
      parser("foo", Seq(handler))
      handler.apply("foo", "") was called.once
    }
    "parse valid pairs" in {
      parser("foo=bar&baz", Seq(handler))
      handler.apply("foo", "bar") was called.once
      handler.apply("baz", "") was called.once
    }
    "parse malformed pairs" in {
      parser("foo=bar&&baz&", Seq(handler))
      handler.apply("foo", "bar") was called.once
      handler.apply("baz", "") was called.once
    }
  }
}