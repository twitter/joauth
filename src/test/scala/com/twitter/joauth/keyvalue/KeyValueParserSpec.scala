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

import org.specs.mock.Mockito
import org.specs.SpecificationWithJUnit
import com.twitter.joauth.{ConversionUtil, Request}

class KeyValueParserSpec extends SpecificationWithJUnit with Mockito {
  val handler = mock[KeyValueHandler]
  val handlers = ConversionUtil.toArrayList(Seq(handler))

  "ConstKeyValueParser" should {
    "call handler with key values" in {
      val parser = new KeyValueParser.ConstKeyValueParser(ConversionUtil.toArrayList(List(new Request.Pair("a", "b"), new Request.Pair("c", "d"))))
      parser.parse("foo", handlers)
      there was one(handler).handle("a", "b")
      there was one(handler).handle("c", "d")
    }
  }

  "StandardKeyValueParser" should {
    val parser = KeyValueParser.QueryKeyValueParser
    "not blow up on null string" in {
      parser.parse(null, handlers)
      there was no(handler).handle(any[String], any[String])
    }
    "not blow up on empty string" in {
      parser.parse("", handlers)
      there was no(handler).handle(any[String], any[String])
    }
    "parse simple string" in {
      parser.parse("foo", handlers)
      there was one(handler).handle("foo", "")
    }
    "parse valid pairs" in {
      parser.parse("foo=bar&baz", handlers)
      there was one(handler).handle("foo", "bar")
      there was one(handler).handle("baz", "")
    }
    "parse malformed pairs" in {
      parser.parse("foo=bar&&baz&", handlers)
      there was one(handler).handle("foo", "bar")
      there was one(handler).handle("baz", "")
    }
  }
}
