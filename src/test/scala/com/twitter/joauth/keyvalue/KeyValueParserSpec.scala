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

class KeyValueParserSpec extends SpecificationWithJUnit with Mockito {
  val handler = mock[KeyValueHandler]

  "ConstKeyValueParser" should {
    "call handler with key values" in {
      val parser = new ConstKeyValueParser(List(("a", "b"), ("c", "d")))
      parser("foo", Seq(handler))
      there was one(handler).apply("a", "b")
      there was one(handler).apply("c", "d")
    }
  }

  "StandardKeyValueParser" should {
    val parser = QueryKeyValueParser
    "not blow up on null string" in {
      parser(null, Seq(handler))
      there was no(handler).apply(any[String], any[String])
    }
    "not blow up on empty string" in {
      parser("", Seq(handler))
      there was no(handler).apply(any[String], any[String])
    }
    "parse simple string" in {
      parser("foo", Seq(handler))
      there was one(handler).apply("foo", "")
    }
    "parse valid pairs" in {
      parser("foo=bar&baz", Seq(handler))
      there was one(handler).apply("foo", "bar")
      there was one(handler).apply("baz", "")
    }
    "parse malformed pairs" in {
      parser("foo=bar&&baz&", Seq(handler))
      there was one(handler).apply("foo", "bar")
      there was one(handler).apply("baz", "")
    }
  }
}
