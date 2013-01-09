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

import com.twitter.joauth.StandardOAuthParamsHelper
import org.specs.mock.Mockito
import org.specs.SpecificationWithJUnit

class KeyValueHandlerSpec extends SpecificationWithJUnit with Mockito {
  "SingleKeyValueHandler" should {
    val handler = new SingleKeyValueHandler
    "use last value for key" in {
      handler("foo", "bar")
      handler("foo", "baz")
      handler("a", "b")
      handler.toMap must haveTheSameElementsAs(Map("foo" -> "baz", "a" -> "b"))
    }
  }
  "DuplicateKeyValueHandler" should {
    val handler = new DuplicateKeyValueHandler
    "use multiple values for key" in {
      handler("foo", "bar")
      handler("foo", "baz")
      handler("a", "b")
      handler.toList must haveTheSameElementsAs(List(("foo", "bar"), ("foo", "baz"), ("a", "b")))
    }
  }
  "MaybeQuotedValueKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new MaybeQuotedValueKeyValueHandler(underlying)
    "only parse quoted values" in {
      handler("foo", "\"baz\"")
      handler("foo", "   \"baz\"  ")
      handler("foo" , "baz")
      // doesn't trim for unquoted values
      handler("foo" , "   baz  ")
      there were 3.times(underlying).apply("foo", "baz")
      there was one(underlying).apply("foo", "   baz  ")
      there were 4.times(underlying).apply(any, any)
    }

  }
  "OneKeyOnlyKeyValueHandler" should {
    val handler = new OneKeyOnlyKeyValueHandler
    "return key for single key, empty value" in {
      handler("foo", "")
      handler.key must beSome("foo")
    }
    "return key for single key, null value" in {
      handler("foo", null)
      handler.key must beSome("foo")
    }
    "return None for single key/value" in {
      handler("foo", "bar")
      handler.key must beNone
    }
    "return None for two keys" in {
      handler("foo", "")
      handler("foo", "")
      handler.key must beNone
    }
  }
}
