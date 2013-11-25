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

import com.twitter.joauth.{Request, ConversionUtil, StandardOAuthParamsHelper}
import org.specs.mock.Mockito
import org.specs.SpecificationWithJUnit

class KeyValueHandlerSpec extends SpecificationWithJUnit with Mockito {
  "SingleKeyValueHandler" should {
    val handler = new KeyValueHandler.SingleKeyValueHandler
    "use last value for key" in {
      handler.handle("foo", "bar")
      handler.handle("foo", "baz")
      handler.handle("a", "b")
      handler.toMap mustEqual ConversionUtil.toHashMap(Map("foo" -> "baz", "a" -> "b"))
    }
  }
  "DuplicateKeyValueHandler" should {
    val handler = new KeyValueHandler.DuplicateKeyValueHandler
    "use multiple values for key" in {
      handler.handle("foo", "bar")
      handler.handle("foo", "baz")
      handler.handle("a", "b")
      handler.toList mustEqual ConversionUtil.toArrayList(List(new Request.Pair("foo", "bar"), new Request.Pair("foo", "baz"), new Request.Pair("a", "b")))
    }
  }
  "MaybeQuotedValueKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new KeyValueHandler.MaybeQuotedValueKeyValueHandler(underlying)
    "only parse quoted values" in {
      handler.handle("foo", "\"baz\"")
      handler.handle("foo", "   \"baz\"  ")
      handler.handle("foo" , "baz")
      // doesn't trim for unquoted values
      handler.handle("foo" , "   baz  ")
      there were 3.times(underlying).handle("foo", "baz")
      there was one(underlying).handle("foo", "   baz  ")
      there were 4.times(underlying).handle(any, any)
    }

  }
  "OneKeyOnlyKeyValueHandler" should {
    val handler = new KeyValueHandler.OneKeyOnlyKeyValueHandler()
    "return key for single key, empty value" in {
      handler.handle("foo", "")
      handler.getKey mustEqual "foo"
    }
    "return key for single key, null value" in {
      handler.handle("foo", null)
      handler.getKey mustEqual  "foo"
    }
    "return None for single key/value" in {
      handler.handle("foo", "bar")
      handler.getKey must beNull
    }
    "return None for two keys" in {
      handler.handle("foo", "")
      handler.handle("foo", "")
      handler.getKey must beNull
    }
  }
}
