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

import org.specs.mock.Mockito
import org.specs.Specification

class KeyValueHandlerSpec extends Specification with Mockito {
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
  "QuotedValueKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new QuotedValueKeyValueHandler(underlying)
    "only parse quoted values" in {
      handler("foo", "\"baz\"")
      handler("foo", "   \"baz\"  ")
      handler("bar" ,"bar")
      there were two(underlying).apply("foo", "baz")
      there was no(underlying).apply("bar", "bar")
      there were two(underlying).apply(any[String], any[String])
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
  "OAuthKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new OAuthKeyValueHandler(underlying)
    "filter non oauth1 fields" in {
      handler("  oauth_token", "foo  ")
      handler("foo", "bar")
      there was one(underlying).apply("oauth_token", "foo")
      there was no(underlying).apply("foo", "bar")
      there was one(underlying).apply(any[String], any[String])
    }
  }
  "NotOAuthKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new NotOAuthKeyValueHandler(underlying)
    "filter non oauth1 fields" in {
      handler("oauth_token", "foo")
      handler("  foo", "bar  ")
      there was no(underlying).apply("oauth_token", "foo")
      there was one(underlying).apply("  foo", "bar  ")
      there was one(underlying).apply(any[String], any[String])
    }
  }
}