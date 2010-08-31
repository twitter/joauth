package com.twitter.joauth

import org.specs.Specification
import org.specs.mock.Mockito

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
      underlying.apply("foo", "baz") was called.twice
      underlying.apply("bar", "bar") was notCalled
      underlying.apply(any[String], any[String]) was called.twice
    }

  }
  "OAuthKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new OAuthKeyValueHandler(underlying)
    "filter non oauth1 fields" in {
      handler("  oauth_token", "foo  ")
      handler("foo", "bar")
      underlying.apply("oauth_token", "foo") was called.once
      underlying.apply("foo", "bar") was notCalled
      underlying.apply(any[String], any[String]) was called.once
    }
  }
  "NotOAuthKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new NotOAuthKeyValueHandler(underlying)
    "filter non oauth1 fields" in {
      handler("oauth_token", "foo")
      handler("  foo", "bar  ")
      underlying.apply("oauth_token", "foo") was notCalled
      underlying.apply("  foo", "bar  ") was called.once
      underlying.apply(any[String], any[String]) was called.once
    }
  }
  "OAuth2HeaderKeyValueHandler" should {
    val underlying = mock[KeyValueHandler]
    val handler = new OAuth2HeaderKeyValueHandler(underlying)
    "pull token from header field, replace key name" in {
      handler("  token", "foo  ")
      handler("foo", "bar")
      underlying.apply("oauth_token", "foo") was called.once
      underlying.apply("foo", "bar") was notCalled
      underlying.apply(any[String], any[String]) was called.once
    }
  }
}