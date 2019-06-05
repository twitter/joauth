// Copyright 2011 Twitter, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package com.twitter.joauth

import org.specs.mock.Mockito
import org.specs.SpecificationWithJUnit

class OAuthParamsSpec extends SpecificationWithJUnit with Mockito {
  val helper = smartMock[OAuthParams.OAuthParamsHelper]
  val builder = new OAuthParams.OAuthParamsBuilder(helper)

  val emptyList = new java.util.ArrayList[Request.Pair]()

  def toPairList(list: List[(String, String)]) = {
    val newList = new java.util.ArrayList[Request.Pair]()
    list foreach { case(k, v) => newList.add(new Request.Pair(k, v))}
    newList
  }

  "OAuthParamsBuilder" should {
    "set one oauth param in query" in {
      builder.token must beNull
      builder.queryHandler.handle("oauth_token", "foo")
      builder.token mustEqual "foo"
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beFalse
    }
    "set one oauth param in header" in {
      builder.token must beNull
      builder.headerHandler.handle("oauth_token", "foo")
      builder.token mustEqual "foo"
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beFalse
    }
    "use last value for oauth key" in {
      builder.token must beNull
      builder.headerHandler.handle("oauth_token", "foo1")
      builder.queryHandler.handle("oauth_token", "foo2")
      builder.queryHandler.handle("oauth_token", "foo3")
      builder.headerHandler.handle("oauth_token", "foo")
      builder.token mustEqual "foo"
    }
    "collect other param in query" in {
      builder.otherParams mustEqual emptyList
      builder.queryHandler.handle("foo", "bar")
      builder.queryHandler.handle("foo", "baz")
      builder.otherParams mustEqual toPairList(List("foo" -> "bar", "foo" -> "baz"))
    }
    "collect oauth param in header, use last value" in {
      builder.otherParams mustEqual emptyList
      builder.headerHandler.handle("oauth_foo", "bar")
      builder.headerHandler.handle("oauth_foo", "baz")
      builder.otherParams mustEqual toPairList(List("oauth_foo" -> "baz"))
    }
    "ignore other param in header" in {
      builder.otherParams mustEqual emptyList
      builder.headerHandler.handle("foo", "bar")
      builder.headerHandler.handle("foo", "baz")
      builder.otherParams mustEqual emptyList
    }
    "not classify OAuth2 without Bearer" in {
      builder.v2Token must beNull
      builder.queryHandler.handle("access_token", "foo")
      builder.v2Token must beNull
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beFalse
    }
    "isOAuth2 works correctly after setting token" in {
      builder.v2Token must beNull
      builder.headerHandler.handle("Bearer", "foo")
      builder.v2Token mustEqual "foo"
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue
    }
    "timestampStr set if timestamp parses" in {
      builder.timestampSecs mustEqual -1
      builder.timestampStr must beNull
      helper.parseTimestamp("foo") returns 4L
      builder.queryHandler.handle("oauth_timestamp", "foo")
      builder.timestampSecs mustEqual 4L
      builder.timestampStr mustEqual "foo"
      there was one(helper).parseTimestamp("foo")
      there was one(helper).parseTimestamp(any[String])
    }
    "timestampStr null if timestamp doesn't parse" in {
      builder.timestampSecs mustEqual -1
      builder.timestampStr must beNull
      helper.parseTimestamp("foo") returns null
      builder.queryHandler.handle("oauth_timestamp", "foo")
      builder.timestampSecs mustEqual -1
      builder.timestampStr must beNull
      there was one(helper).parseTimestamp("foo")
      there was one(helper).parseTimestamp(any[String])
    }
    "set all builder" in {
      builder.v2Token must beNull
      builder.queryHandler.handle("access_token", "0")
      builder.v2Token must beNull
      builder.isOAuth1 must beFalse
      builder.isOAuth1TwoLegged must beFalse
      builder.isOAuth2 must beFalse

      builder.consumerKey must beNull
      builder.queryHandler.handle("oauth_consumer_key", "2")
      builder.consumerKey mustEqual "2"
      builder.isOAuth1 must beFalse
      builder.isOAuth1TwoLegged must beFalse
      builder.isOAuth2 must beFalse

      builder.nonce must beNull
      builder.queryHandler.handle("oauth_nonce", "3")
      builder.nonce mustEqual "3"
      builder.isOAuth1 must beFalse
      builder.isOAuth1TwoLegged must beFalse
      builder.isOAuth2 must beFalse

      helper.parseTimestamp("foo") returns 4L
      builder.queryHandler.handle("oauth_timestamp", "foo")
      builder.isOAuth1 must beFalse
      builder.isOAuth1TwoLegged must beFalse
      builder.isOAuth2 must beFalse

      helper.processSignature("a") returns "a"
      builder.signature must beNull
      builder.queryHandler.handle("oauth_signature", "a")
      builder.signature mustEqual "a"
      builder.isOAuth1 must beFalse
      builder.isOAuth1TwoLegged must beFalse
      builder.isOAuth2 must beFalse
      there was one(helper).processSignature("a")
      there was one(helper).processSignature(any[String])

      builder.signatureMethod must beNull
      builder.queryHandler.handle("oauth_signature_method", "6")
      builder.signatureMethod mustEqual "6"
      builder.isOAuth1 must beFalse
      builder.isOAuth1TwoLegged must beTrue
      builder.isOAuth2 must beFalse

      builder.queryHandler.handle("oauth_token", "")
      builder.token mustEqual ""
      builder.isOAuth1 must beFalse
      builder.isOAuth1TwoLegged must beTrue
      builder.isOAuth2 must beFalse

      builder.queryHandler.handle("oauth_token", "1")
      builder.token mustEqual "1"
      builder.isOAuth1 must beTrue
      builder.isOAuth1TwoLegged must beFalse
      builder.isOAuth2 must beFalse

      builder.toString mustEqual "Bearer=(unset),oauth_token=1,oauth_consumer_key=2,oauth_nonce=3,oauth_timestamp=foo(->4),oauth_signature=a,oauth_signature_method=6,oauth_version=(unset)"

      builder.version must beNull
      builder.queryHandler.handle("oauth_version", "7")
      builder.version mustEqual "7"
      builder.isOAuth1 must beTrue
      builder.isOAuth1TwoLegged must beFalse
      builder.isOAuth2 must beFalse

      builder.otherParams mustEqual toPairList(List("access_token" -> "0"))
      builder.queryHandler.handle("foo", "bar")
      builder.otherParams mustEqual toPairList(List("access_token" -> "0", "foo" -> "bar"))

      builder.toString mustEqual "Bearer=(unset),oauth_token=1,oauth_consumer_key=2,oauth_nonce=3,oauth_timestamp=foo(->4),oauth_signature=a,oauth_signature_method=6,oauth_version=7"
    }
  }
  "StandardOAuthParamsHelper.parseTimestamp" should {
    "parse legit timestamp" in {
      OAuthParams.STANDARD_OAUTH_PARAMS_HELPER.parseTimestamp("45") mustEqual 45
    }
    "return None for bad timestamp" in {
      OAuthParams.STANDARD_OAUTH_PARAMS_HELPER.parseTimestamp("abdf") must beNull
    }
    "return None for null timestamp" in {
      OAuthParams.STANDARD_OAUTH_PARAMS_HELPER.parseTimestamp(null) must beNull
    }
  }
}
