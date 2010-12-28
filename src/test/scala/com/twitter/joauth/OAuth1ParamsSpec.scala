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

package com.twitter.joauth

import org.specs.mock.Mockito
import org.specs.Specification

class OAuthParamsSpec extends Specification with Mockito {
  val helper = mock[OAuthParamsHelper]
  val builder = OAuthParamsBuilder(helper)
  "OAuthParamsBuilder" should {
    "set one param, ignore unknown param" in {
      builder("foo", "bar")
      builder.token must beNull
      builder("oauth_token", "foo")
      builder.token must be_==("foo")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beFalse
    }
    "isOAuth2 works correctly after setting token" in {
      builder.v2Token must beNull
      builder("access_token", "foo")
      builder.v2Token must be_==("foo")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue
    }
    "timestampStr set if timestamp parses" in {
      builder.timestampSecs must be_==(-1)
      builder.timestampStr must beNull
      doReturn(Some(4L)).when(helper).parseTimestamp("foo")
      builder("oauth_timestamp", "foo")
      builder.timestampSecs must be_==(4L)
      builder.timestampStr must be_==("foo")
      there was one(helper).parseTimestamp("foo")
      there was one(helper).parseTimestamp(any[String])
    }
    "timestampStr null if timestamp doesn't parse" in {
      builder.timestampSecs must be_==(-1)
      builder.timestampStr must beNull
      doReturn(None).when(helper).parseTimestamp("foo")
      builder("oauth_timestamp", "foo")
      builder.timestampSecs must be_==(-1)
      builder.timestampStr must beNull
      there was one(helper).parseTimestamp("foo")
      there was one(helper).parseTimestamp(any[String])
    }
    "set all builder" in {
      builder.v2Token must beNull
      builder("access_token", "0")
      builder.v2Token must be_==("0")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue

      builder.token must beNull
      builder("oauth_token", "1")
      builder.token must be_==("1")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue

      builder.consumerKey must beNull
      builder("oauth_consumer_key", "2")
      builder.consumerKey must be_==("2")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue

      builder.nonce must beNull
      builder("oauth_nonce", "3")
      builder.nonce must be_==("3")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue

      doReturn(Some(4L)).when(helper).parseTimestamp("foo")
      builder("oauth_timestamp", "foo")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue

      doReturn("a").when(helper).processSignature("a")
      builder.signature must beNull
      builder("oauth_signature", "a")
      builder.signature must be_==("a")
      builder.isOAuth1 must beFalse
      builder.isOAuth2 must beTrue
      there was one(helper).processSignature("a")
      there was one(helper).processSignature(any[String])

      builder.signatureMethod must beNull
      builder("oauth_signature_method", "6")
      builder.signatureMethod must be_==("6")
      builder.isOAuth1 must beTrue
      builder.isOAuth2 must beFalse

      builder.toString must be_==("access_token=0,oauth_token=1,oauth_consumer_key=2,oauth_nonce=3,oauth_timestamp=foo(->4),oauth_signature=a,oauth_signature_method=6,oauth_version=(unset)")

      // version defaults to 1.0
      builder.version must beNull
      builder("oauth_version", "7")
      builder.version must be_==("7")
      builder.isOAuth1 must beTrue
      builder.isOAuth2 must beFalse

      builder.toString must be_==("access_token=0,oauth_token=1,oauth_consumer_key=2,oauth_nonce=3,oauth_timestamp=foo(->4),oauth_signature=a,oauth_signature_method=6,oauth_version=7")
    }
  }
  "StandardOAuthParamsHelper.parseTimestamp" should {
    "parse legit timestamp" in {
      StandardOAuthParamsHelper.parseTimestamp("45") must be_==(Some(45))
    }
    "return None for bad timestamp" in {
      StandardOAuthParamsHelper.parseTimestamp("abdf") must beNone
    }
    "return None for null timestamp" in {
      StandardOAuthParamsHelper.parseTimestamp(null) must beNone
    }
  }
  "StandardOAuthParamsHelper.processSignature" should {
    "urldecode string" in {
      StandardOAuthParamsHelper.processSignature("a%3Db") must be_==("a=b")
    }
    "return null for null string" in {
      StandardOAuthParamsHelper.processSignature(null) must beNull
    }
  }
}