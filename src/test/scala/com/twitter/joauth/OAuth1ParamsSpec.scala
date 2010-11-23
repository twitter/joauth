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

class OAuth1ParamsSpec extends Specification with Mockito {
  val helper = mock[OAuthParamsHelper]
  val params = OAuthParams(helper)
  "OAuth1Params" should {
    "set one param, ignore unknown param" in {
      params("foo", "bar")
      params.token must beNull
      params("oauth_token", "foo")
      params.token must be_==("foo")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beTrue
    }
    "isOnlyOAuthTokenSet works correctly after setting token and version" in {
      params("oauth_token", "foo")
      params.token must be_==("foo")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beTrue
      params.version must beNull
      params("oauth_version", "7")
      params.version must be_==("7")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beFalse
    }
    "timestampStr set if timestamp parses" in {
      params.timestampSecs must be_==(-1)
      params.timestampStr must beNull
      doReturn(Some(4L)).when(helper).parseTimestamp("foo")
      params("oauth_timestamp", "foo")
      params.timestampSecs must be_==(4L)
      params.timestampStr must be_==("foo")
      there was one(helper).parseTimestamp("foo")
      there was one(helper).parseTimestamp(any[String])
    }
    "timestampStr null if timestamp doesn't parse" in {
      params.timestampSecs must be_==(-1)
      params.timestampStr must beNull
      doReturn(None).when(helper).parseTimestamp("foo")
      params("oauth_timestamp", "foo")
      params.timestampSecs must be_==(-1)
      params.timestampStr must beNull
      there was one(helper).parseTimestamp("foo")
      there was one(helper).parseTimestamp(any[String])
    }
    "set all params" in {
      params.token must beNull
      params("oauth_token", "1")
      params.token must be_==("1")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beTrue

      params.consumerKey must beNull
      params("oauth_consumer_key", "2")
      params.consumerKey must be_==("2")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beFalse

      params.nonce must beNull
      params("oauth_nonce", "3")
      params.nonce must be_==("3")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beFalse

      doReturn(Some(4L)).when(helper).parseTimestamp("foo")
      params("oauth_timestamp", "foo")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beFalse

      doReturn("a").when(helper).processSignature("a")
      params.signature must beNull
      params("oauth_signature", "a")
      params.signature must be_==("a")
      params.areAllOAuth1FieldsSet must beFalse
      params.isOnlyOAuthTokenSet must beFalse
      there was one(helper).processSignature("a")
      there was one(helper).processSignature(any[String])

      params.signatureMethod must beNull
      params("oauth_signature_method", "6")
      params.signatureMethod must be_==("6")
      params.areAllOAuth1FieldsSet must beTrue
      params.isOnlyOAuthTokenSet must beFalse

      params.toString must be_==("oauth_token=1,oauth_consumer_key=2,oauth_nonce=3,oauth_timestamp=foo(->4),oauth_signature=a,oauth_signature_method=6,oauth_version=(unset)")

      // version defaults to 1.0
      params.version must beNull
      params("oauth_version", "7")
      params.version must be_==("7")
      params.areAllOAuth1FieldsSet must beTrue
      params.isOnlyOAuthTokenSet must beFalse

      params.toString must be_==("oauth_token=1,oauth_consumer_key=2,oauth_nonce=3,oauth_timestamp=foo(->4),oauth_signature=a,oauth_signature_method=6,oauth_version=7")
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