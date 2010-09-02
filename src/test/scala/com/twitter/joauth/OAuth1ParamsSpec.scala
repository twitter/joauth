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

import org.specs.Specification

class OAuth1ParamsSpec extends Specification {
  val params = new OAuthParams
  "OAuth1Params" should {
    "set one param, ignore unknown param" in {
      params("foo", "bar")
      params.token must beNull
      params("oauth_token", "foo")
      params.token must be_==("foo")
      params.areAllOAuth1FieldsSet must beFalse
    }
    "set all params" in {
      params.token must beNull
      params("oauth_token", "1")
      params.token must be_==("1")
      params.areAllOAuth1FieldsSet must beFalse

      params.consumerKey must beNull
      params("oauth_consumer_key", "2")
      params.consumerKey must be_==("2")
      params.areAllOAuth1FieldsSet must beFalse

      params.nonce must beNull
      params("oauth_nonce", "3")
      params.nonce must be_==("3")
      params.areAllOAuth1FieldsSet must beFalse

      params.timestamp must be_==(-1)
      params("oauth_timestamp", "e")
      params.timestamp must be_==(-1)
      params("oauth_timestamp", "4")
      params.timestamp must be_==(4)
      params.areAllOAuth1FieldsSet must beFalse

      params.signature must beNull
      params("oauth_signature", "%3D")
      params.signature must be_==("=")
      params.areAllOAuth1FieldsSet must beFalse

      params.signatureMethod must beNull
      params("oauth_signature_method", "6")
      params.signatureMethod must be_==("6")
      params.areAllOAuth1FieldsSet must beFalse

      params.version must beNull
      params("oauth_version", "7")
      params.version must be_==("7")
      params.areAllOAuth1FieldsSet must beTrue
    }
  }
}