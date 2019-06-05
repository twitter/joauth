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

import com.twitter.joauth.keyvalue.KeyValueHandler.NullKeyValueHandler
import org.specs.SpecificationWithJUnit

class OAuth1RequestSpec extends SpecificationWithJUnit {
  "OAuth1Request.verify" should {
    val builder = new OAuthParams.OAuthParamsBuilder(OAuthParams.STANDARD_OAUTH_PARAMS_HELPER)
    def pr(scheme: String, host: String, port: Int, verb: String, path: String) =
      new Request.ParsedRequest(scheme, host, port, verb, path, new java.util.ArrayList[Request.Pair])

    "throw on null scheme" in {
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr(null, "2", 3, "4", "5"), builder.oAuth1Params) must throwA(new MalformedRequest("no value for scheme"))
    }
    "throw on null host" in {
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", null, 3, "4", "5"), builder.oAuth1Params) must throwA(new MalformedRequest("no value for host"))
    }
    "throw on null port" in {
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", -1, "4", "5"), builder.oAuth1Params) must throwA(new MalformedRequest("no value for port"))
    }
    "throw on null verb" in {
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, null, "5"), builder.oAuth1Params) must throwA(new MalformedRequest("no value for verb"))
    }
    "throw on null path" in {
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", null), builder.oAuth1Params) must throwA(new MalformedRequest("no value for path"))
    }
    "throw on null signature method" in {
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params) must throwA(new MalformedRequest("unsupported signature method: null"))
    }
    "throw on unsupported signature method" in {
      builder.queryHandler.handle("oauth_signature_method", "foo")
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params) must throwA(new MalformedRequest("unsupported signature method: foo"))
    }
    "not throw on supported HMAC-SHA1 signature method" in {
      builder.queryHandler.handle("oauth_signature_method", "HMAC-SHA1")
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params) 
      1 must be_==(1)
    }
    "not throw on supported HMAC-SHA256 signature method" in {
      builder.queryHandler.handle("oauth_signature_method", "HMAC-SHA256")
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params) 
      1 must be_==(1)
    }
    "throw on unsupported oauth version" in {
      builder.queryHandler.handle("oauth_signature_method", "HMAC-SHA1")
      builder.queryHandler.handle("oauth_version", "1.1")
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params) must throwA(new MalformedRequest("unsupported oauth version: 1.1"))
    }
    "not throw for null oauth version" in {
      builder.queryHandler.handle("oauth_signature_method", "HMAC-SHA1")
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params)
      1 must be_==(1)
    }
    "not throw for 1.0a oauth version" in {
      builder.queryHandler.handle("oauth_signature_method", "HMAC-SHA1")
      builder.queryHandler.handle("oauth_version", "1.0a")
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params)
      1 must be_==(1)
    }
    "throw on malformed token" in {
      builder.queryHandler.handle("oauth_signature_method", "HMAC-SHA1")
      builder.queryHandler.handle("oauth_version", "1.0")
      builder.queryHandler.handle("oauth_token", "this ain't a token")
      UnpackedRequest.O_AUTH_1_REQUEST_HELPER.verify(pr("1", "2", 3, "4", "5"), builder.oAuth1Params) must throwA(new MalformedRequest("malformed oauth token: this ain't a token"))
    }
    "trim extra spaces on token" in {
      builder.queryHandler.handle("oauth_token", "  some_token  ")
      builder.oAuth1Params.token mustEqual "some_token"
    }
  }
}
