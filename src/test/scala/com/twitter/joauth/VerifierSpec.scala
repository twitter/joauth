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

package com.twitter.joauth

import java.util.Date
import org.specs2.mock.Mockito
import org.specs2.mutable.SpecificationWithJUnit
import org.specs2.specification.Scope


class VerifierSpec extends SpecificationWithJUnit with Mockito {

  trait VerifierScope extends Scope {
    val checkNonce = mock[NonceValidator]
    val signer = new StandardSigner
    val request = mock[OAuth1Request]

    val nowSecs = (new Date).getTime / 1000
    // 10 minutes ago
    val longAgoSecs = nowSecs - (10 * 60)
    // 10 minutes fromNow
    val farAheadSecs = nowSecs + (10 * 60)

    val verify = new StandardVerifier(signer, 5, 5, checkNonce)
  }

  "validateTimestampSec" should {



    "return false for timestamp that is too old" in new VerifierScope  {
      verify.validateTimestampSecs(longAgoSecs) must beFalse
    }
    "return true for timestamp that is new enough" in new VerifierScope {
      val fourMinutesAgo = nowSecs - (4 * 60)
      verify.validateTimestampSecs(fourMinutesAgo) must beTrue
    }
    "return true for timestamp that is new enough" in new VerifierScope {
      val fourMinutesFromNow = nowSecs + (4 * 60)
      verify.validateTimestampSecs(fourMinutesFromNow) must beTrue
    }
    "return false for timestamp that too new" in new VerifierScope {
      verify.validateTimestampSecs(farAheadSecs) must beFalse
    }
  }

  "no timestamp checks" should {

    trait TimestampScope extends Scope {
      val checkNonce = mock[NonceValidator]
      val signer = new StandardSigner
      val noTimestampCheckingVerify = new StandardVerifier(
        signer,
        Verifier.NO_TIMESTAMP_CHECK,
        Verifier.NO_TIMESTAMP_CHECK,
        checkNonce)

      val nowSecs = (new Date).getTime / 1000
      // 10 minutes ago
      val longAgoSecs = nowSecs - (10 * 60)
      // 10 minutes fromNow
      val farAheadSecs = nowSecs + (10 * 60)
    }

    "return true for timestamp that is too old" in new TimestampScope  {
      noTimestampCheckingVerify.validateTimestampSecs(longAgoSecs) must beTrue
    }
    "return true for timestamp that is new enough" in new TimestampScope {
      noTimestampCheckingVerify.validateTimestampSecs((new Date).getTime / 1000) must beTrue
    }
    "return true for timestamp that too new" in new TimestampScope  {
      noTimestampCheckingVerify.validateTimestampSecs(farAheadSecs) must beTrue
    }
  }

  "validateSignature" should {
    "return false for malformed signature" in new VerifierScope {
      request.signature returns "rEh%2FpUnLF9ZSV8WmIMGARQlM2VQ%3D%0"
      request.normalizedRequest returns "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fusers%2Flookup.json&oauth_consumer_key%3Dabcd%26oauth_nonce%3Dnonce%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1363119598%26oauth_token%3Dijkl%26oauth_version%3D1.0%26user_id%3D1234567890"
      verify.validateSignature(request, "readsecret", "writesecret") must beFalse
    }
    "return true for good signature" in new VerifierScope {
      request.signature returns "rEh%2FpUnLF9ZSV8WmIMGARQlM2VQ%3D"
      request.normalizedRequest returns "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fusers%2Flookup.json&oauth_consumer_key%3Dabcd%26oauth_nonce%3Dnonce%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1363119598%26oauth_token%3Dijkl%26oauth_version%3D1.0%26user_id%3D1234567890"
      verify.validateSignature(request, "readsecret", "writesecret") must beTrue
    }
    "return false for bad signature" in new VerifierScope {
      request.signature returns "cNwF13Zo%2FIaX8MT6QdYlJWn%2B4%2F4%3D"
      request.normalizedRequest returns "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fusers%2Flookup.json&oauth_consumer_key%3Dabcd%26oauth_nonce%3Dnonce%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1363119598%26oauth_token%3Dijkl%26oauth_version%3D1.0%26user_id%3D1234567890"
      verify.validateSignature(request, "readsecret", "writesecret") must beFalse
    }
  }

  "Verifier" should {
    "return BAD_NONCE for bad nonce" in new VerifierScope {
      request.nonce returns "nonce"
      checkNonce.apply("nonce") returns false
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_NONCE)
    }
    "return BAD_TIMESTAMP for bad timestamp" in new VerifierScope {
      request.nonce returns "nonce"
      checkNonce.apply("nonce") returns true
      request.timestampSecs returns longAgoSecs
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_TIMESTAMP)
    }
    "return BAD_SIGNATURE for bad signature" in new VerifierScope {
      val verifier = new StandardVerifier(signer, -1, -1, checkNonce)
      request.nonce returns "nonce"
      checkNonce.apply("nonce") returns true
      request.timestampSecs returns 1363119598
      request.signature returns "cNwF13Zo%2FIaX8MT6QdYlJWn%2B4%2F4%3D"
      request.normalizedRequest returns "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fusers%2Flookup.json&oauth_consumer_key%3Dabcd%26oauth_nonce%3Dnonce%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1363119598%26oauth_token%3Dijkl%26oauth_version%3D1.0%26user_id%3D1234567890"
      verifier(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_SIGNATURE)
    }
    "return OK for good request" in new VerifierScope {
      val verifier = new StandardVerifier(signer, -1, -1, checkNonce)
      request.nonce returns "nonce"
      checkNonce.apply("nonce") returns true
      request.timestampSecs returns 1363119598
      request.signature returns "rEh%2FpUnLF9ZSV8WmIMGARQlM2VQ%3D"
      request.normalizedRequest returns "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fusers%2Flookup.json&oauth_consumer_key%3Dabcd%26oauth_nonce%3Dnonce%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1363119598%26oauth_token%3Dijkl%26oauth_version%3D1.0%26user_id%3D1234567890"
      verifier(request, "readsecret", "writesecret") must be_==(VerifierResult.OK)
    }
  }

}
