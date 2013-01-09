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
import org.specs.mock.Mockito
import org.specs.SpecificationWithJUnit

class VerifierSpec extends SpecificationWithJUnit with Mockito {
  val checkNonce = mock[NonceValidator]
  val signer = mock[Signer]
  val request = mock[OAuth1Request]

  val nowSecs = (new Date).getTime / 1000
  // 10 minutes ago
  val longAgoSecs = nowSecs - (10 * 60)
  // 10 minutes fromNow
  val farAheadSecs = nowSecs + (10 * 60)

  val verify = new StandardVerifier(signer, 5, 5, checkNonce)

  "validateTimestampSec" should {
    "return false for timestamp that is too old" in {
      verify.validateTimestampSecs(longAgoSecs) must beFalse
    }
    "return true for timestamp that is new enough" in {
      val fourMinutesAgo = nowSecs - (4 * 60)
      verify.validateTimestampSecs(fourMinutesAgo) must beTrue
    }
    "return true for timestamp that is new enough" in {
      val fourMinutesFromNow = nowSecs + (4 * 60)
      verify.validateTimestampSecs(fourMinutesFromNow) must beTrue
    }
    "return false for timestamp that too new" in {
      verify.validateTimestampSecs(farAheadSecs) must beFalse
    }
  }
  "no timestamp checks" should {
    val noTimestampCheckingVerify = new StandardVerifier(
      signer,
      Verifier.NO_TIMESTAMP_CHECK,
      Verifier.NO_TIMESTAMP_CHECK,
      checkNonce)
    "return true for timestamp that is too old" in {
      noTimestampCheckingVerify.validateTimestampSecs(longAgoSecs) must beTrue
    }
    "return true for timestamp that is new enough" in {
      noTimestampCheckingVerify.validateTimestampSecs((new Date).getTime / 1000) must beTrue
    }
    "return true for timestamp that too new" in {
      noTimestampCheckingVerify.validateTimestampSecs(farAheadSecs) must beTrue
    }
  }
  /*
   TODO: replace these tests with working ones
  "validateSignature" should {
    "return true for good signature" in {
      doReturn("foo".getBytes).when(signer).getBytes("bar", "readsecret", "writesecret")
      doReturn("foo").when(request).signature
      doReturn("foo".getBytes).when(signer).toBytes("foo")
      doReturn("bar").when(request).normalizedRequest
      verify.validateSignature(request, "readsecret", "writesecret") must beTrue
    }
    "return false for bad signature" in {
      doReturn("foo".getBytes).when(signer).getBytes("bar", "readsecret", "writesecret")
      doReturn("baz").when(request).signature
      doReturn("baz".getBytes).when(signer).toBytes("baz")
      doReturn("bar").when(request).normalizedRequest
      verify.validateSignature(request, "readsecret", "writesecret") must beFalse
    }
  }
   */

  "Verifier" should {
    "return BAD_NONCE for bad nonce" in {
      doReturn("nonce").when(request).nonce
      doReturn(false).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_NONCE)
    }
    "return BAD_TIMESTAMP for bad timestamp" in {
      doReturn("nonce").when(request).nonce
      doReturn(longAgoSecs).when(request).timestampSecs
      doReturn(true).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_TIMESTAMP)
    }
    /**
     * TODO: replace these tests with working ones
    "return BAD_SIGNATURE for bad signature" in {
      doReturn("foo".getBytes).when(signer).getBytes("bar", "readsecret", "writesecret")
      doReturn("nonce").when(request).nonce
      doReturn("baz").when(request).signature
      doReturn("baz".getBytes).when(signer).toBytes("baz")
      doReturn("bar").when(request).normalizedRequest
      doReturn(nowSecs).when(request).timestampSecs
      doReturn(true).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_SIGNATURE)
    }
    "return OK for good request" in {
      doReturn("foo".getBytes).when(signer).getBytes("bar", "readsecret", "writesecret")
      doReturn("nonce").when(request).nonce
      doReturn("foo").when(request).signature
      doReturn("foo".getBytes).when(signer).toBytes("foo")
      doReturn("bar").when(request).normalizedRequest
      doReturn(nowSecs).when(request).timestampSecs
      doReturn(true).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.OK)
    }
    */
  }

}
