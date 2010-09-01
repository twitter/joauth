package com.twitter.joauth

import java.util.Date
import org.specs.mock.Mockito
import org.specs.Specification

class VerifierSpec extends Specification with Mockito {
  val checkNonce = mock[NonceValidator]
  val signer = mock[Signer]
  val request = mock[OAuth1Request]

  // 10 minutes ago
  val oldTimestamp = (new Date).getTime - (10 * 60 * 1000)

  val verify = new StandardVerifier(signer, 5, checkNonce)

  "validateTimestamp" should {
    "return false for timestamp that is too old" in {
      verify.validateTimestamp(oldTimestamp) must beFalse
    }
    "return true for timestamp that is new enough" in {
      verify.validateTimestamp((new Date).getTime) must beTrue
    }
  }
  "validateSignature" should {
    "return true for good signature" in {
      doReturn("foo").when(signer).apply("bar", "readsecret", "writesecret")
      doReturn("foo").when(request).signature
      doReturn("bar").when(request).normalizedRequest
      verify.validateSignature(request, "readsecret", "writesecret") must beTrue
    }
    "return false for bad signature" in {
      doReturn("foo").when(signer).apply("bar", "readsecret", "writesecret")
      doReturn("baz").when(request).signature
      doReturn("bar").when(request).normalizedRequest
      verify.validateSignature(request, "readsecret", "writesecret") must beFalse
    }
  }
  "Verifier" should {
    "return BAD_NONCE for bad nonce" in {
      doReturn("nonce").when(request).nonce
      doReturn(false).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_NONCE)
    }
    "return BAD_TIMESTAMP for bad timestamp" in {
      doReturn("nonce").when(request).nonce
      doReturn(oldTimestamp).when(request).timestamp
      doReturn(true).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_TIMESTAMP)
    }
    "return BAD_SIGNATURE for bad signature" in {
      doReturn("foo").when(signer).apply("bar", "readsecret", "writesecret")
      doReturn("nonce").when(request).nonce
      doReturn("baz").when(request).signature
      doReturn("bar").when(request).normalizedRequest
      doReturn((new Date).getTime).when(request).timestamp
      doReturn(true).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.BAD_SIGNATURE)
    }
    "return OK for good request" in {
      doReturn("foo").when(signer).apply("bar", "readsecret", "writesecret")
      doReturn("nonce").when(request).nonce
      doReturn("foo").when(request).signature
      doReturn("bar").when(request).normalizedRequest
      doReturn((new Date).getTime).when(request).timestamp
      doReturn(true).when(checkNonce).apply("nonce")
      verify(request, "readsecret", "writesecret") must be_==(VerifierResult.OK)
    }
  }
}