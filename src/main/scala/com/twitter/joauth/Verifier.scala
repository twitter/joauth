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

import org.slf4j.LoggerFactory

/**
 * A Verifier takes either
 *   a) an OAuth1 request, a token secret, and a consumer secret
 *      or
 *   b) an OAuth1TwoLegged request and a consumer secret
 *
 * and validates the request. It returns a Java enum for compatability
 */
trait Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult
  def apply(request: OAuth1TwoLeggedRequest, consumerSecret: String): VerifierResult
}

/**
 * for testing. always returns the same result.
 */
class ConstVerifier(result: VerifierResult) extends Verifier {
  override def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult = result
  override def apply(request: OAuth1TwoLeggedRequest, consumerSecret: String): VerifierResult = result
}

/**
 * a factory with various convenience constructors for a StandardVerifier
 */
object Verifier {
  val NO_TIMESTAMP_CHECK = -1

  def apply(): Verifier = new StandardVerifier(
    Signer(), NO_TIMESTAMP_CHECK, NO_TIMESTAMP_CHECK, NoopNonceValidator)
  def apply(maxClockFloatAheadMins: Int, maxClockFloatBehindMins: Int) = new StandardVerifier(
    Signer(), maxClockFloatAheadMins, maxClockFloatBehindMins, NoopNonceValidator)
  def apply(
    maxClockFloatAheadMins: Int,
    maxClockFloatBehindMins: Int,
    validateNonce: NonceValidator) = new StandardVerifier(
    Signer(), maxClockFloatAheadMins, maxClockFloatBehindMins, validateNonce)
  def apply(
    sign: Signer,
    maxClockFloatAheadMins: Int,
    maxClockFloatBehindMins: Int,
    validateNonce: NonceValidator) = new StandardVerifier(
    sign, maxClockFloatAheadMins, maxClockFloatBehindMins, validateNonce)
}

/**
 * The standard implementation of a Verifier. Constructed with a Signer, the maximum clock float
 * allowed for a timestamp, and a NonceValidator.
 */
object StandardVerifier {
  private val log = LoggerFactory.getLogger(getClass.getName)
}

class StandardVerifier(
  signer: Signer,
  maxClockFloatAheadMins: Int,
  maxClockFloatBehindMins: Int,
  validateNonce: NonceValidator)
extends Verifier {

  import StandardVerifier._

  val maxClockFloatAheadSecs = maxClockFloatAheadMins * 60L
  val maxClockFloatBehindSecs = maxClockFloatBehindMins * 60L

  override def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult = {
    verifyOAuth1(
      request,
      request.nonce,
      request.timestampSecs,
      tokenSecret,
      consumerSecret,
      request.signature,
      request.normalizedRequest
    )
  }

  override def apply(request: OAuth1TwoLeggedRequest, consumerSecret: String): VerifierResult = {
    verifyOAuth1(
      request,
      request.nonce,
      request.timestampSecs,
      "",
      consumerSecret,
      request.signature,
      request.normalizedRequest
    )
  }

  private def verifyOAuth1(
    request: OAuthRequest,
    nonce: String,
    timestampSecs: Long,
    tokenSecret: String,
    consumerSecret: String,
    signature: String,
    normalizedRequest: String) = {
    if (!validateTimestampSecs(timestampSecs)) {
      log.debug("bad timestamp -> {}", request.toString)
      VerifierResult.BAD_TIMESTAMP
    } else if (!validateNonce(nonce)) {
      log.debug("bad nonce -> {}", request.toString)
      VerifierResult.BAD_NONCE
    } else if (!validateSignature(normalizedRequest, signature, tokenSecret, consumerSecret)) {
      log.debug("bad signature -> {}", request.toString)
      VerifierResult.BAD_SIGNATURE
    }
    else VerifierResult.OK
  }

  def validateTimestampSecs(timestampSecs: Long): Boolean = {
    val nowSecs = System.currentTimeMillis / 1000
    (maxClockFloatBehindMins < 0 || (timestampSecs >= nowSecs - maxClockFloatBehindSecs)) &&
    (maxClockFloatAheadMins < 0 || (timestampSecs <= nowSecs + maxClockFloatAheadSecs))
  }

  def validateSignature(
    normalizedRequest: String,
    signature: String,
    tokenSecret: String,
    consumerSecret: String): Boolean = {
    try {
      Base64Util.equals(UrlDecoder(signature).trim,
        signer.getBytes(normalizedRequest, tokenSecret, consumerSecret))
    } catch {
      case e: Exception => return false
    }
  }
}

