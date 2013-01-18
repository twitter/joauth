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

import java.util.{Arrays, Date}

/**
 * A Validator takes an OAuth1 request, a token secret, and a consumer secret,
 * and validates the request. It returns a Java enum for compatability
 */
trait Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult
}

/**
 * for testing. always returns the same result.
 */
class ConstVerifier(result: VerifierResult) extends Verifier {
  override def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult = result
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
class StandardVerifier(
  signer: Signer,
  maxClockFloatAheadMins: Int,
  maxClockFloatBehindMins: Int,
  validateNonce: NonceValidator)
extends Verifier {

  val maxClockFloatAheadSecs = maxClockFloatAheadMins * 60L
  val maxClockFloatBehindSecs = maxClockFloatBehindMins * 60L

  override def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult = {
    if (!validateNonce(request.nonce)) VerifierResult.BAD_NONCE
    else if (!validateTimestampSecs(request.timestampSecs)) VerifierResult.BAD_TIMESTAMP
    else if (!validateSignature(request, tokenSecret, consumerSecret)) VerifierResult.BAD_SIGNATURE
    else VerifierResult.OK
  }

  def validateTimestampSecs(timestampSecs: Long): Boolean = {
    val nowSecs = System.currentTimeMillis / 1000
    (maxClockFloatBehindMins < 0 || (timestampSecs >= nowSecs - maxClockFloatBehindSecs)) &&
    (maxClockFloatAheadMins < 0 || (timestampSecs <= nowSecs + maxClockFloatAheadSecs))
  }

  def validateSignature(
    request: OAuth1Request,
    tokenSecret: String,
    consumerSecret: String): Boolean = {
    Base64Util.equals(UrlDecoder(request.signature).trim,
      signer.getBytes(request.normalizedRequest, tokenSecret, consumerSecret))
  }
}

