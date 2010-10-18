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

import java.util.Date

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
  
  def apply(): Verifier = new StandardVerifier(Signer(), NO_TIMESTAMP_CHECK, NoopNonceValidator)
  def apply(maxClockFloat: Int) = new StandardVerifier(Signer(), maxClockFloat, NoopNonceValidator)
  def apply(maxClockFloat: Int, validateNonce: NonceValidator) =
    new StandardVerifier(Signer(), maxClockFloat, validateNonce)
  def apply(sign: Signer, maxClockFloat: Int, validateNonce: NonceValidator) =
    new StandardVerifier(sign, maxClockFloat, validateNonce)
}

/**
 * The standard implementation of a Verifier. Constructed with a Signer, the maximum clock float
 * allowed for a timestamp, and a NonceValidator.
 */
class StandardVerifier(
  sign: Signer, maxClockFloatMins: Int, validateNonce: NonceValidator) extends Verifier {

  val maxClockFloatMs = maxClockFloatMins * 60000

  override def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult = {
    if (!validateNonce(request.nonce)) VerifierResult.BAD_NONCE
    else if (!validateTimestamp(request.timestamp)) VerifierResult.BAD_TIMESTAMP
    else if (!validateSignature(request, tokenSecret, consumerSecret)) VerifierResult.BAD_SIGNATURE
    else VerifierResult.OK
  }

  def validateTimestamp(timestamp: Long): Boolean = {
    val now = (new Date).getTime
    (maxClockFloatMs < 0) ||
      ((timestamp >= now - maxClockFloatMs) && (timestamp <= now + maxClockFloatMs))
  }

  def validateSignature(
    request: OAuth1Request,
    tokenSecret: String,
    consumerSecret: String): Boolean = {
    request.signature == sign(request.normalizedRequest, tokenSecret, consumerSecret)
  }
}