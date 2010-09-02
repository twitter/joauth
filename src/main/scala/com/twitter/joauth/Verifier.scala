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

trait NonceValidator {
  def apply(nonce: String): Boolean
}

object NoopNonceValidator extends NonceValidator {
  def apply(nonce: String): Boolean = true
}

class ConstNonceValidator(result: Boolean) extends NonceValidator {
  def apply(nonce: String): Boolean = result
}

trait Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult
}

class ConstVerifier(result: VerifierResult) extends Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult = result
}

object Verifier {
  val NO_TIMESTAMP_CHECK = -1
  
  def apply(): Verifier = new StandardVerifier(Signer(), NO_TIMESTAMP_CHECK, NoopNonceValidator)
  def apply(maxTimestampAge: Int) = new StandardVerifier(Signer(), maxTimestampAge, NoopNonceValidator)
  def apply(maxTimestampAge: Int, validateNonce: NonceValidator) =
    new StandardVerifier(Signer(), maxTimestampAge, validateNonce)
  def apply(sign: Signer, maxTimestampAge: Int, validateNonce: NonceValidator) =
    new StandardVerifier(sign, maxTimestampAge, validateNonce)
}

class StandardVerifier(
  sign: Signer, maxTimestampAgeMins: Int, validateNonce: NonceValidator) extends Verifier {
  
  val maxTimestampAgeMs = maxTimestampAgeMins * 60000

  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): VerifierResult = {
    if (!validateNonce(request.nonce)) VerifierResult.BAD_NONCE
    else if (!validateTimestamp(request.timestamp)) VerifierResult.BAD_TIMESTAMP
    else if (!validateSignature(request, tokenSecret, consumerSecret)) VerifierResult.BAD_SIGNATURE
    else VerifierResult.OK
  }

  def validateTimestamp(timestamp: Long): Boolean = {
    (maxTimestampAgeMs < 0) || (timestamp >= (new Date).getTime - maxTimestampAgeMs)
  }

  def validateSignature(
    request: OAuth1Request,
    tokenSecret: String,
    consumerSecret: String): Boolean = {
    request.signature == sign(request.normalizedRequest, tokenSecret, consumerSecret)
  }
}