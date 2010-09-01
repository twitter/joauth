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
  
  val OK = 0
  val BAD_TIMESTAMP = 1
  val BAD_NONCE = 2
  val BAD_SIGNATURE = 3
  
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
    timestamp >= (new Date).getTime - maxTimestampAgeMs
  }
  
  def validateSignature(
    request: OAuth1Request,
    tokenSecret: String,
    consumerSecret: String): Boolean = {
    request.signature == sign(request.normalizedRequest, tokenSecret, consumerSecret)
  }
}