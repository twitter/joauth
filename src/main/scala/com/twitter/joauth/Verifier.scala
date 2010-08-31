package com.twitter.joauth

import java.util.Date

trait NonceValidator {
  def apply(nonce: String): Boolean
}

object NoopNonceValidator extends NonceValidator {
  def apply(nonce: String): Boolean = true
}

trait Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): Int
}

class ConstVerifier(result: Int) extends Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): Int = result
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
  def apply(signer: Signer, maxTimestampAge: Int, validateNonce: NonceValidator) =
    new StandardVerifier(signer, maxTimestampAge, validateNonce)
}

class StandardVerifier(
  signer: Signer, maxTimestampAgeMins: Int, validateNonce: NonceValidator) extends Verifier {
    
  val maxTimestampAgeMs = maxTimestampAgeMins * 60000

  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): Int = {
    if (!validateNonce(request.nonce)) Verifier.BAD_NONCE
    else if (!validateTimestamp(request.timestamp)) Verifier.BAD_TIMESTAMP
    else if (!validateSignature(request, tokenSecret, consumerSecret)) Verifier.BAD_SIGNATURE
    else Verifier.OK
  }
  
  def validateTimestamp(timestamp: Long): Boolean = {
    timestamp >= (new Date).getTime - maxTimestampAgeMs
  }
  
  def validateSignature(
    request: OAuth1Request,
    tokenSecret: String,
    consumerSecret: String): Boolean = {
    request.signature == signer(request.normalizedRequest, tokenSecret, consumerSecret)
  }
}