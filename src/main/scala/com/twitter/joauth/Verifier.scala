package com.twitter.joauth

trait Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): Boolean
}

object Verifier {
  val NO_TIMESTAMP_CHECK = -1
  val NO_NONCE_VALIDATION = (nonce: String) => true
  def apply(): Verifier = new StandardVerifier(NO_TIMESTAMP_CHECK, NO_NONCE_VALIDATION)
  def apply(maxTimestampAge: Int) = new StandardVerifier(maxTimestampAge, NO_NONCE_VALIDATION)
  def appl(maxTimestampAge: Int, validateNonce: (String) => Boolean) =
    new StandardVerifier(maxTimestampAge, validateNonce)
}

class StandardVerifier(maxTimestampAge: Int, validateNonce: (String) => Boolean) extends Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String) = false
}