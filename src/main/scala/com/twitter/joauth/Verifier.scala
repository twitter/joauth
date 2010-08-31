package com.twitter.joauth

trait Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String): Boolean
}

trait NonceValidator {
  def apply(nonce: String): Boolean
}
object NoopNonceValidator extends NonceValidator {
  def apply(nonce: String): Boolean = true
}

object Verifier {
  val NO_TIMESTAMP_CHECK = -1
  def apply(): Verifier = new StandardVerifier(NO_TIMESTAMP_CHECK, NoopNonceValidator)
  def apply(maxTimestampAge: Int) = new StandardVerifier(maxTimestampAge, NoopNonceValidator)
  def appl(maxTimestampAge: Int, validateNonce: NonceValidator) =
    new StandardVerifier(maxTimestampAge, validateNonce)
}

class StandardVerifier(maxTimestampAge: Int, validateNonce: NonceValidator) extends Verifier {
  def apply(request: OAuth1Request, tokenSecret: String, consumerSecret: String) = false
}