package com.twitter.joauth

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64

trait Signer {
  def apply(str: String, tokenSecret: String, consumerSecret: String): String
}

class ConstSigner(const: String) extends Signer {
  def apply(str: String, tokenSecret: String, consumerSecret: String) = const
}

object Signer {
  def apply(): Signer = StandardSigner
}

object StandardSigner extends Signer {
  val HMACSHA1 = "HmacSHA1"
  val KEY_BASE = "%s&%s"
  def apply(str: String, tokenSecret: String, consumerSecret: String) = {
    val key = KEY_BASE.format(consumerSecret, tokenSecret)
    val signingKey = new SecretKeySpec(key.getBytes, HMACSHA1)

    // TODO: consider synchronizing this, apparently Mac may not be threadsafe
    val mac = Mac.getInstance(HMACSHA1)
    mac.init(signingKey)
    val rawHmac = mac.doFinal(str.getBytes)
    new String(Base64.encodeBase64(rawHmac))
  }
}