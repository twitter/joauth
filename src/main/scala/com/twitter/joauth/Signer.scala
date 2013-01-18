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

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64

/**
 * A Signer takes a string, a token secret and a consumer secret, and produces a signed string
 */
trait Signer {
  /**
   * produce an encoded signature string
   */
  def getString(str: String, tokenSecret: String, consumerSecret: String): String

  /**
   * produce a signature as a byte array
   */
  def getBytes(str: String, tokenSecret: String, consumerSecret: String): Array[Byte]

  /**
   * decode an existing signature to a byte array
   */
  def toBytes(signature: String): Array[Byte]
}

/**
 * For testing. Always returns the same string
 */
class ConstSigner(str: String, bytes: Array[Byte]) extends Signer {
  override def getBytes(str: String, tokenSecret: String, consumerSecret: String) = bytes
  override def getString(str: String, tokenSecret: String, consumerSecret: String) = str
  override def toBytes(signature: String) = bytes
}

/**
 * A convenience factory for a StandardSigner
 */
object Signer {
  def apply(): Signer = StandardSigner
  val HMACSHA1 = "HmacSHA1"
}

/**
 * a singleton of the StandardSigner class
 */
object StandardSigner extends StandardSigner

/**
 * the standard implmenentation of the Signer trait. Though stateless and threadsafe,
 * this is a class rather than an object to allow easy access from Java. Scala codebases
 * should use the corresponding StandardSigner object instead.
 */
class StandardSigner extends Signer {
  override def getString(str: String, tokenSecret: String, consumerSecret: String): String =
    UrlEncoder(Base64.encodeBase64String(getBytes(str, tokenSecret, consumerSecret)))

  override def getBytes(str: String, tokenSecret: String, consumerSecret: String): Array[Byte] = {
    val key = consumerSecret+Normalizer.AND+tokenSecret
    val signingKey = new SecretKeySpec(key.getBytes, Signer.HMACSHA1)

    // TODO: consider synchronizing this, apparently Mac may not be threadsafe
    val mac = Mac.getInstance(Signer.HMACSHA1)
    mac.init(signingKey)
    mac.doFinal(str.getBytes)
  }

  override def toBytes(signature: String): Array[Byte] =
    Base64.decodeBase64(UrlDecoder(signature).trim)
}