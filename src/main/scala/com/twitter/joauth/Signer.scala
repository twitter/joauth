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

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64

/**
 * A Signer takes a string, a token secret and a consumer secret, and produces a signed string
 */
trait Signer {
  def apply(str: String, tokenSecret: String, consumerSecret: String): String
}

/**
 * For testing. Always returns the same string
 */
class ConstSigner(const: String) extends Signer {
  def apply(str: String, tokenSecret: String, consumerSecret: String) = const
}

/**
 * A convenience factory for a StandardSigner
 */
object Signer {
  def apply(): Signer = StandardSigner
}

/**
 * a singleton of the StandardSigner class
 */
object StandardSigner extends StandardSigner {
  val HMACSHA1 = "HmacSHA1"
}

/**
 * the standard implmenentation of the Signer trait. Though stateless and threadsafe,
 * this is a class rather than an object to allow easy access from Java. Scala codebases
 * should use the corresponding StandardSigner object instead.
 */
class StandardSigner extends Signer {
  def apply(str: String, tokenSecret: String, consumerSecret: String) = {
    val key = consumerSecret+StandardNormalizer.AND+tokenSecret
    val signingKey = new SecretKeySpec(key.getBytes, StandardSigner.HMACSHA1)

    // TODO: consider synchronizing this, apparently Mac may not be threadsafe
    val mac = Mac.getInstance(StandardSigner.HMACSHA1)
    mac.init(signingKey)
    val rawHmac = mac.doFinal(str.getBytes)
    new String(Base64.encodeBase64(rawHmac))
  }
}