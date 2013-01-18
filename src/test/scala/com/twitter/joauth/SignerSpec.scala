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

import java.util.Arrays
import org.apache.commons.codec.binary.Base64
import org.specs.SpecificationWithJUnit

class SignerSpec extends SpecificationWithJUnit {
  "Signer" should {
    val signer = Signer()
    "sign correctly" in {
      val tokenSecret = "readsecret"
      val consumerSecret = "writesecret"
      val normalizedRequest = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dreadkey%26oauth_version%3D1.0%26size%3Doriginal"
      val signature = "Dq+QxkRpmASNSiUrwhCBbQYZuBo="
      val bytes = Base64.decodeBase64(signature)
      val encoded = UrlEncoder(signature)
      signer.getString(normalizedRequest, tokenSecret, consumerSecret) mustEqual encoded
      Arrays.equals(signer.getBytes(normalizedRequest, tokenSecret, consumerSecret), bytes) must beTrue
      Arrays.equals(signer.toBytes(encoded), bytes) must beTrue
      Base64Util.equals(signature, bytes) must beTrue
      val badbytes = Base64.decodeBase64(signature)
      badbytes(bytes.length - 1) = 0: Byte
      Base64Util.equals(signature, badbytes) must beFalse
    }
  }
}
