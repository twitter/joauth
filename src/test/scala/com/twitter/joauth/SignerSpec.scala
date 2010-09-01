package com.twitter.joauth

import org.specs.Specification

class SignerSpec extends Specification {
  "Signer" should {
    val sign = Signer()
    "sign correctly" in {
      val tokenSecret = "readsecret"
      val consumerSecret = "writesecret"
      val normalizedRequest = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dreadkey%26oauth_version%3D1.0%26size%3Doriginal"
      val signature = "Dq+QxkRpmASNSiUrwhCBbQYZuBo="
      sign(normalizedRequest, tokenSecret, consumerSecret) must be_==(signature)
    }
  }
}