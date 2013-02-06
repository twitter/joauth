package com.twitter.joauth

import org.specs.SpecificationWithJUnit
import org.specs.mock.Mockito

class UrlEncoderSpec extends SpecificationWithJUnit with Mockito {

  "UrlEncoder" should {

    "properly normalize badly encoded strings" in {
      UrlEncoder.normalize("abcd[]%5F") must be_==("abcd%5B%5D_")
      UrlEncoder.normalize("+-%7E") must be_==("%20-~")
    }

    "not fail when normalizing a malformed urlencoded string" in {
      UrlEncoder.normalize("abcd%") mustEqual "abcd%"
      UrlEncoder.normalize("abcd%f") mustEqual "abcd%f"
    }

    "properly encode special utf-8 characters" in {
      UrlEncoder("%") mustEqual "%25"
      UrlEncoder("+") mustEqual "%2B"
      UrlEncoder(" ") mustEqual "%20"
      UrlEncoder(UrlDecoder("%c3%b8")) mustEqual "%C3%B8"
      UrlEncoder("ø") mustEqual "%C3%B8"
    }
  }
}
