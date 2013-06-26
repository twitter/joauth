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

    "not encode unreserved characters" in {
      UrlEncoder("abcdefgHIJKLMNOP") mustEqual "abcdefgHIJKLMNOP"
      UrlEncoder("0123456789") mustEqual "0123456789"
      UrlEncoder(".-_~") mustEqual ".-_~"
    }

    "properly encode special utf-8 characters" in {
      UrlEncoder("%") mustEqual "%25"
      UrlEncoder("+") mustEqual "%2B"
      UrlEncoder(" ") mustEqual "%20"
      UrlEncoder(UrlDecoder("%c3%b8")) mustEqual "%C3%B8"
      UrlEncoder("ø") mustEqual "%C3%B8"
      UrlEncoder("test123!ABC") mustEqual "test123%21ABC"
    }

    "properly encode CR, LF, and other utf-8 characters whose first byte is 0" in {
      UrlEncoder("\n") mustEqual "%0A"
      UrlEncoder("\r") mustEqual "%0D"
      UrlEncoder("\0") mustEqual "%00"
    }

    "properly encode emoji" in {
      UrlEncoder("\ud83d\ude04") mustEqual "%F0%9F%98%84"
      UrlEncoder("\ud83d\udc4e") mustEqual "%F0%9F%91%8E"
      UrlEncoder("I\ud83d\udc93joauth!") mustEqual "I%F0%9F%92%93joauth%21"
    }
  }
}
