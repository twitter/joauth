package com.twitter.joauth

import org.specs.SpecificationWithJUnit
import org.specs.mock.Mockito

class UrlEncoderSpec extends SpecificationWithJUnit with Mockito {

  "UrlEncoder" should {

    "properly normalize badly encoded strings" in {
      UrlCodec.normalize("abcd[]%5F") must be_==("abcd%5B%5D_")
      UrlCodec.normalize("+-%7E") must be_==("%20-~")
    }

    "not fail when normalizing a malformed urlencoded string" in {
      UrlCodec.normalize("abcd%") mustEqual "abcd%"
      UrlCodec.normalize("abcd%f") mustEqual "abcd%f"
    }

    "not encode unreserved characters" in {
      UrlCodec.encode("abcdefgHIJKLMNOP") mustEqual "abcdefgHIJKLMNOP"
      UrlCodec.encode("0123456789") mustEqual "0123456789"
      UrlCodec.encode(".-_~") mustEqual ".-_~"
    }

    "properly encode special utf-8 characters" in {
      UrlCodec.encode("%") mustEqual "%25"
      UrlCodec.encode("+") mustEqual "%2B"
      UrlCodec.encode(" ") mustEqual "%20"
      UrlCodec.encode(UrlCodec.decode("%c3%b8")) mustEqual "%C3%B8"
      UrlCodec.encode("ø") mustEqual "%C3%B8"
      UrlCodec.encode("test123!ABC") mustEqual "test123%21ABC"
    }

    "properly encode CR, LF, and other utf-8 characters whose first byte is 0" in {
      UrlCodec.encode("\n") mustEqual "%0A"
      UrlCodec.encode("\r") mustEqual "%0D"
      UrlCodec.encode("\0") mustEqual "%00"
    }

    "properly encode emoji" in {
      UrlCodec.encode("\ud83d\ude04") mustEqual "%F0%9F%98%84"
      UrlCodec.encode("\ud83d\udc4e") mustEqual "%F0%9F%91%8E"
      UrlCodec.encode("I\ud83d\udc93joauth!") mustEqual "I%F0%9F%92%93joauth%21"
    }
  }
}
