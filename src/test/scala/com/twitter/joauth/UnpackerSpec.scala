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

import com.twitter.joauth.keyvalue.{KeyValueHandler, UrlEncodingNormalizingTransformer}
import com.twitter.joauth.testhelpers.{MockRequestFactory, OAuth1TestCase, OAuth1TestCases}
import org.specs.matcher.Matcher
import org.specs.mock.Mockito
import org.specs.Specification

class UnpackerSpec extends Specification with Mockito {
  "Unpacked for OAuth2 Request" should {
    case class containTheToken(token: String) extends Matcher[UnpackedRequest] {
      val goodresponse = "oauth request matches token"
      def apply(r: => UnpackedRequest) = {
        val (result, badresponse) = r match {
          case null => (false, "unpacked request is null")
          case u:OAuthRequest => (u.token == token,"unpacked request has incorrect token: " + u.token)
          case _ => (false, "unknown request")
        }
        (result, goodresponse, badresponse)
      }
    }

    val unpacker = StandardUnpacker()
    val kvHandler = mock[KeyValueHandler]

    for ((verbose, header) <- List(
      ("", MockRequestFactory.oAuth2Header(_)),
      ("verbose ", MockRequestFactory.oAuth2HeaderWithKey(_)))) {
      "unpack request with "+verbose+"token in header HTTPS" in {
        val request = MockRequestFactory.requestWithAuthHeader(header("a"))
        request.scheme = "https"
        unpacker(request) must containTheToken("a")
      }
      "unpack as unknown request with "+verbose+"token in header HTTP" in {
        unpacker(MockRequestFactory.requestWithAuthHeader(header("a"))) must throwA[MalformedRequest]
      }
    }
    "unpack request with token in params HTTPS" in {
      val request = MockRequestFactory.oAuth2RequestInParams("a")
      request.scheme = "https"
      unpacker(request) must containTheToken("a")
    }
    "unpack request with token in params HTTPS and junk Auth header" in {
      val request = MockRequestFactory.oAuth2RequestInParams("a")
      request.scheme = "https"
      request.authHeader = Some("BLARG")
      unpacker(request) must containTheToken("a")
    }
    "unpack request with token in params HTTPS in POST" in {
      val request = MockRequestFactory.postRequest(MockRequestFactory.oAuth2RequestInParams("a"))
      request.scheme = "https"
      unpacker(request) must containTheToken("a")
    }
    "unpack as unknown request with token in params HTTP" in {
      unpacker(MockRequestFactory.oAuth2RequestInParams("a")) must throwA[MalformedRequest]
    }
  }

  def getTestName(testName: String, testCaseName: String, oAuthInParams: Boolean, oAuthInHeader: Boolean, paramsInPost: Boolean) =
    "%s for %s oAuthInParams:%s, oAuthInHeader: %s, paramsInPost:%s".format(
      testName, testCaseName, oAuthInParams, oAuthInHeader, paramsInPost)

  def doOAuth1Tests(testCase: OAuth1TestCase, oAuthInParams: Boolean, oAuthInHeader: Boolean, paramsInPost: Boolean) = {

    val kvHandler = mock[KeyValueHandler]
    val unpacker = StandardUnpacker()

    if (testCase.canBeUnpackedAsOAuth) {
      // KV Handler Called Once Per Param
      getTestName("kvHandler called once per parameter", testCase.testName, oAuthInParams, oAuthInHeader, paramsInPost) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInPost)
        val (params, oAuthParamsBuilder) = unpacker.parseRequest(request, Seq(kvHandler))
        if (testCase.parameters == Nil) there was no(kvHandler).apply(any[String], any[String])
        else {
          there were (testCase.parameters.size).times(kvHandler).apply(any[String], any[String])
          testCase.parameters.foreach { e =>
            there was one(kvHandler).apply(UrlEncodingNormalizingTransformer(e._1), UrlEncodingNormalizingTransformer(e._2))
          }
        }
      }
      // Parse Request
      getTestName("parse request", testCase.testName, oAuthInParams, oAuthInHeader, paramsInPost) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInPost)
        val (parsedRequest, oAuthParamsBuilder) = unpacker.parseRequest(request, Seq(kvHandler))
        parsedRequest mustEqual testCase.parsedRequest(paramsInPost)
        oAuthParamsBuilder.oAuth1Params.toString must be_==(testCase.oAuth1Params(paramsInPost).toString)
      }
      // Parse request
      getTestName("parse oauth", testCase.testName, oAuthInParams, oAuthInHeader, paramsInPost) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInPost)
        val (parsedRequest, oAuthParamsBuilder) = unpacker.parseRequest(request, Seq(kvHandler))
        unpacker.getOAuth1Request(parsedRequest, oAuthParamsBuilder.oAuth1Params) must be_==(testCase.oAuth1Request(paramsInPost))
      }
      // make sure get/post parsing still works with junky auth header
      if (!oAuthInHeader) {
        // Parse request
        getTestName("parse oauth with junk auth header", testCase.testName, oAuthInParams, false, paramsInPost) in {
          val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInPost)
          request.authHeader = Some("BLARG")
          val (parsedRequest, oAuthParamsBuilder) = unpacker.parseRequest(request, Seq(kvHandler))
          unpacker.getOAuth1Request(parsedRequest, oAuthParamsBuilder.oAuth1Params) must be_==(testCase.oAuth1Request(paramsInPost))
        }
      }
      // Unpack Request
      val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInPost)
      getTestName("unpack request", testCase.testName, oAuthInParams, oAuthInHeader, paramsInPost) in {
        unpacker(request, Seq(kvHandler)) must be_==(testCase.oAuth1Request(paramsInPost))
      }
    } else {
      // handle unknown
      getTestName("handle unknown", testCase.testName, oAuthInParams, oAuthInHeader, paramsInPost) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInPost)
        unpacker(request) must be_==(UnknownRequest(testCase.parsedRequest(paramsInPost)))
      }
    }
  }

  "Unpacker for OAuth1 Test Cases" should {
    OAuth1TestCases().foreach { (testCase) =>
      for ((paramsInPost) <- List(true, false)) {
        for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
          doOAuth1Tests(testCase, oAuthInParams, oAuthInHeader, paramsInPost)
        }
      }
    }
  }
  "Unpacker for OAuth1 Special Case GET" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      doOAuth1Tests(OAuth1TestCases.oAuthSpecialCaseGet, oAuthInParams, oAuthInHeader, false)
    }
  }
  "Unpacker for OAuth1 Special Case POST" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      doOAuth1Tests(OAuth1TestCases.oAuthSpecialCasePost, oAuthInParams, oAuthInHeader, true)
    }
  }
}
