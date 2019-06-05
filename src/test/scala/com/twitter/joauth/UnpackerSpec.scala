// Copyright 2011 Twitter, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package com.twitter.joauth

import com.twitter.joauth.keyvalue.KeyValueHandler
import com.twitter.joauth.testhelpers.{MockRequestFactory, OAuth1TestCase, OAuth1TestCases}
import org.specs.SpecificationWithJUnit
import org.specs.matcher.Matcher
import org.specs.mock.Mockito
import com.twitter.joauth.UnpackedRequest.{OAuth1Request, OAuth1TwoLeggedRequest}

class UnpackerSpec extends SpecificationWithJUnit with Mockito {
  "Unpacked for OAuth2 Request" should {
    case class containTheToken(token: String) extends Matcher[UnpackedRequest] {
      val goodresponse = "oauth request matches token"
      def apply(r: => UnpackedRequest) = {
        val (result, badresponse) = r match {
          case null => (false, "unpacked request is null")
          case u:UnpackedRequest.OAuth2Request => (u.token == token,"unpacked request has incorrect token: " + u.token)
          case _ => (false, "unknown request")
        }
        (result, goodresponse, badresponse)
      }
    }

    val unpacker = Unpacker.StandardUnpackerFactory.newUnpacker()
    val kvHandler = mock[KeyValueHandler]

    "unpack request with bearer token in header HTTPS" in {
      val request = MockRequestFactory.oAuth2nRequestInHeader("a")
      request.scheme = "https"
      unpacker.unpack(request) must containTheToken("a")
    }
    "unpack request with bearer token containing +=/ in header HTTPS" in {
      val token = "AAA+BBB=CCC/DDD="
      val encodedToken = "AAA%2BBBB%3DCCC%2FDDD%3D"
      val request = MockRequestFactory.oAuth2nRequestInHeader(encodedToken)
      request.scheme = "https"
      unpacker.unpack(request) must containTheToken(token)
    }
    "unpack as unknown request with bearer token in header HTTP" in {
      unpacker.unpack(MockRequestFactory.oAuth2nRequestInHeader("a")) must throwA[MalformedRequest]
    }
    "unpack as unknown request when no bearer token exists" in {
      val request = MockRequestFactory.oAuth2RequestInParams("a")
      request.scheme = "https"
      unpacker.unpack(request) must haveClass[UnpackedRequest.UnknownRequest]
    }
  }

  def getTestName(testName: String, testCaseName: String, oAuthInParams: Boolean, oAuthInHeader: Boolean, paramsInRequestBody: Boolean) =
    "%s for %s oAuthInParams:%s, oAuthInHeader: %s, paramsInRequestBody:%s".format(
      testName, testCaseName, oAuthInParams, oAuthInHeader, paramsInRequestBody)

  def doOAuth1Tests(testCase: OAuth1TestCase, oAuthInParams: Boolean, oAuthInHeader: Boolean, paramsInRequestBody: Boolean) = {

    val kvHandler = smartMock[KeyValueHandler]
    val unpacker = Unpacker.StandardUnpackerFactory.newUnpacker()

    if (testCase.canBeUnpackedAsOAuth) {
      // KV Handler Called Once Per Param
      getTestName("kvHandler called once per parameter", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
        val oAuthParamsBuilder = unpacker.parseRequest(request, ConversionUtil.toArrayList(Seq(kvHandler)))

        val numParams = testCase.parameters.size + (if (oAuthInHeader) 0 else 7)
        there were numParams.times(kvHandler).handle(any[String], any[String])
        if (testCase.parameters != Nil) {
          testCase.parameters.foreach { case (k, v) =>
            // We cannot check against v directly as it might have been encoded to a different value
            there was one(kvHandler).handle(k, _: String)
          }
        }
      }
      // Parse Request
      getTestName("parse request", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
        val oAuthParamsBuilder = unpacker.parseRequest(request, ConversionUtil.toArrayList(Seq(kvHandler)))
        val parsedRequest = Request.factory.parsedRequest(request, oAuthParamsBuilder.otherParams)
        parsedRequest mustEqual testCase.parsedRequest(paramsInRequestBody, oAuthInHeader)
        oAuthParamsBuilder.oAuth1Params.toString must be_==(testCase.oAuth1Params(paramsInRequestBody).toString)
      }
      // Parse request
      getTestName("parse oauth", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
        val oAuthParamsBuilder = unpacker.parseRequest(request, ConversionUtil.toArrayList(Seq(kvHandler)))
        val parsedRequest = Request.factory.parsedRequest(request, oAuthParamsBuilder.otherParams)
        unpacker.getOAuth1Request(parsedRequest, oAuthParamsBuilder.oAuth1Params) must be_==(testCase.oAuth1Request(paramsInRequestBody, oAuthInHeader))
      }

      if (oAuthInHeader) {
        // make sure parsing works without quotes in header
        getTestName("parse oauth with unquoted header", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
          val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody, false)
          val oAuthParamsBuilder = unpacker.parseRequest(request, ConversionUtil.toArrayList(Seq(kvHandler)))
          val parsedRequest = Request.factory.parsedRequest(request, oAuthParamsBuilder.otherParams)
          unpacker.getOAuth1Request(parsedRequest, oAuthParamsBuilder.oAuth1Params) must be_==(testCase.oAuth1Request(paramsInRequestBody, oAuthInHeader))
        }
      } else {
        // make sure get/post parsing still works with junky auth header
        getTestName("parse oauth with junk auth header", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
          val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
          request.authHeader = "BLARG"
          val oAuthParamsBuilder = unpacker.parseRequest(request, ConversionUtil.toArrayList(Seq(kvHandler)))
          val parsedRequest = Request.factory.parsedRequest(request, oAuthParamsBuilder.otherParams)
          unpacker.getOAuth1Request(parsedRequest, oAuthParamsBuilder.oAuth1Params) must be_==(testCase.oAuth1Request(paramsInRequestBody, oAuthInHeader))
        }
      }
      if (paramsInRequestBody) {
        // test with leading ? and & in post query string
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
        val body = request.body
        request.body = "&" + Option(body).getOrElse("")
        getTestName("unpack request with leading &", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
          unpacker.unpack(request, kvHandler) must be_==(testCase.oAuth1Request(paramsInRequestBody, oAuthInHeader))
        }
      } else {
        // test with leading ? and & in get query string
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
        val queryString = request.queryString
        request.queryString = "&" + Option(queryString).getOrElse("")
        getTestName("unpack request with leading &", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
          unpacker.unpack(request, kvHandler) must be_==(testCase.oAuth1Request(paramsInRequestBody, oAuthInHeader))
        }
      }
      // Unpack Request
      val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
      getTestName("unpack request", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
        unpacker.unpack(request, kvHandler) must be_==(testCase.oAuth1Request(paramsInRequestBody, oAuthInHeader))
      }
    } else {
      // handle unknown
      getTestName("handle unknown", testCase.testName, oAuthInParams, oAuthInHeader, paramsInRequestBody) in {
        val request = testCase.request(oAuthInParams, oAuthInHeader, paramsInRequestBody)
        unpacker.unpack(request) must be_==(new UnpackedRequest.UnknownRequest(testCase.parsedRequest(paramsInRequestBody, oAuthInHeader)))
      }
    }
  }

  "Unpacker for OAuth1 Test Cases" should {
    OAuth1TestCases() foreach { (testCase) =>
      for ((paramsInRequestBody) <- List(true, false)) {
        for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
          doOAuth1Tests(testCase, oAuthInParams, oAuthInHeader, paramsInRequestBody)
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
  "Unpacker for OAuth1 Special Case POST2" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      doOAuth1Tests(OAuth1TestCases.oAuthSpecialCasePost2, oAuthInParams, oAuthInHeader, true)
    }
  }
  "Unpacker for OAuth1 Special Case PUT" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      doOAuth1Tests(OAuth1TestCases.oAuthSpecialCasePut, oAuthInParams, oAuthInHeader, true)
    }
  }
  "Unpacker for OAuth1 Special Case GET with request body" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      doOAuth1Tests(OAuth1TestCases.oAuthSpecialCaseGetWithRequestBody, oAuthInParams, oAuthInHeader, true)
    }
  }
  "Unpacker for OAuth1 Special Case GET with comma" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      OAuth1TestCases.commaTestCases().foreach {
        doOAuth1Tests(_, oAuthInParams, oAuthInHeader, false)
      }
    }
  }
  "Unpacker for OAuth1 Special Case GET with brackets" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      OAuth1TestCases.bracketTestCases().foreach {
        doOAuth1Tests(_, oAuthInParams, oAuthInHeader, false)
      }
    }
  }

  "Unpacker for OAuth1 Two Legged" should {
    val kvHandler = smartMock[KeyValueHandler]
    val unpacker = Unpacker.StandardUnpackerFactory.newUnpacker()

    "correctly parse the request with null token" in {
      val testCase = OAuth1TestCases.oAuthTwoLeggedNullToken
      val request = testCase.request(true, false, false)
      val oAuthParamsBuilder = unpacker.parseRequest(request, ConversionUtil.toArrayList(Seq(kvHandler)))
      val parsedRequest = Request.factory.parsedRequest(request, oAuthParamsBuilder.otherParams)
      parsedRequest mustEqual testCase.parsedRequest(false, false)
      oAuthParamsBuilder.oAuth1Params.toString must be_==(testCase.oAuth1Params(false).toString)
    }

    "correctly parse the request with empty token" in {
      val testCase = OAuth1TestCases.oAuthTwoLeggedEmptyToken
      val request = testCase.request(true, false, false)
      val oAuthParamsBuilder = unpacker.parseRequest(request, ConversionUtil.toArrayList(Seq(kvHandler)))
      val parsedRequest = Request.factory.parsedRequest(request, oAuthParamsBuilder.otherParams)
      parsedRequest mustEqual testCase.parsedRequest(false, false)
      oAuthParamsBuilder.oAuth1Params.toString must be_==(testCase.oAuth1Params(false).toString)
    }

    "correctly unpack the request" in {
      val testCase = OAuth1TestCases.oAuthTwoLeggedNullToken
      val request = testCase.request(true, false, false)
      unpacker.unpack(request, kvHandler) must be_==(testCase.oAuth1TwoLeggedRequest(false, false))
    }

    "OAuth1TwoLeggedRequest should not match OAuth1Request" in {
      val testCase = OAuth1TestCases.oAuthTwoLeggedNullToken
      val twoLeggRequest = testCase.oAuth1TwoLeggedRequest(false, false)
      twoLeggRequest.isInstanceOf[OAuth1TwoLeggedRequest] must beTrue
      twoLeggRequest.isInstanceOf[OAuth1Request] must beFalse
    }
  }
}
