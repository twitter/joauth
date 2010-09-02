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

import com.twitter.joauth.keyvalue.{KeyValueHandler, UrlEncodingNormalizingTransformer}
import com.twitter.joauth.testhelpers.{MockRequestFactory, OAuth1TestCase, OAuth1TestCases}
import javax.servlet.http.HttpServletRequest
import org.specs.mock.Mockito
import org.specs.Specification

class UnpackerSpec extends Specification with Mockito {
  "Unpacked for OAuth2 Request" should {

    val unpacker = StandardUnpacker()
    val kvHandler = mock[KeyValueHandler]
    val overriddenUnpacker = StandardUnpacker(
      new UriSchemeGetter { 
        override def apply(request: HttpServletRequest) = "HTTPS"
      },
      StandardPathGetter)

    "unpack request with token in header HTTPS" in {
      val request = MockRequestFactory.oAuth2RequestInHeader("a");
      request.scheme = "HTTPS"
      unpacker(request) must be_==(OAuth2Request("a"))
    }
    "unpack request with token in params HTTPS" in {
      val request = MockRequestFactory.oAuth2RequestInParams("a")
      request.scheme = "https"
      unpacker(request) must be_==(OAuth2Request("a"))
    }
    "unpack request with token in params HTTPS in POST" in {
      val request = MockRequestFactory.postRequest(MockRequestFactory.oAuth2RequestInParams("a"))
      request.scheme = "https"
      unpacker(request) must be_==(OAuth2Request("a"))
    }
    "unpack as unknown request with token in params HTTP" in {
      unpacker(MockRequestFactory.oAuth2RequestInParams("a")) must throwA[MalformedRequest]
    }
    "unpack as unknown request with token in header HTTP" in {
      unpacker(MockRequestFactory.oAuth2RequestInHeader("a")) must throwA[MalformedRequest]
    }
    "respect getScheme override with token in params HTTP" in {
      overriddenUnpacker(MockRequestFactory.oAuth2RequestInParams("a")) must be_==(OAuth2Request("a"))
    }
    "respect getScheme override with token in header HTTP" in {
      overriddenUnpacker(MockRequestFactory.oAuth2RequestInHeader("a")) must be_==(OAuth2Request("a"))
    }
  }

  def getTestName(testName: String, testCaseName: String, oAuthInParams: Boolean, oAuthInHeader: Boolean, useNamespacedPath: Boolean, paramsInPost: Boolean) = 
    "%s for %s oAuthInParams:%s, oAuthInHeader: %s, useNamespacedPath: %s, paramsInPost:%s".format(
      testName, testCaseName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)

  def doOAuth1Tests(testCase: OAuth1TestCase, oAuthInParams: Boolean, oAuthInHeader: Boolean, useNamespacedPath: Boolean, paramsInPost: Boolean) = {
    val getPath = if (useNamespacedPath) new PathGetter {
      def apply(request: HttpServletRequest) = {
        testCase.path
      }
    } else StandardPathGetter

    val unpacker = StandardUnpacker(StandardUriSchemeGetter, getPath)
    val kvHandler = mock[KeyValueHandler]

    if (testCase.exception == null) {
      // KV Handler Called Once Per Param
      getTestName("kvHandler called once per parameter", testCase.testName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost) in {
        val request = testCase.httpServletRequest(oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
        val (params, oAuthParams) = unpacker.parseRequest(request, Seq(kvHandler))
        if (testCase.parameters == Nil) kvHandler.apply(any[String], any[String]) was notCalled
        else {
          kvHandler.apply(any[String], any[String]) was called((testCase.parameters.size).times)
          testCase.parameters.foreach { e =>
            kvHandler.apply(UrlEncodingNormalizingTransformer(e._1), UrlEncodingNormalizingTransformer(e._2)) was called.once
          }
        }
      }
      // Parse Request
      getTestName("parse request", testCase.testName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost) in {
        val request = testCase.httpServletRequest(oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
        val (params, oAuthParams) = unpacker.parseRequest(request, Seq(kvHandler))
        params.toString must be_==(testCase.parameters.map(e => (UrlEncodingNormalizingTransformer(e._1), UrlEncodingNormalizingTransformer(e._2))).toString)
        oAuthParams.toString must be_==(testCase.oAuthParams(paramsInPost).toString)
      }
      // Auth Result
      getTestName("produce correct authresult", testCase.testName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost) in {
        val request = testCase.httpServletRequest(oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
        val (params, oAuthParams) = unpacker.parseRequest(request, Seq(kvHandler))
        unpacker.getOAuth1Request(request, params, oAuthParams) must be_==(testCase.oAuth1Request(paramsInPost))
      }
      // Unpack Request
      val request = testCase.httpServletRequest(oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
      getTestName("unpack request", testCase.testName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost) in {
        unpacker(request, Seq(kvHandler)) must be_==(testCase.oAuth1Request(paramsInPost))
      }
    } else {
      // Throw Exception
      getTestName("throw exception", testCase.testName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost) in {
        try {
          val request = testCase.httpServletRequest(oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
          unpacker(request)
          fail("should have thrown")
        } catch {
          case e => e.toString must be_==(testCase.exception.toString)
        }
        // for compiler
        1
      }
    }
  }

  "Unpacker for OAuth1 Test Cases" should {
    OAuth1TestCases().foreach { (testCase) =>
      for ((paramsInPost) <- List(true, false)) {
        for ((useNamespacedPath) <- List(true, false)) {
          for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
            doOAuth1Tests(testCase, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
          }
        }
      }
    }
  }
  "Unpacker for OAuth1 Special Case GET" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      doOAuth1Tests(OAuth1TestCases.oAuthSpecialCaseGet, oAuthInParams, oAuthInHeader, false, false)
    }
  }
  "Unpacker for OAuth1 Special Case POST" should {
    for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {
      doOAuth1Tests(OAuth1TestCases.oAuthSpecialCasePost, oAuthInParams, oAuthInHeader, false, true)
    }
  }
}
