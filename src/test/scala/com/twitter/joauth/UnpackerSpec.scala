package com.twitter.joauth

import com.twitter.joauth.testhelpers.{MockRequestFactory, OAuth1TestCases}
import javax.servlet.http.HttpServletRequest
import org.specs.mock.Mockito
import org.specs.Specification

class UnpackerSpec extends Specification with Mockito {
  "Unpacked for OAuth2 Request" should {
  
    val unpacker = Unpacker()
    val kvHandler = mock[KeyValueHandler]
    val overriddenUnpacker = Unpacker(
      new UriSchemeGetter { 
        override def apply(request: HttpServletRequest) = "HTTPS"
      },
      StandardPathGetter)

    "unpack request with token in header HTTPS" in {
      val request = MockRequestFactory.oAuth2RequestInHeader("a");
      request.scheme = "HTTPS"
      unpacker(request, Seq(kvHandler)) must be_==(OAuth2Request("a"))
    }
    "unpack request with token in params HTTPS" in {
      val request = MockRequestFactory.oAuth2RequestInParams("a")
      request.scheme = "https"
      unpacker(request, Seq(kvHandler)) must be_==(OAuth2Request("a"))
    }
    "unpack request with token in params HTTPS in POST" in {
      val request = MockRequestFactory.postRequest(MockRequestFactory.oAuth2RequestInParams("a"))
      request.scheme = "https"
      unpacker(request, Seq(kvHandler)) must be_==(OAuth2Request("a"))
    }
    "unpack as unknown request with token in params HTTP" in {
      unpacker(MockRequestFactory.oAuth2RequestInParams("a"), Seq(kvHandler)) must throwA[MalformedRequest]
    }
    "unpack as unknown request with token in header HTTP" in {
      unpacker(MockRequestFactory.oAuth2RequestInHeader("a"), Seq(kvHandler)) must throwA[MalformedRequest]
    }
    "respect getScheme override with token in params HTTP" in {
      overriddenUnpacker(MockRequestFactory.oAuth2RequestInParams("a"), Seq(kvHandler)) must be_==(OAuth2Request("a"))
    }
    "respect getScheme override with token in header HTTP" in {
      overriddenUnpacker(MockRequestFactory.oAuth2RequestInHeader("a"), Seq(kvHandler)) must be_==(OAuth2Request("a"))
    }
  }

  def getTestName(testName: String, testCaseName: String, oAuthInParams: Boolean, oAuthInHeader: Boolean, useNamespacedPath: Boolean, paramsInPost: Boolean) = 
    "%s for %s oAuthInParams:%s, oAuthInHeader: %s, paramsInPost:%s, useNamespacedPath: %s".format(
      testName, testCaseName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)

  "Unpacker for OAuth1 Test Cases" should {
    OAuth1TestCases().foreach { (testCase) =>
      for ((paramsInPost) <- List(true, false)) {
        for ((useNamespacedPath) <- List(true, false)) {
          for ((oAuthInParams, oAuthInHeader) <- List((true, false), (false, true))) {

            val getPath = if (useNamespacedPath) new PathGetter {
              def apply(request: HttpServletRequest) = {
                testCase.path
              }
            } else StandardPathGetter

            val unpacker = Unpacker(StandardUriSchemeGetter, getPath)
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
                    kvHandler.apply(e._1, e._2) was called.once
                  }
                }
              }
              // Parse Request
              getTestName("parse request", testCase.testName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost) in {
                val request = testCase.httpServletRequest(oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
                val (params, oAuthParams) = unpacker.parseRequest(request, Seq(kvHandler))
                params.toString must be_==(testCase.parameters.toString)
                oAuthParams.toString must be_==(testCase.oAuthParams(paramsInPost).toString)
              }
              // Auth Result
              getTestName("produce correct authresult", testCase.testName, oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost) in {
                val request = testCase.httpServletRequest(oAuthInParams, oAuthInHeader, useNamespacedPath, paramsInPost)
                val (params, oAuthParams) = unpacker.parseRequest(request, Seq(kvHandler))
                unpacker.getOAuth1RequestBuilder(request, params, oAuthParams).build must be_==(testCase.oAuth1Request(paramsInPost))
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
                  unpacker(request, Seq(kvHandler))
                  fail("should have thrown")
                } catch {
                  case e => e.toString must be_==(testCase.exception.toString)
                }
                // for compiler
                1
              }
            }
          }
        }
      }
    }
  }
}
