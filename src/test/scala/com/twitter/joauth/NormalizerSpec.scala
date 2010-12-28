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

import com.twitter.joauth.testhelpers.OAuth1TestCases
import org.specs.Specification

class NormalizerSpec extends Specification {
  val normalize = StandardNormalizer
  "Get Port String" should {
    "skip port for  80/HTTP" in { normalize.getPortString(80, "http") must be_==("") }
    "return port for 80/HTTPS" in { normalize.getPortString(80, "https") must be_==(":80") }
    "return port for 443/HTTP" in { normalize.getPortString(443, "http") must be_==(":443") }
    "skip port for 443/HTTPS" in { normalize.getPortString(443, "https") must be_==("") }
    "return port for 3000/HTTP" in { normalize.getPortString(3000, "http") must be_==(":3000") }
    "return port for 3000/HTTPS" in { normalize.getPortString(3000, "https") must be_==(":3000") }
  }
  "Normalizer" should {
    "normalize correctly" in {
      OAuth1TestCases().foreach { (testCase) =>
        if (testCase.exception == null) {
          for ((post) <- List(true, false)) {
            val verb = if (post) "POST" else "GET"
            "normalize %s/%s".format(post, testCase.testName) in {
              normalize(
                testCase.scheme,
                testCase.host,
                testCase.port,
                verb,
                testCase.path,
                testCase.parameters,
                testCase.oAuth1Params(post)) must be_==(testCase.normalizedRequest(post))
            }
          }
        }
      }
    }
  }
}