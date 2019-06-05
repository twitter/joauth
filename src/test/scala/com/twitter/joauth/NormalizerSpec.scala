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

import com.twitter.joauth.keyvalue.Transformer
import com.twitter.joauth.testhelpers.OAuth1TestCases
import org.specs.SpecificationWithJUnit

class NormalizerSpec extends SpecificationWithJUnit {
  val normalize = new Normalizer.StandardNormalizer

  "Include Port String" should {
    "skip port for 80/HTTP" in { normalize.includePortString(80, "http") must beFalse }
    "skip port for 80/hTtP" in { normalize.includePortString(80, "hTtP") must beFalse }
    "return port for 80/HTTPS" in { normalize.includePortString(80, "https") must beTrue }
    "return port for 80/hTtPs" in { normalize.includePortString(80, "hTtPs") must beTrue }
    "return port for 443/HTTP" in { normalize.includePortString(443, "http") must beTrue }
    "return port for 443/hTtP" in { normalize.includePortString(443, "hTtP") must beTrue }
    "skip port for 443/HTTPS" in { normalize.includePortString(443, "https") must beFalse }
    "skip port for 443/hTtpS" in { normalize.includePortString(443, "hTtpS") must beFalse }
    "return port for 3000/HTTP" in { normalize.includePortString(3000, "http") must beTrue }
    "return port for 3000/HTTPS" in { normalize.includePortString(3000, "https") must beTrue }
  }


  "Normalizer" should {
    "normalize correctly" in {
      OAuth1TestCases().foreach { (testCase) =>
        if (testCase.canBeUnpackedAsOAuth) {
          for ((post) <- List(true, false)) {
            val verb = if (post) "POST" else "GET"
            "normalize %s/%s".format(post, testCase.testName) in {

              val result = normalize.normalize(
                testCase.scheme,
                testCase.host,
                testCase.port,
                verb,
                testCase.path,
                ConversionUtil.toArrayList(testCase.parameters.map { case (k, v) =>
                  new Request.Pair(Transformer.URL_ENCODING_NORMALIZING_TRANSFORMER.transform(k), Transformer.URL_ENCODING_NORMALIZING_TRANSFORMER.transform(v))
                }),
                testCase.oAuth1Params(post))

              result must be_==(testCase.normalizedRequest(post, false))
            }
          }
        }
      }
    }
  }
}
