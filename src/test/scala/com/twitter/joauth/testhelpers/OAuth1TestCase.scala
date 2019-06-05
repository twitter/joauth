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

package com.twitter.joauth.testhelpers

import com.twitter.joauth.keyvalue.Transformer
import com.twitter.joauth._

case class HeaderOnlyParams(
  params: Seq[(String, String)],
  val normalizedRequestGet: String,
  val normalizedRequestPost: String)

case class OAuth1TestCase(
  val testName: String,
  val scheme: String,
  val host: String,
  val port: Int,
  val path: String,
  val verb: Option[String],
  val parameters: List[(String, String)],
  val token: String,
  val tokenSecret: String,
  val consumerKey: String,
  val consumerSecret: String,
  val signatureGet: String,
  val signaturePost: String,
  val nonce: String,
  val timestampSecs: Int,
  val normalizedRequestGet: String,
  val normalizedRequestPost: String,
  val urlEncodeParams: Boolean,
  val canBeUnpackedAsOAuth: Boolean,
  val headerOnlyParams: Option[HeaderOnlyParams]) {

  def oAuth1Request(paramsInRequestBody: Boolean, authInHeader: Boolean) = new UnpackedRequest.OAuth1Request(
    token,
    consumerKey,
    nonce,
    timestampSecs,
    signature(paramsInRequestBody),
    OAuthParams.HMAC_SHA1,
    OAuthParams.ONE_DOT_OH,
    parsedRequest(paramsInRequestBody, authInHeader),
    normalizedRequest(paramsInRequestBody, authInHeader))

  def oAuth1TwoLeggedRequest(paramsInRequestBody: Boolean, authInHeader: Boolean) = new UnpackedRequest.OAuth1TwoLeggedRequest(
    consumerKey,
    nonce,
    timestampSecs,
    signature(paramsInRequestBody),
    OAuthParams.HMAC_SHA1,
    OAuthParams.ONE_DOT_OH,
    parsedRequest(paramsInRequestBody, authInHeader),
    normalizedRequest(paramsInRequestBody, authInHeader))

  def parsedRequest(paramsInRequestBody: Boolean, authInHeader: Boolean) = {
    val params = if (authInHeader) {
      parameters ++ headerOnlyParams.map(_.params.filter { case (k, _) =>
        k.indexOf("oauth_") == 0
      }).getOrElse(Nil).toList
    } else {
      parameters
    }

    new Request.ParsedRequest(
      scheme.toUpperCase,
      host,
      port,
      if (paramsInRequestBody) verb.getOrElse("POST") else "GET",
      path,
      ConversionUtil.toArrayList(params.map { case (k, v) =>
        val (ek, ev) =
          if (urlEncodeParams) {
            UrlCodec.encode(k) -> UrlCodec.encode(v)
          } else {
            k -> v
          }
        new Request.Pair(Transformer.URL_ENCODING_NORMALIZING_TRANSFORMER.transform(ek), Transformer.URL_ENCODING_NORMALIZING_TRANSFORMER.transform(ev))
      })
    )
  }

  def oAuth1Params(paramsInRequestBody: Boolean) =
    new OAuthParams.OAuth1Params(
      token,
      consumerKey,
      nonce,
      timestampSecs,
      timestampSecs.toString,
      signature(paramsInRequestBody),
      OAuthParams.HMAC_SHA1,
      OAuthParams.ONE_DOT_OH)

  def normalizedRequest(paramsInRequestBody: Boolean, oAuthInHeader: Boolean) = {
    if (oAuthInHeader) {
      if (paramsInRequestBody) {
        headerOnlyParams.map(_.normalizedRequestPost).getOrElse(normalizedRequestPost)
      } else {
        headerOnlyParams.map(_.normalizedRequestGet).getOrElse(normalizedRequestGet)
      }
    } else {
      if (paramsInRequestBody) {
        normalizedRequestPost
      } else {
        normalizedRequestGet
      }
    }
  }

  def signature(paramsInRequestBody: Boolean) = {
    val signature = if (paramsInRequestBody) signaturePost else signatureGet
    if (urlEncodeParams) UrlCodec.encode(signature)
    else signature
  }

  def request(
    oAuthInParam: Boolean,
    oAuthInHeader: Boolean,
    paramsInRequestBody: Boolean,
    quotedHeaderValues: Boolean = true): MockRequest = {

    val signature = if (paramsInRequestBody) signaturePost else signatureGet
    var request = new MockRequest
    request.method = (verb, paramsInRequestBody) match {
      case (_, false) => "GET"
      case (None, true) => "POST"
      case (Some(method), true) => method
    }
    request.scheme = scheme
    request.host = host
    request.port = port
    request.path = path

    if (oAuthInHeader) {
      val extraHeaderParams = headerOnlyParams.map(_.params).getOrElse(Nil)
      request.authHeader =
        MockRequestFactory.oAuth1Header(token, consumerKey, signature, nonce, timestampSecs.toString, urlEncodeParams, extraHeaderParams, quotedHeaderValues)
    }
    var queryString = ParamHelper.toQueryString(parameters, urlEncodeParams)
    if (oAuthInParam) {
      if (!queryString.isEmpty) queryString += "&"
      queryString += MockRequestFactory.oAuth1QueryString(token, consumerKey, signature, nonce, timestampSecs.toString, urlEncodeParams)
    }
    if (!queryString.isEmpty) {
      request.queryString = queryString
    }

    if (paramsInRequestBody) {
      MockRequestFactory.addParamsToRequestBody(request)
    }

    request
  }
}

object OAuth1TestCases {
  def apply(): List[OAuth1TestCase] = {
    List(
      OAuth1TestCase(
        "http/80/params",
        "http",
        "photos.example.net",
        80,
        "/Photos",
        None,
        List(
          "size"        -> "original",
          "file"        -> "vacation.jpg",
          "since"       -> "Tue%2C+22+Nov+2011+21%3A55%3A05+GMT",
          "bad%5Fparam" -> "bad%2dvalue",
          "bad%2eparam" -> "bad%7Evalue"),
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "pmVlfS3T77Stok94B5AMn784Eb8%3D",
        "29sCGl%2B0UWI5KM0hvHWVVMFHBLc%3D",
        "kllo9940pd9333jh",
        1191242096,
        "GET&http%3A%2F%2Fphotos.example.net%2FPhotos&bad.param%3Dbad~value%26bad_param%3Dbad-value%26file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26since%3DTue%252C%252022%2520Nov%25202011%252021%253A55%253A05%2520GMT%26size%3Doriginal",
        "POST&http%3A%2F%2Fphotos.example.net%2FPhotos&bad.param%3Dbad~value%26bad_param%3Dbad-value%26file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26since%3DTue%252C%252022%2520Nov%25202011%252021%253A55%253A05%2520GMT%26size%3Doriginal",
        false,
        true,
        None
      ),
      OAuth1TestCase(
        "https/3000/no params",
        "https",
        "photos.example.net",
        3000,
        "/photos",
        None,
        Nil,
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "cNyhVC7tajr/NWci0TwPeiIEmok=",
        "wJZODyZosZZpQoi3V64vKAmJnkQ=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        "POST&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        true,
        true,
        None
      ),
      OAuth1TestCase(
        "http/80/duplicated_keys_params",
        "http",
        "photos.example.net",
        80,
        "/photos",
        None,
        List(("key", "b"), ("key", "a")),
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "cNyhVC7tajr/NWci0TwPeiIEmok=",
        "wJZODyZosZZpQoi3V64vKAmJnkQ=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&key%3Da%26key%3Db%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        "POST&http%3A%2F%2Fphotos.example.net%2Fphotos&key%3Da%26key%3Db%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        true,
        true,
        None
      ),
      // this tests throw behavior for malformed request.

    //TODO, (bug) consumer_key is null. what should the normalized request look like? It cant be null.
      OAuth1TestCase(
        "null client key",
        "https",
        "photos.example.net",
        3000,
        "/photos/create",
        None,
        Nil,
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        null,
        "kd94hf93k423kf44",
        "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
        "wPkvxykrw+BTdCcGqKr+3I+PsiM=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Dnull%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        "POST&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Dnull%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        true,
        false,
        None
      ),
      OAuth1TestCase(
        "http/80/params/extra_oauth_params_in_header",
        "http",
        "photos.example.net",
        80,
        "/Photos",
        None,
        List(("size", "original"), ("file", "vacation.jpg")),
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "xKB3aLk5/WhS4kaVMRCYDlvp8u4=",
        "Ng29RlJ3XPn84Nt5hZwaI3kn0jE=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&http%3A%2F%2Fphotos.example.net%2FPhotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
        "POST&http%3A%2F%2Fphotos.example.net%2FPhotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
        true,
        true,
        Some(HeaderOnlyParams(
          Seq(("oauth_callback", "oob"), ("oauth_verifier", "blar"), ("foo", "bar")),
          "GET&http%3A%2F%2Fphotos.example.net%2FPhotos&file%3Dvacation.jpg%26oauth_callback%3Doob%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_verifier%3Dblar%26oauth_version%3D1.0%26size%3Doriginal",
          "POST&http%3A%2F%2Fphotos.example.net%2FPhotos&file%3Dvacation.jpg%26oauth_callback%3Doob%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_verifier%3Dblar%26oauth_version%3D1.0%26size%3Doriginal"
        ))
      )
    )
  }

  val oAuthTwoLeggedEmptyToken = OAuth1TestCase(
    "empty token",
    "https",
    "photos.example.net",
    3000,
    "/photos/create",
    None,
    Nil,
    "",
    "pfkkdhi9sl3r4s00",
    "dpf43f3p2l4k3l03",
    "kd94hf93k423kf44",
    "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
    "wPkvxykrw+BTdCcGqKr+3I+PsiM=",
    "kllo9940pd9333jh",
    1191242096,
    "GET&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3D%26oauth_version%3D1.0",
    "POST&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3D%26oauth_version%3D1.0",
    true,
    false,
    None
  )

  val oAuthTwoLeggedNullToken = OAuth1TestCase(
    "null token",
    "https",
    "photos.example.net",
    3000,
    "/photos/create",
    None,
    Nil,
    null,
    "pfkkdhi9sl3r4s00",
    "dpf43f3p2l4k3l03",
    "kd94hf93k423kf44",
    "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
    "wPkvxykrw+BTdCcGqKr+3I+PsiM=",
    "kllo9940pd9333jh",
    1191242096,
    "GET&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_version%3D1.0",
    "POST&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_version%3D1.0",
    true,
    false,
    None
  )

  val oAuthSpecialCaseGet = OAuth1TestCase(
    "special char in GET",
    "http",
    "localhost",
    9080,
    "/1/statuses/filter.json",
    None,
    List(("track", "%f8ae"), ("delimited", "length"), ("follow", "1")),
    "readkey",
    "readsecret",
    "writekey",
    "writesecret",
    "ChPMC8K%2BpTpS8vg%2B6%2B0ssLeHBZA%3D",
    null,
    "ZSArLiUsGgwwtE4q9Y7nl2Q89jZvqo8wCepxbQbcQg",
    1282246407,
    "GET&http%3A%2F%2Flocalhost%3A9080%2F1%2Fstatuses%2Ffilter.json&delimited%3Dlength%26follow%3D1%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3DZSArLiUsGgwwtE4q9Y7nl2Q89jZvqo8wCepxbQbcQg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1282246407%26oauth_token%3Dreadkey%26oauth_version%3D1.0%26track%3D%25F8ae",
    null,
    false,
    true,
    None
  )
  val oAuthSpecialCasePost = OAuth1TestCase(
    "special char in POST",
    "http",
    "localhost",
    9080,
    "/1/statuses/filter.json",
    None,
    List(("track", "%c3%b8ae"), ("delimited", "length"), ("follow", "1")),
    "readkey",
    "readsecret",
    "writekey",
    "writesecret",
    null,
    "FegoHvFZyzymLIdprn3QVHTfmNY%3D",
    "BMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs",
    1282246447,
    null,
    "POST&http%3A%2F%2Flocalhost%3A9080%2F1%2Fstatuses%2Ffilter.json&delimited%3Dlength%26follow%3D1%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3DBMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1282246447%26oauth_token%3Dreadkey%26oauth_version%3D1.0%26track%3D%25C3%25B8ae",
    false,
    true,
    None
  )
  /**
   * This is a test case that spawned from bugs reported by users related to data that have special characters that are escaped.
   * Here the characters are '/', '(' and ')'.
   */
  val oAuthSpecialCasePost2 = OAuth1TestCase(
    "http url in POST",
    "https",
    "api.twitter.com",
    443,
    "/1.1/statuses/update.json",
    None,
    List(("include_entities", "1"), ("include_user_entities", "1"), ("status", "www.buderats.co.uk/docs/river_duathlon_17-08-12-(1).pdf")),
    "readkey",
    "readsecret",
    "writekey",
    "writesecret",
    null,
    "UDs66OL4QIwzM1tobnKwf/JVcBw=",
    "BMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs",
    1282246447,
    null,
    "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3D1%26include_user_entities%3D1%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3DBMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1282246447%26oauth_token%3Dreadkey%26oauth_version%3D1.0%26status%3Dwww.buderats.co.uk%252Fdocs%252Friver_duathlon_17-08-12-%25281%2529.pdf",
    true,
    true,
    None
  )
  /**
   * This is a test case for signing form-urlencoded data in the body of a
   * request that uses an HTTP method other than POST.
   */
  val oAuthSpecialCasePut = OAuth1TestCase(
    "http PUT request",
    "http",
    "example.net",
    80,
    "/pictures/123",
    Some("PUT"),
    List(("location", "Tokyo"), ("name", "tree")),
    "readkey",
    "readsecret",
    "writekey",
    "writesecret",
    null,
    "o0vn6j/8rZTu5wtVZc8z07tTFdQ=",
    "BMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs",
    1282246447,
    null,
    "PUT&http%3A%2F%2Fexample.net%2Fpictures%2F123&location%3DTokyo%26name%3Dtree%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3DBMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1282246447%26oauth_token%3Dreadkey%26oauth_version%3D1.0",
    true,
    true,
    None
  )
  /**
   * This is a test case for signing form-urlencoded data in the body of a GET request.
   * A GET request with a request body is unusual but technically possible.
   */
  val oAuthSpecialCaseGetWithRequestBody = OAuth1TestCase(
    "http GET request with request body",
    "http",
    "example.net",
    80,
    "/pictures/123",
    Some("GET"),
    List(("location", "Tokyo"), ("name", "tree")),
    "readkey",
    "readsecret",
    "writekey",
    "writesecret",
    null,
    "o0vn6j/8rZTu5wtVZc8z07tTFdQ=",
    "BMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs",
    1282246447,
    null,
    "GET&http%3A%2F%2Fexample.net%2Fpictures%2F123&location%3DTokyo%26name%3Dtree%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3DBMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1282246447%26oauth_token%3Dreadkey%26oauth_version%3D1.0",
    true,
    true,
    None
  )
  /**
   * These are test cases that ensure we are lenient about , in query string.
   * We test with pre encoded, raw and a mix of encoded and raw values. The final
   * result is the same signature no matter what combination is provided.
   */
  def commaTestCases(): Seq[OAuth1TestCase] = {
    def commaTestCase(param: String): OAuth1TestCase = {
      OAuth1TestCase(
        "Comma in GET query string",
        "https",
        "api.twitter.com",
        443,
        "/1.1/users/lookup.json",
        None,
        List(("user_id", param)),
        "readkey",
        "readsecret",
        "writekey",
        "writesecret",
        "uYz%2FUjShixShX74KhM9aca7H4NI%3D",
        null,
        "BMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs",
        1282246447,
        "GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fusers%2Flookup.json&oauth_consumer_key%3Dwritekey%26oauth_nonce%3DBMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1282246447%26oauth_token%3Dreadkey%26oauth_version%3D1.0%26user_id%3D566887847%252C566916631%252C566946128",
        null,
        false,
        true,
        None
      )
    }
    Seq(
      commaTestCase("566887847%2C566916631%2C566946128"),  // encoded
      commaTestCase("566887847,566916631,566946128"),      // raw
      commaTestCase("566887847%2C566916631,566946128")     // mixed
    )
  }

  /**
   * Similar to the above test cases, these test make sure that we are lenient for '[' and ']' in the query string.
   */

  def bracketTestCases(): Seq[OAuth1TestCase] = {
    def bracketTestCases(params: List[(String, String)]): OAuth1TestCase = {
      OAuth1TestCase(
        "Brackets in GET query string",
        "https",
        "api.twitter.com",
        443,
        "/1/account/verify_credentials.json",
        None,
        params,
        "readkey",
        "readsecret",
        "writekey",
        "writesecret",
        "EYJz5YxuBan7jj25SsuatDRvkcY%3D",
        null,
        "BMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs",
        1355433661,
        "GET&https%3A%2F%2Fapi.twitter.com%2F1%2Faccount%2Fverify_credentials.json&include_entities%3Dtrue%26log%255B%255D%3Dxxx%26oauth_consumer_key%3Dwritekey%26oauth_nonce%3DBMJXoQz754IpxjHNJsm06ZeXVjsitznhpSRqampxzs%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1355433661%26oauth_token%3Dreadkey%26oauth_version%3D1.0",
        null,
        false,
        true,
        None
      )
    }
    Seq(
      bracketTestCases(List(("include_entities", "true"), ("log%5B%5D", "xxx"))),  // encoded
      bracketTestCases(List(("include_entities", "true"), ("log[]", "xxx"))),      // raw
      bracketTestCases(List(("include_entities", "true"), ("log%5B]", "xxx")))     // mixed
    )
  }
}
