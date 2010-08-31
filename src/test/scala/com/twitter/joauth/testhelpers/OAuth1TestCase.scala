package com.twitter.joauth.testhelpers

import com.twitter.joauth.MalformedRequest
import com.twitter.joauth.UnknownAuthType
import java.net.URLEncoder
import javax.servlet.http.HttpServletRequest

case class OAuth1TestCase(
  val testName: String,
  val scheme: String,
  val host: String,
  val port: Int,
  val path: String,
  val namespacedPath: String,
  val parameters: List[(String, String)],
  val token: String,
  val tokenSecret: String,
  val consumerKey: String,
  val consumerSecret: String,
  val signatureGet: String,
  val signaturePost: String,
  val nonce: String,
  val timestamp: Int,
  val normalizedRequestGet: String,
  val normalizedRequestPost: String,
  val urlEncodeParams: Boolean,
  val exception: Exception) {

  def oAuth1Request(paramsInPost: Boolean) = new OAuth1Request(
    token,
    consumerKey,
    nonce,
    timestamp,
    if (paramsInPost) signaturePost else signatureGet,
    OAuthUtils.HMAC_SHA1,
    OAuthUtils.ONE_DOT_OH,
    if (paramsInPost) normalizedRequestPost else normalizedRequestGet)
  
  def oAuthParams(paramsInPost: Boolean) = {
    val params = new OAuthParams
    params.token = token
    params.consumerKey = consumerKey
    params.nonce = nonce
    params.timestamp = timestamp
    params.signature = if (paramsInPost) signaturePost else signatureGet
    params.signatureMethod = OAuthUtils.HMAC_SHA1
    params.version = OAuthUtils.ONE_DOT_OH
    params
  }

  def httpServletRequest(oAuthInParam: Boolean, oAuthInHeader: Boolean, useNamespacedPath: Boolean, paramsInPost: Boolean): HttpServletRequest = {
    val signature = if (paramsInPost) signaturePost else signatureGet
    val request = new MockServletRequest(
      "GET", 
      scheme, 
      "123.123.123.123", 
      if (useNamespacedPath) namespacedPath else path, 
      host, 
      port)
    if (oAuthInHeader) {
      request.setHeader(
        "Authorization",
        MockRequestFactory.oAuth1Header(token, consumerKey, signature, nonce, timestamp.toString))
    }
    var queryString = ParamHelper.toQueryString(parameters, urlEncodeParams)
    if (oAuthInParam) {
      if (!queryString.isEmpty) queryString += "&"
      queryString += MockRequestFactory.oAuth1QueryString(token, consumerKey, signature, nonce, timestamp.toString, urlEncodeParams)
    }
    if (!queryString.isEmpty) {
      request.queryString = queryString
    }
    if (paramsInPost) MockRequestFactory.postRequest(request)
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
        "/photos",
        "/1/userauth/photos",
        List(("size", "original"), ("file", "vacation.jpg")),
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
        "wPkvxykrw+BTdCcGqKr+3I+PsiM=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
        "POST&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
        true,
        null
      ),
      OAuth1TestCase(
        "http/3000/no params",
        "http",
        "photos.example.net",
        3000,
        "/photos",
        "/1/userauth/photos",
        Nil,
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "tugth6M2ZGzXaiWphr2yizLdsPk=",
        "7O0+g+fcV4pIN90GPAPB6oiIleI=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&http%3A%2F%2Fphotos.example.net%3A3000%2Fphotos&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        "POST&http%3A%2F%2Fphotos.example.net%3A3000%2Fphotos&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        true,
        null
      ),
      // these two are to test throw behavior for malformed requests. skip them by wrapping your in in a test for testCase.exception == null
      OAuth1TestCase(
        "null access token",
        "https",
        "photos.example.net",
        3000,
        "/photos/create",
        "/1/userauth/photos/create",
        Nil,
        null,
        "pfkkdhi9sl3r4s00",
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
        "wPkvxykrw+BTdCcGqKr+3I+PsiM=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        "POST&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        true,
        new UnknownAuthType("could not determine the authentication type")
      ),
      OAuth1TestCase(
        "null client key",
        "https",
        "photos.example.net",
        3000,
        "/photos/create",
        "/1/userauth/photos/create",
        Nil,
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        null,
        "kd94hf93k423kf44",
        "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
        "wPkvxykrw+BTdCcGqKr+3I+PsiM=",
        "kllo9940pd9333jh",
        1191242096,
        "GET&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        "POST&https%3A%2F%2Fphotos.example.net%3A3000%2Fphotos%2Fcreate&oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0",
        true,
        new UnknownAuthType("could not determine the authentication type")
      )
    )
  }
}