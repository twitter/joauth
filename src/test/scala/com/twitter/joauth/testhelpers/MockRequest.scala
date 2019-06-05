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

import com.twitter.joauth.Request

object MockRequest {
  def apply(request: Request) = {
    val mock = new MockRequest
    mock.authHeader = request.authHeader
    mock.body = request.body
    mock.contentType = request.contentType
    mock.host = request.host
    mock.method = request.method
    mock.path = request.path
    mock.port = request.port
    mock.queryString = request.queryString
    mock.scheme = request.scheme
    mock
  }
}

class MockRequest extends Request {
  var authHeader: String = null
  var body: String = null
  var contentType: String = null
  var host: String = "127.0.0.1"
  var method: String = "get"
  var path: String = "/"
  var port: Int = 80
  var queryString: String = null
  var scheme: String = "http"
}
