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

package com.twitter.joauth.testhelpers

import java.nio.charset.Charset
import com.twitter.thrust.server.Request
import com.twitter.thrust.protocol._
import java.io.ByteArrayInputStream
import scala.collection.mutable

class MockRequest extends Request {
  var method: HttpMethod = Get
  var scheme = "http"
  var inputStream = new ByteArrayInputStream(new Array[Byte](0))
  var params = mapToMultiMap(mutable.Map[String, String]())
  var charset = Charset.forName("UTF-8")
  var serverHost = "localhost"
  var serverPort = 80
  var headers = mapToMultiMap(mutable.Map[String, String]())
  var queryString: String = null
  var uriString = "/"
  var pathString = "/"

  def contentType_=(value: String) {
    headers += "Content-Type" -> value
  }

  private[this] def mapToMultiMap(underlying: mutable.Map[String, String]) = new MultiMap {
    def +=(pair: (String, String)) =  underlying += pair
    def getAll(name: String) = List(underlying(name))
    def get(name: String) = underlying.get(name)
    def names = underlying.keys
  }
}