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

// import java.io.{BufferedReader, StringReader, StringBufferInputStream}
// import java.util.{Locale, Arrays, Vector}
// import javax.servlet.{ServletInputStream, RequestDispatcher}
// import javax.servlet.http.{HttpSession, Cookie, HttpServletRequest}

import com.twitter.thrust.{Format, Headers, HttpMethod, Path, Params, Request}
import java.io.BufferedReader
import java.io.StringReader
import javax.servlet.http.{Cookie, HttpServletRequest, HttpSession}
import javax.servlet.ServletInputStream
import scala.collection.mutable.{HashMap, Map}

class MockRequest(
    var method: HttpMethod,
    var scheme: String,
    var remoteAddr: String,
    var path: Path,
    var serverName: String,
    var serverPort: Int) extends Request {
  def this(m: String, scheme: String, ipaddr: String) = this(HttpMethod(m), scheme, ipaddr, Path("/foo"), "foo", 80)
  def this() = this("GET", "http", "123.123.123.123")

  override val headers = new Headers {
    val underlying = new HashMap[String, String]
    def names: List[String] = underlying.keySet.toList
    def get(name: String) = underlying.get(name)
    def getAll(name: String) = get(name).toList.toSeq
    def += (kv: (String, String)): Map[String, String] = underlying += kv
  }

  var inputStream:ServletInputStream = null
  var queryString:String = null
  var contentType:String = null
  def method_=(m:String) { method = HttpMethod(m) }
  def inputStream_=(i:String) {
    inputStream = new ServletInputStream {
      val reader = new StringReader(if (i == null) "" else i)
      def read = reader.read()
    }
  }

  // not implemented
  val reader: BufferedReader = null
  val lines : Seq[String] = null
  val characterEncoding: String = null
  val contentLength: Int = 0
  val protocol: String = "HTTP 1.0"
  val params: Params = null
  def remoteHost: String = remoteAddr
  val authType: String = null
  val cookies: Seq[Cookie] = null
  val remoteUser: String = null
  val requestedSessionId: String = null
  def requestUri: String = path.toString
  val servletPath: String = ""
  val session: HttpSession = null
  val toHttpServletRequest: HttpServletRequest = null
  val format: Format = null
}