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

import java.io.{BufferedReader, StringReader, StringBufferInputStream}
import java.util.{Locale, Arrays, Vector}
import javax.servlet.{ServletInputStream, RequestDispatcher}
import javax.servlet.http.{HttpSession, Cookie, HttpServletRequest}

class MockServletRequest(var method: String, var scheme: String, ipaddr: String, var path: String, server: String, port: Int) extends HttpServletRequest {
  def this(method: String, scheme: String, ipaddr: String) = this(method, scheme, ipaddr, "/foo", "foo", 80)
  def this() = this("GET", "http", "123.123.123.123")

  var session: HttpSession = new MockHttpSession
  var queryString: String = ""
  var contextPath = ""
  val headers: scala.collection.jcl.HashMap[String, String] =
  new scala.collection.jcl.HashMap[String, String](new java.util.HashMap)
  val attr: scala.collection.jcl.HashMap[String, Any] =
  new scala.collection.jcl.HashMap[String, Any](new java.util.HashMap)
  var cookies: List[Cookie] = Nil
  var authType = null
  var localPort = 0
  var localAddr = null
  var localName = null
  var remotePort = 0
  var remoteHost = null
  var remoteAddr = ipaddr
  var isInitial = true
  var locale = Locale.getDefault
  var reader: BufferedReader = new BufferedReader(new StringReader(method + " " + path + "/\r\n\r\n"))
  var serverPort = port
  var serverName = server
  var protocol = "http 1.0"
  var parameterMap: scala.collection.jcl.HashMap[String, Array[String]] =
  new scala.collection.jcl.HashMap[String, Array[String]](new java.util.HashMap)
  val sbis = new StringBufferInputStream("")
  var inputStream: ServletInputStream = new MockServletInputStream(sbis)
  var contentType:String = null
  var contentLength = 0
  var charEncoding = "ISO-8859-1" // HTTP's default encoding
  var isTimeout = false
  var isResumed = false
  var isSuspended = false

  // add parameter, check to see if there are already values and append if so
  def addParameter(key: String, value:String) {
    if (parameterMap.underlying.containsKey(key)) {
      val values = parameterMap.underlying.get(key)
      parameterMap.underlying.put(key, values ++ Array(value))
    } else {
      parameterMap.underlying.put(key, Array(value))
    }
  }

  def complete {}

  def resume {}

  def suspend {}

  def suspend(l: Long) {}

  def isRequestedSessionIdFromURL = false

  def isRequestedSessionIdFromUrl = false

  def isRequestedSessionIdFromCookie = false

  def isRequestedSessionIdValid = false

  def getSession(p: Boolean) = {
    session
  }

  def getSession = getSession(false)

  def getServletPath = ""

  def getRequestURL = new StringBuffer(path)

  def getRequestURI = path

  def getRequestedSessionId = null

  def getUserPrincipal = null

  def isUserInRole(user: String): Boolean = false

  def getRemoteUser = ""

  def getQueryString = queryString

  def getContextPath = contextPath

  def getPathTranslated = path

  def getPathInfo = path

  def getMethod = method

  def getIntHeader(h: String): Int = {
    headers(h).toInt
  }

  def getHeaderNames = {
    new Vector[AnyRef](headers.underlying.keySet).elements
  }

  def getHeaders = headers

  def getHeaders(s: String) = {
    val v = new Vector[AnyRef]()
    v.add(headers(s))
    v.elements
  }

  def getHeader(h: String) = headers.get(h) match {
    case Some(v) => v
    case None => null
  }

  def getDateHeader(h: String): Long = {
    headers(h).toLong
  }

  def setDateHeader(s: String, l: Long) {
    headers += (s -> l.toString)
  }

  def setHeader(k: String, v: String) {
    headers += (k -> v)
  }

  def getCookies = cookies.toArray

  def getAuthType = authType

  def getLocalPort = localPort

  def getLocalAddr = localAddr

  def getLocalName = localName

  def getRemotePort = remotePort

  def getRealPath(s: String) = s

  def getRequestDispatcher(s: String): RequestDispatcher = null

  def isSecure = false

  type ZZ = Q forSome {type Q}

  def getLocales = new Vector[ZZ](Arrays.asList(Locale.getAvailableLocales: _*)).elements

  def getLocale = locale

  def removeAttribute(key: String) = attr -= key

  def setAttribute(key: String, value: Any) = attr += (key -> value)

  def getRemoteHost = remoteHost

  def getRemoteAddr = remoteAddr

  def getReader = reader

  def getServerPort = serverPort

  def getServerName = serverName

  def getScheme = scheme

  def getProtocol = protocol

  def getParameterMap = parameterMap.underlying

  def getParameterValues(key: String) = parameterMap(key)

  def getParameterNames = new Vector[ZZ](parameterMap.underlying.keySet.asInstanceOf[java.util.Set[ZZ]]).elements

  def getParameter(key: String) = parameterMap(key)(0)

  def getInputStream = inputStream

  def getContentType = contentType

  def getContentLength = contentLength

  def getCharacterEncoding = charEncoding

  def setCharacterEncoding(enc: String) = charEncoding = enc

  def getAttributeNames = new Vector[ZZ](attr.underlying.keySet.asInstanceOf[java.util.Set[ZZ]]).elements

  def getAttribute(key: String) = attr(key).asInstanceOf[Object]

  def getServletContext = null

  def getServletResponse = null
}