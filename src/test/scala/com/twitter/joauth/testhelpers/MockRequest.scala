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
import com.twitter.thrust.server.{Params, Request, Path}
import com.twitter.thrust.protocol.{Get, MultiMap, HttpMethod}
import java.io.{ByteArrayInputStream, InputStream}

case class MockRequest(
  _method:      Option[HttpMethod],
  _scheme:      Option[String],
  _path:        Option[Path],
  _serverHost:  Option[String],
  _serverPort:  Option[Int],
  _headers:     Option[MultiMap],
  _pathString:  Option[String],
  _uriString:   Option[String],
  _charset:     Option[Charset],
  _queryString: Option[String],
  _params:      Option[Params],
  _inputStream: Option[InputStream],
  _contentType: Option[String]) extends Request {

  def this() = this(None, None, None, None, None, None, None, None, None, None, None, None, None)

  def setMethod(_method: HttpMethod)               = copy(_method = Some(_method))
  def setScheme(_scheme: String)                   = copy(_scheme = Some(_scheme))
  def setPath(_path: Path)                         = copy(_path = Some(_path))
  def setServerHost(_serverHost: String)           = copy(_serverHost = Some(_serverHost))
  def setServerPort(_serverPort: Int)              = copy(_serverPort = Some(_serverPort))
  def setPathString(_pathString: String)           = copy(_pathString = Some(_pathString))
  def setHeaders(headers: Map[String, String])     = copy(_headers = Some(mapToMultiMap(headers)))
  def setUriString(_uriString: String)             = copy(_uriString = Some(_uriString))
  def setCharset(_charset: Charset)                = copy(_charset = Some(_charset))
  def setQueryString(_queryString: String)         = copy(_queryString = Some(_queryString))
  def setParams(_params: Params)                   = copy(_params = Some(_params))
  def setInputStream(_inputStream: InputStream)    = copy(_inputStream = Some(_inputStream))
  def setContentType(_contentType: String)         = copy(_contentType = Some(_contentType))

  val serverHost                = "localhost"
  val serverPort                = 0
  lazy val scheme               = _scheme.getOrElse("http")
  override lazy val contentType = _contentType.getOrElse("text/plain; charset=us-ascii")
  lazy val pathString           = _pathString.getOrElse("/")
  lazy val uriString            = _uriString.getOrElse(null)
  lazy val queryString          = _queryString.getOrElse(null)
  lazy val headers              = _headers.getOrElse(mapToMultiMap(Map[String, String]()))
  lazy val charset              = _charset.getOrElse(Charset.forName("UTF-8"))
  override lazy val params      = _params.get
  lazy val inputStream          = _inputStream.getOrElse(new ByteArrayInputStream(new Array[Byte](0)))
  lazy val method               = _method.getOrElse(Get)

  private[this] def mapToMultiMap(underlying: Map[String, String]) = new MultiMap {
    def getAll(name: String) = List(underlying(name))
    def get(name: String) = underlying.get(name)
    def names = underlying.keys
  }
}