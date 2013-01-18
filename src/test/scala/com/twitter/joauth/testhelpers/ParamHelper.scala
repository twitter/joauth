// Copyright 2011 Twitter, Inc.
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

import com.twitter.joauth.UrlEncoder

object ParamHelper {
  def toUrlEncodedQueryString(params: Seq[(String, String)]): String = (params.flatMap { (e) =>
    if (e._1 == null) None
    else if (e._2 == null) Some(UrlEncoder(e._1))
    else Some("%s=%s".format(UrlEncoder(e._1), UrlEncoder(e._2)))
  }).mkString("&")

  def toQueryString(params: Seq[(String, String)]): String = (params.flatMap { (e) =>
    if (e._1 == null) None
    else if (e._2 == null) Some(e._1)
    else Some("%s=%s".format(e._1, e._2))
  }).mkString("&")

  def toQueryString(params: Seq[(String, String)], urlEncode: Boolean): String =
    if (urlEncode) toUrlEncodedQueryString(params) else toQueryString(params)
}
