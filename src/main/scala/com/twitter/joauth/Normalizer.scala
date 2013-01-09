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

package com.twitter.joauth

import scala.collection.JavaConverters.iterableAsScalaIterableConverter

/**
 * a Normalizer takes the fields that describe an OAuth 1.0a request, and produces
 * the normalized string that is used for the signature.
 */
trait Normalizer {
  def apply(
    scheme: String,
    host: String,
    port: Int,
    verb: String,
    path: String,
    params: List[(String, String)],
    oAuth1Params: OAuth1Params): String

  def apply(req: ParsedRequest, oAuth1Params: OAuth1Params): String =
    apply(req.scheme, req.host, req.port, req.verb, req.path, req.params, oAuth1Params)
}

/**
 * ConstNormalizer can be used for testing. It will always return the same String.
 */
class ConstNormalizer(const: String) extends Normalizer {
  override def apply(
    scheme: String,
    host: String,
    port: Int,
    verb: String,
    path: String,
    params: List[(String, String)],
    oAuth1Params: OAuth1Params): String = const
}

/**
 * A convenience factory for a StandardNormalizer
 */
object Normalizer {
  def apply(): Normalizer = StandardNormalizer
  val HTTP = "HTTP"
  val HTTPS = "HTTPS"
  val AND = "&"
  val COLON = ":"
  val EQ = "="
  val COLON_SLASH_SLASH = "://"
}

/**
 * a singleton of the StandardNormalizer class
 */
object StandardNormalizer extends StandardNormalizer {
  private[this] def defaultStringBuilder = new StringBuilder(512)

  protected[StandardNormalizer] val builder = new ThreadLocal[StringBuilder]() {
    override def initialValue() = defaultStringBuilder
  }

  protected[StandardNormalizer] def resetBuilder() {
    builder.set(defaultStringBuilder)
  }
}

/**
 * the standard implmenentation of the Normalizer trait. Though stateless and threadsafe,
 * this is a class rather than an object to allow easy access from Java. Scala codebases
 * should use the corresponding StandardNormalizer object instead.
 */
class StandardNormalizer extends Normalizer {
  import Normalizer._

  case class ParameterValuePair(param: String, value: String)

  override def apply(
    scheme: String,
    host: String,
    port: Int,
    verb: String,
    path: String,
    params: List[(String, String)],
    oAuth1Params: OAuth1Params): String = {
      // We only need the stringbuilder for the duration of this method
      val builder = StandardNormalizer.builder.get()
      builder.clear()

      val normalizedParams = {
        // first, concatenate the params and the oAuth1Params together.
        // the parameters are already URLEncoded, so we leave them alone
        val sigParams = params ::: oAuth1Params.toList(false)

        // sort params first by key, then by value
        val sortedParams = sigParams.sortWith { case ((thisKey, thisValue), (thatKey, thatValue)) =>
          thisKey < thatKey || (thisKey == thatKey && thisValue < thatValue)
        }

        // now turn these back into a standard query string, with keys delimited
        // from values with "=" and pairs delimited from one another by "&"
        builder.clear()
        if (sortedParams.nonEmpty) {
          sortedParams.head match { case (key, value) =>
            builder.append(key).append('=').append(value)
          }
          sortedParams.tail foreach { case (key, value) =>
            builder.append('&').append(key).append('=').append(value)
          }
        }

        builder.toString
      }

      // the normalized URL is scheme://host[:port]/path, lowercased
      val requestUrl = {
        builder.clear()
        scheme foreach { c =>
          builder += c.toLower
        }
        builder += (':', '/', '/')
        host foreach { c =>
          builder += c.toLower
        }
        if (includePortString(port, scheme)) {
          builder.append(':').append(port)
        }
        builder.append(path)

        builder.toString
      }

      // the normalized string is VERB&normalizedParams&requestUrl,
      // where URL and PARAMS are UrlEncoded
      builder.clear()
      verb foreach { c =>
        builder += c.toUpper
      }
      builder.append('&').append(UrlEncoder(requestUrl))
      builder.append('&').append(UrlEncoder(normalizedParams))
      if (builder.length > 4096) {
        // We don't want to keep around very large builders
        StandardNormalizer.resetBuilder()
      }
      builder.toString
    }

    /**
    * The OAuth 1.0a spec says that the port should not be included in the normalized string
    * when (1) it is port 80 and the scheme is HTTP or (2) it is port 443 and the scheme is HTTPS
    */
    def includePortString(port: Int, scheme: String): Boolean = {
      !((port == 80 && HTTP.equalsIgnoreCase(scheme)) || (port == 443 && HTTPS.equalsIgnoreCase(scheme)))
    }

  /**
   * Java bindings
   */
  def normalize(
    scheme: String,
    host: String,
    port: Int,
    verb: String,
    path: String,
    paramsMap: java.util.List[ParameterValuePair],
    oAuth1Params: OAuth1Params
  ): String = {
    val paramsList = paramsMap.asScala.map { pv =>
      (pv.param, pv.value)
    }.toList

    apply(scheme, host, port, verb, path, paramsList, oAuth1Params)
  }
}