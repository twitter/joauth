package com.twitter.joauth

import java.net.URLEncoder

object ParamHelper {
  def toUrlEncodedQueryString(params: Map[String, String]): String = (params.flatMap { (e) =>
    if (e._1 == null) None
    else if (e._2 == null) Some(URLEncoder.encode(e._1))
    else Some("%s=%s".format(URLEncoder.encode(e._1), URLEncoder.encode(e._2)))
  }).mkString("&")

  def toUrlEncodedQueryString(params: List[(String, String)]) = (params.flatMap { (e) =>
    if (e._1 == null) None
    else if (e._2 == null) Some(URLEncoder.encode(e._1))
    else Some("%s=%s".format(URLEncoder.encode(e._1), URLEncoder.encode(e._2)))
  }).mkString("&")
  
  def toQueryString(params: Map[String, String]): String = (params.flatMap { (e) =>
    if (e._1 == null) None
    else if (e._2 == null) Some(e._1)
    else Some("%s=%s".format(e._1, e._2))
  }).mkString("&")

  def toQueryString(params: List[(String, String)]) = (params.flatMap { (e) =>
    if (e._1 == null) None
    else if (e._2 == null) Some(e._1)
    else Some("%s=%s".format(e._1, e._2))
  }).mkString("&")

  def toQueryString(params: Map[String, String], urlEncode: Boolean): String = 
    if (urlEncode) toUrlEncodedQueryString(params) else toQueryString(params)

  def toQueryString(params: List[(String, String)], urlEncode: Boolean): String = 
    if (urlEncode) toUrlEncodedQueryString(params) else toQueryString(params)
}