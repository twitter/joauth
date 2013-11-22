package com.twitter.joauth

object ConversionUtil {

  def toArrayList[T](seq: Seq[T]) = {
    val arrayList = new java.util.ArrayList[T]()
    seq foreach { arrayList.add(_) }
    arrayList
  }
}
