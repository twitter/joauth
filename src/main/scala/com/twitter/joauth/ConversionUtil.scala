package com.twitter.joauth


object ConversionUtil {

  def toArrayList[T](seq: Seq[T]) = {
    val arrayList = new java.util.ArrayList[T]()
    seq foreach { arrayList.add(_) }
    arrayList
  }

  def toHashMap[A, B](map: Map[A, B]) = {
    val hashMap = new java.util.HashMap[A, B]()
    map foreach {
      case (a, b) => hashMap.put(a, b)
    }
    hashMap
  }


}
