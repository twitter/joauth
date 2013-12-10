package com.twitter.joauth

object ConversionUtil {

  def toSeq[T](arrayList: java.util.ArrayList[T]) = {
    import scala.collection.JavaConversions._
    arrayList.toIndexedSeq
  }

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
