package com.twitter.joauth

class UnpackerException(val message: String, t: Throwable) extends Exception(message, t) {
  def this(message: String) = this(message, null)
}

class UnknownAuthType(message: String) extends UnpackerException(message)

class MalformedRequest(message: String) extends UnpackerException(message)