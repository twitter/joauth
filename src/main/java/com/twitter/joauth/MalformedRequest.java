package com.twitter.joauth;

/**
 * thrown if intent is clear, but the request is malformed
 */
public class MalformedRequest extends UnpackerException {

  public MalformedRequest(String message) {
    super(message);
  }
}
