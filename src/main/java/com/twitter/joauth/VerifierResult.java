package com.twitter.joauth;

public enum VerifierResult {
  OK,
  BAD_NONCE,
  BAD_SIGNATURE,
  BAD_TIMESTAMP
}