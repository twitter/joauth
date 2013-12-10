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

package com.twitter.joauth;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A Verifier takes either
 *   a) an OAuth1 request, a token secret, and a consumer secret
 *      or
 *   b) an OAuth1TwoLegged request and a consumer secret
 *
 * and validates the request. It returns a Java enum for compatability
 */
public interface Verifier {
  static int NO_TIMESTAMP_CHECK = -1;

  //TODO: swap the order of the consumerSecret and tokenSecret because consumer secrets are required for all oauth1 requests

  public VerifierResult verify(UnpackedRequest.OAuth1Request request, String tokenSecret, String consumerSecret);
  public VerifierResult verify(UnpackedRequest.OAuth1TwoLeggedRequest request, String consumerSecret);

  /**
   * a factory with various convenience constructors for a StandardVerifier
   */
  public static class VerifierFactory {

    public static Verifier newVerifier() {
      return newVerifier(
        Signer.getStandardSigner(),
        NO_TIMESTAMP_CHECK,
        NO_TIMESTAMP_CHECK,
        NonceValidator.NO_OP_NONCE_VALIDATOR
      );
    }

    public static Verifier newVerifier(int maxClockFloatAheadMins, int maxClockFloatBehindMins) {
      return newVerifier(
        Signer.getStandardSigner(),
        maxClockFloatAheadMins,
        maxClockFloatBehindMins,
        NonceValidator.NO_OP_NONCE_VALIDATOR
      );
    }

    public static Verifier newVerifier(
      int maxClockFloatAheadMins,
      int maxClockFloatBehindMins,
      NonceValidator validateNonce
    ) {
      return newVerifier(Signer.getStandardSigner(), maxClockFloatAheadMins, maxClockFloatBehindMins, validateNonce);
    }

    public static Verifier newVerifier(
      Signer sign,
      int maxClockFloatAheadMins,
      int maxClockFloatBehindMins,
      NonceValidator validateNonce
    ) {
      return new StandardVerifier(sign, maxClockFloatAheadMins, maxClockFloatBehindMins, validateNonce);
    }
  }


  public static class StandardVerifier implements Verifier {

    private final Signer signer;
    private final int maxClockFloatAheadMins;
    private final int maxClockFloatBehindMins;
    private final NonceValidator validateNonce;
    private final long maxClockFloatAheadSecs;
    private final long maxClockFloatBehindSecs;

    private static final Logger log = Logger.getLogger("StandardVerifier");

    public StandardVerifier(
      Signer signer,
      int maxClockFloatAheadMins,
      int maxClockFloatBehindMins,
      NonceValidator validateNonce
    ) {
      this.signer = signer;
      this.maxClockFloatAheadMins = maxClockFloatAheadMins;
      this.maxClockFloatBehindMins = maxClockFloatAheadMins;
      this.validateNonce = validateNonce;

      maxClockFloatAheadSecs = maxClockFloatAheadMins * 60L;
      maxClockFloatBehindSecs = maxClockFloatBehindMins * 60L;
    }

    @Override
    public VerifierResult verify(UnpackedRequest.OAuth1TwoLeggedRequest request, String consumerSecret) {
      return verifyOAuth1(
        request,
        request.nonce(),
        request.timestampSecs(),
        "",
        consumerSecret,
        request.signature(),
        request.normalizedRequest()
      );
    }

    @Override
    public VerifierResult verify(UnpackedRequest.OAuth1Request request, String tokenSecret, String consumerSecret) {
      return verifyOAuth1(
        request,
        request.nonce(),
        request.timestampSecs(),
        tokenSecret,
        consumerSecret,
        request.signature(),
        request.normalizedRequest()
      );
    }

    private VerifierResult verifyOAuth1(
      UnpackedRequest.OAuthRequest request,
      String nonce,
      long timestampSecs,
      String tokenSecret,
      String consumerSecret,
      String signature,
      String normalizedRequest
    ) {
      if (!validateTimestampSecs(timestampSecs)) {
        if (log.isLoggable(Level.FINE)) {
          log.log(Level.FINE, String.format("bad timestamp -> %s", request.toString()));
        }
        return VerifierResult.BAD_TIMESTAMP;
      } else if (!validateNonce.validate(nonce)) {
        if (log.isLoggable(Level.FINE)) {
          log.log(Level.FINE, String.format("bad nonce -> %s", request.toString()));
        }
        return VerifierResult.BAD_NONCE;
      } else if (!validateSignature(normalizedRequest, signature, tokenSecret, consumerSecret)) {
        if (log.isLoggable(Level.FINE)) {
          log.log(Level.FINE, String.format("bad signature -> %s", request.toString()));
        }
        return VerifierResult.BAD_SIGNATURE;
      } else {
        return VerifierResult.OK;
      }
    }

    public boolean validateTimestampSecs(long timestampSecs) {
      long nowSecs = System.currentTimeMillis() / 1000;

      return (maxClockFloatBehindMins < 0 || (timestampSecs >= nowSecs - maxClockFloatBehindSecs)) &&
        (maxClockFloatAheadMins < 0 || (timestampSecs <= nowSecs + maxClockFloatAheadSecs));
    }

    boolean validateSignature(
      String normalizedRequest,
      String signature,
      String tokenSecret,
      String consumerSecret
    ) {
      try {
        return Base64Util.equals(UrlCodec.decode(signature).trim(),
            signer.getBytes(normalizedRequest, tokenSecret, consumerSecret));
      } catch (Exception e) {
        return false;
      }
    }
  }
}
