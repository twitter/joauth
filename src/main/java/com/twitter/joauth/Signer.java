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

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * A Signer takes a string, a token secret and a consumer secret, and produces a signed string
 */
public abstract class Signer {

  private static final Signer STANDARD_SIGNER = new StandardSigner();

  /**
   * produce an encoded signature string
   */
  public abstract String getString(String str, String tokenSecret, String consumerSecret)
    throws InvalidKeyException, NoSuchAlgorithmException;

  /**
   * produce a signature as a byte array
   */
  public abstract byte[] getBytes(String str, String tokenSecret, String consumerSecret)
    throws NoSuchAlgorithmException, InvalidKeyException;

  /**
   * decode an existing signature to a byte array
   */
  public abstract byte[] toBytes(String signature) throws UnsupportedEncodingException;


  public static Signer getStandardSigner() {
    return STANDARD_SIGNER;
  }


  /**
   * the standard implementation of the Signer trait. Though stateless and threadsafe,
   * this is a class rather than an object to allow easy access from Java. Scala codebases
   * should use the corresponding STANDARD_SIGNER object instead.
   */
  public static class StandardSigner extends Signer {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String AND = "&"; //TODO: move to Normalizer
    private static final String HMACSHA1 = "HmacSHA1";

    @Override
    public String getString(String str, String tokenSecret, String consumerSecret)
      throws InvalidKeyException, NoSuchAlgorithmException {

      return UrlCodec.encode(Base64Util.encode(getBytes(str, tokenSecret, consumerSecret)));
    }

    @Override
    public byte[] getBytes(String str, String tokenSecret, String consumerSecret)
      throws NoSuchAlgorithmException, InvalidKeyException {

      String key = consumerSecret + AND + tokenSecret;
      SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(StandardSigner.UTF_8), HMACSHA1);

      //TODO: Mac looks thread safe, if not consider synchronizing this
      Mac mac = Mac.getInstance(HMACSHA1);
      mac.init(signingKey);
      return mac.doFinal(str.getBytes(UTF_8));
    }

    @Override
    public byte[] toBytes(String signature) throws UnsupportedEncodingException {
      return Base64Util.decode(UrlCodec.decode(signature).trim());
    }
  }

  /**
   * For testing. Always returns the same string
   */
  public static class ConstSigner extends Signer {

    private final String str;
    private final byte[] bytes;

    public ConstSigner(String str, byte[] bytes) {
      this.str = str;
      this.bytes = bytes;
    }

    @Override
    public byte[] getBytes(String str, String tokenSecret, String consumerSecret) {
      return bytes;
    }

    @Override
    public String getString(String str, String tokenSecret, String consumerSecret) {
      return str;
    }

    @Override
    public byte[] toBytes(String signature) {
      return bytes;
    }
  }
}
