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

/**
 * a trait for validating a nonce. Nonce-validation is pretty domain-specific,
 * so we leave it as an exercise for the reader
 */
public interface NonceValidator {

  boolean validate(String nonce);

  /**
   * a singleton of the NoopNonceValidator class
   */
  public final NonceValidator NO_OP_NONCE_VALIDATOR = new NoopNonceValidator();

  static class NoopNonceValidator implements NonceValidator {

    @Override
    public boolean validate(String nonce) {
      return true;
    }
  }

  /**
   * for testing. always returns the same result.
   */
  public static class ConstNonceValidator implements NonceValidator {

    private final boolean result;

    public ConstNonceValidator(boolean result) {
      this.result = result;
    }

    @Override
    public boolean validate(String nonce) {
      return result;
    }
  }
}
