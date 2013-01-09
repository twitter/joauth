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

package com.twitter.joauth

/**
 * a trait for validating a nonce. Nonce-validation is pretty domain-specific,
 * so we leave it as an exercise for the reader
 */
trait NonceValidator extends ((String) => Boolean)

/**
 * a singleton of the NoopNonceValidator class
 */
object NoopNonceValidator extends NoopNonceValidator

/**
 * the default nonce validator, which always returns true. Though stateless and threadsafe,
 * this is a class rather than an object to allow easy access from Java. Scala codebases
 * should use the corresponding NonceValidator object instead.
 */
class NoopNonceValidator extends NonceValidator {
  override def apply(nonce: String): Boolean = true
}

/**
 * for testing. always returns the same result.
 */
class ConstNonceValidator(result: Boolean) extends NonceValidator {
  override def apply(nonce: String): Boolean = result
}