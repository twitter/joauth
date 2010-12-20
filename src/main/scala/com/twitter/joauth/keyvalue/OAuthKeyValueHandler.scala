// Copyright 2010 Twitter, Inc.
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

package com.twitter.joauth.keyvalue

/**
 * OAuthKeyValueHandler only calls the underlying KeyValueHandler
 * if the key is an OAuth 1.0a field and the value is non-empty. Also
 * normalizes the URLEncoded values so that the URLEncoded entities are
 * properly capitalized.
 */
class OAuthKeyValueHandler(underlying: KeyValueHandler)
  extends TrimmingKeyValueHandler(
    new FilteredKeyValueHandler(
      new UrlEncodingNormalizingKeyValueHandler(underlying),
      OAuthFieldFilter))

/**
 * NotOAuthKeyValueHandler only calls the underlying KeyValueHandler
 * if the field is a non-OAuth field. Also normalizes the URLEncoded values
 * so that the URLEncoded entities are properly capitalized.
 */
class NotOAuthKeyValueHandler(underlying: KeyValueHandler)
  extends FilteredKeyValueHandler(
    new UrlEncodingNormalizingKeyValueHandler(underlying), NotOAuthFieldFilter)
