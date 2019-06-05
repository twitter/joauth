// Copyright 2011 Twitter, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// file except in compliance with the License. You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package com.twitter.joauth.keyvalue;

import com.twitter.joauth.Request;
import org.junit.Test;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;

public class KeyValueHandlerTest  {

  @Test
  public void testSingleKeyValueHandler() {
    KeyValueHandler.SingleKeyValueHandler handler = new KeyValueHandler.SingleKeyValueHandler();
    handler.handle("foo", "bar");
    handler.handle("foo", "baz");
    handler.handle("a", "b");
    HashMap<String, String> map = new HashMap<String, String>();
    map.put("foo", "baz");
    map.put("a", "b");
    assertEquals("use last value for key", handler.toMap(), map);
  }


  @Test
  public void testDuplicateKeyValueHandler() {
    KeyValueHandler.DuplicateKeyValueHandler handler = new KeyValueHandler.DuplicateKeyValueHandler();
    handler.handle("foo", "bar");
    handler.handle("foo", "baz");
    handler.handle("a", "b");
    ArrayList<Request.Pair> result = new ArrayList<Request.Pair>();
    result.add(new Request.Pair("foo", "bar"));
    result.add(new Request.Pair("foo", "baz"));
    result.add(new Request.Pair("a", "b"));

    assertEquals("use multiple values for key", handler.toList(), result);
  }

  @Test
  public void testMaybeQuotedValueKeyValueHandler() {
    KeyValueHandler underlying = mock(KeyValueHandler.class);

    KeyValueHandler.MaybeQuotedValueKeyValueHandler handler = new KeyValueHandler.MaybeQuotedValueKeyValueHandler(underlying);

    //"only parse quoted values" in {
    handler.handle("foo", "\"baz\"");
    handler.handle("foo", "   \"baz\"  ");
    handler.handle("foo" , "baz");
    // doesn't trim for unquoted values
    handler.handle("foo" , "   baz  ");

    verify(underlying, atLeast(3)).handle("foo", "baz");
    verify(underlying, atLeast(1)).handle("foo", "   baz  ");
    verify(underlying, atLeast(4)).handle(anyString(), anyString());
  }

  @Test
  public void testOneKeyOnlyKeyValueHandler() {
    KeyValueHandler.OneKeyOnlyKeyValueHandler handler = new KeyValueHandler.OneKeyOnlyKeyValueHandler();


    //"return key for single key, empty value" in {
    handler.handle("foo", "");
    assertEquals("return key for single key, empty value", "foo", handler.getKey());

    //"return key for single key, null value" in {
    handler.handle("foo", null);
    assertEquals("return key for single key, null value", null, handler.getKey());

    //"return None for single key/value" in {
    handler.handle("foo", "bar");
    assertEquals("return None for single key/value", handler.getKey(), null);

    //"return None for two keys" in {
    handler.handle("foo", "");
    handler.handle("foo", "");
    assertEquals("return None for two keys", handler.getKey(), null);
  }
}
