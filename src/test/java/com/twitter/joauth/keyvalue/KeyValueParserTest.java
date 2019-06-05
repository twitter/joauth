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

public class KeyValueParserTest  {

  KeyValueHandler handler = mock(KeyValueHandler.class);
  ArrayList<KeyValueHandler> handlers = initKeyValueHandlers();

  private ArrayList<KeyValueHandler> initKeyValueHandlers() {
    ArrayList<KeyValueHandler> list = new ArrayList<KeyValueHandler>();
    list.add(handler);
    return list;
  }

  @Test
  public void testConstKeyValueParser() {
    ArrayList<Request.Pair> requestPairs = new ArrayList<Request.Pair>();
    requestPairs.add(new Request.Pair("a", "b"));
    requestPairs.add(new Request.Pair("c", "d"));

    KeyValueParser.ConstKeyValueParser parser = new KeyValueParser.ConstKeyValueParser(requestPairs);
    parser.parse("foo", handlers);
    verify(handler, atLeast(1)).handle("a", "b");
    verify(handler, atLeast(1)).handle("c", "d");
  }

  @Test
  public void testStandardKeyValueParser() {
    KeyValueParser parser = KeyValueParser.QueryKeyValueParser;

    //"not blow up on null string" in {
    parser.parse(null, handlers);
    verify(handler, never()).handle(anyString(), anyString());


    //"not blow up on empty string" in {
    parser.parse("", handlers);
    verify(handler, never()).handle(anyString(), anyString());

    //"parse simple string" in {
    parser.parse("foo", handlers);
    verify(handler, atLeastOnce()).handle("foo", "");

    //"parse valid pairs" in {
    parser.parse("foo=bar&baz", handlers);
    verify(handler, atLeast(1)).handle("foo", "bar");
    verify(handler, atLeast(1)).handle("baz", "");

    //"parse malformed pairs" in {
    parser.parse("foo=bar&&baz&", handlers);
    verify(handler, atLeast(1)).handle("foo", "bar");
    verify(handler, atLeast(1)).handle("baz", "");
  }
}
