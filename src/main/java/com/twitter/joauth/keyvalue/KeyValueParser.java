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

package com.twitter.joauth.keyvalue;

import com.twitter.joauth.Request;

import java.util.List;

/**
 * The KeyValueParser trait describes a parser that takes a String and a Seq[KeyValueHandler],
 * and calls each handler for each key/value pair encountered in the parsed String
 */
public interface KeyValueParser {

  public void parse(String input, List<KeyValueHandler> handlers);


  /**
   * HeaderKeyValueParser is a KeyValueParser for Authorization headers
   */
  public final KeyValueParser HeaderKeyValueParser = new StandardKeyValueParser("\\s*,\\s*", "\\s*=\\s*");

  /**
   * QueryKeyValueParser is a KeyValueParser for a query string
   */
  public final KeyValueParser QueryKeyValueParser = new StandardKeyValueParser("&", "=");


  /**
   * StandardKeyValueParser is a KeyValueParser that splits a string on a delimiter,
   * and then splits each pair with the kvDelimiter. both delimiters can be java-style
   * regular expressions.
   */
  public static class StandardKeyValueParser implements KeyValueParser {
    private final String delimiter;
    private final String kvDelimiter;

    /*
     TODO: optimize this, no need for regex here
     */
    public StandardKeyValueParser(String delimiter, String kvDelimiter) {
      this.delimiter = delimiter;
      this.kvDelimiter = kvDelimiter;
    }

    @Override
    public void parse(String input, List<KeyValueHandler> handlers) {
      if (empty(input)) return;

      String[] tokens = input.split(delimiter);

      for (String token : tokens) {
        String[] keyAndValue = token.split(kvDelimiter);
        switch (keyAndValue.length) {
          case 2:
            if (!empty(keyAndValue[0])) {
              for (KeyValueHandler handler : handlers) handler.handle(keyAndValue[0], keyAndValue[1]);
            }
            break;
          case 1:
            if (!empty(keyAndValue[0])) {
              for (KeyValueHandler handler : handlers) handler.handle(keyAndValue[0], "");
            }
            break;
          default:
            //ignore ?
            break;
        }
      }
    }

    private boolean empty(String str) {
      return str == null || str.length() == 0;
    }
  }

  /**
   * For testing. Calls the KeyValueParsers with the same List of key/value pairs every time
   */
  //TODO: This is not used, remove?
  public static class ConstKeyValueParser implements KeyValueParser {
    private final List<Request.Pair> pairs;

    public ConstKeyValueParser(List <Request.Pair> pairs) {
      this.pairs = pairs;

    }

    @Override
    public void parse(String input, List<KeyValueHandler> handlers) {
      for (Request.Pair pair : pairs) {
        for (KeyValueHandler handler : handlers) {
          handler.handle(pair.key, pair.value);
        }
      }
    }
  }
}
