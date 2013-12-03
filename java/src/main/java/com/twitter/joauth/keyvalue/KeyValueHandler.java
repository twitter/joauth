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

import java.util.*;

/**
 * KeyValueHandler is a trait for a callback with a key and a value.
 * What you do with the key and value are up to you.
 */
public interface KeyValueHandler {
  public void handle(String key, String value);

  public final KeyValueHandler NULL_KEY_VALUE_HANDLER = new NullKeyValueHandler();

  static class NullKeyValueHandler implements KeyValueHandler {
    public void handle(String key, String value) {
    }
  }

  /**
   * DuplicateKeyValueHandler produces a List[(String, String)] of key
   * value pairs, allowing duplicate values for keys.
   */
  public static class DuplicateKeyValueHandler implements KeyValueHandler {
    ArrayList<Request.Pair> buffer = new ArrayList<Request.Pair>();

    public void handle(String key, String value) {
     buffer.add(new Request.Pair(key, value));
    }

    public ArrayList<Request.Pair> toList() {
      return buffer;
    }
  }

  /**
   * SingleKeyValueHandler produces either a List[(String, String)]
   * or a Map[String, String] of key/value pairs, and will override
   * duplicate values for keys, using the last value encountered
   */
  public static class SingleKeyValueHandler implements KeyValueHandler {
    HashMap<String, String> kv = new LinkedHashMap<String, String>();

    public void handle(String key, String value) {
      kv.put(key, value);
    }

    public HashMap<String, String> toMap() {
      return kv;
    }

    public ArrayList<Request.Pair> toList() {
      Iterator<Map.Entry<String, String>> iterator = kv.entrySet().iterator();
      ArrayList<Request.Pair> list = new ArrayList<Request.Pair>(kv.size());

      while(iterator.hasNext()) {
        Map.Entry<String, String> next = iterator.next();
        list.add(new Request.Pair(next.getKey(), next.getValue()));
      }

      return list;
    }
  }

  public static class MaybeQuotedValueKeyValueHandler implements KeyValueHandler {
    private KeyValueHandler underlying;
    //private static String QUOTED_REGEX = Pattern.compile("^\s*\"(.*)\"\s*$");

    public MaybeQuotedValueKeyValueHandler(KeyValueHandler underlying) {
      this.underlying = underlying;
    }

    public void handle(String key, String value) {
      String trimmed = value.trim();
      if (trimmed.length() > 1 && trimmed.charAt(0) == '"' && trimmed.charAt(trimmed.length()-1) == '"') {
        underlying.handle(key, trimmed.substring(1, trimmed.length()-1));
      } else {
        underlying.handle(key, value);
      }
    }
  }

  /**
   * PrintlnKeyValueHandler is very nice for debugging!
   * Pass it in to the Unpacker to see what's going on.
   */
  class PrintlnKeyValueHandler implements KeyValueHandler {
    private String prefix;

    public PrintlnKeyValueHandler(String prefix) {
      this.prefix = prefix;
    }

    public void handle(String key, String value) {
      System.out.println("%s%s=%s".format(prefix, key, value));
    }
  }


  /**
   * TransformingKeyValueHandler applies the Transformers to
   * their respective key and value before passing along to the
   * underlying KeyValueHandler
   */
  public static class TransformingKeyValueHandler implements KeyValueHandler {
    protected final KeyValueHandler underlying;
    protected final Transformer keyTransformer;
    protected final Transformer valueTransformer;

    public TransformingKeyValueHandler(KeyValueHandler underlying, Transformer keyTransformer, Transformer valueTransformer) {
      this.underlying = underlying;
      this.keyTransformer = keyTransformer;
      this.valueTransformer = valueTransformer;
    }

    public void handle(String key, String value) {
      underlying.handle(keyTransformer.transform(key), valueTransformer.transform(value));
    }
  }

  /**
   * TrimmingKeyValueHandler trims the key and value before
   * passing them to the underlying KeyValueHandler
   */
  public class TrimmingKeyValueHandler extends TransformingKeyValueHandler {

    public TrimmingKeyValueHandler(KeyValueHandler underlying) {
      super(underlying, Transformer.TRIM_TRANSFORMER, Transformer.TRIM_TRANSFORMER);
    }
  }

  /**
   * KeyTransformingKeyValueHandler applies a Transformer to the key
   * before passing the key value pair to the underlying KeyValueHandler
   */
  public static class KeyTransformingKeyValueHandler extends TransformingKeyValueHandler {

    public KeyTransformingKeyValueHandler(KeyValueHandler underlying, Transformer keyTransformer) {
      super(underlying, keyTransformer, null);
    }

    public void handle(String key, String value) {
      underlying.handle(keyTransformer.transform(key), value);
    }
  }

  /**
   * ValueTransformingKeyValueHandler applies a Transformer to the value
   * before passing the key value pair to the underlying KeyValueHandler
   */
  public static class ValueTransformingKeyValueHandler extends TransformingKeyValueHandler {

    public ValueTransformingKeyValueHandler(KeyValueHandler underlying, Transformer valueTransformer) {
      super(underlying, null, valueTransformer);
    }

    public void handle(String key, String value) {
      underlying.handle(key, valueTransformer.transform(value));
    }
  }

  /**
   * UrlEncodingNormalizingKeyValueHandler normalizes URLEncoded
   * keys and values, to properly capitalize them
   */
  public static class UrlEncodingNormalizingKeyValueHandler extends TransformingKeyValueHandler {

    public UrlEncodingNormalizingKeyValueHandler(KeyValueHandler underlying) {
      super(underlying, Transformer.URL_ENCODING_NORMALIZING_TRANSFORMER, Transformer.URL_ENCODING_NORMALIZING_TRANSFORMER);
    }
  }


/**
 * key is set iff the handler was invoked exactly once with an empty value
 */
  public static class OneKeyOnlyKeyValueHandler implements KeyValueHandler {
    private boolean invoked = false;
    private String _key = null;

    @Override
    public void handle(String key, String value) {
      if (invoked) {
        if (_key != null) _key = null;
      } else {
        invoked = true; //TODO: bug? should invoked be set to true, if _key is not set?
        if (value == null || value.equals("")) _key = key;
      }
    }

    public String getKey() {
      return _key;
    }
  }
}