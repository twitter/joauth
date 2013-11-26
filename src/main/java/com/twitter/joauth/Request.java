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

import java.util.ArrayList;

public abstract class Request {
  abstract public String authHeader();
  abstract public String body();
  abstract public String contentType();
  abstract public String host();
  abstract public String method();
  abstract public String path();
  abstract public int port();
  abstract public String queryString();
  abstract public String scheme();


  public ParsedRequest parsedRequest(ArrayList<Pair> params) {
    ParsedRequest request = new ParsedRequest();
    if (scheme() != null) request.scheme = scheme().toUpperCase();
    request.host = host();
    request.port = port();
    if (method() != null) request.verb = method().toUpperCase();
    request.path = path();
    request.params = params;

    return request;
  }

  public static class Pair {
    public Pair(String key, String value) {
      this.key = key;
      this.value = value;
    }

    public String key;
    public String value;

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      Pair pair = (Pair) o;

      if (key != null ? !key.equals(pair.key) : pair.key != null) return false;
      if (value != null ? !value.equals(pair.value) : pair.value != null) return false;

      return true;
    }

    @Override
    public int hashCode() {
      int result = key != null ? key.hashCode() : 0;
      result = 31 * result + (value != null ? value.hashCode() : 0);
      return result;
    }

    @Override
    public String toString() {
      return "Pair{" +
          "key='" + key + '\'' +
          ", value='" + value + '\'' +
          '}';
    }
  }

  public static class ParsedRequest {
    ParsedRequest() {
    }

    public ParsedRequest(String scheme, String host, int port, String verb, String path, ArrayList<Pair> params) {
      this.scheme = scheme;
      this.host = host;
      this.port = port;
      this.verb = verb;
      this.path = path;
      this.params = params;
    }

    public String scheme;
    public String host;
    public int port;
    public String verb;
    public String path;
    public ArrayList<Pair> params;

    @Override
    public String toString() {
      return "ParsedRequest{" +
          "scheme='" + scheme + '\'' +
          ", host='" + host + '\'' +
          ", port=" + port +
          ", verb='" + verb + '\'' +
          ", path='" + path + '\'' +
          ", params=" + params +
          '}';
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      ParsedRequest that = (ParsedRequest) o;

      if (port != that.port) return false;
      if (host != null ? !host.equals(that.host) : that.host != null) return false;
      if (params != null ? !params.equals(that.params) : that.params != null) return false;
      if (path != null ? !path.equals(that.path) : that.path != null) return false;
      if (scheme != null ? !scheme.equals(that.scheme) : that.scheme != null) return false;
      if (verb != null ? !verb.equals(that.verb) : that.verb != null) return false;

      return true;
    }

    @Override
    public int hashCode() {
      int result = scheme != null ? scheme.hashCode() : 0;
      result = 31 * result + (host != null ? host.hashCode() : 0);
      result = 31 * result + port;
      result = 31 * result + (verb != null ? verb.hashCode() : 0);
      result = 31 * result + (path != null ? path.hashCode() : 0);
      result = 31 * result + (params != null ? params.hashCode() : 0);
      return result;
    }
  }
}