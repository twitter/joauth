# JOAuth [![Build Status](https://travis-ci.org/twitter/joauth.png?branch=master)](https://travis-ci.org/twitter/joauth) [![Coverage Status](https://coveralls.io/repos/twitter/joauth/badge.png)](https://coveralls.io/r/twitter/joauth)

A Java library for authenticating HTTP Requests using OAuth

## Features

* Supports OAuth 1.0a and 2.0 (draft 25)
* Unpacks Requests, extracts and verifies OAuth parameters from headers, GET, and POST
* Incidentally parses Non-OAuth GET and POST parameters and makes them accessible via a callback
* Custom callbacks to obtain scheme and path from the request in a non-standard way
* Configurable timestamp checking
* Correctly works around various weird URLEncoder bugs in the JVM
* Written in Java, with minimal dependencies

The Github source repository is [here](https://github.com/twitter/joauth/). Patches and contributions are welcome.

## Non-Features

* It's not a full OAuth solution; There's nothing here about creating request tokens, access token/secret pairs, or consumer key/secret pairs. This library is primarily for verifying (and potentially signing) requests.
* There's no framework for looking up access token/secret pairs and consumer key/secret pairs from a backing store. You're on your own there.
* There's no Nonce-validation, though there's support for adding your own.

## Building

*Dependencies*: commons-codec (specs & mockito-all to run the tests). These dependencies are managed by the build system.

v3.0.1 and higher - Use maven to build:

    % mvn clean install

**v.1.1.2 is the last version that can be built using scala 2.7.7, and now resides in the scala27 branch. v1.2 and above require scala > 2.8.1. v3.0.1 and above uses maven instead of sbt, and require scala 2.9.2**

**v.6.0.0 require JDK 1.6. Test require scala 2.9.2**

Below v3.0.1 - Use sbt (simple-build-tool) to build:

    % sbt clean update compile

The finished jar will be in `dist/`.

## Understanding the Implementation

JOAuth consists of five traits, each of which is invoked with an apply method.

* The OAuthRequest trait models the data needed to validate a request. There are three subclasses, OAuth1Request, OAuth1TwoLeggedRequest and OAuth2Request.
* The Unpacker trait unpacks the HttpServletRequest into an OAuthRequest, which models the data needed to validate the request
* The Normalizer trait produces a normalized String representation of the request, used for signature calculation
* The Signer trait signs a String, using the OAuth token secret and consumer secret.
* The Verifier trait verifies that a OAuth1Request is valid, checking the timestamp, nonce, and signature

There are "Standard" and "Const" implementations of the Unpacker, Normalizer, Signer, and the Verifier traits, for easy dependency injection. Each trait has a companion object with apply methods for the default instantiation of the corresponding Standard implementations.

## Usage

### Basic Usage

Create an unpacker, and use it to unpack the Request. The Unpacker will either return an OAuth1Request or OAuth2Request object or throw an UnpackerException.

    import com.twitter.joauth.Unpacker

    val unpack = Unpacker()
    try {
      unpack(request) match {
        case req: OAuth1Request => handleOAuth1(req)
	case req: OAuth1TwoLeggedRequest => handleOAuth1TwoLegged(req)
        case req: OAuth2Request => handleOAuth2(req)
        case _ => // ignore or throw
      }
    } catch {
      case e:UnpackerException => // handle or rethrow
      case _ => // handle or rethrow
    }

Once the request is unpacked, the credentials need to be validated. For an OAuth2Request, the OAuth Access Token must be retrieved and validated by your authentication service. For an OAuth1Request the Access Token, the Consumer Key, and their respective secrets must be retrieved, and then passed to the Verifier for validation. For an OAuth1TwoLeggedRequest, the Consumer Key must be retrieved and passed to the Verifier for validation.

    import com.twitter.joauth.{Verifier, VerifierResult}

    val verify = Verifier()
    verify(oAuth1Request, tokenSecret, consumerSecret) match {
      case VerifierResult.BAD_NONCE => // handle bad nonce
      case VerifierResult.BAD_SIGNATURE => // handle bad signature
      case VerifierResult.BAD_TIMESTAMP => // handle bad timestamp
      case VerifierResult.OK => //success!
    }

That's it!

### Advanced Usage

#### Getting Parameter Key/Values

There are two apply methods in the Unpacker trait. The one-argument version takes a Request, and the two-argument version takes a Request and a Seq[KeyValueHandler]. A KeyValueHandler is a simple trait that the Unpacker uses as a callback for every Key/Value pair encountered in either the query string or POST data (if the Content-Type is application/x-www-form-urlencoded). If there are duplicate keys, the KeyValueHandler will get invoked for each.

The JOAuth library provides a few basic KeyValueHandlers, and it's easy to add your own. For example, suppose you want to get a list of key/values, including duplicates, from the request you're unpacking. You can do this by passing a DuplicateKeyValueHandler to the unpacker.

    val unpack = Unpacker()
    val handler = new DuplicateKeyValueHandler
    val unpackedRequest = unpack(request, Seq(handler))
    doSomethingWith(handler.toList)

The DuplicateKeyValueHandler is invoked for each key/value pair encountered, and a List[(String, String)] can be extracted afterwards.

You can also construct your own KeyValueHandlers, and there are a few useful KeyValueHandlers already defined. There's a TransformingKeyValueHandler, which wraps an underlying KeyValueHandler such that either the key or value or both are transformed before the underlying handler is invoked.

For example, suppose you want to get all values of a single parameter, and you want it UrlDecoded first.

    class ValuesOnlyKeyValueHandler(key: String) extends KeyValueHandler {
      val buffer = new ArrayBuffer[String]
      def apply(k: String, v: String) {
        if (k == key)
          buffer += v
      }
      def toList = buffer.toList
    }

    object UrlDecodingTransformer extends Transformer {
      def apply(str: String) = URLDecoder.decode(str)
    }

    class UrlDecodedKeyValueHandler(underlying: KeyValueHandler)
      extends TransformingKeyValueHandler(underlying, UrlDecodingTransformer, UrlDecodingTransformer)

    val unpack = Unpacker()
    val handler = new ValuesOnlyKeyValueHandler("SpecialKey")
    val wrappedHandler = UrlDecodedMyValueOnlyKeyValueHandler(handler)
    val unpackedRequest = unpack(request, Seq(wrappedHandler))
    doSomethingWith(handler.toList)

Obviously it would be a little easier to just call request.getParameterValues("SpecialKey") in this example, but we hope it's not hard to see that passing custom KeyValueHandlers into the unpacker can be a powerful tool. In particular, they're an easy way to get access to POST data after the Unpacker has ruined your HttpServletRequest by calling getInputStream.

KeyValueHandlers are used in the JOAuth source code to collect OAuth and non-OAuth parameters from the GET, POST and Authorization header.

#### Other Unpacker Tricks

You can pass in a custom Normalizer or custom parameter and header KeyValueParsers to the Unpacker apply method if you really want to, but you're on your own.

#### Using Normalizer and Signer

You can use the Normalizer and Signer to sign OAuth 1.0a requests.

    val normalize = Normalizer()
    val sign = Signer()

    val normalizedRequest = normalize(scheme, host, port, verb, path, params, oAuthParams)
    val signedRequest = sign(normalizedRequest, tokenSecret, consumerSecret)

The parameters are passed as a List[(String, String)], and the OAuth params are passed in an OAuthParams instance.

## Running Tests

The tests are completely self contained, and can be run using Maven:

    % mvn test

## Reporting problems

The Github issue tracker is [here](https://github.com/9len/joauth/issues).

## Contributors

* Jeremy Cloud
* Tina Huang
* Steve Jenson
* Nick Kallen
* John Kalucki
* Raffi Krikorian
* Mark McBride
* Marcel Molina
* Glen Sanford
* Fiaz Hossain
* Steven Liu
* Manoj Cheenath

## License

Copyright 2010-2013 Twitter, Inc.

Licensed under the Apache License, Version 2.0: https://www.apache.org/licenses/LICENSE-2.0

