# JOAuth

A library for authenticating HttpServletRequests using OAuth

## License

Copyright 2010 Twitter, Inc. See included LICENSE file.

## Features

* Supports OAuth 1.0a and 2.0
* Unpacks HttpServletRequests, extracts and verifies OAuth parameters from headers, GET, and POST
* Incidentally parses Non-OAuth GET and POST parameters and makes them accessible via a callback
* Overridable callbacks to obtain scheme and path from the request
* Overridable callback to verify nonce
* Configurable timestamp checking
* Correctly works around various weird URLEncoder bugs in the JVM

The Github source repository is [here](http://github.com/9len/joauth/). Patches and contributions are  welcome.

## Understanding the Implementation

JOAuth consists of five traits, each of which is invoked with an apply method.

* The OAuthRequest trait models the data needed to validate a request. There are two concrete subclasses, OAuth1Request and OAuth2Request.
* The Unpacker trait unpacks the HttpServletRequest into an OAuthRequest, which models the data needed to validate the request
* The Normalizer trait produces a normalized String representation of the request, used for signature calculation
* The Signer trait signs a String, using the OAuth token secret and consumer secret.
* The Verifier trait verifies that a OAuth1Request is valid, checking the timestamp, nonce, and signature

There are "Standard" and "Const" implementations of the Unpacker, Normalizer, Signer, and the Verifier traits, for easy dependency injection. Each trait has a companion object with apply methods for the default instantiation of the corresponding Standard implementations. 

## Usage

## Basic Usage

Create an unpacker:

    import com.twitter.joauth.Unpacker
    
    val unpack = Unpacker()
    
Use the unpacker to unpack the HttpServletRequest. The Unpacker will either return an OAuth1Request or OAuth2Request object or throw an UnpackerException. 

    try {
      unpack(request) match {
        case req: OAuth1Request => handleOAuth1(req)
        case req: OAuth2Request => handleOAuth2(req)
        case _ => // ignore or throw
      }
    } catch {
      case e:UnpackerException => // handle or rethrow
      case _ => // handle or rethrow
    } 
      
Once the request is unpacked, the credentials need to be validated. For an OAuth2Request, the OAuth Access Token must be retrieved and validated by your authentication service. For an OAuth1Request the Access Token, the Consumer Key, and their respective secrets must be retrieved, and then passed to the Verifier for validation. 

    import com.twitter.joauth.{Verifier, VerifierResult}
    
    val verify = Verifier()
    verify(oAuth1Request, tokenSecret, consumerSecret) match {
      case VerifierResult.BAD_NONCE => // handle bad nonce
      case VerifierResult.BAD_SIGNATURE => // handle bad signature
      case VerifierResult.BAD_TIMESTAMP => // handle bad timestamp
      case VerifierResult.OK => //success!
    }

    
