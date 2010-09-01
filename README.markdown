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

### Basic Usage

Create an unpacker, and use it to unpack the HttpServletRequest. The Unpacker will either return an OAuth1Request or OAuth2Request object or throw an UnpackerException. 

    import com.twitter.joauth.Unpacker

    val unpack = Unpacker()
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
    
*WARNING*: The StandardUnpacker will call the HttpRequest.getReader method if the method of the request is POST and the Content-Type is "application/x-www-form-urlencoded." If you need to read the POST yourself, this will cause you problems, since getReader can only be called once. There are two solutions: (1) Write an HttpServletWrapper to buffer the POST data and allow multiple calls to getReader, and pass the HttpServletWrapper into the Unpacker. (2) Pass a KeyValueHandler into the unpacker call (See "Getting Parameter Key/Values" below for more), which will let you get the parameters in the POST as a side effect of unpacking.
      
Once the request is unpacked, the credentials need to be validated. For an OAuth2Request, the OAuth Access Token must be retrieved and validated by your authentication service. For an OAuth1Request the Access Token, the Consumer Key, and their respective secrets must be retrieved, and then passed to the Verifier for validation. 

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

#### Overriding Path and Scheme
    
If you're building an internal authentication service, it may serve multiple endpoints, and need to calculate signatures for all of them. it may also live on a server hosting multiple services on the same port, in which case you'll need a specific endpoint for your authentication service, while simultaneously needing to validate requests as if they had their original endpoints. You can accommodate this by passing in a method for extracting the path from the HttpServletRequest, via the PathGetter trait. 

For example, if you have an authentication service that responded to the /auth endpoint, and you are authenticating requests to an external server serving the /foo endpoint, the path of the request the authentication service receives is /auth/foo. This won't do, because the signature of the request depends on the path being /foo. We can construct a PathGetter that strips /auth out of the path.

    import com.twitter.joauth.PathGetter

    class MyPathGetter extends PathGetter {
      def apply(request: HttpServletRequest): String = {
        request.getPathInfo.match {
          case "^/auth/(/*)$".r(realPath) => realPath
          case => // up to you whether to return path or throw here, depends on your circumstances
        }
      }
    }

If you're running a high throughput authentication service, you might want to avoid using SSL, and listen only for HTTP. Unfortunately, the URI Scheme is part of the signature as well, so you need a way to force the Unpacker to treat the request as HTTPS, even though it isn't. One approach would be for your authentication service to take a custom header to indicate the scheme of the originating request. You can then use the UrlSchemeGetter trait to pull this header out of the request.

    import com.twitter.joauth.UriSchemeGetter
    
    classs MySchemeGetter extends UrlSchemeGetter {
      def apply(request; HttpServletRequest): String = {
        val header = request.getHeader("X-My-Scheme-Header")
        if (header == null) request.getScheme
        else header.toUpperCase
      }
    }

You can now construct your unpacker with your Getters.

    val unpack = Unpacker(new MySchemeGetter, new MyPathGetter)
    
if you only want to pass in one or the other, you can use the StandardSchemeGetter and StandardPathGetter classes when calling the two-argument Unpacker.apply.

#### Getting Parameter Key/Values



#### Other Unpacker Tricks

You can pass in a custom Normalizer or custom parameter and header KeyValueParsers to the Unpacker apply method if you really want to, but you're on your own.