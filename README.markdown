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

The Github source repository is [here](http://github.com/9len/joauth/). Patches and contributions are  
welcome.

## Understanding the Implementation

`JOAuth` consists of five traits, each of which is invoked with an apply method.

* The OAuthRequest trait models the data needed to validate a request. There are two concrete subclasses, OAuth1Request and OAuth2Request.
* The Unpacker trait unpacks the HttpServletRequest into an OAuthRequest, which models the data needed to validate the request
* The Normalizer trait produces a normalized String representation of the request, used for signature calculation
* The Signer trait signs a String, using the OAuth token secret and consumer secret.
* The Verifier trait verifies that a OAuth1Request is valid, checking the timestamp, nonce, and signature

There are "Standard" and "Const" implementations of the Unpacker, Normalizer, Signer, and the Verifier traits. 