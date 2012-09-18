# OAuth2
This library is designed to simplify the implementation of the server side
of OAuth2 (http://tools.ietf.org/html/draft-ietf-oauth-v2-31). It provides
**no** support for developing clients.

## tl;dr
Check out the [examples](https://github.com/kivra/oauth2_example)

## Concepts

### Tokens
A token is a (randomly generated) string provided to the client by the server
in response to some form of authorization request.
There are several types of tokens:

* *Access Token*: An access token identifies the origin of a request for a
privileged resource.
* *Refresh Token*: A refresh token can be used to replace an expired access token.

#### Expiry
Access tokens can (optionally) be set to expire after a certain amount of time.
An expired token cannot be used to gain access to resources.

### Identities
A token is associated with an *identity* -- a value that uniquely identifies
a user, client or agent within your system. Typically, this is a user identifier.

### Clients
If you have many diverse clients connecting to your service -- for instance,
a web client and an iPhone app -- it's desirable to be able to distinguish
them from one another and to be able to grant or revoke privileges based
on the type the client issuing a request. As described in the OAuth2 specification,
clients come in two flavors:

* *Confidential* clients, which can be expected to keep their credentials
from being disclosed. For instance, a web site owned and operated by you
could be regarded as confidential.
* *Public* clients, whose credentials are assumed to be compromised the
moment the client software is released to the public.

Clients are distinguished by their identifiers, and can (optionally) be
authenticated using a secret key shared between the client and server.

## Building
This library is built using rebar wrapped with make. It has been developed
and tested under Erlang R15B01; nothing's stopping you from trying it with another
version, but your mileage may vary.

Build with:

    $ make

If you want to run the EUnit test cases, you can do so with:

    $ make test

To generate documentation, run:

    $ make doc

## Customization
The library makes no assumptions as to how you want to implement authentication and persistence of
users, clients and tokens. Instead, it provides a proxy module (`oauth2_backend`) for directing
calls to a backend plugin supplied by you. To direct calls to a different backend module,
simply set `{backend, your_backend_module}` in the `oauth2` section of your app.config.

A complete list of functions that your backend must provide is available by looking
at `oauth2_backend.erl`, which contains documentation and function specifications.

## License
The KIVRA oauth2 library uses an [MIT license](http://en.wikipedia.org/wiki/MIT_License). So go ahead and do what
you want!

