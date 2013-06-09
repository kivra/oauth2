# OAuth2 (v0.2.0)  [![BuildStatus](https://travis-ci.org/kivra/oauth2.png?branch=master)](https://travis-ci.org/kivra/oauth2)
This library is designed to simplify the implementation of the server side
of OAuth2 (http://tools.ietf.org/html/rfc6749). It provides
**no** support for developing clients. See
[oauth2_client](https://github.com/kivra/oauth2_client) for support in
accessing Oauth2 enabled services.

oauth2 is released under the terms of the [MIT](http://en.wikipedia.org/wiki/MIT_License) license

Current stable version: [0.2.0](https://github.com/kivra/oauth2/tree/0.2.0)

Current α alpha version: [0.3.0](https://github.com/kivra/oauth2)

copyright 2012-2013 Kivra

## tl;dr
Check out the [examples](https://github.com/kivra/oauth2_example).

There's also a webmachine server implementation by Oauth2 contributor
Ivan Martinez: [oauth2_webmachine](https://github.com/IvanMartinez/oauth2_webmachine).

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

### Scope
The scope is handled by the backend implementation. The specification outlines
that the scope is a space delimetered set of parameters. This library
has been developed with the following in mind.

Scope is implemented as a set and loosely modeled after the Solaris RBAC priviliges, i.e.
`solaris.x.*` and implemented as a [MAC](http://en.wikipedia.org/wiki/Mandatory_access_control)
with the ability to narrow the scope but not extend it beyond the predefined scope.

But since the scope is opaque to this Oauth2 implementation you can use the
scoping strategy that best suit your workflow.

There is a utility module to work with scope. The recommendation is to pass
a Scope as a list of binaries, i.e. `[<<"root.a.c.b">>, <<"root.x.y.z">>]`
you can then validate these against another set like:

``` erlang
> oauth2_priv_set:is_subset(oauth2_priv_set:new([<<"root.a.b">>, <<"root.x.y">>]),
                            oauth2_priv_set:new([<<"root.*">>])).
true
> oauth2_priv_set:is_subset(oauth2_priv_set:new([<<"root.a.b">>, <<"root.x.y">>]),
                            oauth2_priv_set:new([<<"root.x.y">>])).
false
> oauth2_priv_set:is_subset(oauth2_priv_set:new([<<"root.a.b">>, <<"root.x.y">>]),
                            oauth2_priv_set:new([<<"root.a.*">>, <<"root.x.y">>])).
true
```

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

## Testing
If you want to run the EUnit test cases, you can do so with:

    $ make ct

## Customization
The library makes no assumptions as to how you want to implement
authentication and persistence of users, clients and tokens. Instead, it
provides a behavior (`oauth2_backend`) with functions that needs to be
implemented. To direct calls to a different backend module, simply set
`{backend, your_backend_module}` in the `oauth2` section of your app.config.

Look at [oauth2_mock_backend](test/oauth2_mock_backend.erl) for how a backend
can be implemented.

The following example demonstrates a basic app.config section for oauth2.

``` erlang
[
    {oauth2, [
        %% Default expiry_time for access_tokens unless
        %% overridden per flow
        {expiry_time, 3600}
        ,{backend, backend_goes_here}

        %% Optional expiry_time override per flow
        ,{password_credentials, [
            {expiry_time, 7200}
        ]}
        ,{client_credentials, [
            {expiry_time, 86400}
        ]}
        ,{code_grant, [
            %% Recommended absolute expiry time from the spec
            {expiry_time, 600}
        ]}
    ]}
].
```

A complete list of functions that your backend must provide is available by looking
at `oauth2_backend.erl`, which contains documentation and function specifications.

To implement a custom token generation backend you can change your
app.config as such:

``` erlang

    [
        {oauth2, [
            {token_generation, YOUR_TOKEN_GENERATOR}
        ]}
    ].

```

The default token generator is called oauth2_token. To implement your
own you should create your own module implementing the
oauth2_token_generation behavior exporting one function
generate/0.

## License
The KIVRA oauth2 library uses an [MIT license](http://en.wikipedia.org/wiki/MIT_License). So go ahead and do what
you want!

