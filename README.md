Oauth2 -- An erlang Oauth2 library
====================================

## DESCRIPTION

Oauth2 is a library to build Oauth2 aware servers. This library tries to adhere to the spec as close as possible: <http://tools.ietf.org/html/draft-ietf-oauth-v2-23>.

Currently tested and supported flows are:

* Authentication Code Flow (Web Server Flow)
* Implicit Flow (Client Side Flow)

Other flows should work but hasn't been tested yet.

## USAGE

Include Oauth2 as a rebar dependency with:

	{deps, [{oauth2, ".*", {git, "git://github.com/bipthelin/oauth2.git", "master"}}]}.

Then you will have to write a DB module to handle various tasks such as verifying client_id, redirect_uri, etc.

There's a mock db adapter included which is a good reference for implementing your own. It should be no more than a couple of lines of code to implement your own.

	-module(my_oauth2_db).

	-export([get/2, set/3, delete/2]).
	-export([verify_redirect_uri/2]).

	-include_lib("include/oauth2.hrl").

	%%
	%% Oauth2 DB Behavior
	-behavior(oauth2_db).

	%%
	%% Get Oauth2 record from the Auth DB
	get(auth, Key) ->
    	get_from_table(?TAB_AUTH, Key);
	%%
	%% Get Oauth2 record from the Access DB
	get(access, Key) ->
    	get_from_table(?TAB_ACC, Key).

	%%
	%% Put Oauth2 record to the Auth DB
	set(auth, Key, Value) ->
	    CliendId = Value#oauth2.client_id,
 	    Expires = Value#oauth2.expires,
    	Scope = Value#oauth2.scope,
 
    	put_to_table(?TAB_AUTH, Key, Value);
	%%
	%% Put Oauth2 record to the Access DB
	set(access, Key, Value) ->
 	    CliendId = Value#oauth2.client_id,
 	    Expires = Value#oauth2.expires,
    	Scope = Value#oauth2.scope,
 
    	put_to_table(?TAB_ACC, Key, Value).

	%%
	%% Delete Oauth2 record from the Auth DB
	delete(auth, Key) ->
    	delete_from_table(?TAB_AUTH, Key);
	%%
	%% Delete Oauth2 record from the Access DB
	delete(access, Key) ->
    	delete_from_table(?TAB_ACC, Key).

	%%
	%% Verify if a given Client ID and RedirectUri match
	verify_redirect_uri(CliendId, RedirectUri) ->
    	true.

Here's a step by step to the various flows:

## Implicit Flow

	1> RedirectUri = "http://REDIRECT.URL/here?this=that".
	"http://REDIRECT.URL/here?this=that"
	2> Scope = "This That".
	"This That"
	3> State = "Just a little state".
	"Just a little state"
	4> ClientId = "123abcABC".
	"123abcABC"
	5> oauth2:authorize(token, my_oauth2_db, ClientId, RedirectUri, Scope, State).
	{ok,"226a4OHh8NgasQv.1330703188.Qegej3cFVewKHr7",
	    "http://REDIRECT.URL/here?state=Just+a+little+state&this=that#code=226a4OHh8NgasQv.1330703188.Qegej3cFVewKHr7",
	    7200}

## Authentication Code Flow

	1> RedirectUri = "http://REDIRECT.URL/here?this=that".
	"http://REDIRECT.URL/here?this=that"
	2> Scope = "This That".
	"This That"
	3> State = [].
	[]
	4> ClientId = "123abcABC".
	"123abcABC"
	5> oauth2:authorize(code, my_oauth2_db, ClientId, RedirectUri, Scope, State).
	{ok,"n2HqNFz3QhZ_EjcXP8QuWgpCrbZCJx",
    "http://REDIRECT.URL/here?code=n2HqNFz3QhZ_EjcXP8QuWgpCrbZCJx&this=that",
    30}
    6> oauth2:verify_token(authorization_code,oauth2_mock_db,"n2HqNFz3QhZ_EjcXP8QuWgpCrbZCJx", ClientId, RedirectUri).
    {ok,[{access_token,"aTjJHonW0nsHzUp.1330937706.xS__1bdSYTYcZlB"},
     	{token_type,"Bearer"},
     	{expires_in,7200}]}
     7> oauth2:verify_token(access_token,oauth2_mock_db,"aTjJHonW0nsHzUp.1330937706.xS__1bdSYTYcZlB", ClientId).
     {ok,[{audience,"123abcABC"},
        {scope,"This That"},
     	{expires_in,7046}]}

xoxo

