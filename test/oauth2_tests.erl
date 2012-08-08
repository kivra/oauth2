%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 implementation
%%
%% Copyright (c) 2012 KIVRA
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.
%%
%% ----------------------------------------------------------------------------

-module(oauth2_tests).

-include_lib("eunit/include/eunit.hrl").

%%% Placeholder values that the mock backend will recognize.
-define(USER_NAME,     <<"herp">>).
-define(USER_PASSWORD, <<"derp">>).
-define(USER_SCOPE,    <<"xyz">>).

-define(CLIENT_ID,     <<"TiaUdYODLOMyLkdaKkqlmhsl9QJ94a">>).
-define(CLIENT_SECRET, <<"fvfDMAwjlruC9rv5FsLjmyrihCcIKJL">>).
-define(CLIENT_SCOPE,  <<"abc">>).
-define(CLIENT_URI,    <<"https://no.where/cb">>).

-define(ETS_TABLE, access_tokens).

%%%===================================================================
%%% Test cases
%%%===================================================================

bad_authorize_password_test_() ->
    {setup,
        fun start/0,
        fun stop/1,
        fun(_) -> 
                [
                 ?_assertMatch({ok, _},
                               oauth2:authorize_password(
                                 <<"herp">>,
                                 <<"derp">>,
                                 <<"xyz">>)),
                 ?_assertMatch({error, access_denied},
                               oauth2:authorize_password(
                                 <<"herp">>,
                                 <<"derp">>,
                                 <<"bad_scope">>)),
                 ?_assertMatch({error, access_denied},
                               oauth2:authorize_password(
                                 <<"herp">>,
                                 <<"herp">>,
                                 <<"xyz">>)),
                 ?_assertMatch({error, access_denied},
                               oauth2:authorize_password(
                                 <<"derp">>,
                                 <<"derp">>,
                                 <<"xyz">>))
                ]
        end}.

bad_authorize_client_credentials_test_() ->
    {setup,
        fun start/0,
        fun stop/1,
        fun(_) ->
                [
                 ?_assertMatch({error, access_denied},
                               oauth2:authorize_client_credentials(
                                 <<"XoaUdYODRCMyLkdaKkqlmhsl9QQJ4b">>,
                                 <<"fvfDMAwjlruC9rv5FsLjmyrihCcIKJL">>,
                                 <<"abc">>)),
                 ?_assertMatch({error, access_denied},
                               oauth2:authorize_client_credentials(
                                 <<"TiaUdYODLOMyLkdaKkqlmdhsl9QJ94a">>,
                                 <<"gggDMAwklAKc9kq5FsLjKrzihCcI123">>,
                                 <<"abc">>)),
                 ?_assertMatch({error, access_denied},
                                oauth2:authorize_client_credentials(
                                 <<"TiaUdYODLOMyLkdaKkqlmdhsl9QJ94a">>,
                                 <<"fvfDMAwjlruC9rv5FsLjmyrihCcIKJL">>,
                                 <<"cba">>))
                ]
        end}.

verify_access_token_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              fun() ->
                      {ok, Response} = oauth2:authorize_client_credentials(
                                         ?CLIENT_ID,
                                         ?CLIENT_SECRET,
                                         ?CLIENT_SCOPE),
                      {ok, Token} = oauth2_response:access_token(Response),
                      ?assertMatch({ok, _}, oauth2:verify_access_token(Token))
              end,
              ?_assertMatch({error, access_denied},
                 oauth2:verify_access_token(<<"nonexistent_token">>))
             ]
     end}.

verify_redirection_uri_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              ?_assertEqual(ok,
                            oauth2:verify_redirection_uri(
                              ?CLIENT_ID,
                              ?CLIENT_URI)),
              ?_assertMatch({error, mismatch},
                            oauth2:verify_redirection_uri(
                              ?CLIENT_ID,
                              <<"https://the.wrong.url.ru">>)),
              ?_assertMatch({error, notfound},
                            oauth2:verify_redirection_uri(
                              <<"the_wrong_client">>,
                              ?CLIENT_URI))
             ]
     end}.

%%%===================================================================
%%% Setup/teardown
%%%===================================================================

start() ->
    %% Set up the ETS table for holding access tokens.
    ets:new(?ETS_TABLE, [public, named_table, {read_concurrency, true}]),
    meck:new(oauth2_backend),
    meck:expect(oauth2_backend,
                authenticate_username_password,
                fun authenticate_username_password/3),
    meck:expect(oauth2_backend,
                authenticate_client,
                fun authenticate_client/3),
    meck:expect(oauth2_backend,
                associate_access_token,
                fun associate_access_token/2),
    meck:expect(oauth2_backend,
                resolve_access_token,
                fun resolve_access_token/1),
    meck:expect(oauth2_backend,
                revoke_access_token,
                fun revoke_access_token/1),
    meck:expect(oauth2_backend,
                get_redirection_uri,
                fun get_redirection_uri/1),
    ok.

stop(_State) ->
    ets:delete(?ETS_TABLE),
    meck:unload(oauth2_backend).

%%%===================================================================
%%% Mockup backend functions
%%%===================================================================

authenticate_username_password(?USER_NAME, ?USER_PASSWORD, ?USER_SCOPE) ->
    {ok, {user, 31337}};
authenticate_username_password(?USER_NAME, ?USER_PASSWORD, _) ->
    {error, badscope};
authenticate_username_password(?USER_NAME, _, _) ->
    {error, badpass};
authenticate_username_password(_, _, _) ->
    {error, notfound}.

authenticate_client(?CLIENT_ID, ?CLIENT_SECRET, ?CLIENT_SCOPE) ->
    {ok, {client, 4711}};
authenticate_client(?CLIENT_ID, ?CLIENT_SECRET, _) ->
    {error, badscope};
authenticate_client(?CLIENT_ID, _, _) ->
    {error, badsecret};
authenticate_client(_, _, _) ->
    {error, notfound}.

associate_access_token(AccessToken, Context) ->
    ets:insert(?ETS_TABLE, {AccessToken, Context}),
    ok.

resolve_access_token(AccessToken) ->
    case ets:lookup(?ETS_TABLE, AccessToken) of
        [] ->
            {error, notfound};
        [{_, Context}] ->
            {ok, Context}
    end.

revoke_access_token(AccessToken) ->
    ets:delete(?ETS_TABLE, AccessToken),
    ok.

get_redirection_uri(?CLIENT_ID) ->
    {ok, ?CLIENT_URI};
get_redirection_uri(_) ->
    {error, notfound}.
