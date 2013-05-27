%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 implementation
%%
%% Copyright (c) 2012-2013 KIVRA
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

-module(oauth2_mock_backend).

-behavior(oauth2_backend).

%%% Behavior API
-export([authenticate_username_password/2]).
-export([authenticate_client/2]).
-export([get_client_identity/1]).
-export([associate_access_code/2]).
-export([associate_refresh_token/2]).
-export([associate_access_token/2]).
-export([resolve_access_code/1]).
-export([resolve_refresh_token/1]).
-export([resolve_access_token/1]).
-export([revoke_access_code/1]).
-export([revoke_access_token/1]).
-export([revoke_refresh_token/1]).
-export([get_redirection_uri/1]).
-export([verify_redirection_uri/2]).
-export([verify_client_scope/2]).
-export([verify_resowner_scope/2]).

%%% mock_backend-specifics
-export([start/0]).
-export([stop/0]).

%%% Placeholder values that the mock backend will recognize.
-define(USER_NAME,     <<"herp">>).
-define(USER_PASSWORD, <<"derp">>).
-define(USER_SCOPE,    [<<"xyz">>]).
-define(RESOURCE_OWNER, <<"user">>).

-define(CLIENT_ID,     <<"TiaUdYODLOMyLkdaKkqlmhsl9QJ94a">>).
-define(CLIENT_SECRET, <<"fvfDMAwjlruC9rv5FsLjmyrihCcIKJL">>).
-define(CLIENT_SCOPE,  <<"abc">>).
-define(CLIENT_URI,    <<"https://no.where/cb">>).

-define(ETS_TABLE, access_tokens).

%%%===================================================================
%%% API
%%%===================================================================

authenticate_username_password(?USER_NAME, ?USER_PASSWORD) ->
    {ok, {user, 31337}};
authenticate_username_password(?USER_NAME, _) ->
    {error, badpass};
authenticate_username_password(_, _) ->
    {error, notfound}.

authenticate_client(?CLIENT_ID, ?CLIENT_SECRET) ->
    {ok, {client, 4711}};
authenticate_client(?CLIENT_ID, _) ->
    {error, badsecret};
authenticate_client(_, _) ->
    {error, notfound}.

get_client_identity(?CLIENT_ID) ->
    {ok, {client, 4711}};
get_client_identity(_) ->
    {error, notfound}.

associate_access_code(AccessCode, Context) ->
    associate_access_token(AccessCode, Context).

associate_refresh_token(RefreshToken, Context) ->
    ets:insert(?ETS_TABLE, {RefreshToken, Context}),
    ok.

associate_access_token(AccessToken, Context) ->
    ets:insert(?ETS_TABLE, {AccessToken, Context}),
    ok.

resolve_access_code(AccessCode) ->
    resolve_access_token(AccessCode).

resolve_refresh_token(RefreshToken) ->
    resolve_access_token(RefreshToken).

resolve_access_token(AccessToken) ->
    case ets:lookup(?ETS_TABLE, AccessToken) of
        [] ->
            {error, notfound};
        [{_, Context}] ->
            {ok, Context}
    end.

revoke_access_code(AccessCode) ->
    revoke_access_token(AccessCode).

revoke_access_token(AccessToken) ->
    ets:delete(?ETS_TABLE, AccessToken),
    ok.

revoke_refresh_token(_RefreshToken) ->
    ok.

get_redirection_uri(?CLIENT_ID) ->
    {ok, ?CLIENT_URI};
get_redirection_uri(_) ->
    {error, notfound}.

verify_redirection_uri({client, 4711}, ?CLIENT_URI) ->
    ok;
verify_redirection_uri(_, _) ->
    {error, mismatch}.

verify_client_scope({client, 4711}, []) ->
    {ok, []};
verify_client_scope({client, 4711}, ?CLIENT_SCOPE) ->
    {ok, ?CLIENT_SCOPE};
verify_client_scope(_, _) ->
    {error, invalid_scope}.

verify_resowner_scope({user, 31337}, ?USER_SCOPE) ->
    {ok, ?USER_SCOPE};
verify_resowner_scope(_, _) ->
    {error, invalid_scope}.

start() ->
    %% Set up the ETS table for holding access tokens.
    ets:new(?ETS_TABLE, [public, named_table, {read_concurrency, true}]).

stop() ->
    ets:delete(?ETS_TABLE).
