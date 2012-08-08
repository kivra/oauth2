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

-module(oauth2_example_backend).

%%% API
-export([
         start/0
         ,stop/0
         ,add_user/2
         ,delete_user/1
         ,add_client/2, add_client/3
         ,delete_client/1
        ]).

%%% OAuth2 backend functionality
-export([
         authenticate_username_password/3
         ,authenticate_client/3
         ,associate_access_token/2
         ,resolve_access_token/1
         ,get_redirection_uri/1
        ]).

-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(USER_TABLE, users).
-define(CLIENT_TABLE, clients).

-define(TABLES, [?ACCESS_TOKEN_TABLE,
                 ?USER_TABLE,
                 ?CLIENT_TABLE]).

-record(client, {
          client_id     :: binary(),
          client_secret :: binary(),
          redirect_uri  :: binary()
         }).

-record(user, {
          username :: binary(),
          password :: binary()
         }).

%%%===================================================================
%%% API
%%%===================================================================

start() ->
    lists:foreach(fun(Table) ->
                          ets:new(Table, [named_table, public])
                  end,
                  ?TABLES),
    oauth2_example_backend:add_client(<<"my_client">>,<<"ohai">>,<<"https://kivra.com">>),
    oauth2_example_backend:add_user(<<"martin">>,<<"ohai">>).

stop() ->
    lists:foreach(fun ets:delete/1, ?TABLES).

add_user(Username, Password) ->
    put(?USER_TABLE, Username, #user{username = Username, password = Password}).

delete_user(Username) ->
    delete(?USER_TABLE, Username).

add_client(Id, Secret, RedirectUri) ->
    put(?CLIENT_TABLE, Id, #client{client_id = Id,
                                   client_secret = Secret,
                                   redirect_uri = RedirectUri
                                  }).

add_client(Id, Secret) ->
    add_client(Id, Secret, undefined).

delete_client(Id) ->
    delete(?CLIENT_TABLE, Id).

%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

authenticate_username_password(Username, Password, _Scope) ->
    case get(?USER_TABLE, Username) of
        {ok, #user{password = UserPw}} ->
            case Password of
                UserPw ->
                    {ok, {<<"user">>, Username}};
                _ ->
                    {error, badpass}
            end;
        Error = {error, notfound} ->
            Error
    end.

authenticate_client(ClientId, ClientSecret, _Scope) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, #client{client_secret = ClientSecret}} ->
            {ok, {<<"client">>, ClientId}};
        {ok, #client{client_secret = _WrongSecret}} ->
            {error, badsecret};
        _ ->
            {error, notfound}
    end.

associate_access_token(AccessToken, Context) ->
    put(?ACCESS_TOKEN_TABLE, AccessToken, Context).

resolve_access_token(AccessToken) ->
    %% The case trickery is just here to make sure that
    %% we don't propagate errors that cannot be legally
    %% returned from this function according to the spec.
    case get(?ACCESS_TOKEN_TABLE, AccessToken) of
        Value = {ok, _} ->
            Value;
        Error = {error, notfound} ->
            Error
    end.

get_redirection_uri(ClientId) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, #client{redirect_uri = RedirectUri}} ->
            {ok, RedirectUri};
        Error = {error, notfound} ->
            Error
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            {error, notfound};
        [{_Key, Value}] ->
            {ok, Value}
    end.

put(Table, Key, Value) ->
    ets:insert(Table, {Key, Value}).

delete(Table, Key) ->
    ets:delete(Table, Key).
