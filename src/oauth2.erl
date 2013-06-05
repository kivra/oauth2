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

-module(oauth2).

%%% API
-export([authorize_password/3]).
-export([authorize_client_credentials/3]).
-export([authorize_code_grant/4]).
-export([authorize_code_request/5]).
-export([issue_code/1]).
-export([issue_token/1]).
-export([issue_token_and_refresh/1]).
-export([verify_access_token/1]).
-export([verify_access_code/1]).
-export([verify_access_code/2]).
-export([refresh_access_token/3]).

%%% Exported types
-type context()  :: proplists:proplist(binary(), term()).
-type token()    :: binary().
-type lifetime() :: non_neg_integer().
-type scope()    :: list(binary()) | binary().
-type error()    :: access_denied | invalid_client | invalid_request
                  | invalid_scope | unauthorized_client
                  | unsupported_response_type | server_error
                  | temporarily_unavailable.

-export_type([
              token/0
              ,context/0
              ,lifetime/0
              ,scope/0
              ,error/0
             ]).

%%% Defines
-define(BACKEND, (oauth2_config:backend())).
-define(TOKEN, (oauth2_config:token_generation())).

%%% Internal types
-record(authorization, {
                        client = undefined      :: undefined | term(),
                        resowner = undefined    :: undefined | term(),
                        scope                   :: scope(),
                        ttl = 0                 :: non_neg_integer()
                       }).

%%%===================================================================
%%% API functions
%%%===================================================================

%% @doc Authorizes a client via Resource Owner Password Credentials.
-spec authorize_password(Username, Password, Scope)
                        -> {ok, Authorization} | {error, Reason} when
      Username      :: binary(),
      Password      :: binary(),
      Scope         :: scope(),
      Authorization :: #authorization{},
      Reason        :: error().
authorize_password(Username, Password, Scope) ->
    case ?BACKEND:authenticate_username_password(Username, Password) of
        {ok, ResOwner} ->
            case ?BACKEND:verify_resowner_scope(ResOwner, Scope) of
                {ok, Scope2} ->
                    TTL = oauth2_config:expiry_time(password_credentials),
                    {ok, #authorization{resowner = ResOwner, scope = Scope2,
                                        ttl = TTL}};
                {error, _Reason} ->
                    {error, invalid_scope}
            end;
        {error, _Reason} ->
            {error, access_denied}
    end.

%% @doc Authorize client via its own credentials, i.e., a combination
%% of a public client identifier and a shared client secret.
%% Should only be used for confidential clients; see the OAuth2 draft
%% for clarification.
-spec authorize_client_credentials(ClientId, ClientSecret, Scope)
                                  -> {ok, Authorization}
                                   | {error, Reason} when
      ClientId      :: binary(),
      ClientSecret  :: binary(),
      Scope         :: scope(),
      Authorization :: #authorization{},
      Reason        :: error().
authorize_client_credentials(ClientId, ClientSecret, Scope) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret) of
        {ok, Client} ->
            case ?BACKEND:verify_client_scope(Client, Scope) of
                {ok, Scope2} ->
                    TTL = oauth2_config:expiry_time(client_credentials),
                    {ok, #authorization{client = Client, scope = Scope2,
                                        ttl = TTL}};
                {error, _Reason} ->
                    {error, invalid_scope}
            end;
        {error, _Reason} ->
            {error, invalid_client}
    end.

%% @doc Authorize client via its own credentials, i.e., a combination
%% of a public client identifier and a shared client secret.
%% Should only be used for confidential clients; see the OAuth2 draft
%% for clarification.
%%
%% Then verify the supplied RedirectionUri and Code and if valid issue
%% an Access Token and an optional Refresh Token
-spec authorize_code_grant(ClientId, ClientSecret, AccessCode, RedirectionUri)
                                  -> {ok, Authorization}
                                   | {error, Reason} when
      ClientId       :: binary(),
      ClientSecret   :: binary(),
      AccessCode     :: token(),
      RedirectionUri :: binary(),
      Authorization  :: #authorization{},
      Reason         :: error().
authorize_code_grant(ClientId, ClientSecret, AccessCode, RedirectionUri) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret) of
        {ok, Client} ->
            case ?BACKEND:verify_redirection_uri(Client, RedirectionUri) of
                ok ->
                    case verify_access_code(AccessCode, Client) of
                        {ok, Context} ->
                            TTL = oauth2_config:expiry_time(password_credentials),
                            {_, Scope} = lists:keyfind(<<"scope">>, 1, Context),
                            {_, ResOwner} = lists:keyfind(<<"resource_owner">>,
                                                          1, Context),
                            ?BACKEND:revoke_access_code(AccessCode),
                            {ok, #authorization{client = Client,
                                                resowner = ResOwner,
                                                scope = Scope,
                                                ttl = TTL}};
                        Error ->
                            Error
                    end;
                _ ->
                    {error, invalid_grant}
            end;
        {error, _Reason} ->
            {error, invalid_client}
    end.

%% @doc Issue a Code via Access Code Grant
-spec authorize_code_request( ClientId, RedirectionUri
                            , Username, Password, Scope )
                       -> {ok, Authorization} | {error, Reason} when
      ClientId          :: binary(),
      RedirectionUri    :: scope(),
      Username          :: binary(),
      Password          :: binary(),
      Scope             :: scope(),
      Authorization     :: #authorization{},
      Reason            :: error().
authorize_code_request(ClientId, RedirectionUri, Username, Password, Scope) ->
    case ?BACKEND:get_client_identity(ClientId) of
        {ok, Client} ->
            case ?BACKEND:verify_redirection_uri(Client, RedirectionUri) of
                ok ->
                    case ?BACKEND:verify_client_scope(Client, Scope) of
                        {ok, VerifiedScope} ->
                            case ?BACKEND:authenticate_username_password(
                                   Username, Password) of
                                {ok, ResOwner} ->
                                    TTL = oauth2_config:expiry_time(code_grant),
                                    {ok, #authorization{client = Client,
                                                        resowner = ResOwner,
                                                        scope = VerifiedScope,
                                                        ttl = TTL}};
                                {error, _Reason} ->
                                    {error, access_denied}
                            end;
                        {error, _Reason} ->
                            {error, invalid_scope}
                    end;
                _ ->
                    {error, unauthorized_client}
            end;
        {error, _Reason} ->
            {error, unauthorized_client}
    end.

-spec issue_code(Authorization) -> Response when
      Authorization :: #authorization{},
      Response :: oauth2_response:response().
issue_code(#authorization{client = Client, resowner = ResOwner,
                           scope = Scope, ttl = TTL}) ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    Context = build_context(Client, ExpiryAbsolute, ResOwner, Scope),
    AccessCode = ?TOKEN:generate(Context),
    ok = ?BACKEND:associate_access_code(AccessCode, Context),
    oauth2_response:new(<<>>, TTL, ResOwner, Scope, <<>>, AccessCode).

-spec issue_token(Authorization) -> Response when
      Authorization :: #authorization{},
      Response :: oauth2_response:response().
issue_token(#authorization{client = Client, resowner = ResOwner,
                           scope = Scope, ttl = TTL}) ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    Context = build_context(Client, ExpiryAbsolute, ResOwner, Scope),
    AccessToken = ?TOKEN:generate(Context),
    ok = ?BACKEND:associate_access_token(AccessToken, Context),
    oauth2_response:new(AccessToken, TTL, ResOwner, Scope).

%% @doc Issue an Access Token and a Refresh Token.
%% The OAuth2 specification forbids or discourages issuing a refresh token
%% when no resource owner is authenticated (See 4.2.2 and 4.4.3)
-spec issue_token_and_refresh(Authorization) -> Response when
      Authorization :: #authorization{resowner :: term()},
      Response :: oauth2_response:response().
issue_token_and_refresh(#authorization{client = Client, resowner = ResOwner,
                                       scope = Scope, ttl = TTL})
                                       when ResOwner /= undefined ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    Context = build_context(Client, ExpiryAbsolute, ResOwner, Scope),
    AccessToken = ?TOKEN:generate(Context),
    RefreshToken = ?TOKEN:generate(Context),
    ok = ?BACKEND:associate_access_token(AccessToken, Context),
    ok = ?BACKEND:associate_refresh_token(RefreshToken, Context),
    oauth2_response:new(AccessToken, TTL, ResOwner, Scope, RefreshToken).

%% @doc Verifies an access code AccessCode, returning its associated
%% context if successful. Otherwise, an OAuth2 error code is returned.
-spec verify_access_code(AccessCode) -> {ok, Context} | {error, Reason} when
      AccessCode  :: token(),
      Context     :: context(),
      Reason      :: error().
verify_access_code(AccessCode) ->
    case ?BACKEND:resolve_access_code(AccessCode) of
        {ok, Context} ->
            {_, ExpiryAbsolute} = lists:keyfind(<<"expiry_time">>, 1, Context),
            case ExpiryAbsolute > seconds_since_epoch(0) of
                true ->
                    {ok, Context};
                false ->
                    ?BACKEND:revoke_access_code(AccessCode),
                    {error, invalid_grant}
            end;
        _ ->
            {error, invalid_grant}
    end.

%% @doc Verifies an access code AccessCode and it's corresponding Identity,
%% returning its associated context if successful. Otherwise, an OAuth2
%% error code is returned.
-spec verify_access_code(AccessCode, Client) -> {ok, Context}
                                              | {error, Reason} when
      AccessCode  :: token(),
      Client      :: term(),
      Context     :: context(),
      Reason      :: error().
verify_access_code(AccessCode, Client) ->
    case verify_access_code(AccessCode) of
        {ok, Context} ->
            case lists:keyfind(<<"client">>, 1, Context) of
                {_, Client} -> {ok, Context};
                _ -> {error, invalid_grant}
            end;
        Error -> Error
    end.

%% @doc Verifies an refresh token RefreshToken, returning a new Access Token
%% if successful. Otherwise, an OAuth2 error code is returned.
-spec refresh_access_token(ClientId, ClientSecret, RefreshToken)
                                       -> {ok, Client, Response}
                                        | {error, Reason} when
      ClientId     :: binary(),
      ClientSecret :: binary(),
      RefreshToken :: token(),
      Client     :: term(),
      Response     :: oauth2_response:response(),
      Reason       :: error().
refresh_access_token(ClientId, ClientSecret, RefreshToken) ->
    case ?BACKEND:resolve_refresh_token(RefreshToken) of
        {ok, Context} ->
            {_, ExpiryAbsolute} = lists:keyfind(<<"expiry_time">>, 1, Context),
            case ExpiryAbsolute > seconds_since_epoch(0) of
                true ->
                    {_, Client} = lists:keyfind(<<"client">>, 1, Context),
                    case ?BACKEND:authenticate_client(ClientId, ClientSecret) of
                        {ok, Client} ->
                            {_, ResOwner} = lists:keyfind(<<"resource_owner">>, 1, Context),
                            {_, Scope} = lists:keyfind(<<"scope">>, 1, Context),
                            TTL = oauth2_config:expiry_time(password_credentials),
                            Response = issue_token(
                                         #authorization{client = Client,
                                                        resowner = ResOwner,
                                                        scope = Scope,
                                                        ttl = TTL}),
                            {ok, Client, Response};
                        _ -> {error, access_denied}
                    end;
                false ->
                    ?BACKEND:revoke_refresh_token(RefreshToken),
                    {error, access_denied}
            end;
        _ ->
            {error, access_denied}
    end.

%% @doc Verifies an access token AccessToken, returning its associated
%% context if successful. Otherwise, an OAuth2 error code is returned.
-spec verify_access_token(AccessToken) -> {ok, Context} | {error, Reason} when
      AccessToken :: token(),
      Context     :: context(),
      Reason      :: error().
verify_access_token(AccessToken) ->
    case ?BACKEND:resolve_access_token(AccessToken) of
        {ok, Context} ->
            {_, ExpiryAbsolute} = lists:keyfind(<<"expiry_time">>, 1, Context),
            case ExpiryAbsolute > seconds_since_epoch(0) of
                true ->
                    {ok, Context};
                false ->
                    ?BACKEND:revoke_access_token(AccessToken),
                    {error, access_denied}
            end;
        _ ->
            {error, access_denied}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec build_context(Client, ExpiryTime, ResOwner, Scope) -> Context when
      Client     :: term(),
      ExpiryTime :: non_neg_integer(),
      ResOwner   :: term(),
      Scope      :: scope(),
      Context    :: context().
build_context(Client, ExpiryTime, ResOwner, Scope) ->
    [{<<"client">>, Client},
     {<<"resource_owner">>, ResOwner},
     {<<"expiry_time">>, list_to_binary(integer_to_list(ExpiryTime))},
     {<<"scope">>, Scope}].

-spec seconds_since_epoch(Diff :: integer()) -> non_neg_integer().
seconds_since_epoch(Diff) ->
    {Mega, Secs, _Micro} = now(),
    Mega * 1000000 + Secs + Diff.
