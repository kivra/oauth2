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
-export([authorize_password/4]).
-export([authorize_client_credentials/4]).
-export([authorize_code_grant/5]).
-export([authorize_code_request/6]).
-export([issue_code/2]).
-export([issue_token/2]).
-export([issue_token_and_refresh/2]).
-export([verify_access_token/2]).
-export([verify_access_code/2]).
-export([verify_access_code/3]).
-export([refresh_access_token/5]).

%%% Exported types
-type context()  :: proplists:proplist(binary(), term()).
-type token()    :: binary().
-type lifetime() :: non_neg_integer().
-type scope()    :: list(binary()) | binary().
-type error()    :: access_denied | invalid_client | invalid_grant |
                    invalid_request | invalid_scope | unauthorized_client |
                    unsupported_response_type | server_error |
                    temporarily_unavailable.

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

%% @doc Authorizes a resource owner's credentials. Useful for 
%% Resource Owner Password Credentials Grant and Implicit Grant.
-spec authorize_password(Username, Password, Scope, AppContext)
                        -> {ok, Authorization} | {error, Reason} when
      Username      :: binary(),
      Password      :: binary(),
      Scope         :: scope(),
      AppContext    :: term(),
      Authorization :: #authorization{},
      Reason        :: error().
authorize_password(Username, Password, Scope, AppContext) ->
    case ?BACKEND:authenticate_username_password(Username, Password, 
                                                 AppContext) of
        {ok, ResOwner} ->
            case ?BACKEND:verify_resowner_scope(ResOwner, Scope, AppContext) of
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
-spec authorize_client_credentials(ClientId, ClientSecret, Scope, AppContext)
                                  -> {ok, Authorization}
                                   | {error, Reason} when
      ClientId      :: binary(),
      ClientSecret  :: binary(),
      Scope         :: scope(),
      AppContext    :: term(),
      Authorization :: #authorization{},
      Reason        :: error().
authorize_client_credentials(ClientId, ClientSecret, Scope, AppContext) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret, AppContext) of
        {ok, Client} ->
            case ?BACKEND:verify_client_scope(Client, Scope, AppContext) of
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
-spec authorize_code_grant(ClientId, ClientSecret, AccessCode, RedirectionUri,
                           AppContext)
                                  -> {ok, Authorization}
                                   | {error, Reason} when
      ClientId          :: binary(),
      ClientSecret      :: binary(),
      AccessCode        :: token(),
      RedirectionUri    :: binary(),
      AppContext        :: term(),
      Authorization     :: #authorization{},
      Reason            :: error().
authorize_code_grant(ClientId, ClientSecret, AccessCode, RedirectionUri,
                     AppContext) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret, AppContext) of
        {ok, Client} ->
            case ?BACKEND:verify_redirection_uri(Client, RedirectionUri, 
                                                 AppContext) of
                ok ->
                    case verify_access_code(AccessCode, Client) of
                        {ok, GrantContext} ->
                            TTL = oauth2_config:expiry_time(
                                    password_credentials),
                            {_, Scope} = lists:keyfind(<<"scope">>, 1, 
                                                       GrantContext),
                            {_, ResOwner} = lists:keyfind(<<"resource_owner">>,
                                                          1, GrantContext),
                            ?BACKEND:revoke_access_code(AccessCode, AppContext),
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
-spec authorize_code_request(ClientId, RedirectionUri, Username, Password, 
                             Scope, AppContext)
                       -> {ok, Authorization} | {error, Reason} when
      ClientId          :: binary(),
      RedirectionUri    :: scope(),
      Username          :: binary(),
      Password          :: binary(),
      Scope             :: scope(),
      AppContext        :: term(),
      Authorization     :: #authorization{},
      Reason            :: error().
authorize_code_request(ClientId, RedirectionUri, Username, Password, Scope,
                       AppContext) ->
    case ?BACKEND:get_client_identity(ClientId, AppContext) of
        {ok, Client} ->
            case ?BACKEND:verify_redirection_uri(Client, RedirectionUri, 
                                                 AppContext) of
                ok ->
                    case ?BACKEND:verify_client_scope(Client, Scope, 
                                                      AppContext) of
                        {ok, VerifiedScope} ->
                            case ?BACKEND:authenticate_username_password(
                                   Username, Password, AppContext) of
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

-spec issue_code(Authorization, AppContext) -> Response when
      Authorization :: #authorization{},
      AppContext    :: term(),
      Response      :: oauth2_response:response().
issue_code(#authorization{client = Client, resowner = ResOwner,
                           scope = Scope, ttl = TTL}, AppContext) ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    GrantContext = build_context(Client, ExpiryAbsolute, ResOwner, Scope),
    AccessCode = ?TOKEN:generate(GrantContext),
    ok = ?BACKEND:associate_access_code(AccessCode, GrantContext, AppContext),
    oauth2_response:new(<<>>, TTL, ResOwner, Scope, <<>>, AccessCode).

-spec issue_token(Authorization, AppContext) -> Response when
      Authorization :: #authorization{},
      AppContext    :: term(),
      Response      :: oauth2_response:response().
issue_token(#authorization{client = Client, resowner = ResOwner,
                           scope = Scope, ttl = TTL}, AppContext) ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    GrantContext = build_context(Client, ExpiryAbsolute, ResOwner, Scope),
    AccessToken = ?TOKEN:generate(GrantContext),
    ok = ?BACKEND:associate_access_token(AccessToken, GrantContext,
                                         AppContext),
    oauth2_response:new(AccessToken, TTL, ResOwner, Scope).

%% @doc Issue an Access Token and a Refresh Token.
%% The OAuth2 specification forbids or discourages issuing a refresh token
%% when no resource owner is authenticated (See 4.2.2 and 4.4.3)
-spec issue_token_and_refresh(Authorization, AppContext) -> Response when
      Authorization :: #authorization{resowner :: term()},
      AppContext    :: term(),
      Response      :: oauth2_response:response().
issue_token_and_refresh(#authorization{client = Client, resowner = ResOwner,
                                       scope = Scope, ttl = TTL}, AppContext)
                                       when ResOwner /= undefined ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    GrantContext = build_context(Client, ExpiryAbsolute, ResOwner, Scope),
    AccessToken = ?TOKEN:generate(GrantContext),
    RefreshToken = ?TOKEN:generate(GrantContext),
    ok = ?BACKEND:associate_access_token(AccessToken, GrantContext,
                                         AppContext),
    ok = ?BACKEND:associate_refresh_token(RefreshToken, GrantContext,
                                          AppContext),
    oauth2_response:new(AccessToken, TTL, ResOwner, Scope, RefreshToken).

%% @doc Verifies an access code AccessCode, returning its associated
%% context if successful. Otherwise, an OAuth2 error code is returned.
-spec verify_access_code(AccessCode, AppContext) ->
          {ok, GrantContext} | {error, Reason} when
      AccessCode    :: token(),
      AppContext    :: term(),
      GrantContext  :: context(),
      Reason        :: error().
verify_access_code(AccessCode, AppContext) ->
    case ?BACKEND:resolve_access_code(AccessCode, AppContext) of
        {ok, GrantContext} ->
            {_, ExpiryAbsolute} = lists:keyfind(<<"expiry_time">>, 1,
                                                GrantContext),
            case ExpiryAbsolute > seconds_since_epoch(0) of
                true ->
                    {ok, GrantContext};
                false ->
                    ?BACKEND:revoke_access_code(AccessCode, AppContext),
                    {error, invalid_grant}
            end;
        _ ->
            {error, invalid_grant}
    end.

%% @doc Verifies an access code AccessCode and it's corresponding Identity,
%% returning its associated context if successful. Otherwise, an OAuth2
%% error code is returned.
-spec verify_access_code(AccessCode, Client, AppContext) -> {ok, GrantContext}
                                              | {error, Reason} when
      AccessCode    :: token(),
      Client        :: term(),
      AppContext    :: term(),
      GrantContext  :: context(),
      Reason        :: error().
verify_access_code(AccessCode, Client, AppContext) ->
    case verify_access_code(AccessCode, AppContext) of
        {ok, GrantContext} ->
            case lists:keyfind(<<"client">>, 1, GrantContext) of
                {_, Client} -> {ok, GrantContext};
                _ -> {error, invalid_grant}
            end;
        Error -> Error
    end.

%% @doc Verifies an refresh token RefreshToken, returning a new Access Token
%% if successful. Otherwise, an OAuth2 error code is returned.
-spec refresh_access_token(ClientId, ClientSecret, RefreshToken, Scope,
                           AppContext)
                                       -> {ok, Client, Response}
                                        | {error, Reason} when
      ClientId      :: binary(),
      ClientSecret  :: binary(),
      RefreshToken  :: token(),
      Scope         :: scope(),
      AppContext    :: term(),
      Client        :: term(),
      Response      :: oauth2_response:response(),
      Reason        :: error().
refresh_access_token(ClientId, ClientSecret, RefreshToken, Scope, AppContext) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret, AppContext) of
        {ok, Client} ->
            case ?BACKEND:resolve_refresh_token(RefreshToken, AppContext) of
                {ok, GrantContext} ->
                    {_, ExpiryAbsolute} = lists:keyfind(<<"expiry_time">>, 1, 
                                                        GrantContext),
                    case ExpiryAbsolute > seconds_since_epoch(0) of
                        true ->
                            {_, Client} = lists:keyfind(<<"client">>, 1, 
                                                        GrantContext),
                            {_, RegisteredScope} = lists:keyfind(<<"scope">>, 1,
                                                                 GrantContext),
                            case ?BACKEND:verify_scope(RegisteredScope, 
                                                       Scope, AppContext) of
                                {ok, VerifiedScope} ->
                                    {_, ResOwner} = lists:keyfind(
                                                      <<"resource_owner">>, 1, 
                                                      GrantContext),
                                    TTL = oauth2_config:expiry_time(
                                            password_credentials),
                                    Response = issue_token(
                                                 #authorization{
                                                   client = Client,
                                                   resowner = ResOwner,
                                                   scope = VerifiedScope,
                                                   ttl = TTL}, AppContext),
                                    {ok, Client, Response};
                                {error, _Reason} ->
                                    {error, invalid_scope}
                            end;
                        false ->
                            ?BACKEND:revoke_refresh_token(RefreshToken, 
                                                          AppContext),
                            {error, invalid_grant}
                    end;
                _ ->
                    {error, invalid_grant}
            end;
        _ -> {error, invalid_client}
    end.

%% @doc Verifies an access token AccessToken, returning its associated
%% context if successful. Otherwise, an OAuth2 error code is returned.
-spec verify_access_token(AccessToken, AppContext) ->
          {ok, GrantContext} | {error, Reason} when
      AccessToken   :: token(),
      AppContext    :: term(),
      GrantContext  :: context(),
      Reason        :: error().
verify_access_token(AccessToken, AppContext) ->
    case ?BACKEND:resolve_access_token(AccessToken, AppContext) of
        {ok, GrantContext} ->
            {_, ExpiryAbsolute} = lists:keyfind(<<"expiry_time">>, 1,
                                                GrantContext),
            case ExpiryAbsolute > seconds_since_epoch(0) of
                true ->
                    {ok, GrantContext};
                false ->
                    ?BACKEND:revoke_access_token(AccessToken, AppContext),
                    {error, access_denied}
            end;
        _ ->
            {error, access_denied}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec build_context(Client, ExpiryTime, ResOwner, Scope) -> GrantContext when
      Client        :: term(),
      ExpiryTime    :: non_neg_integer(),
      ResOwner      :: term(),
      Scope         :: scope(),
      GrantContext  :: context().
build_context(Client, ExpiryTime, ResOwner, Scope) ->
    [{<<"client">>, Client},
     {<<"resource_owner">>, ResOwner},
     {<<"expiry_time">>, list_to_binary(integer_to_list(ExpiryTime))},
     {<<"scope">>, Scope}].

-spec seconds_since_epoch(Diff :: integer()) -> non_neg_integer().
seconds_since_epoch(Diff) ->
    {Mega, Secs, _Micro} = now(),
    Mega * 1000000 + Secs + Diff.
