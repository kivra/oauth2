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
-export([issue_code_grant/3]).
-export([issue_code_grant/4]).
-export([issue_code_grant/5]).
-export([verify_access_token/1]).
-export([verify_access_code/1]).
-export([verify_access_code/2]).
-export([refresh_access_token/3]).

%%% Exported types
-type context()  :: proplists:proplist(binary(), term()).
-type token()    :: binary().
-type lifetime() :: non_neg_integer().
-type scope()    :: list(binary()) | binary().
-type error()    :: invalid_request | unauthorized_client
                  | access_denied | unsupported_response_type
                  | invalid_scope | server_error
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

%%%===================================================================
%%% API functions
%%%===================================================================

%% @doc Authorizes a client via Resource Owner Password Credentials.
-spec authorize_password(Username, Password, Scope)
                        -> {ok, Identity, Response} | {error, Reason} when
      Username :: binary(),
      Password :: binary(),
      Scope    :: scope(),
      Identity :: term(),
      Response :: oauth2_response:response(),
      Reason   :: error().
authorize_password(Username, Password, Scope) ->
    case ?BACKEND:authenticate_username_password(Username, Password) of
        {ok, Identity} ->
            case ?BACKEND:verify_resowner_scope(Identity, Scope) of
                {ok, Scope2} ->
                    TTL = oauth2_config:expiry_time(password_credentials),
                    Response = issue_token(Identity, <<>>, Scope2, TTL),
                    {ok, Identity, Response};
                {error, _Reason} ->
                    {error, invalid_scope}
            end;
        {error, _Reason} ->
            {error, access_denied}
    end.

%% @doc Issue a Code via Access Code Grant
-spec issue_code_grant(ClientId, ResOwner, Scope)
                       -> {ok, Identity, Response} | {error, Reason} when
      ClientId       :: binary(),
      ResOwner       :: term(),
      Scope          :: scope(),
      Identity       :: term(),
      Response       :: oauth2_response:response(),
      Reason         :: error().
issue_code_grant(ClientId, ResOwner, Scope) ->
    case ?BACKEND:get_client_identity(ClientId) of
        {ok, Identity} ->
            TTL = oauth2_config:expiry_time(code_grant),
            Response = issue_code(Identity, Scope, ResOwner, TTL),
            {ok, Identity, Response};
        {error, _Reason} ->
            {error, invalid_client}
    end.

%% @doc Issue a Code via Access Code Grant
-spec issue_code_grant(ClientId, RedirectionUri, ResOwner, Scope)
                       -> {ok, Identity, Response} | {error, Reason} when
      ClientId       :: binary(),
      RedirectionUri :: scope(),
      ResOwner       :: term(),
      Scope          :: scope(),
      Identity       :: term(),
      Response       :: oauth2_response:response(),
      Reason         :: error().
issue_code_grant(ClientId, RedirectionUri, ResOwner, Scope) ->
    case ?BACKEND:get_client_identity(ClientId) of
        {ok, Identity} ->
            case ?BACKEND:verify_redirection_uri(Identity, RedirectionUri) of
                ok ->
                    TTL = oauth2_config:expiry_time(code_grant),
                    Response = issue_code(Identity, Scope, ResOwner, TTL),
                    {ok, Identity, Response};
                _ ->
                    {error, access_denied}
            end;
        {error, _Reason} ->
            {error, invalid_client}
    end.

%% @doc Issue a Code via Access Code Grant.
-spec issue_code_grant(ClientId, ClientSecret, RedirectionUri, ResOwner, Scope)
                       -> {ok, Identity, Response} | {error, Reason} when
      ClientId       :: binary(),
      ClientSecret   :: binary(),
      RedirectionUri :: scope(),
      ResOwner       :: term(),
      Scope          :: scope(),
      Identity       :: term(),
      Response       :: oauth2_response:response(),
      Reason         :: error().
issue_code_grant(ClientId, ClientSecret, RedirectionUri, ResOwner, Scope) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret) of
        {ok, Identity} ->
            case ?BACKEND:verify_redirection_uri(Identity, RedirectionUri) of
                ok ->
                    TTL = oauth2_config:expiry_time(code_grant),
                    Response = issue_code(Identity, Scope, ResOwner, TTL),
                    {ok, Identity, Response};
                _ ->
                    {error, access_denied}
            end;
        {error, _Reason} ->
            {error, unauthorized_client}
    end.

%% @doc Authorize client via its own credentials, i.e., a combination
%% of a public client identifier and a shared client secret.
%% Should only be used for confidential clients; see the OAuth2 draft
%% for clarification.
%%
%% Then verify the supplied RedirectionUri and Code and if valid issue
%% an Access Token and an optional Refresh Token
%% @end
-spec authorize_code_grant(ClientId, ClientSecret, AccessCode, RedirectionUri)
                                  -> {ok, Identity, Response}
                                   | {error, Reason} when
      ClientId       :: binary(),
      ClientSecret   :: binary(),
      AccessCode     :: token(),
      RedirectionUri :: binary(),
      Identity       :: term(),
      Response       :: oauth2_response:response(),
      Reason         :: error().
authorize_code_grant(ClientId, ClientSecret, AccessCode, RedirectionUri) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret) of
        {ok, Identity} ->
            case ?BACKEND:verify_redirection_uri(Identity, RedirectionUri) of
                ok ->
                    case verify_access_code(AccessCode, Identity) of
                        {ok, Context} ->
                            TTL = oauth2_config:expiry_time(password_credentials),
                            {_, Scope} = lists:keyfind(<<"scope">>, 1, Context),
                            {_, ResOwner} = lists:keyfind(<<"resource_owner">>,
                                                          1, Context),
                            Response = issue_token_and_refresh(Identity,
                                                               ResOwner,
                                                               Scope, TTL),
                            ?BACKEND:revoke_access_code(AccessCode),
                            {ok, Identity, Response};
                        Error ->
                            Error
                    end;
                _ ->
                    {error, invalid_grant}
            end;
        {error, _Reason} ->
            {error, invalid_client}
    end.

%% @doc Authorize client via its own credentials, i.e., a combination
%% of a public client identifier and a shared client secret.
%% Should only be used for confidential clients; see the OAuth2 draft
%% for clarification.
%% @end
-spec authorize_client_credentials(ClientId, ClientSecret, Scope)
                                  -> {ok, Identity, Response}
                                   | {error, Reason} when
      ClientId     :: binary(),
      ClientSecret :: binary(),
      Scope        :: scope(),
      Identity     :: term(),
      Response     :: oauth2_response:response(),
      Reason       :: error().
authorize_client_credentials(ClientId, ClientSecret, Scope) ->
    case ?BACKEND:authenticate_client(ClientId, ClientSecret) of
        {ok, Identity} ->
            case ?BACKEND:verify_client_scope(Identity, Scope) of
                {ok, Scope2} ->
                    %% NOTE: The OAuth2 draft dictates that no refresh token be issued here.
                    TTL = oauth2_config:expiry_time(client_credentials),
                    Response = issue_token(Identity, <<>>, Scope2, TTL),
                    {ok, Identity, Response};
                {error, _Reason} ->
                    {error, invalid_scope}
            end;
        {error, _Reason} ->
            {error, invalid_client}
    end.

%% @doc Verifies an access code AccessCode, returning its associated
%% context if successful. Otherwise, an OAuth2 error code is returned.
%% @end
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
%% @end
-spec verify_access_code(AccessCode, Identity) -> {ok, Context} | {error, Reason} when
      AccessCode  :: token(),
      Identity    :: term(),
      Context     :: context(),
      Reason      :: error().
verify_access_code(AccessCode, Identity) ->
    case verify_access_code(AccessCode) of
        {ok, Context} ->
            case lists:keyfind(<<"identity">>, 1, Context) of
                {_, Identity} -> {ok, Context};
                _ -> {error, invalid_grant}
            end;
        Error -> Error
    end.

%% @doc Verifies an refresh token RefreshToken, returning a new Access Token
%% if successful. Otherwise, an OAuth2 error code is returned.
%% @end
-spec refresh_access_token(ClientId, ClientSecret, RefreshToken)
                                       -> {ok, Identity, Response}
                                        | {error, Reason} when
      ClientId     :: binary(),
      ClientSecret :: binary(),
      RefreshToken :: token(),
      Identity     :: term(),
      Response     :: oauth2_response:response(),
      Reason       :: error().
refresh_access_token(ClientId, ClientSecret, RefreshToken) ->
    case ?BACKEND:resolve_refresh_token(RefreshToken) of
        {ok, Context} ->
            {_, ExpiryAbsolute} = lists:keyfind(<<"expiry_time">>, 1, Context),
            case ExpiryAbsolute > seconds_since_epoch(0) of
                true ->
                    {_, Identity} = lists:keyfind(<<"identity">>, 1, Context),
                    case ?BACKEND:authenticate_client(ClientId, ClientSecret) of
                        {ok, Identity} ->
                            {_, ResOwner} = lists:keyfind(<<"resource_owner">>, 1, Context),
                            {_, Scope} = lists:keyfind(<<"scope">>, 1, Context),
                            TTL = oauth2_config:expiry_time(password_credentials),
                            Response = issue_token(Identity, ResOwner, Scope, TTL),
                            {ok, Identity, Response};
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
%% @end
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

-spec issue_code(Identity, Scope, ResOwner, TTL) -> Response when
      Identity :: term(),
      Scope    :: scope(),
      ResOwner :: term(),
      TTL      :: non_neg_integer(),
      Response :: oauth2_response:response().
issue_code(Identity, Scope, ResOwner, TTL) ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    Context = build_context(Identity, ExpiryAbsolute, ResOwner, Scope),
    AccessCode = ?TOKEN:generate(Context),
    ok = ?BACKEND:associate_access_code(AccessCode, Context),
    oauth2_response:new(<<>>, TTL, ResOwner, Scope, <<>>, AccessCode).

-spec issue_token_and_refresh(Identity, ResOwner, Scope, TTL) -> Response when
      Identity :: term(),
      ResOwner :: term(),
      Scope    :: scope(),
      TTL      :: non_neg_integer(),
      Response :: oauth2_response:response().
issue_token_and_refresh(Identity, ResOwner, Scope, TTL) ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    Context = build_context(Identity, ExpiryAbsolute, ResOwner, Scope),
    AccessToken = ?TOKEN:generate(Context),
    RefreshToken = ?TOKEN:generate(Context),
    ok = ?BACKEND:associate_access_token(AccessToken, Context),
    ok = ?BACKEND:associate_refresh_token(RefreshToken, Context),
    oauth2_response:new(AccessToken, TTL, ResOwner, Scope, RefreshToken).

-spec issue_token(Identity, ResOwner, Scope, TTL) -> Response when
      Identity :: term(),
      ResOwner :: term(),
      Scope    :: scope(),
      TTL      :: non_neg_integer(),
      Response :: oauth2_response:response().
issue_token(Identity, ResOwner, Scope, TTL) ->
    ExpiryAbsolute = seconds_since_epoch(TTL),
    Context = build_context(Identity, ExpiryAbsolute, ResOwner, Scope),
    AccessToken = ?TOKEN:generate(Context),
    ok = ?BACKEND:associate_access_token(AccessToken, Context),
    oauth2_response:new(AccessToken, TTL, ResOwner, Scope).

-spec build_context(Identity, ExpiryTime, ResOwner, Scope) -> Context when
      Identity   :: term(),
      ExpiryTime :: non_neg_integer(),
      ResOwner   :: term(),
      Scope      :: scope(),
      Context    :: context().
build_context(Identity, ExpiryTime, ResOwner, Scope) ->
    [{<<"identity">>, Identity},
     {<<"resource_owner">>, ResOwner},
     {<<"expiry_time">>, list_to_binary(integer_to_list(ExpiryTime))},
     {<<"scope">>, Scope}].

-spec seconds_since_epoch(Diff :: integer()) -> non_neg_integer().
seconds_since_epoch(Diff) ->
    {Mega, Secs, _Micro} = now(),
    Mega * 1000000 + Secs + Diff.
