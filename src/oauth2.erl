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

-module(oauth2).

%%% API
-export([
         authorize_password/3
         ,authorize_client_credentials/3
         ,verify_access_token/1
         ,verify_redirection_uri/2
        ]).

%%% Internal types
-type proplist(TyKey, TyVal) :: [{TyKey, TyVal}].

%%% Exported types
-type token()    :: binary().
-type lifetime() :: non_neg_integer().
-type scope()    :: binary().
-type error()    :: invalid_request | unauthorized_client
                  | access_denied | unsupported_response_type
                  | invalid_scope | server_error
                  | temporarily_unavailable.

-export_type([
              token/0
              ,lifetime/0
              ,scope/0
              ,error/0
             ]).

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
    case oauth2_backend:authenticate_username_password(Username, Password, Scope) of
        {ok, Identity} ->
            TTL = oauth2_config:expiry_time(password_credentials),
            Response = issue_token(Identity, Scope, TTL),
            {ok, Identity, Response};
        {error, _Reason} ->
            {error, access_denied}
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
    case oauth2_backend:authenticate_client(ClientId, ClientSecret, Scope) of
        {ok, Identity} ->
            %% NOTE: The OAuth2 draft dictates that no refresh token be issued here.
            TTL = oauth2_config:expiry_time(client_credentials),
            Response = issue_token(Identity, Scope, TTL),
            {ok, Identity, Response};
        {error, _Reason} ->
            {error, access_denied}
    end.

%% @doc Verifies an access token AccessToken, returning its associated
%% context if successful. Otherwise, an OAuth2 error code is returned.
%% @end
-spec verify_access_token(AccessToken) -> {ok, Context} | {error, Reason} when
      AccessToken :: token(),
      Context     :: proplist(atom(), term()),
      Reason      :: error().
verify_access_token(AccessToken) ->
    case oauth2_backend:resolve_access_token(AccessToken) of
        {ok, Context} ->
            ExpiryAbsolute = proplists:get_value(expiry_time, Context),
            case ExpiryAbsolute > seconds_since_epoch(0) of
                true ->
                    {ok, Context};
                false ->
                    oauth2_backend:revoke_access_token(AccessToken),
                    {error, access_denied}
            end;
        _ ->
            {error, access_denied}
    end.

%% @doc Verifies that RedirectionUri matches the redirection URI registered
%% for the client identified by ClientId.
%% @end
-spec verify_redirection_uri(ClientId, RedirectionUri) -> Result when
      ClientId       :: binary(),
      RedirectionUri :: binary(),
      Result         :: ok | {error, Reason :: term()}.
verify_redirection_uri(ClientId, RedirectionUri) ->
    case oauth2_backend:get_redirection_uri(ClientId) of
        {ok, RedirectionUri} ->
            ok;
        {ok, _OtherUri} ->
            {error, mismatch};
        Error = {error, _} ->
            Error
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec issue_token(Identity, Scope, TTL) -> oauth2_response:response() when
      Identity :: term(),
      Scope    :: scope(),
      TTL      :: non_neg_integer().
issue_token(Identity, Scope, TTL) ->
    AccessToken = oauth2_token:generate(),
    ExpiryAbsolute = seconds_since_epoch(TTL),
    Context = build_context(Identity, ExpiryAbsolute, Scope),
    oauth2_backend:associate_access_token(AccessToken, Context),
    oauth2_response:new(AccessToken, TTL, Scope).

-spec build_context(Identity, ExpiryTime, Scope) -> Context when
      Identity   :: term(),
      ExpiryTime :: non_neg_integer(),
      Scope      :: scope(),
      Context    :: proplist(binary(), term()).
build_context(Identity, ExpiryTime, Scope) ->
    [{<<"identity">>, Identity},
     {<<"expiry_time">>, list_to_binary(integer_to_list(ExpiryTime))},
     {<<"scope">>, Scope}].

-spec seconds_since_epoch(Diff :: integer()) -> non_neg_integer().
seconds_since_epoch(Diff) ->
    {Mega, Secs, _Micro} = now(),
    Mega * 1000000 + Secs + Diff.
