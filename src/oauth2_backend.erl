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

-module(oauth2_backend).

%%% API
-export([
         authenticate_username_password/3
         ,authenticate_client/3
         ,associate_access_token/2
         ,associate_refresh_token/2
         ,associate_access_code/2
         ,resolve_access_token/1
         ,resolve_access_code/1
         ,resolve_refresh_token/1
         ,revoke_access_token/1
         ,revoke_access_code/1
         ,revoke_refresh_token/1
         ,get_redirection_uri/1
         ,get_client_identity/2
         ,verify_redirection_uri/2
        ]).

-type proplist(Key, Val) :: [{Key, Val}].

-define(BACKEND, (oauth2_config:backend())).

%%%===================================================================
%%% API functions
%%%===================================================================

%% @doc Authenticates a combination of username, password and scope.
%% Returns true if the user's credentials are valid and all items
%% in scope are within the user's privileges to grant.
%% @end
-spec authenticate_username_password(Username, Password, Scope)
                                    -> {ok, Identity, NewScope} | {error, Reason} when
      Username :: binary(),
      Password :: binary(),
      Scope    :: oauth2:scope(),
      Identity :: term(),
      NewScope :: binary(),
      Reason   :: notfound | badpass | badscope.
authenticate_username_password(Username, Password, Scope) ->
    ?BACKEND:authenticate_username_password(Username, Password, Scope).

%% @doc Authenticates a client's credentials for a given scope.
-spec authenticate_client(ClientId, ClientSecret, Scope) -> {ok, Identity, NewScope} |
                                                            {error, Reason} when
      ClientId     :: binary(),
      ClientSecret :: binary(),
      Scope        :: oauth2:scope(),
      Identity     :: term(),
      NewScope     :: binary(),
      Reason       :: notfound | badsecret | badscope.
authenticate_client(ClientId, ClientSecret, Scope) ->
    ?BACKEND:authenticate_client(ClientId, ClientSecret, Scope).

%% @doc Stores a new access code AccessCode, associating it with Context.
%% The context is a proplist carrying information about the identity
%% with which the code is associated, when it expires, etc.
%% @end
-spec associate_access_code(AccessCode, Context) -> ok | {error, Reason} when
      AccessCode  :: oauth2:token(),
      Context     :: proplist(atom(), term()),
      Reason      :: notfound.
associate_access_code(AccessCode, Context) ->
    ?BACKEND:associate_access_code(AccessCode, Context).

%% @doc Stores a new access token AccessToken, associating it with Context.
%% The context is a proplist carrying information about the identity
%% with which the token is associated, when it expires, etc.
%% @end
-spec associate_access_token(AccessToken, Context) -> ok | {error, Reason} when
      AccessToken :: oauth2:token(),
      Context     :: proplist(atom(), term()),
      Reason      :: notfound.
associate_access_token(AccessToken, Context) ->
    ?BACKEND:associate_access_token(AccessToken, Context).

%% @doc Stores a new refresh token RefreshToken, associating it with Context.
%% The context is a proplist carrying information about the identity
%% with which the token is associated, when it expires, etc.
%% @end
-spec associate_refresh_token(RefreshToken, Context) -> ok | {error, Reason} when
      RefreshToken :: oauth2:token(),
      Context      :: proplist(atom(), term()),
      Reason       :: notfound.
associate_refresh_token(RefreshToken, Context) ->
    ?BACKEND:associate_refresh_token(RefreshToken, Context).

%% @doc Looks up an access token AccessToken, returning the corresponding
%% context if a match is found.
%% @end
-spec resolve_access_token(AccessToken) -> {ok, Context} | {error, Reason} when
      AccessToken :: oauth2:token(),
      Context     :: proplist(atom(), term()),
      Reason      :: notfound.
resolve_access_token(AccessToken) ->
    ?BACKEND:resolve_access_token(AccessToken).

%% @doc Looks up an access code AccessCode, returning the corresponding
%% context if a match is found.
%% @end
-spec resolve_access_code(AccessCode) -> {ok, Context} | {error, Reason} when
      AccessCode  :: oauth2:token(),
      Context     :: proplist(atom(), term()),
      Reason      :: notfound.
resolve_access_code(AccessCode) ->
    ?BACKEND:resolve_access_code(AccessCode).

%% @doc Looks up an refresh token RefreshToken, returning the corresponding
%% context if a match is found.
%% @end
-spec resolve_refresh_token(RefreshToken) -> {ok, Context} | {error, Reason} when
      RefreshToken :: oauth2:token(),
      Context      :: proplist(atom(), term()),
      Reason       :: notfound.
resolve_refresh_token(RefreshToken) ->
    ?BACKEND:resolve_refresh_token(RefreshToken).

%% @doc Revokes an access token AccessToken, so that it cannot be used again.
-spec revoke_access_token(AccessToken) -> ok | {error, Reason} when
      AccessToken :: oauth2:token(),
      Reason      :: notfound.
revoke_access_token(AccessToken) ->
    ?BACKEND:revoke_access_token(AccessToken).

%% @doc Revokes an access code AccessCode, so that it cannot be used again.
-spec revoke_access_code(AccessCode) -> ok | {error, Reason} when
      AccessCode  :: oauth2:token(),
      Reason      :: notfound.
revoke_access_code(AccessCode) ->
    ?BACKEND:revoke_access_code(AccessCode).

%% @doc Revokes an refresh token RefreshToken, so that it cannot be used again.
-spec revoke_refresh_token(RefreshToken) -> ok | {error, Reason} when
      RefreshToken :: oauth2:token(),
      Reason       :: notfound.
revoke_refresh_token(RefreshToken) ->
    ?BACKEND:revoke_refresh_token(RefreshToken).

%% @doc Returns the redirection URI associated with the client ClientId.
-spec get_redirection_uri(ClientId) -> Result when
      ClientId :: binary(),
      Result   :: {error, Reason :: term()} | {ok, RedirectionUri :: binary()}.
get_redirection_uri(ClientId) ->
    ?BACKEND:get_redirection_uri(ClientId).

%% @doc Returns a client identity for a given id and scope.
-spec get_client_identity(ClientId, Scope) -> {ok, Identity, NewScope} |
                                                  {error, Reason} when
      ClientId     :: binary(),
      Scope        :: oauth2:scope(),
      Identity     :: term(),
      NewScope     :: binary(),
      Reason       :: notfound | badsecret | badscope.
get_client_identity(ClientId, Scope) ->
    ?BACKEND:get_identity(ClientId, Scope).

%% @doc Verifies that RedirectionUri matches the redirection URI registered
%% for the client identified by ClientId.
%% @end
-spec verify_redirection_uri(Identity, RedirectionUri) -> Result when
      Identity       :: term(),
      RedirectionUri :: binary(),
      Result         :: ok | {error, Reason :: term()}.
verify_redirection_uri(Identity, RedirectionUri) ->
    ?BACKEND:verify_redirection_uri(Identity, RedirectionUri).
