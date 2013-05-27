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

-module(oauth2_backend).

%%%===================================================================
%%% API functions
%%%===================================================================

%% @doc Authenticates a combination of username and password.
%% Returns the resource owner identity if the credentials are valid.
%% @end
-callback authenticate_username_password(Username, Password) ->
                                {ok, Identity} | {error, Reason} when
      Username :: binary(),
      Password :: binary(),
      Identity :: term(),
      Reason   :: notfound | badpass.

%% @doc Authenticates a client's credentials for a given scope.
-callback authenticate_client(ClientId, ClientSecret) ->
                                {ok, Identity} | {error, Reason} when
      ClientId     :: binary(),
      ClientSecret :: binary(),
      Identity     :: term(),
      Reason       :: notfound | badsecret.

%% @doc Stores a new access code AccessCode, associating it with Context.
%% The context is a proplist carrying information about the identity
%% with which the code is associated, when it expires, etc.
%% @end
-callback associate_access_code(AccessCode, Context) ->
                                                      ok | {error, Reason} when
      AccessCode  :: oauth2:token(),
      Context     :: oauth2:context(),
      Reason      :: notfound.

%% @doc Stores a new access token AccessToken, associating it with Context.
%% The context is a proplist carrying information about the identity
%% with which the token is associated, when it expires, etc.
%% @end
-callback associate_access_token(AccessToken, Context) ->
                                                      ok | {error, Reason} when
      AccessToken :: oauth2:token(),
      Context     :: oauth2:context(),
      Reason      :: notfound.

%% @doc Stores a new refresh token RefreshToken, associating it with Context.
%% The context is a proplist carrying information about the identity
%% with which the token is associated, when it expires, etc.
%% @end
-callback associate_refresh_token(RefreshToken, Context) ->
                                                      ok | {error, Reason} when
      RefreshToken :: oauth2:token(),
      Context      :: oauth2:context(),
      Reason       :: notfound.

%% @doc Looks up an access token AccessToken, returning the corresponding
%% context if a match is found.
%% @end
-callback resolve_access_token(AccessToken) ->
                                           {ok, Context} | {error, Reason} when
      AccessToken :: oauth2:token(),
      Context     :: oauth2:context(),
      Reason      :: notfound.

%% @doc Looks up an access code AccessCode, returning the corresponding
%% context if a match is found.
%% @end
-callback resolve_access_code(AccessCode) ->
                                           {ok, Context} | {error, Reason} when
      AccessCode  :: oauth2:token(),
      Context     :: oauth2:context(),
      Reason      :: notfound.

%% @doc Looks up an refresh token RefreshToken, returning the corresponding
%% context if a match is found.
%% @end
-callback resolve_refresh_token(RefreshToken) ->
                                           {ok, Context} | {error, Reason} when
      RefreshToken :: oauth2:token(),
      Context      :: oauth2:context(),
      Reason       :: notfound.

%% @doc Revokes an access token AccessToken, so that it cannot be used again.
-callback revoke_access_token(AccessToken) -> ok | {error, Reason} when
      AccessToken :: oauth2:token(),
      Reason      :: notfound.

%% @doc Revokes an access code AccessCode, so that it cannot be used again.
-callback revoke_access_code(AccessCode) -> ok | {error, Reason} when
      AccessCode  :: oauth2:token(),
      Reason      :: notfound.

%% @doc Revokes an refresh token RefreshToken, so that it cannot be used again.
-callback revoke_refresh_token(RefreshToken) -> ok | {error, Reason} when
      RefreshToken :: oauth2:token(),
      Reason       :: notfound.

%% @doc Returns the redirection URI associated with the client ClientId.
-callback get_redirection_uri(ClientId) -> {error, Reason} | {ok, RedirectionUri} when
      ClientId :: binary(),
      Reason :: notfound, 
      RedirectionUri :: binary().

%% @doc Returns a client identity for a given id.
-callback get_client_identity(ClientId) ->
                                {ok, Identity} | {error, Reason} when
      ClientId     :: binary(),
      Identity     :: term(),
      Reason       :: notfound | badsecret.

%% @doc Verifies that RedirectionUri is a valid redirection URI for the
%% client identified by Identity.
%% @end
-callback verify_redirection_uri(Identity, RedirectionUri) -> ok | {error, Reason} when
      Identity       :: term(),
      RedirectionUri :: binary(),
      Reason         :: notfound | baduri.

%% @doc Verifies that Scope is a valid scope for the client identified 
%% by Identity.
%% @end
-callback verify_client_scope(Identity, Scope) -> {ok, Scope2} | {error, Reason} when
      Identity       :: term(),
      Scope          :: oauth2:scope(),
      Scope2         :: oauth2:scope(), 
      Reason         :: notfound | badscope.

%% @doc Verifies that Scope is a valid scope for the resource
%% owner identified by Identity.
%% @end
-callback verify_resowner_scope(Identity, Scope) -> {ok, Scope2} | {error, Reason} when
      Identity       :: term(),
      Scope          :: oauth2:scope(),
      Scope2         :: oauth2:scope(),
      Reason         :: notfound | badscope.
