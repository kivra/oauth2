%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2012-2014 Kivra
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%% @doc Erlang OAuth 2.0 implementation
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(oauth2_backend).

%%%_ * Types -----------------------------------------------------------
-type grantctx() :: oauth2:context().
-type appctx()   :: oauth2:appctx().
-type token()    :: oauth2:token().
-type scope()    :: oauth2:scope().
-type user()     :: oauth2:user().
-type client()   :: oauth2:client().

%%%_* Behaviour ========================================================
%% @doc Authenticates a combination of username and password.
%%      Returns the resource owner identity if the credentials are valid.
-callback authenticate_user(user(), appctx()) -> {ok, {appctx(), term()}}
                                               | {error, notfound | badpass}.

%% @doc Authenticates a client's credentials for a given scope.
-callback authenticate_client(client(), appctx()) -> {ok, {appctx(), client()}}
                                                | {error, notfound | badsecret}.

%% @doc Stores a new access code token(), associating it with Context.
%%      The context is a proplist carrying information about the identity
%%      with which the code is associated, when it expires, etc.
-callback associate_access_code(token(), grantctx(), appctx()) ->
                                          {ok, appctx()} | {error, notfound}.

%% @doc Stores a new access token token(), associating it with Context.
%%      The context is a proplist carrying information about the identity
%%      with which the token is associated, when it expires, etc.
-callback associate_access_token(token(), grantctx(), appctx()) ->
                                          {ok, appctx()} | {error, notfound}.

%% @doc Stores a new refresh token token(), associating it with
%%      grantctx(). The context is a proplist carrying information about the
%%      identity with which the token is associated, when it expires, etc.
-callback associate_refresh_token(token(), grantctx(), appctx()) ->
                                          {ok, appctx()} | {error, notfound}.

%% @doc Looks up an access token token(), returning the corresponding
%%      context if a match is found.
-callback resolve_access_token(token(), appctx()) ->
                            {ok, {appctx(), grantctx()}} | {error, notfound}.

%% @doc Looks up an access code token(), returning the corresponding
%%      context if a match is found.
-callback resolve_access_code(token(), appctx()) ->
                            {ok, {appctx(), grantctx()}} | {error, notfound}.

%% @doc Looks up an refresh token token(), returning the corresponding
%%      context if a match is found.
-callback resolve_refresh_token(token(), appctx()) ->
                            {ok, {appctx(), grantctx()}} | {error, notfound}.

%% @doc Revokes an access token token(), so that it cannot be used again.
-callback revoke_access_token(token(), appctx()) ->
                                          {ok, appctx()} | {error, notfound}.

%% @doc Revokes an access code token(), so that it cannot be used again.
-callback revoke_access_code(token(), appctx()) ->
                                          {ok, appctx()} | {error, notfound}.

%% @doc Revokes an refresh token token(), so that it cannot be used again.
-callback revoke_refresh_token(token(), appctx()) ->
                                          {ok, appctx()} | {error, notfound}.

%% @doc Returns a client identity for a given id.
-callback get_client_identity(client(), appctx()) ->
                    {ok, {appctx(), client()}} | {error, notfound | badsecret}.

%% @doc Verifies that RedirectionUri is a valid redirection URI for the
%%      client identified by Identity.
-callback verify_redirection_uri(client(), binary(), appctx()) ->
                                 {ok, appctx()} | {error, notfound | baduri}.

%% @doc Verifies that scope() is a valid scope for the client identified
%%      by Identity.
-callback verify_client_scope(client(), scope(), appctx()) ->
                    {ok, {appctx(), scope()}} | {error, notfound | badscope}.

%% @doc Verifies that scope() is a valid scope for the resource
%%      owner identified by Identity.
-callback verify_resowner_scope(term(), scope(), appctx()) ->
                    {ok, {appctx(), scope()}} | {error, notfound | badscope}.

%% @doc Verifies that scope() is a valid scope of the set of scopes defined
%%      by Validscope()s.
-callback verify_scope(scope(), scope(), appctx()) ->
                    {ok, {appctx(), scope()}} | {error, notfound | badscope}.

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 4
%%% End:
