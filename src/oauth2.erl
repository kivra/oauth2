%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2012-2015 Kivra
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
%%%
%%%      This library is designed to simplify the implementation of the
%%%      server side of OAuth2 (http://tools.ietf.org/html/rfc6749).
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(oauth2).
-compile({no_auto_import, [get/2]}).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------
-export([authorize_password/3]).
-export([authorize_password/4]).
-export([authorize_password/5]).
-export([authorize_client_credentials/3]).
-export([authorize_code_grant/4]).
-export([authorize_code_request/5]).
-export([authorize_directly/4]).
-export([issue_code/2]).
-export([issue_token/2]).
-export([issue_jwt/2]).
-export([issue_token_and_refresh/2]).
-export([issue_jwt_and_refresh/3]).
-export([verify_access_token/2]).
-export([verify_access_code/2]).
-export([verify_access_code/3]).
-export([verify_jwt/1]).
-export([refresh_access_token/4]).
-export([refresh_jwt/4]).

-export_type([token/0]).
-export_type([user/0]).
-export_type([client/0]).
-export_type([context/0]).
-export_type([auth/0]).
-export_type([lifetime/0]).
-export_type([scope/0]).
-export_type([appctx/0]).
-export_type([error/0]).

%%%_* Macros ===========================================================
-define(BACKEND, (oauth2_config:backend())).
-define(TOKEN,   (oauth2_config:token_generation())).

%%%_ * Types -----------------------------------------------------------
%% Opaque authentication record
-record(a, { client   = undefined    :: undefined | term()
           , device_id = undefined   :: undefined | device_id()
           , resowner = undefined    :: undefined | term()
           , scope                   :: scope()
           , ttl      = 0            :: non_neg_integer()
           , issuer   = undefined    :: undefined | binary()
           }).

-type context()   :: proplists:proplist().
-type auth()      :: #a{}.
-type user()      :: any().                      %% Opaque User Object
-type client()    :: any().                      %% Opaque Client Object
-type resowner()  :: any().                      %% Opaque Resource Owner Object
-type rediruri()  :: any().                      %% Opaque Redirection URI
-type device_id() :: any().
-type token()     :: binary().
-type response()  :: oauth2_response:response().
-type lifetime()  :: non_neg_integer().
-type scope()     :: list(binary()) | binary().
-type appctx()    :: term().
-type error()     :: access_denied | invalid_client | invalid_grant |
                     invalid_request | invalid_authorization | invalid_scope |
                     unauthorized_client | unsupported_grant_type |
                     unsupported_response_type | server_error |
                     temporarily_unavailable | atom().

%%%_* Code =============================================================
%%%_ * API -------------------------------------------------------------
%% @doc Validates a request for an access token from resource owner's
%%      credentials. Use it to implement the following steps of RFC 6749:
%%      - 4.3.2. Resource Owner Password Credentials Grant >
%%        Access Token Request, when the client is public.
-spec authorize_password(user(), scope(), appctx())
                            -> {ok, {appctx(), auth()}} | {error, error()}.
authorize_password(User, Scope, Ctx0) ->
    case auth_user(User, Scope, Ctx0) of
        {error, _}=E -> E;
        {ok, _}=Auth -> Auth
    end.

%% @doc Validates a request for an access token from client and resource
%%      owner's credentials. Use it to implement the following steps of
%%      RFC 6749:
%%      - 4.3.2. Resource Owner Password Credentials Grant >
%%        Access Token Request, when the client is confidential.
-spec authorize_password(user(), client(), scope(), appctx())
                            -> {ok, {appctx(), auth()}} | {error, error()}.
authorize_password(User, Client, Scope, Ctx0) ->
    case auth_client(Client, no_redir, Ctx0) of
        {error, _}      -> {error, invalid_client};
        {ok, {Ctx1, C}} ->
            case auth_user(User, Scope, Ctx1) of
                {error, _} = E     -> E;
                {ok, {Ctx2, Auth}} -> {ok, {Ctx2, Auth#a{client=C}}}
            end
    end.

%% @doc Validates a request for an access token from client and resource
%%      owner's credentials. Use it to implement the following steps of
%%      RFC 6749:
%%      - 4.2.1. Implicit Grant > Authorization Request, when the client
%%      is public.
-spec authorize_password(user(), client(), rediruri(), scope(), appctx())
                            -> {ok, {appctx(), auth()}} | {error, error()}.
authorize_password(User, Client, RedirUri, Scope, Ctx0) ->
    case ?BACKEND:get_client_identity(Client,Ctx0) of
      {error, _}   ->{error, invalid_client};
      {ok,{Ctx1,C}} ->
        case ?BACKEND:verify_redirection_uri(C, RedirUri, Ctx1) of
          {error, _}      -> {error, invalid_client};
          {ok, Ctx2} ->
            case auth_user(User, Scope, Ctx2) of
                {error, _} = E     -> E;
                {ok, {Ctx3, Auth}} -> {ok, {Ctx3, Auth#a{client=C}}}
            end
        end
    end.

%% @doc Validates a request for an access token from client's credentials.
%%      Use it to implement the following steps of RFC 6749:
%%      - 4.4.2. Client Credentials Grant > Access Token Request.
-spec authorize_client_credentials(client(), scope(), appctx())
                            -> {ok, {appctx(), auth()}} | {error, error()}.
authorize_client_credentials(Client, Scope0, Ctx0) ->
    case auth_client(Client, no_redir, Ctx0) of
        {error, _}      -> {error, invalid_client};
        {ok, {Ctx1, C}} ->
            case ?BACKEND:verify_client_scope(C, Scope0, Ctx1) of
                {error, _}           -> {error, invalid_scope};
                {ok, {Ctx2, Scope1}} ->
                    {ok, {Ctx2, #a{ client=C
                                  , scope =Scope1
                                  , ttl   =oauth2_config:expiry_time(
                                                       client_credentials)
                                  }}}
            end

    end.

%% @doc Validates a request for an access token from an authorization code.
%%      Use it to implement the following steps of RFC 6749:
%%      - 4.1.3. Authorization Code Grant > Access Token Request.
-spec authorize_code_grant(client(), binary(), rediruri(), appctx())
                            -> {ok, {appctx(), auth()}} | {error, error()}.
authorize_code_grant(Client, Code, RedirUri, Ctx0) ->
    case auth_client(Client, RedirUri, Ctx0) of
        {error, _}      -> {error, invalid_client};
        {ok, {Ctx1, C}} ->
            case verify_access_code(Code, C, Ctx1) of
                {error, _}=E           -> E;
                {ok, {Ctx2, GrantCtx}} ->
                    {ok, Ctx3} = ?BACKEND:revoke_access_code(Code, Ctx2),
                    {ok, {Ctx3, #a{ client  =C
                                  , resowner=get_(GrantCtx,<<"resource_owner">>)
                                  , scope   =get_(GrantCtx, <<"scope">>)
                                  , ttl     =oauth2_config:expiry_time(
                                                      password_credentials)
                                  }}}
            end
    end.

%% @doc Validates a request for an authorization code from client and resource
%%      owner's credentials. Use it to implement the following steps of
%%      RFC 6749:
%%      - 4.1.1. Authorization Code Grant > Authorization Request.
-spec authorize_code_request(user(), client(), rediruri(), scope(), appctx()) ->
                                   {ok, {appctx(), auth()}} | {error, error()}.
authorize_code_request(User, Client, RedirUri, Scope, Ctx0) ->
    case ?BACKEND:get_client_identity(Client, Ctx0) of
        {error, _}      -> {error, unauthorized_client};
        {ok, {Ctx1, C}} ->
            case ?BACKEND:verify_redirection_uri(C, RedirUri, Ctx1) of
                {error, _} -> {error, unauthorized_client};
                {ok, Ctx2} ->
                    case auth_user(User, Scope, Ctx2) of
                        {error, _}=E       -> E;
                        {ok, {Ctx3, Auth}} ->
                            {ok, { Ctx3
                                 , Auth#a{ client=C
                                         , ttl   =oauth2_config:expiry_time(
                                                                    code_grant)
                                         } }}
                    end
            end
    end.

%% @doc Sometimes one wishes to authorize directly with a specific scope and/or
%%      a specific TTL, and this function is for that.
-spec authorize_directly(client(), resowner(), scope(), non_neg_integer()) ->
  auth().
authorize_directly(Client, ResOwner, Scope, TTL) ->
  #a{ client   = Client
    , resowner = ResOwner
    , scope    = Scope
    , ttl      = TTL
    }.

%% @doc Issues an authorization code from an authorization. Use it to implement
%%      the following steps of RFC 6749:
%%      - 4.1.2. Authorization Code Grant > Authorization Response, with the
%%        result of authorize_code_request/6.
-spec issue_code(auth(), appctx()) -> {ok, {appctx(), response()}}.
issue_code(#a{client=Client, resowner=Owner, scope=Scope, ttl=TTL}, Ctx0) ->
    GrantContext = build_context(Client, seconds_since_epoch(TTL), Owner, Scope),
    AccessCode   = ?TOKEN:generate(GrantContext),
    {ok, Ctx1}   = ?BACKEND:associate_access_code(AccessCode,GrantContext,Ctx0),
    {ok, {Ctx1, oauth2_response:new(<<>>,TTL,Owner,Scope,<<>>,<<>>,AccessCode)}}.

%% @doc Issues an access token without refresh token from an authorization.
%%      Use it to implement the following steps of RFC 6749:
%%      - 4.1.4. Authorization Code Grant > Authorization Response, with the
%%        result of authorize_code_grant/5 when no refresh token must be issued.
%%      - 4.2.2. Implicit Grant > Access Token Response, with the result of
%%        authorize_password/7.
%%      - 4.3.3. Resource Owner Password Credentials Grant >
%%        Access Token Response, with the result of authorize_password/4 or
%%        authorize_password/6 when the client is public or no refresh token
%%        must be issued.
%%      - 4.4.3. Client Credentials Grant > Access Token Response, with the
%%        result of authorize_client_credentials/4.
-spec issue_token(auth(), appctx()) -> {ok, {appctx(), response()}} | {error, error()}.
issue_token(#a{client=Client, resowner=Owner, scope=Scope, ttl=TTL}, Ctx0) ->
    GrantContext = build_context(Client,seconds_since_epoch(TTL),Owner,Scope),
    AccessToken  = ?TOKEN:generate(GrantContext),
    case ?BACKEND:associate_access_token(AccessToken, GrantContext, Ctx0) of
        {ok, Ctx1} ->
            {ok, {Ctx1, oauth2_response:new(AccessToken, TTL, Owner, Scope)}};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Issues an JWT without refresh token from an authorization.
-spec issue_jwt(auth(), appctx()) -> {ok, {appctx(), context(), response()}}.
issue_jwt(#a{ client   = Client
            , resowner = ResOwner
            , scope    = Scope
            , ttl      = TTL
            , issuer   = Issuer}, Ctx) ->
    ExpiryTime = seconds_since_epoch(TTL),
    IssuedAt   = seconds_since_epoch(0),
    AccessCtx  = build_jwt_context( Issuer, ResOwner, ExpiryTime, IssuedAt
                                  , Client, Scope),
    {ok, JWT}  = ?BACKEND:jwt_sign(AccessCtx, Ctx),
    {ok, {Ctx, AccessCtx, oauth2_response:new(JWT, TTL)}}.

%% @doc Issues access and refresh tokens from an authorization.
%%      Use it to implement the following steps of RFC 6749:
%%      - 4.1.4. Authorization Code Grant > Access Token Response, with the
%%        result of authorize_code_grant/5 when a refresh token must be issued.
%%      - 4.3.3. Resource Owner Password Credentials Grant >
%%        Access Token Response, with the result of authorize_password/6 when
%%        the client is confidential and a refresh token must be issued.
-spec issue_token_and_refresh(auth(), appctx()) -> {ok, {appctx(), response()}}
                                                 | {error, invalid_authorization}.
issue_token_and_refresh(#a{client = undefined}, _Ctx)   ->
  {error, invalid_authorization};
issue_token_and_refresh(#a{resowner = undefined}, _Ctx) ->
  {error, invalid_authorization};
issue_token_and_refresh( #a{client=Client, resowner=Owner, scope=Scope, ttl=TTL, device_id = DeviceId}
                       , Ctx0 ) ->
    RTTL         = oauth2_config:expiry_time(refresh_token),
    RefreshCtx   = build_context(Client,seconds_since_epoch(RTTL),Owner,Scope),
    RefreshToken = ?TOKEN:generate(RefreshCtx),
    AccessCtx    = build_context(Client,seconds_since_epoch(TTL),Owner,Scope,RefreshToken),
    AccessToken  = ?TOKEN:generate(AccessCtx),
    {ok, Ctx1}   = ?BACKEND:associate_access_token( AccessToken
                                                  , AccessCtx
                                                  , Ctx0),
    {ok, Ctx2}   = ?BACKEND:associate_refresh_token( RefreshToken
                                                   , RefreshCtx
                                                   , Ctx1 ),
    {ok, Ctx2}   =
        case DeviceId of
            undefined -> ?BACKEND:associate_refresh_token(RefreshToken, RefreshCtx, Ctx1);
            _         -> ?BACKEND:associate_refresh_token(RefreshToken, RefreshCtx, DeviceId, Ctx1)
        end,
    {ok, {Ctx2, oauth2_response:new( AccessToken
                                   , TTL
                                   , Owner
                                   , Scope
                                   , RefreshToken
                                   , RTTL )}}.

%% @doc Issues JWT and refresh token from an authorization.
-spec issue_jwt_and_refresh(auth(), binary(), appctx()) ->
                              {ok, {appctx(), context(), response()}}
                            | {error, invalid_authorization}.
issue_jwt_and_refresh(#a{client = undefined}, _, _)   ->
    {error, invalid_authorization};
issue_jwt_and_refresh(#a{resowner = undefined}, _, _) ->
    {error, invalid_authorization};
issue_jwt_and_refresh( #a{ client   = Client
                         , resowner = ResOwner
                         , scope    = Scope
                         , ttl      = TTL
                         , issuer   = Issuer}
                     , DeviceId
                     , Ctx0) ->
    % access_token
    AccessExpiry  = seconds_since_epoch(TTL),
    IssuedAt      = seconds_since_epoch(0),
    AccessCtx     = build_jwt_context( Issuer, ResOwner, AccessExpiry, IssuedAt
                                     , Client, Scope),
    {ok, JWT}     = ?BACKEND:jwt_sign(AccessCtx, Ctx0),

    % refresh_token
    RefreshTTL    = oauth2_config:expiry_time(jwt_refresh_token),
    RefreshExpiry = seconds_since_epoch(RefreshTTL),
    RefreshCtx    = build_context(Client, RefreshExpiry, ResOwner, Scope),
    RefreshToken  = ?TOKEN:generate(RefreshCtx),
    {ok, Ctx1}    = ?BACKEND:associate_refresh_token( RefreshToken, RefreshCtx
                                                    , DeviceId, Ctx0),
    {ok, {Ctx1, AccessCtx, oauth2_response:new(JWT, TTL, RefreshToken)}}.

%% @doc Verifies an access code AccessCode, returning its associated
%%      context if successful. Otherwise, an OAuth2 error code is returned.
-spec verify_access_code(token(), appctx()) -> {ok, {appctx(), context()}}
                                             | {error, error()}.
verify_access_code(AccessCode, Ctx0) ->
    case ?BACKEND:resolve_access_code(AccessCode, Ctx0) of
        {error, _}             -> {error, invalid_grant};
        {ok, {Ctx1, GrantCtx}} ->
            case get_(GrantCtx, <<"expiry_time">>) > seconds_since_epoch(0) of
                true  -> {ok, {Ctx1, GrantCtx}};
                false ->
                    ?BACKEND:revoke_access_code(AccessCode, Ctx1),
                    {error, invalid_grant}
            end
    end.

%% @doc Verifies an access code AccessCode and it's corresponding Identity,
%%      returning its associated context if successful. Otherwise, an OAuth2
%%      error code is returned.
-spec verify_access_code(token(), client(), appctx()) ->
                                {ok, {appctx(), context()}} | {error, error()}.
verify_access_code(AccessCode, Client, Ctx0) ->
    case verify_access_code(AccessCode, Ctx0) of
        {error, _}=E           -> E;
        {ok, {Ctx1, GrantCtx}} ->
            case get(GrantCtx, <<"client">>) of
                {ok, Client} -> {ok, {Ctx1, GrantCtx}};
                _            -> {error, invalid_grant}
            end
    end.

%% @doc Validates a request for an access token from a refresh token, issuing
%%      a new access token if valid. Use it to implement the following steps of
%%      RFC 6749:
%%      - 6. Refreshing an Access Token.
-spec refresh_access_token(client(), token(), scope(), appctx())
                            -> {ok, {appctx(), response()}} | {error, error()}.
refresh_access_token(Client, RefreshToken, Scope, Ctx0) ->
    case verify_refresh_token_basic(Client, RefreshToken, Scope, Ctx0) of
      {ok, {Ctx1, ClientId, ResOwner, VerifiedScope, TTL, DeviceId}} ->
          issue_token(#a{ client    = ClientId
                        , resowner  = ResOwner
                        , scope     = VerifiedScope
                        , ttl       = TTL
                        , device_id = DeviceId
                        }, Ctx1);
      {error, _} = E -> E
    end.

%% @doc Validates a request for a JWT from a refresh token, issuing a new JWT
%%      if valid.
-spec refresh_jwt(client(), token(), scope(), appctx()) ->
                    {ok, {appctx(), context(), response()}}
                  | {error, error()}.
refresh_jwt(Client, RefreshToken, Scope, Ctx0) ->
    case verify_refresh_token_basic(Client, RefreshToken, Scope, Ctx0) of
        {ok, {Ctx1, ClientId, ResOwner, VerifiedScope, TTL, DeviceId}} ->
            % RFC 6749 Section 10.4 (Security Considerations for refresh_token)
            %
            % Authorization server could employ refresh token rotation in which
            % a new refresh token is issued with every access token refresh
            % response.  The previous refresh token is invalidated but retained
            % by the authorization server.  If a refresh token is compromised
            % and subsequently used by both the attacker and the legitimate
            % client, one of them will present an invalidated refresh token,
            % which will inform the authorization server of the breach.
            %
            % TODO: implement this
            ?BACKEND:revoke_refresh_token(RefreshToken, Ctx1),
            issue_jwt_and_refresh( #a{ client   = ClientId
                                     , resowner = ResOwner
                                     , scope    = VerifiedScope
                                     , ttl      = TTL
                                     , issuer   = ?BACKEND:jwt_issuer()
                                     }
                                 , DeviceId
                                 , Ctx1);
        {error, _} = E -> E
    end.

%% @doc Verifies an access token AccessToken, returning its associated
%%      context if successful. Otherwise, an OAuth2 error code is returned.
-spec verify_access_token(token(), appctx()) -> {ok, {appctx(), context()}}
                                              | {error, error()}.
verify_access_token(AccessToken, Ctx0) ->
    case ?BACKEND:resolve_access_token(AccessToken, Ctx0) of
        {error, _}             -> {error, access_denied};
        {ok, {Ctx1, GrantCtx}} ->
            case get_(GrantCtx, <<"expiry_time">>) > seconds_since_epoch(0) of
                true  -> {ok, {Ctx1, GrantCtx}};
                false ->
                    ?BACKEND:revoke_access_token(AccessToken, Ctx1),
                    {error, access_denied}
            end
    end.

%% @doc Verifies a JWT, returning its associated context if successful.
%%      Otherwise, an OAuth2 error code is returned.
-spec verify_jwt(token()) -> {ok, context()} | {error, error()}.
verify_jwt(JWT) ->
    case ?BACKEND:jwt_verify(JWT) of
        {error, _}     -> {error, access_denied};
        {ok, GrantCtx} ->
            case get_(GrantCtx, <<"exp">>) > seconds_since_epoch(0) of
                true  -> {ok, GrantCtx};
                false -> {error, access_denied}
            end
    end.

%%%_* Private functions ================================================
auth_user(User, Scope0, Ctx0) ->
    case ?BACKEND:authenticate_user(User, Ctx0) of
        {error, _}=E        -> E;
        {ok, {Ctx1, Owner}} ->
            case ?BACKEND:verify_resowner_scope(Owner, Scope0, Ctx1) of
                {error, _}           -> {error, invalid_scope};
                {ok, {Ctx2, Scope1}} ->
                    {ok, {Ctx2, #a{ resowner = Owner
                                  , scope    = Scope1
                                  , ttl      = oauth2_config:expiry_time(
                                                         password_credentials)
                                  , issuer   = ?BACKEND:jwt_issuer()
                                  }}}
            end
    end.

auth_client(Client, no_redir, Ctx0) ->
    ?BACKEND:authenticate_client(Client, Ctx0);
auth_client(Client, RedirUri, Ctx0) ->
    case auth_client(Client, no_redir, Ctx0) of
        {error, _}=E    -> E;
        {ok, {Ctx1, C}} ->
            case ?BACKEND:verify_redirection_uri(C, RedirUri, Ctx1) of
                {error, _} -> {error, invalid_grant};
                {ok, Ctx2} -> {ok, {Ctx2, C}}
            end
    end.

verify_refresh_token_basic(Client, RefreshToken, Scope, Ctx0) ->
    case auth_client(Client, no_redir, Ctx0) of
        {error, _}             -> {error, invalid_client};
        {ok, {Ctx1, ClientId}} ->
            case ?BACKEND:resolve_refresh_token(RefreshToken, Ctx1) of
                {error, _}             -> {error, invalid_grant};
                {ok, {Ctx2, GrantCtx}} ->
                    {ok, ExpiryAbsolute} = get(GrantCtx, <<"expiry_time">>),
                    case ExpiryAbsolute > seconds_since_epoch(0) of
                        true ->
                            {ok, ResOwner} = get(GrantCtx, <<"resource_owner">>),
                            case ?BACKEND:verify_resowner_scope(ResOwner, Scope, Ctx2) of
                                {error, _}                  -> {error, invalid_scope};
                                {ok, {Ctx3, VerifiedScope}} ->
                                    {ok, ClientId} = get(GrantCtx, <<"client">>),
                                    {ok, ResOwner} = get(GrantCtx, <<"resource_owner">>),
                                    DeviceId       = get(GrantCtx, <<"device_id">>, undefined),
                                    TTL            = oauth2_config:expiry_time(
                                                       password_credentials),
                                    {ok, { Ctx3, ClientId, ResOwner
                                         , VerifiedScope, TTL, DeviceId}}
                            end;
                        false ->
                            ?BACKEND:revoke_refresh_token(RefreshToken, Ctx2),
                            {error, invalid_grant}
                    end
            end
    end.

-spec build_context(term(), non_neg_integer(), term(), scope()) -> context().
build_context(Client, ExpiryTime, ResOwner, Scope) ->
    [ {<<"client">>,         Client}
    , {<<"resource_owner">>, ResOwner}
    , {<<"expiry_time">>,    ExpiryTime}
    , {<<"scope">>,          Scope}
    ].

build_context(Client, ExpiryTime, ResOwner, Scope, RefreshToken) ->
  [{<<"refresh_token">>, RefreshToken} | build_context(Client, ExpiryTime, ResOwner, Scope)].

build_jwt_context(Issuer, ResOwner, ExpiryTime, IssuedAt, Client, Scope) ->
    [ {<<"iss">>,    Issuer}
    , {<<"sub">>,    ResOwner}
    , {<<"exp">>,    ExpiryTime}
    , {<<"iat">>,    IssuedAt}
    , {<<"client">>, Client}
    , {<<"scope">>,  Scope}
    ].

-spec seconds_since_epoch(integer()) -> non_neg_integer().
seconds_since_epoch(Diff) ->
    {Mega, Secs, _} = os:timestamp(),
    Mega * 1000000 + Secs + Diff.

get(O, K)  ->
    case lists:keyfind(K, 1, O) of
        {K, V} -> {ok, V};
        false  -> {error, notfound}
    end.

get(O, K, D) ->
    case get(O, K) of
        {ok, V}           -> V;
        {error, notfound} -> D
    end.

get_(O, K) ->
    {ok, V} = get(O, K),
    V.

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 4
%%% End:
