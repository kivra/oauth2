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
-module(oauth2_config).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------
-export([backend/0]).
-export([expiry_time/0]).
-export([expiry_time/1]).
-export([token_generation/0]).

%%%_* Macros ===========================================================
%% Default time in seconds before an authentication token expires.
-define(DEFAULT_TOKEN_EXPIRY, 3600).

%%%_* Code =============================================================
%%%_ * API -------------------------------------------------------------
%% @doc Gets the default expiry time for access tokens.
-spec expiry_time() -> non_neg_integer().
expiry_time() -> get_optional(expiry_time, ?DEFAULT_TOKEN_EXPIRY).

%% @doc Gets a specific expiry time for access tokens if available
%%      returns the default if non found
-spec expiry_time(atom()) -> non_neg_integer().
expiry_time(Flow) ->
    case application:get_env(oauth2, Flow) of
        undefined   -> expiry_time();
        {ok, Value} ->
            case lists:keyfind(expiry_time, 1, Value) of
                false       -> expiry_time();
                {_Key, Val} -> Val
            end
    end.

%% @doc Gets the backend for validating passwords, storing tokens, etc.
-spec backend() -> atom().
backend() -> get_required(backend).

%% @doc Gets the backend for generating tokens.
-spec token_generation() -> atom().
token_generation() -> get_optional(token_generation, oauth2_token).

%%%_* Private functions ================================================
get_optional(Key, Default) ->
    case application:get_env(oauth2, Key) of
        undefined   -> Default;
        {ok, Value} -> Value
    end.

get_required(Key) ->
    case application:get_env(oauth2, Key) of
        undefined   -> throw({missing_config, Key});
        {ok, Value} -> Value
    end.

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 4
%%% End:
