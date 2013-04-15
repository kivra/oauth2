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

-module(oauth2_config).

%%% API
-export([backend/0]).
-export([expiry_time/0]).
-export([expiry_time/1]).
-export([token_generation/0]).

%% Default time in seconds before an authentication token expires.
-define(DEFAULT_TOKEN_EXPIRY, 3600).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Gets the default expiry time for access tokens.
-spec expiry_time() -> ExpiryTime when
   ExpiryTime :: non_neg_integer().
expiry_time() ->
    get_optional(expiry_time, ?DEFAULT_TOKEN_EXPIRY).


%% @doc Gets a specific expiry time for access tokens if available
%%      returns the default if non found
-spec expiry_time(Flow) -> ExpiryTime when
    Flow       :: atom(),
    ExpiryTime :: non_neg_integer().
expiry_time(Flow) ->
    case application:get_env(oauth2, Flow) of
        undefined ->
            expiry_time();
        {ok, Value} ->
            case lists:keyfind(expiry_time, 1, Value) of
                false -> expiry_time();
                {_Key, Val} -> Val
            end
    end.


%% @doc Gets the backend for validating passwords, storing tokens, etc.
-spec backend() -> Module when
   Module :: atom().
backend() ->
    get_required(backend).


%% @doc Gets the backend for generating tokens.
-spec token_generation() -> Module when
   Module :: atom().
token_generation() ->
    get_optional(token_generation, oauth2_token).

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_optional(Key, Default) ->
    case application:get_env(oauth2, Key) of
        undefined ->
            Default;
        {ok, Value} ->
            Value
    end.

get_required(Key) ->
    case application:get_env(oauth2, Key) of
        undefined ->
            throw({missing_config, Key});
        {ok, Value} ->
            Value
    end.
