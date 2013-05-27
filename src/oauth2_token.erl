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

-module(oauth2_token).

-behaviour(oauth2_token_generation).

-include("oauth2.hrl").

%%% API
-export([generate/1]).

%%% Exported for testability
-export([strong_rand_bytes_proxy/1]).

%%%===================================================================
%%% API functions
%%%===================================================================

%% @doc Generates a random OAuth2 token.
-spec generate(Context) -> Token when
    Context :: oauth2:context(),
    Token   :: oauth2:token().
generate(_Context) ->
    generate_fragment(?TOKEN_LENGTH).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec generate_fragment(N) -> Fragment when
   N        :: integer(),
   Fragment :: binary().
generate_fragment(0) ->
    <<>>;
generate_fragment(N) ->
    Rand = base64:encode(rand_bytes(N)),
    Frag = << <<C>> || <<C>> <= <<Rand:N/bytes>>, is_alphanum(C) >>,
    <<Frag/binary, (generate_fragment(N - byte_size(Frag)))/binary>>.

%% @doc Returns true for alphanumeric ASCII characters, false for all others.
-spec is_alphanum(Char) -> Result when
    Char   :: char(),
    Result :: boolean().
is_alphanum(C) when C >= 16#30 andalso C =< 16#39 ->
    true;
is_alphanum(C) when C >= 16#41 andalso C =< 16#5A ->
    true;
is_alphanum(C) when C >= 16#61 andalso C =< 16#7A ->
    true;
is_alphanum(_) ->
    false.

%% @doc Generate N random bytes, using the crypto:strong_rand_bytes
%% function if sufficient entropy exists. If not, use crypto:rand_bytes
%% as a fallback.
-spec rand_bytes(N) -> Result when
    N      :: non_neg_integer(),
    Result :: binary().
rand_bytes(N) ->
    try
        %% NOTE: Apparently we can't meck away the crypto module,
        %% so we install this proxy to allow for testing the low_entropy
        %% situation.
        ?MODULE:strong_rand_bytes_proxy(N)
    catch
        throw:low_entropy ->
            crypto:rand_bytes(N)
    end.

%% @equiv crypto:strong_rand_bytes(N)
-spec strong_rand_bytes_proxy(N) -> Result when
    N      :: non_neg_integer(),
    Result :: binary().
strong_rand_bytes_proxy(N) ->
    crypto:strong_rand_bytes(N).
