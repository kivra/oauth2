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

-module(oauth2_token).

-include("oauth2.hrl").

%%% API
-export([
         generate/0
        ]).

%%%===================================================================
%%% API functions
%%%===================================================================

%% @doc Generates a random OAuth2 token.
-spec generate() -> Token :: oauth2:token().
generate() ->
    generate_fragment(?TOKEN_LENGTH).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec generate_fragment(N :: integer()) -> binary().
generate_fragment(0) ->
    <<>>;
generate_fragment(N) ->
    Rand = base64:encode(crypto:rand_bytes(N)),
    Frag = << <<C>> || <<C>> <= <<Rand:N/bytes>>, is_alphanum(C) >>,
    <<Frag/binary, (generate_fragment(N - byte_size(Frag)))/binary>>.

%% @doc Returns true for alphanumeric ASCII characters, false for all others.
-spec is_alphanum(Char :: char()) -> boolean().
is_alphanum(C) when C >= 16#30 andalso C =< 16#39 ->
    true;
is_alphanum(C) when C >= 16#41 andalso C =< 16#5A ->
    true;
is_alphanum(C) when C >= 16#61 andalso C =< 16#7A ->
    true;
is_alphanum(_) ->
    false.
