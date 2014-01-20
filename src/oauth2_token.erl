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
-module(oauth2_token).

-behaviour(oauth2_token_generation).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------
-export([generate/1]).

%%% Exported for testability
-export([strong_rand_bytes_proxy/1]).

%%%_* Macros ===========================================================
-define(TOKEN_LENGTH, 32).

%%%_* Code =============================================================
%%%_ * API -------------------------------------------------------------
%% @doc Generates a random OAuth2 token.
-spec generate(oauth2:context()) -> oauth2:token().
generate(_Context) -> generate_fragment(?TOKEN_LENGTH).

%%%_* Private functions ================================================
-spec generate_fragment(integer()) -> binary().
generate_fragment(0) -> <<>>;
generate_fragment(N) ->
    Rand = base64:encode(rand_bytes(N)),
    Frag = << <<C>> || <<C>> <= <<Rand:N/bytes>>, is_alphanum(C) >>,
    <<Frag/binary, (generate_fragment(N - byte_size(Frag)))/binary>>.

%% @doc Returns true for alphanumeric ASCII characters, false for all others.
-spec is_alphanum(char()) -> boolean().
is_alphanum(C) when C >= 16#30 andalso C =< 16#39 -> true;
is_alphanum(C) when C >= 16#41 andalso C =< 16#5A -> true;
is_alphanum(C) when C >= 16#61 andalso C =< 16#7A -> true;
is_alphanum(_)                                    -> false.

%% @doc Generate N random bytes, using the crypto:strong_rand_bytes
%%      function if sufficient entropy exists. If not, use crypto:rand_bytes
%%      as a fallback.
-spec rand_bytes(non_neg_integer()) -> binary().
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
-spec strong_rand_bytes_proxy(non_neg_integer()) -> binary().
strong_rand_bytes_proxy(N) -> crypto:strong_rand_bytes(N).

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 4
%%% End:
